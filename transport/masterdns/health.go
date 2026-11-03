package masterdns

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/wire"
)

const (
	PacketTimeout           = 10 * time.Second
	autoDisableWindow       = 30 * time.Second
	streamFailoverThreshold = 2
	streamFailoverCooldown  = 2500 * time.Millisecond
	confirmDownAttempts     = 2
)

// runHealthLoop sweeps timed out sends and re-probes inactive resolvers at the session MTUs, like the reference resolver health loop.
func (c *Client) runHealthLoop(ctx context.Context) {
	active, inactive := c.healthCounts()
	recheckInterval := resolverHealthInterval(active, inactive)
	parallelism := resolverHealthBatchSize(active, inactive)
	for {
		if ctx.Err() != nil {
			return
		}
		if c.resolversChanged.Swap(false) {
			c.refreshResolvers(ctx, true)
		}
		c.balancer.CollectExpiredTimeouts(time.Now(), PacketTimeout)
		c.runHealthBatch(ctx, recheckInterval, parallelism)
		timer := time.NewTimer(autoDisableCheckInterval(max(c.balancer.ActiveCount(), 1), autoDisableWindow))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-c.healthWake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (c *Client) healthCounts() (active int, inactive int) {
	active = c.balancer.ActiveCount()
	total := max(c.balancer.TotalCount(), active)
	return active, total - active
}

func (c *Client) runHealthBatch(ctx context.Context, recheckInterval time.Duration, parallelism int) {
	connections := make([]Connection, 0, parallelism)
	now := time.Now()
	for len(connections) < parallelism {
		conn, loaded := c.balancer.NextInactiveForHealthCheck(now, recheckInterval)
		if !loaded || conn.Valid {
			break
		}
		connections = append(connections, conn)
	}
	var group sync.WaitGroup
	for _, conn := range connections {
		group.Go(func() {
			c.recheckResolver(ctx, conn)
		})
	}
	group.Wait()
}

func (c *Client) recheckResolver(ctx context.Context, conn Connection) {
	probeConn, err := c.dialResolver(ctx, conn.Resolver)
	if err != nil {
		return
	}
	defer probeConn.Close()
	domain := c.domains[conn.Domain]
	timeout := c.healthProbeTimeout()
	passed := false
	for range c.config.MTU.TestRetries {
		if ctx.Err() != nil {
			return
		}
		upload, _ := c.syncedMTU()
		if outcome, _, err := c.uploadProbe(ctx, probeConn, domain, upload, timeout); err == nil && outcome == probePassed {
			passed = true
			break
		}
	}
	if !passed {
		return
	}
	passed = false
	for range c.config.MTU.TestRetries {
		if ctx.Err() != nil {
			return
		}
		upload, download := c.syncedMTU()
		if outcome, _, err := c.downloadProbe(ctx, probeConn, domain, download, upload, timeout); err == nil && outcome == probePassed {
			passed = true
			break
		}
	}
	if !passed {
		return
	}
	upload, download := c.syncedMTU()
	if !c.balancer.SetMTU(conn.Key, upload, wire.EncodedChars(upload, c.config.EncryptionMethod), download) || !c.balancer.SetValid(conn.Key, true) {
		return
	}
	c.balancer.SeedConservativeStats(conn.Key)
	c.logger.Info("resolver ", conn.Resolver, " reactivated for ", conn.Domain, ", ", c.balancer.ActiveCount(), " active")
}

func (c *Client) healthProbeTimeout() time.Duration {
	timeout := c.config.MTU.TestTimeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	active := max(c.balancer.ActiveCount(), 1)
	switch {
	case active <= 3:
		timeout = max(timeout, 7*time.Second)
	case active <= 5:
		timeout = max(timeout, 6*time.Second)
	case active <= 8:
		timeout = max(timeout, 5500*time.Millisecond)
	case active <= 10:
		timeout = max(timeout, 5*time.Second)
	case active <= 15:
		timeout = max(timeout, 4500*time.Millisecond)
	}
	return timeout
}

// confirmResolverDown sends two small upload probes before a resolver whose sends all timed out is disabled.
func (c *Client) confirmResolverDown(conn Connection, window time.Duration) bool {
	ctx := c.lifetime()
	probeConn, err := c.dialResolver(ctx, conn.Resolver)
	if err != nil {
		return true
	}
	defer probeConn.Close()
	timeout := 350 * time.Millisecond
	if window > 0 && window < time.Second {
		timeout = window / 3
	}
	timeout = min(max(timeout, 200*time.Millisecond), time.Second)
	upload, _ := c.syncedMTU()
	size := min(max(upload, 32), 96)
	for range confirmDownAttempts {
		if outcome, _, err := c.uploadProbe(ctx, probeConn, c.domains[conn.Domain], size, timeout); err == nil && outcome == probePassed {
			return false
		}
	}
	return true
}

func resolverHealthInterval(active int, inactive int) time.Duration {
	if inactive <= 0 {
		return 12 * time.Second
	}
	var interval time.Duration
	switch {
	case inactive <= 3:
		interval = 12 * time.Second
	case inactive <= 6:
		interval = 10 * time.Second
	case inactive <= 12:
		interval = 8 * time.Second
	case inactive <= 24:
		interval = 6 * time.Second
	case inactive <= 48:
		interval = 5 * time.Second
	case inactive <= 96:
		interval = 4 * time.Second
	default:
		interval = 3 * time.Second
	}
	switch {
	case active <= 3:
		interval = max(interval, 12*time.Second)
	case active <= 5:
		interval = max(interval, 10*time.Second)
	case active <= 10:
		interval = max(interval, 8*time.Second)
	case active >= 100 && inactive >= 40:
		interval = min(interval, 2*time.Second)
	case active >= 50 && inactive >= 20:
		interval = min(interval, 3*time.Second)
	}
	return min(max(interval, 2*time.Second), 12*time.Second)
}

func resolverHealthBatchSize(active int, inactive int) int {
	if inactive <= 0 {
		return 1
	}
	var batch int
	switch {
	case inactive <= 2:
		batch = 1
	case inactive <= 5:
		batch = 2
	case inactive <= 10:
		batch = 3
	case inactive <= 20:
		batch = 4
	case inactive <= 40:
		batch = 6
	case inactive <= 80:
		batch = 8
	case inactive <= 120:
		batch = 10
	case inactive <= 200:
		batch = 12
	default:
		batch = 14
	}
	switch {
	case active <= 3:
		batch = min(batch, 2)
	case active <= 5:
		batch = min(batch, 3)
	case active <= 10:
		batch = min(batch, 4)
	case active >= 100 && inactive >= 40:
		batch += 2
	case active >= 50 && inactive >= 20:
		batch++
	}
	if active >= 20 && inactive*4 < active && batch > 2 {
		batch--
	}
	return max(min(batch, 16, inactive), 1)
}
