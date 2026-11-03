package masterdns

import (
	"context"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/wire"
)

const (
	defaultUploadMaxCap = 512
	minUploadMTUFloor   = 10
	minDownloadMTUFloor = wire.SessionAcceptSize
)

var downloadProbeReserve = max(wire.MaxHeaderSize-wire.HeaderSize(wire.PacketMTUDownResponse), 0)

type MTURejectReason uint8

const (
	MTURejectNone MTURejectReason = iota
	MTURejectUpload
	MTURejectDownload
	// MTURejectTimeout and MTURejectDecode are upload rejections where no answer arrived or none carried a tunnel packet.
	MTURejectTimeout
	MTURejectDecode
)

type MTUResult struct {
	UploadMTU      int
	UploadMTUChars int
	DownloadMTU    int
	ResolveTime    time.Duration
}

type probeOutcome uint8

const (
	probeNoAnswer probeOutcome = iota
	probeUndecodable
	probeRejected
	probePassed
)

// BinarySearchMTU checks the maximum first, then the minimum, then bisects between them; each check gets retries attempts.
func BinarySearchMTU(ctx context.Context, minValue int, maxValue int, minFloor int, retries int, test func(size int, retry bool) (bool, time.Duration, error)) (int, time.Duration) {
	if maxValue <= 0 {
		return 0, 0
	}
	low := max(minValue, minFloor)
	high := maxValue
	if high < low {
		return 0, 0
	}
	check := func(value int) (bool, time.Duration) {
		for attempt := range retries {
			if ctx.Err() != nil {
				return false, 0
			}
			passed, rtt, err := test(value, attempt > 0)
			if err == nil && passed {
				return true, rtt
			}
		}
		return false, 0
	}
	if passed, rtt := check(high); passed {
		return high, rtt
	}
	if low == high {
		return 0, 0
	}
	passed, bestRTT := check(low)
	if !passed {
		return 0, 0
	}
	best := low
	for left, right := low+1, high-1; left <= right; {
		if ctx.Err() != nil {
			return 0, 0
		}
		middle := (left + right) / 2
		if passed, rtt := check(middle); passed {
			best, bestRTT = middle, rtt
			left = middle + 1
		} else {
			right = middle - 1
		}
	}
	return best, bestRTT
}

// OptimizeMTU drops low-MTU outliers when that lifts the session minimum enough, as the reference AUTO_REMOVE_LOW_MTU_SERVERS does.
func OptimizeMTU(connections []Connection, autoRemove bool) (kept []Connection, removed []Connection, minUpload int, minDownload int, minUploadChars int) {
	valid, oldMinUpload, oldMinDownload, oldMinUploadChars := summarizeMTU(connections)
	total := len(valid)
	if !autoRemove || total < 5 {
		return valid, nil, oldMinUpload, oldMinDownload, oldMinUploadChars
	}
	var (
		maxDropRatio    float64
		toleranceRatio  float64
		minGainUpload   int
		minGainDownload int
	)
	switch {
	case total > 1000:
		maxDropRatio, toleranceRatio, minGainUpload, minGainDownload = 0.35, 0.85, 24, 64
	case total > 200:
		maxDropRatio, toleranceRatio, minGainUpload, minGainDownload = 0.30, 0.80, 32, 96
	case total > 150:
		maxDropRatio, toleranceRatio, minGainUpload, minGainDownload = 0.28, 0.78, 40, 96
	case total > 100:
		maxDropRatio, toleranceRatio, minGainUpload, minGainDownload = 0.27, 0.77, 44, 104
	case total > 75:
		maxDropRatio, toleranceRatio, minGainUpload, minGainDownload = 0.26, 0.76, 46, 112
	case total > 50:
		maxDropRatio, toleranceRatio, minGainUpload, minGainDownload = 0.25, 0.75, 48, 128
	case total >= 25:
		maxDropRatio, toleranceRatio, minGainUpload, minGainDownload = 0.22, 0.72, 56, 128
	default:
		maxDropRatio, toleranceRatio, minGainUpload, minGainDownload = 0.20, 0.70, 64, 160
	}
	maxDrops := max(int(float64(total)*maxDropRatio), 1)
	uploads := make([]int, total)
	downloads := make([]int, total)
	for i, conn := range valid {
		uploads[i] = conn.UploadMTU
		downloads[i] = conn.DownloadMTU
	}
	slices.Sort(uploads)
	slices.Sort(downloads)
	targetUpload, worthUpload, relativeUpload := mtuOutlierTarget(uploads, oldMinUpload, toleranceRatio, 24, minGainUpload, maxDrops)
	targetDownload, worthDownload, relativeDownload := mtuOutlierTarget(downloads, oldMinDownload, toleranceRatio, 96, minGainDownload, maxDrops)
	if !worthUpload && !worthDownload {
		return valid, nil, oldMinUpload, oldMinDownload, oldMinUploadChars
	}
	isOutlier := func(conn Connection) bool {
		return worthUpload && conn.UploadMTU < targetUpload || worthDownload && conn.DownloadMTU < targetDownload
	}
	projectedDrops := 0
	for _, conn := range valid {
		if isOutlier(conn) {
			projectedDrops++
		}
	}
	if projectedDrops > maxDrops {
		if relativeUpload >= relativeDownload {
			worthDownload = false
		} else {
			worthUpload = false
		}
		if !worthUpload && !worthDownload {
			return valid, nil, oldMinUpload, oldMinDownload, oldMinUploadChars
		}
	}
	for _, conn := range valid {
		if isOutlier(conn) {
			removed = append(removed, conn)
		} else {
			kept = append(kept, conn)
		}
	}
	if len(kept) == 0 {
		return valid, nil, oldMinUpload, oldMinDownload, oldMinUploadChars
	}
	_, minUpload, minDownload, minUploadChars = summarizeMTU(kept)
	return kept, removed, minUpload, minDownload, minUploadChars
}

func mtuOutlierTarget(sorted []int, oldMinimum int, toleranceRatio float64, minGap int, minGain int, maxDrops int) (target int, worthIt bool, relativeGain float64) {
	total := len(sorted)
	p75 := sorted[total*3/4]
	threshold := int(float64(p75) * toleranceRatio)
	if p75-threshold < minGap {
		threshold = p75 - minGap
	}
	threshold = max(threshold, 1)
	drops := 0
	for _, value := range sorted {
		if value < threshold {
			drops++
		}
	}
	drops = min(drops, maxDrops)
	achievable := oldMinimum
	if drops > 0 && drops < total {
		achievable = sorted[drops]
	}
	gain := achievable - oldMinimum
	if oldMinimum > 0 {
		relativeGain = float64(gain) / float64(oldMinimum)
	}
	worthIt = drops > 0 && (gain >= minGain || relativeGain >= 0.35)
	if !worthIt {
		return oldMinimum, false, relativeGain
	}
	return achievable, true, relativeGain
}

func summarizeMTU(connections []Connection) (valid []Connection, minUpload int, minDownload int, minUploadChars int) {
	valid = make([]Connection, 0, len(connections))
	for _, conn := range connections {
		if !conn.Valid {
			continue
		}
		valid = append(valid, conn)
		minUpload = minPositive(minUpload, conn.UploadMTU)
		minDownload = minPositive(minDownload, conn.DownloadMTU)
		minUploadChars = minPositive(minUploadChars, conn.UploadMTUChars)
	}
	return
}

func minPositive(current int, candidate int) int {
	if candidate <= 0 {
		return current
	}
	if current == 0 || candidate < current {
		return candidate
	}
	return current
}

func mtuTestParallelism(parallelism int, resolvers int, rxtxWorkers int) int {
	if resolvers <= 1 {
		return max(1, parallelism)
	}
	var recommended int
	switch {
	case resolvers <= 4:
		recommended = 2
	case resolvers <= 8:
		recommended = 4
	case resolvers <= 16:
		recommended = 6
	case resolvers <= 32:
		recommended = 8
	case resolvers <= 64:
		recommended = 12
	case resolvers <= 128:
		recommended = 16
	default:
		recommended = 20
	}
	recommended = min(recommended, min(max(rxtxWorkers*2, 4), 24))
	return max(parallelism, recommended)
}

func (c *Client) runMTUScan(ctx context.Context) error {
	connections := c.balancer.AllConnections()
	if len(connections) == 0 {
		return ErrNoValidConnections
	}
	uploadCaps := make(map[string]int, len(c.config.Domains))
	for _, domain := range c.config.Domains {
		uploadCaps[domain] = wire.MaxUploadPayload(domain, c.config.EncryptionMethod)
	}
	c.access.Lock()
	workers := min(mtuTestParallelism(c.config.MTU.TestParallelism, len(c.resolvers), c.settings.RXTXWorkers), len(connections))
	c.access.Unlock()
	c.logger.Info("testing MTU of ", len(connections), " resolver connections, ", workers, " at a time")
	if workers <= 1 {
		for _, conn := range connections {
			if ctx.Err() != nil {
				return nil
			}
			c.testConnectionMTU(ctx, conn, uploadCaps[conn.Domain])
		}
	} else {
		jobs := make(chan Connection, len(connections))
		var group sync.WaitGroup
		for range workers {
			group.Go(func() {
				for conn := range jobs {
					if ctx.Err() != nil {
						return
					}
					c.testConnectionMTU(ctx, conn, uploadCaps[conn.Domain])
				}
			})
		}
		for _, conn := range connections {
			select {
			case <-ctx.Done():
				close(jobs)
				group.Wait()
				return nil
			case jobs <- conn:
			}
		}
		close(jobs)
		group.Wait()
	}
	kept, removed, minUpload, minDownload, minUploadChars := OptimizeMTU(c.balancer.ActiveConnections(), c.config.MTU.AutoRemoveLow)
	for _, conn := range removed {
		c.logger.Debug("MTU optimizer dropped ", conn.Resolver, " for ", conn.Domain, ": upload ", conn.UploadMTU, ", download ", conn.DownloadMTU)
		c.balancer.SetValid(conn.Key, false)
	}
	if len(kept) == 0 {
		return ErrNoValidConnections
	}
	c.applySyncedMTU(minUpload, minDownload, minUploadChars)
	c.logger.Info("MTU test finished: ", len(kept), " of ", len(connections), " resolver connections usable, upload MTU ", minUpload, ", download MTU ", minDownload)
	return nil
}

func (c *Client) testConnectionMTU(ctx context.Context, conn Connection, maxUploadPayload int) {
	result, reason := c.ProbeConnection(ctx, conn, maxUploadPayload)
	switch reason {
	case MTURejectNone:
		c.balancer.ApplyProbeResult(conn.Key, result.UploadMTU, result.UploadMTUChars, result.DownloadMTU, result.ResolveTime, true)
		c.logger.Debug("resolver ", conn.Resolver, " accepted for ", conn.Domain, ": upload MTU ", result.UploadMTU, ", download MTU ", result.DownloadMTU)
	case MTURejectDownload:
		c.balancer.ApplyProbeResult(conn.Key, result.UploadMTU, result.UploadMTUChars, 0, 0, false)
		c.logger.Debug("resolver ", conn.Resolver, " rejected for ", conn.Domain, ": download MTU")
	default:
		c.balancer.ApplyProbeResult(conn.Key, 0, 0, 0, 0, false)
		c.logger.Debug("resolver ", conn.Resolver, " rejected for ", conn.Domain, ": upload MTU")
	}
}

func (c *Client) applySyncedMTU(upload int, download int, uploadChars int) {
	c.access.Lock()
	defer c.access.Unlock()
	c.uploadMTU = upload
	c.downloadMTU = download
	c.uploadMTUChars = uploadChars
	c.safeUploadMTU = wire.SafeUploadMTU(upload, c.config.EncryptionMethod)
	c.maxPackedBlocks = wire.MaxPackedBlocks(upload, 80, c.settings.MaxPacketsPerBatch)
	c.applyCompressionPolicyLocked()
}

func (c *Client) syncedMTU() (upload int, download int) {
	c.access.Lock()
	defer c.access.Unlock()
	return c.uploadMTU, c.downloadMTU
}

// ProbeConnection runs the reference MTU test of one resolver and domain on a fresh socket without touching the balancer.
func (c *Client) ProbeConnection(ctx context.Context, conn Connection, maxUploadPayload int) (MTUResult, MTURejectReason) {
	return c.probeConnection(ctx, conn, maxUploadPayload, false)
}

// probeConnection in quick mode only checks the minimum upload and download sizes.
func (c *Client) probeConnection(ctx context.Context, conn Connection, maxUploadPayload int, quick bool) (MTUResult, MTURejectReason) {
	probeConn, err := c.dialResolver(ctx, conn.Resolver)
	if err != nil {
		return MTUResult{}, MTURejectTimeout
	}
	defer probeConn.Close()
	domain := c.domains[conn.Domain]
	outcome := probeNoAnswer
	upload, uploadRTT := c.testUploadMTU(ctx, probeConn, domain, maxUploadPayload, quick, &outcome)
	if upload == 0 {
		switch outcome {
		case probeNoAnswer:
			return MTUResult{}, MTURejectTimeout
		case probeUndecodable:
			return MTUResult{}, MTURejectDecode
		default:
			return MTUResult{}, MTURejectUpload
		}
	}
	result := MTUResult{
		UploadMTU:      upload,
		UploadMTUChars: wire.EncodedChars(upload, c.config.EncryptionMethod),
	}
	download, downloadRTT := c.testDownloadMTU(ctx, probeConn, domain, upload, quick)
	if download == 0 {
		return result, MTURejectDownload
	}
	result.DownloadMTU = download
	result.ResolveTime = averageRTT(uploadRTT, downloadRTT)
	return result, MTURejectNone
}

func (c *Client) testUploadMTU(ctx context.Context, conn net.Conn, domain wire.Domain, maxPayload int, quick bool, outcome *probeOutcome) (int, time.Duration) {
	c.access.Lock()
	limit := c.settings.MaxUploadMTU
	c.access.Unlock()
	if limit <= 0 || limit > defaultUploadMaxCap {
		limit = defaultUploadMaxCap
	}
	maxValue := min(maxPayload, limit)
	if quick {
		maxValue = min(maxValue, max(c.config.MTU.MinUpload, minUploadMTUFloor))
	}
	if maxValue < max(c.config.MTU.MinUpload, minUploadMTUFloor) {
		*outcome = probeRejected
		return 0, 0
	}
	best, rtt := BinarySearchMTU(ctx, c.config.MTU.MinUpload, maxValue, minUploadMTUFloor, c.config.MTU.TestRetries, func(size int, retry bool) (bool, time.Duration, error) {
		result, rtt, err := c.uploadProbe(ctx, conn, domain, size, c.config.MTU.TestTimeout)
		*outcome = max(*outcome, result)
		return result == probePassed, rtt, err
	})
	if best < max(minUploadMTUFloor, c.config.MTU.MinUpload) {
		return 0, 0
	}
	return best, rtt
}

func (c *Client) testDownloadMTU(ctx context.Context, conn net.Conn, domain wire.Domain, uploadMTU int, quick bool) (int, time.Duration) {
	c.access.Lock()
	maxValue := c.settings.MaxDownloadMTU
	c.access.Unlock()
	if quick {
		maxValue = min(maxValue, max(c.config.MTU.MinDownload, minDownloadMTUFloor))
	}
	best, rtt := BinarySearchMTU(ctx, c.config.MTU.MinDownload, maxValue, minDownloadMTUFloor, c.config.MTU.TestRetries, func(size int, retry bool) (bool, time.Duration, error) {
		result, rtt, err := c.downloadProbe(ctx, conn, domain, size, uploadMTU, c.config.MTU.TestTimeout)
		return result == probePassed, rtt, err
	})
	if best < max(minDownloadMTUFloor, c.config.MTU.MinDownload) {
		return 0, 0
	}
	return best, rtt
}

func (c *Client) uploadProbe(ctx context.Context, conn net.Conn, domain wire.Domain, size int, timeout time.Duration) (probeOutcome, time.Duration, error) {
	if size < wire.MinUploadProbe {
		return probeNoAnswer, 0, nil
	}
	if err := ctx.Err(); err != nil {
		return probeNoAnswer, 0, err
	}
	code := c.probeCode.Add(1)
	query, err := c.buildQuery(domain, wire.ProbePacket(wire.PacketMTUUpRequest, wire.NewUploadProbe(size, c.config.Base64Response, code)))
	if err != nil {
		return probeRejected, 0, nil
	}
	startedAt := time.Now()
	response, err := exchange(ctx, conn, query, timeout)
	if err != nil {
		return probeNoAnswer, 0, nil
	}
	rtt := time.Since(startedAt)
	packet, err := wire.ParseResponse(response, c.config.Base64Response)
	if err != nil {
		return probeUndecodable, 0, nil
	}
	if !wire.CheckUploadProbe(packet, code, size) {
		return probeRejected, 0, nil
	}
	return probePassed, rtt, nil
}

func (c *Client) downloadProbe(ctx context.Context, conn net.Conn, domain wire.Domain, size int, uploadMTU int, timeout time.Duration) (probeOutcome, time.Duration, error) {
	if size < minDownloadMTUFloor {
		return probeNoAnswer, 0, nil
	}
	if err := ctx.Err(); err != nil {
		return probeNoAnswer, 0, err
	}
	size += downloadProbeReserve
	code := c.probeCode.Add(1)
	query, err := c.buildQuery(domain, wire.ProbePacket(wire.PacketMTUDownRequest, wire.NewDownloadProbe(uploadMTU, size, c.config.Base64Response, code)))
	if err != nil {
		return probeRejected, 0, nil
	}
	startedAt := time.Now()
	response, err := exchange(ctx, conn, query, timeout)
	if err != nil {
		return probeNoAnswer, 0, nil
	}
	rtt := time.Since(startedAt)
	packet, err := wire.ParseResponse(response, c.config.Base64Response)
	if err != nil {
		return probeUndecodable, 0, nil
	}
	if !wire.CheckDownloadProbe(packet, code, size) {
		return probeRejected, 0, nil
	}
	return probePassed, rtt, nil
}

func averageRTT(values ...time.Duration) time.Duration {
	var (
		sum   time.Duration
		count time.Duration
	)
	for _, value := range values {
		if value > 0 {
			sum += value
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sum / count
}
