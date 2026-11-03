package masterdns

import (
	"crypto/rand"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/compress"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
)

// Ping cadence of the reference client defaults.
const (
	pingWarmThreshold    = 8 * time.Second
	pingCoolThreshold    = 20 * time.Second
	pingColdThreshold    = 30 * time.Second
	pingLazyInterval     = 750 * time.Millisecond
	pingCooldownInterval = 2 * time.Second
	pingColdInterval     = 15 * time.Second
	pingWakeThrottle     = 100 * time.Millisecond
	minPingCheckInterval = 100 * time.Millisecond
	maxPingCheckInterval = time.Second
)

// pinger is the reference PingManager: pings on stream 0 poll the server faster while traffic is recent.
type pinger struct {
	aggressive          time.Duration
	lastPingSent        atomic.Int64
	lastNonPingSent     atomic.Int64
	lastNonPongReceived atomic.Int64
	lastWake            atomic.Int64
	sequence            atomic.Uint32
	wake                chan struct{}
}

func (p *pinger) reset(aggressive time.Duration) {
	now := time.Now().UnixNano()
	p.aggressive = aggressive
	p.lastPingSent.Store(now)
	p.lastNonPingSent.Store(now)
	p.lastNonPongReceived.Store(now)
	p.lastWake.Store(now)
	p.wake = make(chan struct{}, 1)
}

func (p *pinger) notify(packetType uint8, inbound bool) {
	now := time.Now().UnixNano()
	if inbound {
		if packetType == wire.PacketPong {
			return
		}
		p.lastNonPongReceived.Store(now)
	} else {
		if packetType == wire.PacketPing {
			p.lastPingSent.Store(now)
			return
		}
		p.lastNonPingSent.Store(now)
	}
	if now-p.lastWake.Load() < int64(pingWakeThrottle) {
		return
	}
	p.lastWake.Store(now)
	wakeup(p.wake)
}

func (p *pinger) interval(now int64) time.Duration {
	idleSent := time.Duration(now - p.lastNonPingSent.Load())
	idleReceived := time.Duration(now - p.lastNonPongReceived.Load())
	if idleSent < pingWarmThreshold || idleReceived < pingWarmThreshold {
		return p.aggressive
	}
	switch idle := min(idleSent, idleReceived); {
	case idle < pingCoolThreshold:
		return pingLazyInterval
	case idle < pingColdThreshold:
		return pingCooldownInterval
	default:
		return pingColdInterval
	}
}

func (r *tunnelRuntime) pingLoop() {
	timer := time.NewTimer(r.ping.aggressive)
	defer timer.Stop()
	var nonce [4]byte
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.ping.wake:
		case <-timer.C:
		}
		now := time.Now().UnixNano()
		interval := r.ping.interval(now)
		if time.Duration(now-r.ping.lastPingSent.Load()) >= interval {
			if stream := r.stream(0); stream != nil {
				rand.Read(nonce[:])
				stream.queue.PushTXPacket(wire.DefaultPriority(wire.PacketPing), wire.PacketPing, uint16(r.ping.sequence.Add(1)), 0, 0,
					compress.Off, 0, wire.AppendPingPayload(nil, nonce))
			}
		}
		timer.Reset(clampDuration(interval/2, minPingCheckInterval, maxPingCheckInterval))
	}
}

func clampDuration(value time.Duration, minValue time.Duration, maxValue time.Duration) time.Duration {
	return min(max(value, minValue), maxValue)
}
