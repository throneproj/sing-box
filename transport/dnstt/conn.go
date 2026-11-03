package dnstt

import (
	"bytes"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"time"
)

const (
	initPollDelay = 500 * time.Millisecond
	maxPollDelay  = 10 * time.Second
	pollLimit     = 16
)

var _ net.PacketConn = (*packetConn)(nil)

// KCP sees one remote address whatever resolver carried a reply, so its source filter drops nothing.
type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "dnstt" }
func (tunnelAddr) String() string  { return "dnstt" }

type queryWriter interface {
	writeQuery(query []byte)
}

type packetConn struct {
	wire      *wireFormat
	clientID  []byte
	writer    queryWriter
	limiter   *rateLimiter
	random    io.Reader
	onError   func(error)
	incoming  chan []byte
	outgoing  chan []byte
	pollChan  chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	loopDone  chan struct{}
}

func newPacketConn(wire *wireFormat, clientID []byte, writer queryWriter, limiter *rateLimiter, random io.Reader, onError func(error)) *packetConn {
	return &packetConn{
		wire:     wire,
		clientID: clientID,
		writer:   writer,
		limiter:  limiter,
		random:   random,
		onError:  onError,
		incoming: make(chan []byte, wire.queueSize()),
		outgoing: make(chan []byte, wire.queueSize()),
		pollChan: make(chan struct{}, pollLimit),
		done:     make(chan struct{}),
		loopDone: make(chan struct{}),
	}
}

func (c *packetConn) start() {
	go c.sendLoop()
}

func (c *packetConn) sendLoop() {
	defer close(c.loopDone)
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	defer pollTimer.Stop()
	for {
		var (
			packet       []byte
			timerExpired bool
		)
		select {
		case <-c.done:
			return
		case packet = <-c.outgoing:
		default:
			select {
			case <-c.done:
				return
			case packet = <-c.outgoing:
			case <-c.pollChan:
			case <-pollTimer.C:
				timerExpired = true
			}
		}
		if len(packet) > 0 {
			select {
			case <-c.pollChan:
			default:
			}
		}
		if timerExpired {
			pollDelay = min(pollDelay*2, maxPollDelay)
		} else {
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)
		if !c.limiter.wait(c.done) {
			return
		}
		query, err := c.wire.encodeQuery(c.clientID, packet, c.random)
		if err != nil {
			c.onError(err)
			return
		}
		c.writer.writeQuery(query)
	}
}

func (c *packetConn) handleResponse(content []byte) bool {
	message, err := parseMessage(content)
	if err != nil {
		return false
	}
	payload, loaded := c.wire.responsePayload(message)
	if !loaded {
		return false
	}
	var received bool
	for {
		var packet []byte
		packet, payload, loaded = nextPacket(payload)
		if !loaded {
			break
		}
		received = true
		select {
		case c.incoming <- bytes.Clone(packet):
		default:
		}
	}
	if received {
		select {
		case c.pollChan <- struct{}{}:
		default:
		}
	}
	return true
}

func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.done:
		return 0, nil, net.ErrClosed
	default:
	}
	select {
	case <-c.done:
		return 0, nil, net.ErrClosed
	case packet := <-c.incoming:
		return copy(p, packet), tunnelAddr{}, nil
	}
}

func (c *packetConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	select {
	case c.outgoing <- bytes.Clone(p):
	default:
	}
	return len(p), nil
}

func (c *packetConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
	})
	return nil
}

func (c *packetConn) wait() {
	<-c.loopDone
}

func (c *packetConn) LocalAddr() net.Addr {
	return tunnelAddr{}
}

func (c *packetConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

// The bucket holds at least one token so rates below one query per second still make progress.
type rateLimiter struct {
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

func newRateLimiter(rps float64) *rateLimiter {
	if rps <= 0 || math.IsNaN(rps) || math.IsInf(rps, 0) {
		return nil
	}
	capacity := max(rps, 1)
	return &rateLimiter{
		rate:     rps,
		capacity: capacity,
		tokens:   capacity,
		last:     time.Now(),
	}
}

func (l *rateLimiter) wait(done <-chan struct{}) bool {
	if l == nil {
		return true
	}
	for {
		now := time.Now()
		l.tokens = min(l.tokens+now.Sub(l.last).Seconds()*l.rate, l.capacity)
		l.last = now
		if l.tokens >= 1 {
			l.tokens--
			return true
		}
		timer := time.NewTimer(time.Duration((1 - l.tokens) / l.rate * float64(time.Second)))
		select {
		case <-done:
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}
