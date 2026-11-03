package dnstt

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/smux"

	"github.com/xtaci/kcp-go/v5"
)

const (
	openStreamTimeout = 10 * time.Second
	maxStreamBuffer   = 1024 * 1024
)

// Any failure retires the whole session, as the reference rebuild loop does.
type session struct {
	resolvers  *resolverSet
	packetConn *packetConn
	kcpConn    *kcp.UDPSession
	smux       *smux.Session
	failed     chan struct{}
	failOnce   sync.Once
	err        error
	streams    int
	wg         sync.WaitGroup
}

func (c *Client) newSession(ctx context.Context) (*session, error) {
	clientID := make([]byte, c.wire.clientIDSize)
	_, err := rand.Read(clientID)
	if err != nil {
		return nil, err
	}
	s := &session{failed: make(chan struct{})}
	s.resolvers = newResolverSet(c.transportConfig, c.resolvers, c.systemResolvers, c.strategy, s.fail)
	s.packetConn = newPacketConn(c.wire, clientID, s.resolvers, newRateLimiter(c.rps), rand.Reader, s.fail)
	err = s.resolvers.start(s.packetConn)
	if err != nil {
		return nil, err
	}
	s.packetConn.start()
	s.kcpConn, err = kcp.NewConn2(tunnelAddr{}, nil, 0, 0, s.packetConn)
	if err != nil {
		s.closeTransport()
		return nil, E.Cause(err, "open KCP conn")
	}
	windowSize := c.wire.queueSize() / 2
	s.kcpConn.SetStreamMode(true) //nolint:staticcheck
	s.kcpConn.SetNoDelay(0, 0, 0, 1)
	s.kcpConn.SetWindowSize(windowSize, windowSize)
	if !s.kcpConn.SetMtu(c.mtu) {
		s.closeTransport()
		return nil, E.New("set KCP MTU to ", c.mtu)
	}
	err = s.handshake(ctx, c)
	if err != nil {
		s.closeTransport()
		return nil, err
	}
	c.logger.Debug("session ", s.id(), " established")
	return s, nil
}

func (s *session) handshake(ctx context.Context, c *Client) error {
	handshakeDone := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-handshakeDone:
		case <-s.failed:
			s.kcpConn.Close()
		case <-ctx.Done():
			s.kcpConn.Close()
		}
	}()
	s.kcpConn.SetDeadline(time.Now().Add(c.handshakeTimeout))
	sendCipher, receiveCipher, err := noiseClientHandshake(s.kcpConn, c.publicKey)
	s.kcpConn.SetDeadline(time.Time{})
	close(handshakeDone)
	<-watchDone
	if err != nil {
		select {
		case <-s.failed:
			err = s.err
		default:
			if ctx.Err() != nil {
				err = ctx.Err()
			}
		}
		return E.Cause(err, "noise handshake")
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = c.keepAliveInterval
	smuxConfig.KeepAliveTimeout = c.idleTimeout
	smuxConfig.MaxStreamBuffer = maxStreamBuffer
	s.smux, err = smux.Client(newNoiseConn(s.kcpConn, sendCipher, receiveCipher), smuxConfig)
	if err != nil {
		return E.Cause(err, "open smux session")
	}
	return nil
}

func (s *session) fail(err error) {
	s.failOnce.Do(func() {
		s.err = err
		close(s.failed)
	})
}

func (s *session) active() bool {
	select {
	case <-s.failed:
		return false
	default:
		return !s.smux.IsClosed()
	}
}

func (s *session) wait() {
	select {
	case <-s.smux.CloseChan():
	case <-s.failed:
	}
}

func (s *session) openStream(ctx context.Context) (*smux.Stream, error) {
	type openResult struct {
		stream *smux.Stream
		err    error
	}
	resultChan := make(chan openResult, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		stream, err := s.smux.OpenStream()
		resultChan <- openResult{stream, err}
	}()
	timer := time.NewTimer(openStreamTimeout)
	defer timer.Stop()
	var err error
	select {
	case result := <-resultChan:
		return result.stream, result.err
	case <-timer.C:
		err = E.New("open stream: timed out after ", openStreamTimeout)
	case <-ctx.Done():
		err = ctx.Err()
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		result := <-resultChan
		if result.stream != nil {
			result.stream.Close()
		}
	}()
	return nil, err
}

func (s *session) close() {
	s.smux.Close()
	s.wg.Wait()
	s.closeTransport()
}

func (s *session) closeTransport() {
	if s.kcpConn != nil {
		s.kcpConn.Close()
	}
	s.packetConn.Close()
	s.packetConn.wait()
	s.resolvers.close()
}

func (s *session) id() string {
	return fmt.Sprintf("%08x", s.kcpConn.GetConv())
}
