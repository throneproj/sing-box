package masterdns

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/arq"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
)

var (
	errSessionClosed = E.New("session closed")
	errSetupTimeout  = E.New("stream setup timed out")
	errNoStreamID    = E.New("no free stream id")
	errConnectFailed = E.New("remote: connect failed")
)

type streamStatus uint8

const (
	streamPending streamStatus = iota
	streamConnecting
	streamSOCKSConnecting
	streamActive
	streamSOCKSFailed
	streamCancelled
	streamDraining
	streamClosing
	streamTimeWait
	streamClosed
)

// clientStream is the reference Stream_client: an ARQ stream, its TX queue and its setup status.
type clientStream struct {
	runtime *tunnelRuntime
	id      uint16
	arq     *arq.Stream
	queue   *arq.TXQueue
	result  chan error

	access        sync.Mutex
	status        streamStatus
	terminalSince time.Time
	resultSent    bool
	finalized     bool
}

func (r *tunnelRuntime) newStream(id uint16, config arq.Config, status streamStatus) *clientStream {
	stream := &clientStream{
		runtime: r,
		id:      id,
		status:  status,
		result:  make(chan error, 1),
	}
	stream.queue = arq.NewTXQueue(id, r.streamQueueSize, r.signalDispatch)
	stream.arq = arq.New(id, r.session.UploadMTU, config, stream.queue, stream.onClosed)
	return stream
}

func (r *tunnelRuntime) streamConfig() arq.Config {
	settings := r.session.Settings
	return arq.Config{
		WindowSize:               settings.ARQWindowSize,
		RTO:                      settings.ARQInitialRTO,
		MaxRTO:                   settings.ARQMaxRTO,
		StartPaused:              true,
		EnableControlReliability: true,
		ControlRTO:               settings.ARQControlInitialRTO,
		ControlMaxRTO:            settings.ARQControlMaxRTO,
		ControlMaxRetries:        arq.DefaultControlMaxRetries,
		InactivityTimeout:        arq.DefaultInactivityTimeout,
		DataPacketTTL:            arq.DefaultDataPacketTTL,
		MaxDataRetries:           arq.DefaultMaxDataRetries,
		ControlPacketTTL:         arq.DefaultControlPacketTTL,
		DataNackMaxGap:           settings.ARQDataNackMaxGap,
		DataNackInitialDelay:     arq.DefaultDataNackInitialDelay,
		DataNackRepeat:           arq.DefaultDataNackRepeat,
		TerminalDrainTimeout:     arq.DefaultTerminalDrainTimeout,
		TerminalAckWaitTimeout:   arq.DefaultTerminalAckWaitTimeout,
		Compression:              r.session.UploadCompression,
		IsClient:                 true,
	}
}

// openVirtualStream creates stream 0, the control and ping channel of the reference (stream_client.go:563).
func (r *tunnelRuntime) openVirtualStream() {
	settings := r.session.Settings
	stream := r.newStream(0, arq.Config{
		WindowSize:               settings.ARQWindowSize,
		RTO:                      settings.ARQInitialRTO,
		MaxRTO:                   settings.ARQMaxRTO,
		IsVirtual:                true,
		EnableControlReliability: true,
		ControlRTO:               settings.ARQControlInitialRTO,
		ControlMaxRTO:            settings.ARQControlMaxRTO,
		ControlMaxRetries:        arq.DefaultControlMaxRetries,
		InactivityTimeout:        999999 * time.Second,
		DataPacketTTL:            999999 * time.Second,
		MaxDataRetries:           99999,
		ControlPacketTTL:         999999 * time.Second,
		DataNackInitialDelay:     arq.DefaultDataNackInitialDelay,
		DataNackRepeat:           arq.DefaultDataNackRepeat,
		TerminalDrainTimeout:     arq.DefaultTerminalDrainTimeout,
		TerminalAckWaitTimeout:   arq.DefaultTerminalAckWaitTimeout,
		Compression:              r.session.UploadCompression,
	}, streamPending)
	r.streams[0] = stream
	r.streamVersion.Add(1)
	r.clock.schedule(stream.arq, time.Now().Add(stream.arq.NextTick()))
}

func (r *tunnelRuntime) openStream() (*clientStream, error) {
	status := streamSOCKSConnecting
	if r.mode == ModeTCP {
		status = streamConnecting
	}
	r.streamAccess.Lock()
	if r.closed {
		r.streamAccess.Unlock()
		return nil, errSessionClosed
	}
	id, loaded := r.nextStreamIDLocked()
	if !loaded {
		r.streamAccess.Unlock()
		return nil, errNoStreamID
	}
	stream := r.newStream(id, r.streamConfig(), status)
	r.streams[id] = stream
	r.streamVersion.Add(1)
	r.streamAccess.Unlock()
	r.balancer.EnsureStream(id)
	r.clock.schedule(stream.arq, time.Now().Add(stream.arq.NextTick()))
	return stream, nil
}

func (r *tunnelRuntime) nextStreamIDLocked() (uint16, bool) {
	id := r.lastStreamID + 1
	for range 1 << 16 {
		if id == 0 {
			id = 1
		}
		if _, used := r.streams[id]; !used {
			r.lastStreamID = id
			return id, true
		}
		id++
	}
	return 0, false
}

func (r *tunnelRuntime) stream(id uint16) *clientStream {
	r.streamAccess.RLock()
	defer r.streamAccess.RUnlock()
	return r.streams[id]
}

func (r *tunnelRuntime) dial(ctx context.Context, destination M.Socksaddr) (*streamConn, error) {
	var target []byte
	if r.mode == ModeSOCKS5 {
		var err error
		target, err = wire.AppendSOCKSTarget(nil, destination)
		if err != nil {
			return nil, err
		}
	}
	mtu := max(r.session.UploadMTU, 1)
	fragments := (len(target) + mtu - 1) / mtu
	if fragments > 255 {
		return nil, E.New("destination too long for upload MTU ", mtu)
	}
	stream, err := r.openStream()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if r.mode == ModeSOCKS5 {
		for index := range fragments {
			fragment := target[index*mtu : min((index+1)*mtu, len(target))]
			stream.arq.SendControl(wire.PacketSOCKS5SYN, 0, uint8(index), uint8(fragments), fragment,
				wire.DefaultPriority(wire.PacketSOCKS5SYN), true, 0, arq.SetupPacketTTL, now)
		}
	} else {
		stream.arq.SendControl(wire.PacketStreamSYN, 0, 0, 0, nil, wire.DefaultPriority(wire.PacketStreamSYN), true, 0, arq.SetupPacketTTL, now)
	}
	timer := time.NewTimer(arq.SetupPacketTTL)
	defer timer.Stop()
	select {
	case err = <-stream.result:
	case <-ctx.Done():
		stream.cancelSetup("local setup cancelled")
		return nil, ctx.Err()
	case <-timer.C:
		stream.cancelSetup("stream setup timed out")
		return nil, errSetupTimeout
	}
	if err != nil {
		return nil, err
	}
	return &streamConn{
		stream:        stream,
		destination:   destination,
		readDeadline:  pipe.MakeDeadline(),
		writeDeadline: pipe.MakeDeadline(),
	}, nil
}

func (s *clientStream) setResult(err error) {
	s.access.Lock()
	if s.resultSent {
		s.access.Unlock()
		return
	}
	s.resultSent = true
	s.access.Unlock()
	s.result <- err
}

func (s *clientStream) markTerminalLocked(now time.Time) {
	if s.terminalSince.IsZero() {
		s.terminalSince = now
	}
}

func (s *clientStream) isTerminal() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return !s.terminalSince.IsZero()
}

// cancelSetup is the local side giving up on a dial: a pending setup is reset, a connected stream is closed.
func (s *clientStream) cancelSetup(reason string) {
	s.access.Lock()
	switch s.status {
	case streamConnecting, streamSOCKSConnecting:
		s.status = streamCancelled
		s.markTerminalLocked(time.Now())
		s.access.Unlock()
		s.arq.Close(reason, arq.CloseOptions{SendRST: true})
	case streamActive:
		s.access.Unlock()
		s.arq.CloseWrite()
		s.arq.CloseRead()
	default:
		s.access.Unlock()
	}
}

// onClosed runs outside the ARQ lock once the stream is finalized.
func (s *clientStream) onClosed(reason string) {
	s.runtime.closedStreams.remember(s.id, reason, time.Now())
	s.setResult(E.New("stream closed: ", reason))
	s.runtime.finalizeStream(s)
}

func (r *tunnelRuntime) finalizeStream(stream *clientStream) {
	stream.access.Lock()
	if stream.finalized {
		stream.access.Unlock()
		return
	}
	stream.finalized = true
	stream.status = streamClosed
	stream.access.Unlock()
	r.balancer.CleanupStream(stream.id)
	r.streamAccess.Lock()
	if r.streams[stream.id] == stream {
		delete(r.streams, stream.id)
		r.streamVersion.Add(1)
	}
	r.streamAccess.Unlock()
	stream.queue.Clear()
}

func (r *tunnelRuntime) removeStream(stream *clientStream) {
	r.streamAccess.Lock()
	if r.streams[stream.id] == stream {
		delete(r.streams, stream.id)
		r.streamVersion.Add(1)
	}
	r.streamAccess.Unlock()
	stream.arq.Close("stream cleanup", arq.CloseOptions{Force: true})
	r.finalizeStream(stream)
}

func (r *tunnelRuntime) closeStreams() {
	r.streamAccess.Lock()
	r.closed = true
	streams := make([]*clientStream, 0, len(r.streams))
	for _, stream := range r.streams {
		streams = append(streams, stream)
	}
	clear(r.streams)
	r.streamVersion.Add(1)
	r.streamAccess.Unlock()
	for _, stream := range streams {
		stream.setResult(errSessionClosed)
		stream.arq.Close("stream cleanup", arq.CloseOptions{Force: true})
		r.finalizeStream(stream)
	}
}

// cleanupStreams is the reference stream cleanup pass: statuses follow the ARQ state and terminal streams expire.
func (r *tunnelRuntime) cleanupStreams(now time.Time) {
	r.streamAccess.RLock()
	streams := make([]*clientStream, 0, len(r.streams))
	for id, stream := range r.streams {
		if id != 0 {
			streams = append(streams, stream)
		}
	}
	r.streamAccess.RUnlock()
	for _, stream := range streams {
		if stream.expired(now, stream.arq.State(), stream.arq.IsClosed()) {
			r.removeStream(stream)
		}
	}
}

func (s *clientStream) expired(now time.Time, state arq.State, closed bool) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if s.status != streamCancelled {
		switch state {
		case arq.StateDraining:
			s.status = streamDraining
		case arq.StateHalfClosedLocal, arq.StateHalfClosedRemote, arq.StateClosing:
			s.status = streamClosing
		case arq.StateTimeWait:
			s.status = streamTimeWait
		}
	}
	if !closed {
		return s.status == streamCancelled && !s.terminalSince.IsZero() && now.Sub(s.terminalSince) >= cancelledSetupRetention
	}
	s.markTerminalLocked(now)
	if s.status != streamCancelled {
		s.status = streamTimeWait
	}
	return now.Sub(s.terminalSince) >= terminalStreamRetention
}

func socksError(packetType uint8) error {
	switch packetType {
	case wire.PacketSOCKS5RulesetDenied:
		return E.New("remote: connection not allowed by ruleset")
	case wire.PacketSOCKS5NetworkUnreachable:
		return E.Cause(syscall.ENETUNREACH, "remote")
	case wire.PacketSOCKS5HostUnreachable:
		return E.Cause(syscall.EHOSTUNREACH, "remote")
	case wire.PacketSOCKS5ConnectionRefused:
		return E.Cause(syscall.ECONNREFUSED, "remote")
	case wire.PacketSOCKS5TTLExpired:
		return E.New("remote: TTL expired")
	case wire.PacketSOCKS5CommandUnsupported:
		return E.New("remote: command not supported")
	case wire.PacketSOCKS5AddressTypeUnsupported:
		return E.New("remote: address type not supported")
	case wire.PacketSOCKS5AuthFailed:
		return E.New("remote: upstream SOCKS5 authentication failed")
	case wire.PacketSOCKS5UpstreamUnavailable:
		return E.New("remote: upstream SOCKS5 unavailable")
	default:
		return E.New("remote: general SOCKS server failure")
	}
}

var _ net.Conn = (*streamConn)(nil)

// streamConn is a net.Conn over an ARQ stream; it runs no goroutine of its own.
type streamConn struct {
	stream        *clientStream
	destination   M.Socksaddr
	readDeadline  pipe.Deadline
	writeDeadline pipe.Deadline
	onClose       func()
	closeOnce     sync.Once
}

func (c *streamConn) Read(p []byte) (int, error) {
	cancel := c.readDeadline.Wait()
	if deadlineExceeded(cancel) {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.stream.arq.Read(p, cancel)
	return n, connError(err)
}

func (c *streamConn) Write(p []byte) (int, error) {
	cancel := c.writeDeadline.Wait()
	if deadlineExceeded(cancel) {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.stream.arq.Write(p, cancel)
	return n, connError(err)
}

func deadlineExceeded(cancel <-chan struct{}) bool {
	select {
	case <-cancel:
		return true
	default:
		return false
	}
}

func connError(err error) error {
	if errors.Is(err, arq.ErrCanceled) {
		return os.ErrDeadlineExceeded
	}
	return err
}

func (c *streamConn) CloseWrite() error {
	c.stream.arq.CloseWrite()
	return nil
}

func (c *streamConn) Close() error {
	c.closeOnce.Do(func() {
		c.stream.arq.CloseWrite()
		c.stream.arq.CloseRead()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *streamConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *streamConn) RemoteAddr() net.Addr {
	return c.destination
}

func (c *streamConn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	c.writeDeadline.Set(t)
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}
