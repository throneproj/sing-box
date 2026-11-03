package masterdns

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ Runtime = (*Tunnel)(nil)

// Tunnel starts the client session on the first dial and carries streams over it.
type Tunnel struct {
	ctx    context.Context
	logger logger.ContextLogger
	client *Client
	dialer N.Dialer

	access         sync.Mutex
	run            *tunnelRun
	runtime        *tunnelRuntime
	runtimeChanged chan struct{}
	streams        int
	closeIdle      bool
	closed         bool
}

type tunnelRun struct {
	cancel   context.CancelFunc
	done     chan struct{}
	stopping bool
}

func NewTunnel(ctx context.Context, logger logger.ContextLogger, config Config, dialer N.Dialer) (*Tunnel, error) {
	client, err := NewClient(ctx, logger, config, dialer)
	if err != nil {
		return nil, err
	}
	return &Tunnel{
		ctx:            ctx,
		logger:         logger,
		client:         client,
		dialer:         dialer,
		runtimeChanged: make(chan struct{}),
	}, nil
}

// DialContext opens a stream: SOCKS5 mode connects the server to destination, TCP mode to its fixed target.
func (t *Tunnel) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	keepSession := adapter.KeepSessionFromContext(ctx)
	runtime, err := t.acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := runtime.dial(ctx, destination)
	if err != nil {
		t.release(false)
		return nil, err
	}
	conn.onClose = func() {
		t.release(keepSession)
	}
	return conn, nil
}

// acquire counts a stream and waits for a running session; the session runs on the tunnel context, so a caller that stops waiting does not abort it.
func (t *Tunnel) acquire(ctx context.Context) (*tunnelRuntime, error) {
	t.access.Lock()
	for {
		if t.closed {
			t.access.Unlock()
			return nil, net.ErrClosed
		}
		run := t.run
		if run == nil {
			run = t.startRunLocked()
		}
		if !run.stopping {
			break
		}
		t.access.Unlock()
		select {
		case <-run.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		t.access.Lock()
	}
	t.streams++
	t.access.Unlock()
	runtime, err := t.waitRuntime(ctx)
	if err != nil {
		t.access.Lock()
		t.streams--
		if ctx.Err() == nil {
			t.closeIdleLocked()
		}
		t.access.Unlock()
		return nil, err
	}
	return runtime, nil
}

func (t *Tunnel) waitRuntime(ctx context.Context) (*tunnelRuntime, error) {
	for {
		_, err := t.client.WaitSession(ctx)
		if err != nil {
			return nil, err
		}
		t.access.Lock()
		runtime, changed := t.runtime, t.runtimeChanged
		t.access.Unlock()
		if runtime != nil {
			return runtime, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (t *Tunnel) release(keepSession bool) {
	t.access.Lock()
	t.streams--
	if !keepSession {
		t.closeIdleLocked()
	}
	t.access.Unlock()
}

func (t *Tunnel) startRunLocked() *tunnelRun {
	ctx, cancel := context.WithCancel(t.ctx)
	run := &tunnelRun{cancel: cancel, done: make(chan struct{})}
	t.run = run
	t.client.setState(nil, nil)
	go t.loop(ctx, run)
	return run
}

func (t *Tunnel) loop(ctx context.Context, run *tunnelRun) {
	err := t.client.Run(ctx, t)
	run.cancel()
	if err != nil && !E.IsClosedOrCanceled(err) {
		t.logger.Error(err)
	}
	t.access.Lock()
	if t.run == run {
		t.run = nil
	}
	t.notifyRuntimeLocked()
	t.access.Unlock()
	close(run.done)
}

func (t *Tunnel) stopRunLocked() {
	run := t.run
	if run == nil || run.stopping {
		return
	}
	run.stopping = true
	run.cancel()
}

func (t *Tunnel) closeIdleLocked() {
	if t.closeIdle && t.streams == 0 {
		t.stopRunLocked()
	}
}

// Start is called by Client.Run once a session is accepted.
func (t *Tunnel) Start(ctx context.Context, session Session) error {
	runtime, err := newTunnelRuntime(ctx, t.logger, t.client, t.dialer, session)
	if err != nil {
		return err
	}
	t.access.Lock()
	t.runtime = runtime
	t.notifyRuntimeLocked()
	t.access.Unlock()
	return nil
}

// Stop is called by Client.Run before a session restart and after the close burst.
func (t *Tunnel) Stop() {
	t.access.Lock()
	runtime := t.runtime
	t.runtime = nil
	t.notifyRuntimeLocked()
	t.access.Unlock()
	if runtime != nil {
		runtime.close()
	}
}

func (t *Tunnel) notifyRuntimeLocked() {
	close(t.runtimeChanged)
	t.runtimeChanged = make(chan struct{})
}

// InterfaceUpdated rebinds the tunnel sockets and makes the next session scan the resolvers again.
func (t *Tunnel) InterfaceUpdated() {
	t.access.Lock()
	runtime := t.runtime
	t.access.Unlock()
	if runtime != nil {
		runtime.rebind()
	}
	t.client.RecheckResolvers()
}

func (t *Tunnel) SetKeepIdleConnections(keep bool) {
	t.access.Lock()
	t.closeIdle = !keep
	t.closeIdleLocked()
	t.access.Unlock()
}

func (t *Tunnel) CloseIdleConnections() {
	t.access.Lock()
	if t.streams == 0 {
		t.stopRunLocked()
	}
	t.access.Unlock()
}

// Close sends the session close burst and waits for every goroutine.
func (t *Tunnel) Close() error {
	t.access.Lock()
	if t.closed {
		t.access.Unlock()
		return nil
	}
	t.closed = true
	run := t.run
	t.stopRunLocked()
	t.access.Unlock()
	if run != nil {
		<-run.done
	}
	return t.client.Close()
}
