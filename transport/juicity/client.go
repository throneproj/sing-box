package juicity

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ClientOptions struct {
	Context       context.Context
	Dialer        N.Dialer
	ServerAddress M.Socksaddr
	TLSConfig     aTLS.Config
	UUID          [16]byte
	Password      string
}

type Client struct {
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr
	tlsConfig  aTLS.Config
	quicConfig *quic.Config
	uuid       [16]byte
	password   string

	connAccess sync.Mutex
	conns      []*clientQUICConnection
	closeIdle  atomic.Bool
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		HandshakeIdleTimeout:           8 * time.Second,
		InitialStreamReceiveWindow:     initialStreamReceiveWindow,
		MaxStreamReceiveWindow:         maxStreamReceiveWindow,
		InitialConnectionReceiveWindow: initialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     maxConnectionReceiveWindow,
		KeepAlivePeriod:                5 * time.Second,
		DisablePathMTUDiscovery:        disablePathMTUDiscovery,
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	return &Client{
		ctx:        options.Context,
		dialer:     options.Dialer,
		serverAddr: options.ServerAddress,
		tlsConfig:  options.TLSConfig,
		quicConfig: quicConfig,
		uuid:       options.UUID,
		password:   options.Password,
	}, nil
}

func (c *Client) openStream(ctx context.Context) (*clientQUICConnection, *quic.Stream, error) {
	for {
		c.connAccess.Lock()
		conn, stream := c.openStreamLocked()
		if stream != nil {
			c.connAccess.Unlock()
			return conn, stream, nil
		}
		pending := c.pending
		if pending == nil {
			// The dial is shared by all waiters, so it must outlive any single request ctx.
			offerCtx := c.ctx
			if offerCtx == nil {
				offerCtx = context.Background()
			}
			offerCtx, cancel := context.WithCancelCause(offerCtx)
			pending = &clientOffer{
				done:   make(chan struct{}),
				cancel: cancel,
			}
			c.pending = pending
			go c.completeOffer(pending, offerCtx)
		}
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			if pending.err != nil {
				return nil, nil, pending.err
			}
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
}

func (c *Client) openStreamLocked() (*clientQUICConnection, *quic.Stream) {
	c.conns = slices.DeleteFunc(c.conns, func(conn *clientQUICConnection) bool {
		return !conn.active()
	})
	for _, conn := range c.conns {
		stream, err := conn.openStream()
		if err == nil {
			return conn, stream
		}
		var limitErr *quic.StreamLimitReachedError
		if !errors.As(err, &limitErr) {
			conn.closeWithError(err)
		}
	}
	return nil, nil
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	conn, err := c.offerNew(offerCtx)
	pending.cancel(nil)

	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.err = err
		if err == nil {
			c.conns = append(c.conns, conn)
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	udpConn, err := c.dialer.DialContext(ctx, N.NetworkUDP, c.serverAddr)
	if err != nil {
		return nil, err
	}
	quicConn, err := qtls.Dial(ctx, udpConn, c.tlsConfig, c.quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, E.Cause(err, "open connection")
	}
	setCongestion(quicConn)
	conn := &clientQUICConnection{
		quicConn:  quicConn,
		rawConn:   udpConn,
		connDone:  make(chan struct{}),
		closeIdle: &c.closeIdle,
	}
	go func() {
		hErr := c.clientHandshake(quicConn)
		if hErr != nil {
			conn.closeWithError(hErr)
		}
	}()
	go conn.loopClose()
	return conn, nil
}

func (c *Client) clientHandshake(conn *quic.Conn) error {
	authStream, err := conn.OpenUniStream()
	if err != nil {
		return E.Cause(err, "open handshake stream")
	}
	defer authStream.Close()
	handshakeState := conn.ConnectionState()
	authToken, err := handshakeState.TLS.ExportKeyingMaterial(string(c.uuid[:]), []byte(c.password), 32)
	if err != nil {
		return E.Cause(err, "export keying material")
	}
	authRequest := buf.NewSize(AuthenticateLen)
	defer authRequest.Release()
	common.Must(authRequest.WriteByte(Version))
	common.Must(authRequest.WriteByte(CommandAuthenticate))
	common.Must1(authRequest.Write(c.uuid[:]))
	common.Must1(authRequest.Write(authToken))
	return common.Error(authStream.Write(authRequest.Bytes()))
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, stream, err := c.openStream(ctx)
	if err != nil {
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		parent:      conn,
		network:     NetworkTCP,
		destination: destination,
		keepSession: qtls.KeepSessionFromContext(ctx),
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, stream, err := c.openStream(ctx)
	if err != nil {
		return nil, err
	}
	return newUDPPacketConn(&clientConn{
		Stream:      stream,
		parent:      conn,
		network:     NetworkUDP,
		destination: destination,
		keepSession: qtls.KeepSessionFromContext(ctx),
	}, false), nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	conns := c.conns
	c.conns = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
		pending.cause = err
	}
	c.connAccess.Unlock()

	if pending != nil {
		pending.cancel(err)
	}
	for _, conn := range conns {
		conn.closeWithError(err)
	}
	return nil
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.closeIdle.Store(!keep)
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	c.connAccess.Lock()
	conns := slices.Clone(c.conns)
	c.connAccess.Unlock()
	for _, conn := range conns {
		conn.access.Lock()
		closed := conn.streams == 0 && conn.markClosedLocked(os.ErrClosed)
		conn.access.Unlock()
		if closed {
			conn.closeTransport()
		}
	}
}

type clientOffer struct {
	done      chan struct{}
	cancel    context.CancelCauseFunc
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	quicConn  *quic.Conn
	rawConn   io.Closer
	connDone  chan struct{}
	connErr   error
	access    sync.Mutex
	streams   int
	closeIdle *atomic.Bool
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	case <-c.connDone:
		return false
	default:
		return true
	}
}

func (c *clientQUICConnection) openStream() (*quic.Stream, error) {
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.connDone:
		return nil, os.ErrClosed
	default:
	}
	stream, err := c.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	c.streams++
	return stream, nil
}

func (c *clientQUICConnection) releaseStream(keepSession bool) {
	c.access.Lock()
	c.streams--
	closed := c.closeIdle.Load() && !keepSession && c.streams == 0 && c.markClosedLocked(os.ErrClosed)
	c.access.Unlock()
	if closed {
		c.closeTransport()
	}
}

func (c *clientQUICConnection) loopClose() {
	select {
	case <-c.quicConn.Context().Done():
		c.closeWithError(context.Cause(c.quicConn.Context()))
	case <-c.connDone:
	}
}

func (c *clientQUICConnection) markClosedLocked(err error) bool {
	select {
	case <-c.connDone:
		return false
	default:
	}
	c.connErr = err
	close(c.connDone)
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.access.Lock()
	closed := c.markClosedLocked(err)
	c.access.Unlock()
	if closed {
		c.closeTransport()
	}
}

func (c *clientQUICConnection) closeTransport() {
	_ = c.quicConn.CloseWithError(0, "")
	_ = c.rawConn.Close()
}

type clientConn struct {
	*quic.Stream
	parent         *clientQUICConnection
	network        byte
	destination    M.Socksaddr
	keepSession    bool
	requestWritten bool
	closeOnce      sync.Once
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	n, err = c.Stream.Read(b)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	if !c.requestWritten {
		request := buf.NewSize(1 + M.SocksaddrSerializer.AddrPortLen(c.destination) + len(b))
		defer request.Release()
		common.Must(request.WriteByte(c.network))
		err = M.SocksaddrSerializer.WriteAddrPort(request, c.destination)
		if err != nil {
			return
		}
		common.Must1(request.Write(b))
		_, err = c.Stream.Write(request.Bytes())
		if err != nil {
			return 0, qtls.WrapError(err)
		}
		c.requestWritten = true
		return len(b), nil
	}
	n, err = c.Stream.Write(b)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// Stream.Close does not unblock a Write waiting on flow control, a past write deadline does.
	c.Stream.SetWriteDeadline(time.Now())
	c.closeOnce.Do(func() { c.parent.releaseStream(c.keepSession) })
	return err
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.destination
}
