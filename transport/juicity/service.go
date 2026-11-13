package juicity

import (
	"context"
	"crypto/hmac"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/gofrs/uuid/v5"
)

type ServiceOptions struct {
	Context     context.Context
	Logger      logger.Logger
	TLSConfig   aTLS.ServerConfig
	AuthTimeout time.Duration
	Handler     ServiceHandler
}

type ServiceHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[U comparable] struct {
	ctx         context.Context
	logger      logger.Logger
	tlsConfig   aTLS.ServerConfig
	quicConfig  *quic.Config
	userMap     map[[16]byte]U
	passwordMap map[U]string
	authTimeout time.Duration
	handler     ServiceHandler

	quicListener io.Closer
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	if options.AuthTimeout == 0 {
		options.AuthTimeout = 10 * time.Second
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     initialStreamReceiveWindow,
		MaxStreamReceiveWindow:         maxStreamReceiveWindow,
		InitialConnectionReceiveWindow: initialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     maxConnectionReceiveWindow,
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          100,
		KeepAlivePeriod:                10 * time.Second,
		DisablePathMTUDiscovery:        disablePathMTUDiscovery,
		DisablePathManager:             true,
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	return &Service[U]{
		ctx:         options.Context,
		logger:      options.Logger,
		tlsConfig:   options.TLSConfig,
		quicConfig:  quicConfig,
		userMap:     make(map[[16]byte]U),
		authTimeout: options.AuthTimeout,
		handler:     options.Handler,
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, uuidList [][16]byte, passwordList []string) {
	userMap := make(map[[16]byte]U)
	passwordMap := make(map[U]string)
	for index := range userList {
		userMap[uuidList[index]] = userList[index]
		passwordMap[userList[index]] = passwordList[index]
	}
	s.userMap = userMap
	s.passwordMap = passwordMap
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	listener, err := qtls.Listen(conn, s.tlsConfig, s.quicConfig)
	if err != nil {
		return err
	}
	s.quicListener = listener
	go func() {
		for {
			connection, hErr := listener.Accept(s.ctx)
			if hErr != nil {
				if E.IsClosedOrCanceled(hErr) || errors.Is(hErr, quic.ErrServerClosed) {
					s.logger.Debug(E.Cause(hErr, "listener closed"))
				} else {
					s.logger.Error(E.Cause(hErr, "listener closed"))
				}
				return
			}
			go s.handleConnection(connection)
		}
	}()
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(
		s.quicListener,
	)
}

func (s *Service[U]) handleConnection(connection *quic.Conn) {
	setCongestion(connection)
	session := &serverSession[U]{
		Service:  s,
		ctx:      s.ctx,
		quicConn: connection,
		connDone: make(chan struct{}),
		authDone: make(chan struct{}),
	}
	session.handle()
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx        context.Context
	quicConn   *quic.Conn
	connAccess sync.Mutex
	connDone   chan struct{}
	connErr    error
	authAccess sync.Mutex
	authDone   chan struct{}
	authUser   U
}

func (s *serverSession[U]) handle() {
	if s.ctx.Done() != nil {
		go func() {
			select {
			case <-s.ctx.Done():
				s.closeWithError(s.ctx.Err())
			case <-s.connDone:
			}
		}()
	}
	go s.loopUniStreams()
	go s.loopStreams()
	go s.handleAuthTimeout()
}

func (s *serverSession[U]) loopUniStreams() {
	for {
		uniStream, err := s.quicConn.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			hErr := s.handleUniStream(uniStream)
			if hErr != nil {
				s.closeWithError(E.Cause(hErr, "handle uni stream"))
			}
		}()
	}
}

func (s *serverSession[U]) handleUniStream(stream *quic.ReceiveStream) error {
	defer stream.CancelRead(0)
	buffer := buf.NewSize(AuthenticateLen)
	defer buffer.Release()
	_, err := buffer.ReadFullFrom(stream, AuthenticateLen)
	if err != nil {
		return E.Cause(err, "read request")
	}
	version := buffer.Byte(0)
	if version != Version {
		return E.New("unknown version ", version)
	}
	command := buffer.Byte(1)
	if command != CommandAuthenticate {
		return E.New("unknown command ", command)
	}
	var userUUID [16]byte
	copy(userUUID[:], buffer.Range(2, 2+16))
	user, loaded := s.userMap[userUUID]
	if !loaded {
		return E.New("authentication: unknown user ", uuid.UUID(userUUID))
	}
	handshakeState := s.quicConn.ConnectionState()
	authToken, err := handshakeState.TLS.ExportKeyingMaterial(string(userUUID[:]), []byte(s.passwordMap[user]), 32)
	if err != nil {
		return E.Cause(err, "authentication: export keying material")
	}
	if !hmac.Equal(authToken, buffer.Range(2+16, AuthenticateLen)) {
		return E.New("authentication: token mismatch")
	}
	s.authAccess.Lock()
	select {
	case <-s.authDone:
		s.authAccess.Unlock()
		return E.New("authentication: multiple authentication requests")
	default:
	}
	s.authUser = user
	close(s.authDone)
	s.authAccess.Unlock()
	// The official client keeps writing unsupported underlay requests to this stream.
	_, _ = io.Copy(io.Discard, stream)
	return nil
}

func (s *serverSession[U]) handleAuthTimeout() {
	select {
	case <-s.connDone:
	case <-s.authDone:
	case <-time.After(s.authTimeout):
		s.closeWithError(E.New("authentication timeout"))
	}
}

func (s *serverSession[U]) loopStreams() {
	for {
		stream, err := s.quicConn.AcceptStream(s.ctx)
		if err != nil {
			s.closeWithError(E.Cause(qtls.WrapError(err), "accept stream"))
			return
		}
		go func() {
			hErr := s.handleStream(stream)
			if hErr != nil {
				stream.CancelRead(0)
				stream.Close()
				s.logger.Error(E.Cause(hErr, "handle stream request"))
			}
		}()
	}
}

func (s *serverSession[U]) handleStream(stream *quic.Stream) error {
	buffer := buf.NewSize(1 + M.MaxSocksaddrLength)
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 1)
	if err != nil {
		return E.Cause(err, "read request")
	}
	network, _ := buffer.ReadByte()
	if network != NetworkTCP && network != NetworkUDP {
		return E.New("unknown network ", network)
	}
	destination, err := M.SocksaddrSerializer.ReadAddrPort(io.MultiReader(buffer, stream))
	if err != nil {
		return E.Cause(err, "read request destination")
	}
	select {
	case <-s.connDone:
		return s.connErr
	case <-s.authDone:
	}
	var conn net.Conn = &serverConn{
		Stream:      stream,
		destination: destination,
	}
	if !buffer.IsEmpty() {
		conn = bufio.NewCachedConn(conn, buffer.ToOwned())
	}
	ctx := auth.ContextWithUser(s.ctx, s.authUser)
	source := M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap()
	if network == NetworkTCP {
		s.handler.NewConnectionEx(ctx, conn, source, destination, nil)
	} else {
		s.handler.NewPacketConnectionEx(ctx, newUDPPacketConn(conn, true), source, destination, nil)
	}
	return nil
}

func (s *serverSession[U]) closeWithError(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	_ = s.quicConn.CloseWithError(0, "")
}

type serverConn struct {
	*quic.Stream
	destination M.Socksaddr
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.destination
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// Stream.Close does not unblock a Write waiting on flow control, a past write deadline does.
	c.Stream.SetWriteDeadline(time.Now())
	return err
}
