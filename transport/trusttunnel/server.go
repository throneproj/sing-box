package trusttunnel

import (
	std_bufio "bufio"
	"context"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/common/badhttp"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat2"

	"golang.org/x/net/http2"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type ServerOptions struct {
	Context               context.Context
	Logger                logger.ContextLogger
	Users                 []auth.User
	QUICCongestionControl string
}

type Server struct {
	ctx                   context.Context
	logger                logger.ContextLogger
	authenticator         *auth.Authenticator
	quicCongestionControl string
	http2Server           *http2.Server
}

func NewServer(options ServerOptions) *Server {
	return &Server{
		ctx:                   options.Context,
		logger:                options.Logger,
		authenticator:         auth.NewAuthenticator(options.Users),
		quicCongestionControl: options.QUICCongestionControl,
		http2Server: &http2.Server{
			IdleTimeout: idleTimeout,
		},
	}
}

func (s *Server) ServeConnection(ctx context.Context, conn net.Conn, handler Handler, source M.Socksaddr, onClose N.CloseHandlerFunc) {
	s.http2Server.ServeConn(conn, &http2.ServeConnOpts{
		Context: ctx,
		Handler: &httpHandler{
			server:  s,
			handler: handler,
			source:  source,
		},
	})
	if onClose != nil {
		onClose(nil)
	}
}

type httpHandler struct {
	server  *Server
	handler Handler
	source  M.Socksaddr
}

func (h *httpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := log.ContextWithNewID(request.Context())
	source := h.source
	if !source.IsValid() {
		source = M.ParseSocksaddr(request.RemoteAddr).Unwrap()
	}
	username, password, loaded := badhttp.ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
	if !loaded || !h.server.authenticator.Verify(username, password) {
		h.server.logger.ErrorContext(ctx, "process connection from ", source, ": authentication failed")
		writer.Header().Set("Proxy-Authenticate", "Basic realm=Authorization Required")
		writer.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	ctx = auth.ContextWithUser(ctx, username)
	if request.Method != http.MethodConnect {
		h.server.logger.ErrorContext(ctx, "process connection from ", source, ": unexpected method: ", request.Method)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	switch request.Host {
	case healthCheckAuthority:
		writer.WriteHeader(http.StatusOK)
	case udpAuthority:
		h.serveUDP(ctx, writer, request, source)
	case icmpAuthority:
		h.server.logger.DebugContext(ctx, "process connection from ", source, ": ICMP is not supported")
		// Like the official endpoint without ICMP forwarding: the stream is accepted and then reset.
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	default:
		h.serveConnect(ctx, writer, request, source)
	}
}

func (h *httpHandler) serveConnect(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr) {
	destination := M.ParseSocksaddr(request.Host).Unwrap()
	if !destination.IsValid() || destination.Port == 0 {
		h.server.logger.ErrorContext(ctx, "process connection from ", source, ": invalid CONNECT target: ", request.Host)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()
	conn := v2rayhttp.NewHTTP2Wrapper(&v2rayhttp.ServerHTTPConn{
		HTTP2Conn: v2rayhttp.NewHTTPConn(request.Body, writer),
		Flusher:   writer.(http.Flusher),
	})
	done := make(chan struct{})
	h.handler.NewConnectionEx(ctx, conn, source, destination, N.OnceClose(func(it error) {
		close(done)
	}))
	<-done
	conn.CloseWrapper()
}

func (h *httpHandler) serveUDP(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr) {
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()
	session := &udpSession{
		ctx:     ctx,
		handler: h.handler,
		source:  source,
		writer:  writer,
	}
	service := udpnat.New(session, session.preparePacketConnection, C.UDPTimeout, false)
	err := session.loopInput(std_bufio.NewReader(request.Body), service)
	session.close()
	service.Purge()
	if err != nil && !E.IsClosedOrCanceled(err) {
		h.server.logger.DebugContext(ctx, E.Cause(err, "process UDP stream from ", source))
	}
}
