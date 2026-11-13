package trusttunnel

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trusttunnel"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TrustTunnelInboundOptions](registry, C.TypeTrustTunnel, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router    adapter.ConnectionRouterEx
	logger    log.ContextLogger
	listener  *listener.Listener
	server    *trusttunnel.Server
	tlsConfig tls.ServerConfig
	network   []string
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrustTunnelInboundOptions) (adapter.Inbound, error) {
	network := options.Network.Build()
	if common.Contains(network, N.NetworkUDP) && (options.TLS == nil || !options.TLS.Enabled) {
		return nil, C.ErrTLSRequired
	}
	if len(options.Users) == 0 {
		return nil, E.New("missing users")
	}
	if invalidIndex := common.Index(options.Users, func(it auth.User) bool {
		return it.Username == "" || it.Password == ""
	}); invalidIndex >= 0 {
		return nil, E.New("missing username or password of user ", invalidIndex)
	}
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeTrustTunnel, tag),
		router:  router,
		logger:  logger,
		server: trusttunnel.NewServer(trusttunnel.ServerOptions{
			Context:               ctx,
			Logger:                logger,
			Users:                 options.Users,
			QUICCongestionControl: options.QUICCongestionControl,
		}),
		network: network,
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		if tlsConfig != nil && common.Contains(network, N.NetworkTCP) && len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		inbound.tlsConfig = tlsConfig
	}
	var listenNetwork []string
	if common.Contains(network, N.NetworkTCP) {
		listenNetwork = []string{N.NetworkTCP}
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           listenNetwork,
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
		scope.Add(h.tlsConfig.Close)
	}
	scope.Add(h.listener.Close)
	if common.Contains(h.network, N.NetworkUDP) {
		udpConn, err := h.listener.ListenUDP()
		if err != nil {
			return err
		}
		var metadata adapter.InboundContext
		//nolint:staticcheck
		metadata.InboundDetour = h.listener.ListenOptions().Detour
		http3Server, err := h.server.ListenHTTP3(udpConn, adapter.NewUpstreamHandler(metadata, h.newUserConnection, h.newUserPacketConnection), h.tlsConfig)
		if err != nil {
			return err
		}
		scope.Add(http3Server.Close)
	}
	return h.listener.Start()
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	h.server.ServeConnection(ctx, conn, adapter.NewUpstreamHandler(metadata, h.newUserConnection, h.newUserPacketConnection), metadata.Source, onClose)
}

func (h *Inbound) newUserConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.User, _ = auth.UserFromContext[string](ctx)
	h.logger.InfoContext(ctx, "[", metadata.User, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) newUserPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.User, _ = auth.UserFromContext[string](ctx)
	h.logger.InfoContext(ctx, "[", metadata.User, "] inbound packet connection to ", metadata.Destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
