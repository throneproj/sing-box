package trusttunnel

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trusttunnel"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TrustTunnelOutboundOptions](registry, C.TypeTrustTunnel, NewOutbound)
}

var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger    log.ContextLogger
	client    *trusttunnel.Client
	dnsRouter adapter.DNSRouter
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrustTunnelOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.Username == "" || options.Password == "" {
		return nil, E.New("require auth")
	}
	if options.ClientRandom != "" && options.ClientRandomAuthKey != "" {
		return nil, E.New("client_random and client_random_auth_key are mutually exclusive")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, *options.TLS)
	if err != nil {
		return nil, err
	}
	if options.CustomSNI != "" {
		err = setCustomSNI(tlsConfig, options.CustomSNI, *options.TLS)
		if err != nil {
			return nil, err
		}
	}
	if options.ClientRandom != "" {
		tlsConfig, err = newClientRandomConfig(tlsConfig, options.ClientRandom, *options.TLS)
		if err != nil {
			return nil, err
		}
	} else if options.ClientRandomAuthKey != "" {
		serverName := options.CustomSNI
		if serverName == "" {
			serverName = tlsConfig.ServerName()
		}
		tlsConfig, err = newClientRandomAuthKeyConfig(tlsConfig, options.ClientRandomAuthKey, serverName, *options.TLS)
		if err != nil {
			return nil, err
		}
	}
	client, err := trusttunnel.NewClient(trusttunnel.ClientOptions{
		Context:               ctx,
		Logger:                logger,
		Dialer:                outboundDialer,
		Server:                options.ServerOptions.Build(),
		TLSConfig:             tlsConfig,
		Username:              options.Username,
		Password:              options.Password,
		QUIC:                  options.QUIC,
		QUICCongestionControl: options.QUICCongestionControl,
		HealthCheck:           options.HealthCheck,
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeTrustTunnel, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:    logger,
		client:    client,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
	}, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := h.client.Start()
	if err != nil {
		return err
	}
	scope.Add(h.client.Close)
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		ctx, metadata := adapter.ExtendContext(ctx)
		metadata.Outbound = h.Tag()
		metadata.Destination = destination
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		packetConn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsDomain() {
		destinationAddresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, err := h.client.ListenPacket(ctx)
		if err != nil {
			return nil, err
		}
		return bufio.NewNATPacketConn(bufio.NewPacketConn(iponly.NewPacketConn(h.logger, packetConn)), M.SocksaddrFrom(destinationAddresses[0], destination.Port), destination), nil
	}
	packetConn, err := h.client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return iponly.NewPacketConn(h.logger, packetConn), nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.ResetConnections()
}
