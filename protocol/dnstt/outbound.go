package dnstt

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/systemdns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DNSTTOutboundOptions](registry, C.TypeDNSTT, NewOutbound)
}

var (
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger    logger.ContextLogger
	client    *dnstt.Client
	system    *systemdns.Source
	dialer    N.Dialer
	ssh       *sshClient
	uotClient *uot.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DNSTTOutboundOptions) (adapter.Outbound, error) {
	var backends int
	for _, enabled := range []bool{options.SOCKS != nil, options.Shadowsocks != nil, options.SSH != nil} {
		if enabled {
			backends++
		}
	}
	if backends > 1 {
		return nil, E.New("only one of socks, shadowsocks and ssh can be set")
	}
	tunnel := new(tunnelDialer)
	var (
		backendDialer N.Dialer = tunnel
		backendSSH    *sshClient
		uotOptions    option.UDPOverTCPOptions
	)
	switch {
	case options.SOCKS != nil:
		backendDialer = socks.NewClient(tunnel, M.Socksaddr{}, socks.Version5, options.SOCKS.Username, options.SOCKS.Password)
		uotOptions = common.PtrValueOrDefault(options.SOCKS.UDPOverTCP)
	case options.Shadowsocks != nil:
		method, err := shadowsocks.CreateMethod(ctx, options.Shadowsocks.Method, shadowsocks.MethodOptions{
			Password: options.Shadowsocks.Password,
		})
		if err != nil {
			return nil, err
		}
		backendDialer = &shadowsocksDialer{dialer: tunnel, method: method}
		uotOptions = common.PtrValueOrDefault(options.Shadowsocks.UDPOverTCP)
	case options.SSH != nil:
		var err error
		backendSSH, err = newSSHClient(ctx, tunnel, options.Domain, *options.SSH)
		if err != nil {
			return nil, err
		}
		backendDialer = backendSSH
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, common.Any(options.Resolvers, func(it option.DNSTTResolverOptions) bool {
		return it.ServerIsDomain()
	}))
	if err != nil {
		return nil, err
	}
	clientOptions, system, err := newClientOptions(ctx, logger, outboundDialer, options)
	if err != nil {
		return nil, err
	}
	clientOptions.SharedUDPSocket = options.Detour != ""
	client, err := dnstt.NewClient(clientOptions)
	if err != nil {
		if system != nil {
			system.Close()
		}
		return nil, err
	}
	tunnel.client = client
	networks := []string{N.NetworkTCP}
	var uotClient *uot.Client
	if uotOptions.Enabled {
		uotClient = &uot.Client{
			Dialer:  backendDialer,
			Version: uotOptions.Version,
		}
		networks = append(networks, N.NetworkUDP)
	}
	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeDNSTT, tag, networks, options.DialerOptions),
		logger:    logger,
		client:    client,
		system:    system,
		dialer:    backendDialer,
		ssh:       backendSSH,
		uotClient: uotClient,
	}, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(h.close)
	return nil
}

func (h *Outbound) close() error {
	if h.ssh != nil {
		h.ssh.Close()
	}
	err := h.client.Close()
	if h.system != nil {
		h.system.Close()
	}
	return err
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.dialer.DialContext(ctx, N.NetworkTCP, destination)
	case N.NetworkUDP:
		if h.uotClient != nil {
			h.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
			return h.uotClient.DialContext(ctx, network, destination)
		}
	}
	return nil, E.Extend(N.ErrUnknownNetwork, network)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.uotClient == nil {
		return nil, os.ErrInvalid
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.system != nil {
		h.system.Reset()
	}
	h.client.InterfaceUpdated()
}

func (h *Outbound) MultiplexEnabled() bool {
	return true
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	if h.ssh != nil {
		h.ssh.SetKeepIdleConnections(keep)
	}
	h.client.SetKeepIdleConnections(keep)
}

func (h *Outbound) CloseIdleConnections() {
	if h.ssh != nil {
		h.ssh.CloseIdleConnections()
	}
	h.client.CloseIdleConnections()
}

var (
	_ N.Dialer = (*tunnelDialer)(nil)
	_ N.Dialer = (*shadowsocksDialer)(nil)
)

type tunnelDialer struct {
	client *dnstt.Client
}

func (d *tunnelDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	return d.client.DialContext(ctx)
}

func (d *tunnelDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type shadowsocksDialer struct {
	dialer N.Dialer
	method shadowsocks.Method
}

func (d *shadowsocksDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return d.method.DialEarlyConn(conn, destination), nil
}

func (d *shadowsocksDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
