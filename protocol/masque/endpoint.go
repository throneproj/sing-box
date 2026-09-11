package masque

import (
	"context"
	"crypto/ecdsa"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/iponly"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	masquetransport "github.com/sagernet/sing-box/transport/masque"
	ovpntransport "github.com/sagernet/sing-box/transport/openvpn"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/http2"
)

const (
	defaultMTU               = 1280
	defaultServerPort        = 443
	defaultKeepAlivePeriod   = 30 * time.Second
	defaultInitialPacketSize = 1242
	// quic-go's worst-case packet overhead (37) plus the quarter stream ID and context ID.
	datagramOverhead = 39
)

var (
	_ adapter.FlowOutbound               = (*Endpoint)(nil)
	_ adapter.InterfaceUpdateListener    = (*Endpoint)(nil)
	_ dialer.PacketDialerWithDestination = (*Endpoint)(nil)
	_ tun.Port                           = (*Endpoint)(nil)
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.MASQUEEndpointOptions](registry, C.TypeMASQUE, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	ctx             context.Context
	router          adapter.Router
	logger          log.ContextLogger
	dnsRouter       adapter.DNSRouter
	loopContext     context.Context
	cancelLoop      context.CancelFunc
	outboundDialer  N.Dialer
	serverName      string
	serverAddr      M.Socksaddr
	tlsOptions      option.OutboundTLSOptions
	privateKey      *ecdsa.PrivateKey
	privateKeyPEM   string
	timeFunc        func() time.Time
	quicConfig      *quic.Config
	h2Transport     *http2.Transport
	versionFallback bool
	preferHTTP2     bool
	localAddresses  []netip.Prefix
	mtu             uint32
	device          ovpntransport.Device
	access          sync.Mutex
	conn            masquetransport.Conn
	cancelConnect   context.CancelFunc
	loopDone        chan struct{}
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEEndpointOptions) (adapter.Endpoint, error) {
	if options.Server == "" {
		return nil, E.New("missing `server`")
	}
	if len(options.Address) == 0 {
		return nil, E.New("missing `address`")
	}
	for addressIndex, address := range options.Address {
		if !address.IsValid() {
			return nil, E.New("`address[", addressIndex, "]` is invalid")
		}
	}
	switch options.HTTPVersion {
	case 0, 2, 3:
	default:
		return nil, E.New("unknown HTTP version: ", options.HTTPVersion)
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsOptions := *options.TLS
	if tlsOptions.Reality != nil && tlsOptions.Reality.Enabled {
		return nil, E.New("reality is not supported")
	}
	if len(tlsOptions.ClientCertificate) > 0 || tlsOptions.ClientCertificatePath != "" || len(tlsOptions.ClientKey) > 0 || tlsOptions.ClientKeyPath != "" {
		return nil, E.New("`tls.client_certificate` and `tls.client_key` are derived from `private_key`")
	}
	if options.PeerPublicKey != "" {
		if len(tlsOptions.CertificatePublicKeySHA256) > 0 {
			return nil, E.New("`peer_public_key` is conflict with `tls.certificate_public_key_sha256`")
		}
		if len(tlsOptions.Certificate) > 0 || tlsOptions.CertificatePath != "" {
			return nil, E.New("`peer_public_key` is conflict with `tls.certificate` and `tls.certificate_path`")
		}
		publicKeySHA256, err := peerPublicKeySHA256(options.PeerPublicKey)
		if err != nil {
			return nil, err
		}
		tlsOptions.CertificatePublicKeySHA256 = badoption.Listable[[]byte]{publicKeySHA256}
	}
	if options.PrivateKey == "" {
		return nil, E.New("missing `private_key`")
	}
	privateKey, err := parsePrivateKey(options.PrivateKey)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := encodePrivateKey(privateKey)
	if err != nil {
		return nil, E.Cause(err, "encode private_key")
	}
	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}
	connectTLSOptions, err := clientTLSOptions(tlsOptions, privateKey, privateKeyPEM, timeFunc())
	if err != nil {
		return nil, err
	}
	useHTTP3 := options.HTTPVersion != 2
	useHTTP2 := options.HTTPVersion == 2 || !options.DisableVersionFallback
	stdConfig, err := tls.NewSTDClient(ctx, logger, options.Server, connectTLSOptions)
	if err != nil {
		return nil, err
	}
	if useHTTP2 {
		_, err = tls.NewClient(ctx, logger, options.Server, connectTLSOptions)
		if err != nil {
			return nil, err
		}
	}
	mtu := options.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	keepAlivePeriod := time.Duration(options.KeepAlivePeriod)
	if keepAlivePeriod == 0 {
		keepAlivePeriod = defaultKeepAlivePeriod
	}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout:           stdConfig.HandshakeTimeout(),
		MaxIdleTimeout:                 time.Duration(options.IdleTimeout),
		InitialStreamReceiveWindow:     options.StreamReceiveWindow.Value(),
		MaxStreamReceiveWindow:         options.StreamReceiveWindow.Value(),
		InitialConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
		MaxConnectionReceiveWindow:     options.ConnectionReceiveWindow.Value(),
		KeepAlivePeriod:                keepAlivePeriod,
		InitialPacketSize:              defaultInitialPacketSize,
		DisablePathMTUDiscovery:        options.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
	}
	if options.InitialPacketSize > 0 {
		quicConfig.InitialPacketSize = uint16(options.InitialPacketSize)
	} else if options.DisablePathMTUDiscovery {
		// Without PMTUD the packet size never grows, so it must fit a full-MTU packet from the start.
		quicConfig.InitialPacketSize = uint16(min(mtu+datagramOverhead, math.MaxUint16))
	}
	if options.MaxConcurrentStreams > 0 {
		quicConfig.MaxIncomingStreams = int64(options.MaxConcurrentStreams)
	}
	http2Options := options.HTTP2Options
	http2Options.KeepAlivePeriod = badoption.Duration(keepAlivePeriod)
	h2Transport, err := httpclient.ConfigureHTTP2Transport(http2Options)
	if err != nil {
		return nil, err
	}
	h2Transport.DisableCompression = true
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   options.ServerIsDomain(),
		ResolverOnDetour: true,
		NewDialer:        true,
	})
	if err != nil {
		return nil, err
	}
	serverAddr := options.ServerOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = defaultServerPort
	}
	name := options.Name
	if options.System && name == "" {
		name = tun.CalculateInterfaceName("masque")
	}
	udpTimeout := C.UDPTimeout
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	}
	loopContext, cancelLoop := context.WithCancel(ctx)
	ep := &Endpoint{
		Adapter:         endpoint.NewAdapterWithDialerOptions(C.TypeMASQUE, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:             ctx,
		router:          router,
		logger:          logger,
		dnsRouter:       service.FromContext[adapter.DNSRouter](ctx),
		loopContext:     loopContext,
		cancelLoop:      cancelLoop,
		outboundDialer:  outboundDialer,
		serverName:      options.Server,
		serverAddr:      serverAddr,
		tlsOptions:      tlsOptions,
		privateKey:      privateKey,
		privateKeyPEM:   privateKeyPEM,
		timeFunc:        timeFunc,
		quicConfig:      quicConfig,
		h2Transport:     h2Transport,
		versionFallback: useHTTP3 && useHTTP2,
		preferHTTP2:     !useHTTP3,
		localAddresses:  options.Address,
		mtu:             mtu,
	}
	device, err := ovpntransport.NewDevice(ovpntransport.DeviceOptions{
		Context:         ctx,
		Logger:          logger,
		System:          options.System,
		Handler:         ep,
		UDPTimeout:      udpTimeout,
		ICMPTimeout:     C.ICMPTimeout,
		UDPMapping:      tun.NATMapping(options.UDPMapping),
		UDPFiltering:    tun.NATFiltering(options.UDPFiltering),
		UDPNATMax:       options.UDPNATMax,
		InterfaceFinder: service.FromContext[adapter.NetworkManager](ctx).InterfaceFinder(),
		Name:            name,
		MTU:             mtu,
		Configuration: ovpntransport.Configuration{
			MTU:     mtu,
			Address: options.Address,
		},
	})
	if err != nil {
		cancelLoop()
		return nil, err
	}
	ep.device = device
	device.SetPacketWriter(ep.writePacketBuffers)
	return ep, nil
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	err := e.device.Start()
	if err != nil {
		return E.Cause(err, "start device")
	}
	loopDone := make(chan struct{})
	e.access.Lock()
	e.loopDone = loopDone
	e.access.Unlock()
	go e.loop(loopDone)
	return nil
}

func (e *Endpoint) Close() error {
	e.cancelLoop()
	e.access.Lock()
	conn := e.conn
	e.conn = nil
	loopDone := e.loopDone
	e.access.Unlock()
	if conn != nil {
		conn.Close()
	}
	err := e.device.Close()
	if loopDone != nil {
		<-loopDone
	}
	return err
}

func (e *Endpoint) InterfaceUpdated(ctx context.Context) {
	e.access.Lock()
	conn := e.conn
	e.conn = nil
	cancelConnect := e.cancelConnect
	e.access.Unlock()
	if cancelConnect != nil {
		cancelConnect()
	}
	if conn != nil {
		go conn.Close()
	}
}

func (e *Endpoint) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (e *Endpoint) PortAddresses() (netip.Addr, netip.Addr) {
	return e.device.PortAddresses()
}

func (e *Endpoint) PortMTU() uint32 {
	return e.device.PortMTU()
}

func (e *Endpoint) AttachReturn(returnPath tun.Return) error {
	return e.device.AttachReturn(returnPath)
}

func (e *Endpoint) DetachReturn(returnPath tun.Return) error {
	return e.device.DetachReturn(returnPath)
}

func (e *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	if e.isLocalAddress(destination.Addr()) {
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	return adapter.JudgeFlow(e.router, e.Tag(), e.Type(), network, source, destination, firstPacket)
}

func (e *Endpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	ctx := log.ContextWithNewID(e.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Network = N.NetworkUDP
	metadata.Source = source
	metadata.Destination = destination
	metadata.Protocol = C.ProtocolDNS
	e.logger.InfoContext(ctx, "inbound DNS packet from ", source)
	e.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func (e *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	if e.isLocalAddress(destination.Addr) {
		metadata.OriginDestination = destination
		destination.Addr = loopbackAddressFor(destination.Addr)
	}
	metadata.Destination = destination
	e.logger.InfoContext(ctx, "inbound connection from ", source)
	e.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	e.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	if e.isLocalAddress(destination.Addr) {
		metadata.OriginDestination = destination
		destination.Addr = loopbackAddressFor(destination.Addr)
		conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, destination)
	}
	metadata.Destination = destination
	e.logger.InfoContext(ctx, "inbound packet connection from ", source)
	e.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	e.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) isLocalAddress(address netip.Addr) bool {
	for _, localPrefix := range e.localAddresses {
		if address == localPrefix.Addr() {
			return true
		}
	}
	return false
}

func loopbackAddressFor(address netip.Addr) netip.Addr {
	if address.Is4() {
		return netip.AddrFrom4([4]uint8{127, 0, 0, 1})
	}
	return netip.IPv6Loopback()
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		e.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsDomain() {
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, e.device, network, destination, destinationAddresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return e.device.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsDomain() {
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		packetConn, destinationAddress, err := N.ListenSerial(ctx, e.device, destination, destinationAddresses)
		if err != nil {
			return nil, netip.Addr{}, err
		}
		return iponly.NewPacketConn(e.logger, packetConn), destinationAddress, nil
	}
	packetConn, err := e.device.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return iponly.NewPacketConn(e.logger, packetConn), destination.Addr, nil
	}
	return iponly.NewPacketConn(e.logger, packetConn), netip.Addr{}, nil
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := e.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}
