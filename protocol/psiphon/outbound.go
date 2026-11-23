//go:build with_psiphon

package psiphon

import (
	"cmp"
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	"github.com/sagernet/sing-box/common/proxybridge"
	"github.com/sagernet/sing-box/common/systemdns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/refraction"
)

const (
	defaultPropagationChannelID = "FFFFFFFFFFFFFFFF"
	defaultSponsorID            = "FFFFFFFFFFFFFFFF"
	defaultRemoteServerListURL  = "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	defaultSignaturePublicKey   = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
	clientVersion               = "1"
	minRestartDelay             = 5 * time.Second
	maxRestartDelay             = 5 * time.Minute
	tunnelWaitTimeout           = time.Minute
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.PsiphonOutboundOptions](registry, C.TypePsiphon, NewOutbound)
}

var (
	_ adapter.InterfaceUpdateListener    = (*Outbound)(nil)
	_ dialer.PacketDialerWithDestination = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	ctx                  context.Context
	logger               logger.ContextLogger
	dialer               N.Dialer
	dnsRouter            adapter.DNSRouter
	serverList           ServerListProvider
	system               *systemdns.Source
	deviceBinder         psiphon.DeviceBinder
	dnsServerGetter      psiphon.DNSServerGetter
	networkIDGetter      psiphon.NetworkIDGetter
	dataDirectory        string
	egressRegion         string
	propagationChannelID string
	sponsorID            string
	remoteServerListURLs parameters.TransferURLs
	signaturePublicKey   string
	tunnelProtocols      []string
	chained              bool
	access               sync.Mutex
	scope                *adapter.Scope
	proxy                *proxybridge.Bridge
	runContext           context.Context
	cancel               context.CancelFunc
	done                 chan struct{}
	controller           atomic.Pointer[psiphon.Controller]
	udpgwAccess          chan struct{}
	udpgw                *udpgwStream
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.PsiphonOutboundOptions) (adapter.Outbound, error) {
	serverListURLs := []string(options.RemoteServerListURLs)
	if len(serverListURLs) == 0 {
		serverListURLs = []string{defaultRemoteServerListURL}
	}
	var remoteServerListURLs parameters.TransferURLs
	for _, serverListURL := range serverListURLs {
		parsedURL, err := url.Parse(serverListURL)
		if err != nil {
			return nil, E.Cause(err, "parse remote server list URL")
		}
		if parsedURL.Scheme != "https" || parsedURL.Hostname() == "" {
			return nil, E.New("remote server list URL must be an https URL: ", serverListURL)
		}
		remoteServerListURLs = append(remoteServerListURLs, &parameters.TransferURL{
			URL: base64.StdEncoding.EncodeToString([]byte(serverListURL)),
		})
	}
	dataDirectory := filemanager.BasePath(ctx, os.ExpandEnv(cmp.Or(options.DataDirectory, "psiphon")))
	dataDirectory, _ = filepath.Abs(dataDirectory)
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, false)
	if err != nil {
		return nil, err
	}
	var (
		system          *systemdns.Source
		deviceBinder    psiphon.DeviceBinder
		dnsServerGetter psiphon.DNSServerGetter
	)
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if options.Detour == "" && networkManager != nil {
		// Psiphon's own sockets get what direct dials get: interface binding, routing marks and the auto_redirect mark.
		defaultDialer, isDefaultDialer := common.Cast[*dialer.DefaultDialer](outboundDialer)
		if isDefaultDialer {
			socketControl := defaultDialer.SocketControl()
			if socketControl != nil {
				deviceBinder = &controlBinder{control: socketControl}
			}
		}
		system, err = systemdns.NewSource(ctx)
		if err != nil {
			return nil, err
		}
		dnsServerGetter = &systemDNSServers{source: system}
	}
	return &Outbound{
		Adapter:              outbound.NewAdapterWithDialerOptions(C.TypePsiphon, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:                  ctx,
		logger:               logger,
		dialer:               outboundDialer,
		dnsRouter:            service.FromContext[adapter.DNSRouter](ctx),
		serverList:           service.FromContext[ServerListProvider](ctx),
		system:               system,
		deviceBinder:         deviceBinder,
		dnsServerGetter:      dnsServerGetter,
		networkIDGetter:      &defaultInterfaceID{networkManager: networkManager},
		dataDirectory:        dataDirectory,
		egressRegion:         options.EgressRegion,
		propagationChannelID: cmp.Or(options.PropagationChannelID, defaultPropagationChannelID),
		sponsorID:            cmp.Or(options.SponsorID, defaultSponsorID),
		remoteServerListURLs: remoteServerListURLs,
		signaturePublicKey:   cmp.Or(options.RemoteServerListSignaturePublicKey, defaultSignaturePublicKey),
		tunnelProtocols:      limitTunnelProtocols(options.Detour != ""),
		chained:              options.Detour != "",
		udpgwAccess:          make(chan struct{}, 1),
	}, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if h.system != nil {
			scope.Add(h.system.Close)
		}
	case adapter.StartStateStart:
		// Registered before the scope is published: a launch can only happen while this cleanup is pending.
		scope.Add(func() error {
			h.access.Lock()
			defer h.access.Unlock()
			return h.stop()
		})
		h.access.Lock()
		h.scope = scope
		h.access.Unlock()
	}
	return nil
}

// Warm starts Psiphon in the background ahead of the first connection.
func (h *Outbound) Warm() {
	go func() {
		_, err := h.prepare()
		if err != nil && !E.IsClosedOrCanceled(err) {
			h.logger.Error(err)
		}
	}()
}

func (h *Outbound) prepare() (context.Context, error) {
	h.access.Lock()
	defer h.access.Unlock()
	if h.runContext != nil {
		return h.runContext, nil
	}
	if h.scope == nil {
		return nil, E.New("Psiphon outbound is not started")
	}
	if h.scope.Context().Err() != nil {
		return nil, net.ErrClosed
	}
	err := h.start()
	if err != nil {
		h.stop()
		return nil, E.Cause(err, "start psiphon")
	}
	return h.runContext, nil
}

func (h *Outbound) start() error {
	err := filemanager.MkdirAll(h.ctx, h.dataDirectory, 0o755)
	if err != nil {
		return err
	}
	config := &psiphon.Config{
		DataRootDirectory:                  h.dataDirectory,
		PropagationChannelId:               h.propagationChannelID,
		SponsorId:                          h.sponsorID,
		ClientPlatform:                     clientPlatform(),
		ClientVersion:                      clientVersion,
		EgressRegion:                       h.egressRegion,
		LimitTunnelProtocols:               h.tunnelProtocols,
		RemoteServerListURLs:               h.remoteServerListURLs,
		RemoteServerListSignaturePublicKey: h.signaturePublicKey,
		DeviceBinder:                       h.deviceBinder,
		DNSServerGetter:                    h.dnsServerGetter,
		NetworkIDGetter:                    h.networkIDGetter,
		EstablishTunnelTimeoutSeconds:      common.Ptr(0),
		DisableLocalSocksProxy:             true,
		DisableLocalHTTPProxy:              true,
		DisableDSLFetcher:                  true,
		DisableForcedGarbageCollection:     true,
	}
	if h.chained {
		proxy, err := proxybridge.New(h.ctx, h.logger, "proxy", h.dialer)
		if err != nil {
			return err
		}
		err = proxy.Start()
		if err != nil {
			return err
		}
		h.proxy = proxy
		config.UpstreamProxyURL = (&url.URL{
			Scheme: "socks5",
			User:   url.UserPassword(proxy.Username(), proxy.Password()),
			Host:   "127.0.0.1:" + F.ToString(proxy.Port()),
		}).String()
	}
	err = hub.register(h)
	if err != nil {
		return err
	}
	err = config.Commit(false)
	if err != nil {
		return E.Cause(err, "commit config")
	}
	h.runContext, h.cancel = context.WithCancel(h.scope.Context())
	h.done = make(chan struct{})
	go h.loop(h.runContext, config, h.done)
	return nil
}

func (h *Outbound) stop() error {
	var err error
	if h.cancel != nil {
		h.cancel()
		timer := time.NewTimer(C.StopTimeout)
		select {
		case <-h.done:
		case <-timer.C:
			err = E.New("Psiphon did not stop in ", C.StopTimeout)
		}
		timer.Stop()
	}
	hub.unregister(h)
	h.udpgwAccess <- struct{}{}
	if h.udpgw != nil {
		h.udpgw.close(net.ErrClosed)
		h.udpgw = nil
	}
	<-h.udpgwAccess
	err = E.Errors(err, common.Close(common.PtrOrNil(h.proxy)))
	h.proxy = nil
	h.runContext = nil
	h.cancel = nil
	h.done = nil
	return err
}

func (h *Outbound) loop(ctx context.Context, config *psiphon.Config, done chan struct{}) {
	defer close(done)
	delay := minRestartDelay
	for {
		startTime := time.Now()
		err := h.run(ctx, config)
		if ctx.Err() != nil {
			return
		}
		if time.Since(startTime) > maxRestartDelay {
			delay = minRestartDelay
		}
		if err != nil {
			h.logger.Error(err, ", restarting in ", delay)
		} else {
			h.logger.Error("psiphon stopped unexpectedly, restarting in ", delay)
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
		delay = min(delay*2, maxRestartDelay)
	}
}

func (h *Outbound) run(ctx context.Context, config *psiphon.Config) error {
	err := psiphon.OpenDataStore(config)
	if err != nil {
		return E.Cause(err, "open datastore")
	}
	defer psiphon.CloseDataStore()
	if h.serverList != nil {
		err = importServerList(ctx, config, h.serverList)
		if err != nil && ctx.Err() == nil {
			h.logger.Warn(err)
		}
	}
	controller, err := psiphon.NewController(config)
	if err != nil {
		return E.Cause(err, "create controller")
	}
	h.controller.Store(controller)
	defer h.controller.Store(nil)
	controller.Run(ctx)
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		ctx, metadata := adapter.ExtendContext(ctx)
		metadata.Outbound = h.Tag()
		metadata.Destination = destination
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		runContext, err := h.prepare()
		if err != nil {
			return nil, err
		}
		return h.dial(ctx, runContext, destination.String())
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

// udpgw carries IP destinations only, so a domain is resolved here and packets to other domains are dropped.
func (h *Outbound) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	var destinationAddress netip.Addr
	if destination.IsFqdn() {
		destinationAddresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		if len(destinationAddresses) == 0 {
			return nil, netip.Addr{}, E.New("no addresses for ", destination.Fqdn)
		}
		destinationAddress = destinationAddresses[0]
		for _, address := range destinationAddresses {
			if address.Is4() {
				destinationAddress = address
				break
			}
		}
	} else if destination.IsIP() {
		destinationAddress = destination.Addr
	}
	runContext, err := h.prepare()
	if err != nil {
		return nil, netip.Addr{}, err
	}
	stream, err := h.prepareUDPGW(ctx, runContext)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	return iponly.NewPacketConn(h.logger, newUDPGWPacketConn(stream)), destinationAddress, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := h.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.system != nil {
		h.system.Reset()
	}
	controller := h.controller.Load()
	if controller != nil {
		controller.NetworkChanged()
	}
}

// A channel rather than a mutex, so that each caller can stop waiting for a tunnel on its own context.
func (h *Outbound) prepareUDPGW(ctx context.Context, runContext context.Context) (*udpgwStream, error) {
	select {
	case h.udpgwAccess <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() {
		<-h.udpgwAccess
	}()
	if h.udpgw != nil && !h.udpgw.closed() {
		return h.udpgw, nil
	}
	conn, err := h.dial(ctx, runContext, protocol.DEFAULT_UDPGW_INTERCEPT_ADDRESS)
	if err != nil {
		return nil, err
	}
	h.udpgw = newUDPGWStream(conn)
	return h.udpgw, nil
}

// Notices carry no instance identity, so dials are retried whenever any tunnel count changes.
func (h *Outbound) dial(ctx context.Context, runContext context.Context, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, tunnelWaitTimeout)
	defer cancel()
	for {
		tunnelsChanged := hub.tunnelsChanged()
		controller := h.controller.Load()
		if controller != nil {
			conn, err := dialController(ctx, runContext, controller, address)
			// Psiphon reports a missing tunnel only through the error text.
			if err == nil || !strings.HasSuffix(err.Error(), "no active tunnels") {
				return conn, err
			}
		}
		select {
		case <-tunnelsChanged:
		case <-ctx.Done():
			return nil, E.Cause(ctx.Err(), "wait for Psiphon tunnel")
		case <-runContext.Done():
			return nil, net.ErrClosed
		}
	}
}

// Controller.Dial takes no context; a dial abandoned by the caller is closed once it completes.
func dialController(ctx context.Context, runContext context.Context, controller *psiphon.Controller, address string) (net.Conn, error) {
	type dialResult struct {
		conn net.Conn
		err  error
	}
	results := make(chan dialResult)
	go func() {
		conn, err := controller.Dial(address, nil)
		select {
		case results <- dialResult{conn, err}:
		case <-ctx.Done():
			common.Close(conn)
		case <-runContext.Done():
			common.Close(conn)
		}
	}()
	select {
	case result := <-results:
		return result.conn, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-runContext.Done():
		return nil, net.ErrClosed
	}
}

func clientPlatform() string {
	var platform string
	switch {
	case C.IsWindows:
		platform = "Windows"
	case C.IsDarwin:
		platform = "macOS"
	case C.IsLinux:
		platform = "Linux"
	default:
		platform = runtime.GOOS
	}
	return platform + "_Throne"
}

// Psiphon's protocol lists ignore build tags: keep its default selection minus what this build or a detour cannot carry.
func limitTunnelProtocols(chained bool) []string {
	var tunnelProtocols []string
	for _, tunnelProtocol := range protocol.SupportedTunnelProtocols.PruneInvalid() {
		if slices.Contains(protocol.DefaultDisabledTunnelProtocols, tunnelProtocol) ||
			protocol.TunnelProtocolUsesQUIC(tunnelProtocol) && !quic.Enabled() ||
			protocol.TunnelProtocolUsesInproxy(tunnelProtocol) && !inproxy.Enabled() ||
			protocol.TunnelProtocolUsesRefractionNetworking(tunnelProtocol) && !refraction.Enabled() ||
			chained && !protocol.TunnelProtocolSupportsUpstreamProxy(tunnelProtocol) {
			continue
		}
		tunnelProtocols = append(tunnelProtocols, tunnelProtocol)
	}
	return tunnelProtocols
}
