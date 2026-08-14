package transport

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var _ adapter.DNSTransport = (*Underlying)(nil)

func RegisterUnderlying(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteDNSServerOptions](registry, C.DNSTypeUnderlying, NewUnderlying)
}

// Underlying is a UDP transport that follows the DNS server systemd-resolved
// hands out for the current default interface, so queries can be sent to
// whatever the underlying network would have used.
type Underlying struct {
	*UDPTransport
	logger     logger.ContextLogger
	ifcMonitor tun.DefaultInterfaceMonitor

	access sync.Mutex
	server M.Socksaddr
}

func NewUnderlying(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options)
	if err != nil {
		return nil, err
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil || networkManager.InterfaceMonitor() == nil {
		return nil, E.New("interface monitor is not available")
	}
	t := &Underlying{
		logger:     logger,
		ifcMonitor: networkManager.InterfaceMonitor(),
	}
	// The server address is resolved per dial instead of being baked into the
	// transport, so an interface change is picked up without a data race on it.
	t.UDPTransport = NewUDPRaw(
		logger,
		dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeUnderlying, tag, options),
		&underlyingDialer{Dialer: transportDialer, transport: t},
		M.Socksaddr{},
	)
	t.ifcMonitor.RegisterCallback(t.handleInterfaceUpdate)
	t.updateServer(t.ifcMonitor.DefaultInterface())
	return t, nil
}

func (t *Underlying) handleInterfaceUpdate(defaultInterface *control.Interface, flags int) {
	t.updateServer(defaultInterface)
	t.Reset()
}

func (t *Underlying) updateServer(defaultInterface *control.Interface) {
	var (
		server M.Socksaddr
		err    error
	)
	if defaultInterface == nil {
		err = E.New("no default interface")
	} else {
		server, err = resolvectlDNS(defaultInterface.Name)
	}
	t.access.Lock()
	defer t.access.Unlock()
	if err != nil {
		t.logger.Error(E.Cause(err, "detect underlying DNS server"))
		t.server = M.Socksaddr{}
		return
	}
	if t.server != server {
		t.logger.Info("underlying DNS server set to ", server)
	}
	t.server = server
}

// currentServer returns the detected server, retrying detection when the last
// attempt failed so a transient resolvectl failure does not disable the
// transport until the next interface update.
func (t *Underlying) currentServer() (M.Socksaddr, error) {
	t.access.Lock()
	server := t.server
	t.access.Unlock()
	if server.IsValid() {
		return server, nil
	}
	t.updateServer(t.ifcMonitor.DefaultInterface())
	t.access.Lock()
	server = t.server
	t.access.Unlock()
	if !server.IsValid() {
		return M.Socksaddr{}, E.New("no underlying DNS server detected")
	}
	return server, nil
}

func resolvectlDNS(interfaceName string) (M.Socksaddr, error) {
	output, err := exec.Command("resolvectl", "-i", interfaceName, "dns").Output()
	if err != nil {
		return M.Socksaddr{}, E.Cause(err, "execute resolvectl")
	}
	// Link 2 (eth0): 192.168.1.1
	fields := strings.Fields(string(output))
	if len(fields) < 4 {
		return M.Socksaddr{}, E.New("unexpected resolvectl output: ", string(output))
	}
	server := M.ParseSocksaddrHostPortStr(fields[3], "53")
	if !server.IsValid() {
		return M.Socksaddr{}, E.New("unexpected resolvectl output: ", string(output))
	}
	return server, nil
}

type underlyingDialer struct {
	N.Dialer
	transport *Underlying
}

func (d *underlyingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	server, err := d.transport.currentServer()
	if err != nil {
		return nil, err
	}
	return d.Dialer.DialContext(ctx, network, server)
}
