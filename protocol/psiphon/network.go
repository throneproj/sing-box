//go:build with_psiphon

package psiphon

import (
	"os"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/systemdns"
	"github.com/sagernet/sing/common/control"
	N "github.com/sagernet/sing/common/network"
)

// controlBinder applies the socket controls of the outbound dialer to the sockets Psiphon creates.
type controlBinder struct {
	control control.Func
}

func (b *controlBinder) BindToDevice(fileDescriptor int) (string, error) {
	network, err := socketNetwork(fileDescriptor)
	if err != nil {
		return "", err
	}
	return "", b.control(network, "", rawConn(fileDescriptor))
}

func networkName(isUDP bool, isIPv6 bool) string {
	network := N.NetworkTCP
	if isUDP {
		network = N.NetworkUDP
	}
	if isIPv6 {
		return network + "6"
	}
	return network + "4"
}

var _ syscall.RawConn = rawConn(0)

// Psiphon calls BindToDevice from inside the Control callback of the real RawConn, so the descriptor is used directly.
type rawConn int

func (c rawConn) Control(f func(fd uintptr)) error {
	f(uintptr(c))
	return nil
}

func (c rawConn) Read(f func(fd uintptr) bool) error {
	return os.ErrInvalid
}

func (c rawConn) Write(f func(fd uintptr) bool) error {
	return os.ErrInvalid
}

type systemDNSServers struct {
	source *systemdns.Source
}

func (s *systemDNSServers) GetDNSServers() []string {
	var servers []string
	for _, server := range s.source.Servers() {
		if !server.IsIP() || server.Addr.IsLoopback() || server.Addr.IsUnspecified() || server.Addr.IsLinkLocalUnicast() {
			continue
		}
		servers = append(servers, server.String())
	}
	if len(servers) == 0 {
		return []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return servers
}

type defaultInterfaceID struct {
	networkManager adapter.NetworkManager
}

func (i *defaultInterfaceID) GetNetworkID() string {
	if i.networkManager == nil || i.networkManager.InterfaceMonitor() == nil {
		return "UNKNOWN"
	}
	defaultInterface := i.networkManager.DefaultNetworkInterface()
	if defaultInterface == nil {
		return "UNKNOWN"
	}
	// Psiphon sends the type before the dash to its servers and keeps the rest local.
	return "UNKNOWN-" + defaultInterface.Name
}
