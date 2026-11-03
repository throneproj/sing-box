package systemdns

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/local/systemconfig"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type Source struct {
	networkManager adapter.NetworkManager
	configSource   *systemconfig.Source
}

func NewSource(ctx context.Context) (*Source, error) {
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("system resolvers require a network manager")
	}
	return &Source{
		networkManager: networkManager,
		configSource:   systemconfig.NewSource(ctx),
	}, nil
}

// Servers inside our own Tun addresses are dropped, as queries to them would loop back into the router.
func (s *Source) Servers() []M.Socksaddr {
	var servers []M.Socksaddr
	interfaceMonitor := s.networkManager.InterfaceMonitor()
	if interfaceMonitor != nil {
		defaultInterface := s.networkManager.DefaultNetworkInterface()
		if defaultInterface != nil {
			for _, server := range defaultInterface.DNSServers {
				serverAddr, err := netip.ParseAddr(server)
				if err == nil {
					servers = append(servers, M.SocksaddrFrom(serverAddr, 53))
				}
			}
		}
	}
	if len(servers) == 0 {
		systemConfig := s.configSource.Configuration()
		servers = systemConfig.Servers
		if systemConfig.SystemdResolved {
			servers = resolvedUplinkServers(servers)
		}
	}
	if interfaceMonitor == nil {
		return servers
	}
	var ownAddresses []*net.IPNet
	for _, interfaceName := range interfaceMonitor.MyInterfaces() {
		netInterface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			continue
		}
		addresses, err := netInterface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if ipNet, isIPNet := address.(*net.IPNet); isIPNet {
				ownAddresses = append(ownAddresses, ipNet)
			}
		}
	}
	return common.Filter(servers, func(server M.Socksaddr) bool {
		return !common.Any(ownAddresses, func(it *net.IPNet) bool {
			return it.Contains(server.Addr.AsSlice())
		})
	})
}

func (s *Source) Reset() {
	s.configSource.Reset()
}

func (s *Source) Close() error {
	return s.configSource.Close()
}
