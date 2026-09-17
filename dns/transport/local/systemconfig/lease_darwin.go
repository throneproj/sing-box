//go:build darwin && cgo

package systemconfig

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
)

func replaceOwnTunServers(config *Config, interfaceIndex int, myInterfaces []string) {
	if interfaceIndex == 0 || !serversOnInterfaces(config.Servers, myInterfaces) {
		return
	}
	iface, err := net.InterfaceByIndex(interfaceIndex)
	if err != nil {
		return
	}
	if servers := leaseServers(iface.Name); len(servers) > 0 {
		config.Servers = servers
	}
}

func serversOnInterfaces(servers []M.Socksaddr, interfaceNames []string) bool {
	if len(servers) == 0 {
		return false
	}
	var interfaceAddresses []*net.IPNet
	for _, interfaceName := range interfaceNames {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if ipNet, isIPNet := address.(*net.IPNet); isIPNet {
				interfaceAddresses = append(interfaceAddresses, ipNet)
			}
		}
	}
	return common.All(servers, func(server M.Socksaddr) bool {
		return server.Addr.IsValid() && common.Any(interfaceAddresses, func(it *net.IPNet) bool {
			return it.Contains(server.Addr.AsSlice())
		})
	})
}

var leaseServersRegexp = regexp.MustCompile(`(?m)^\s*domain_name_server \((?:ip|ip_mult)\): \{?([^}\n]*)\}?$`)

func leaseServers(interfaceName string) []M.Socksaddr {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/sbin/ipconfig", "getsummary", interfaceName).Output()
	if err != nil {
		return nil
	}
	return parseLeaseServers(string(output))
}

func parseLeaseServers(summary string) []M.Socksaddr {
	match := leaseServersRegexp.FindStringSubmatch(strings.ReplaceAll(summary, "\r\n", "\n"))
	if match == nil {
		return nil
	}
	var servers []M.Socksaddr
	for field := range strings.SplitSeq(match[1], ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(field))
		if err != nil {
			continue
		}
		servers = append(servers, M.SocksaddrFrom(addr, 53))
	}
	return servers
}
