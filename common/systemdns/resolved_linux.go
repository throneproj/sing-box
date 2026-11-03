package systemdns

import (
	"bufio"
	"net/netip"
	"os"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
)

const resolvedUplinkConfigPath = "/run/systemd/resolve/resolv.conf"

// The resolved stub forwards on unmarked sockets that our Tun captures, so queries go to its uplinks directly.
func resolvedUplinkServers(stubServers []M.Socksaddr) []M.Socksaddr {
	file, err := os.Open(resolvedUplinkConfigPath)
	if err != nil {
		return stubServers
	}
	defer file.Close()
	var servers []M.Socksaddr
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		serverAddr, parseErr := netip.ParseAddr(fields[1])
		if parseErr == nil {
			servers = append(servers, M.SocksaddrFrom(serverAddr, 53))
		}
	}
	if len(servers) == 0 {
		return stubServers
	}
	return servers
}
