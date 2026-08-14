//go:build darwin

package transport

import (
	"net/netip"
	"os/exec"
	"regexp"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

var (
	scutilServiceKeyRegexp    = regexp.MustCompile(`(?m)^\s*subKey \[\d+\] = (State:/Network/Service/([^/\s]+)/IPv[46])$`)
	scutilInterfaceNameRegexp = regexp.MustCompile(`(?m)^\s*InterfaceName : (\S+)$`)
	scutilServerArrayRegexp   = regexp.MustCompile(`(?s)ServerAddresses : <array> \{\n(.*?)\n\s*\}`)
	scutilArrayEntryRegexp    = regexp.MustCompile(`(?m)^\s*\d+ : (\S+)$`)
)

// The system resolver may be pointed at a local forwarder, so the servers are
// read from the network service of the interface instead: the ones set by the
// user (Setup:) first, then the ones from DHCP or router advertisements (State:),
// skipping loopback servers, which are such forwarders.
func detectUnderlyingServer(interfaceName string) (M.Socksaddr, error) {
	serviceID, err := scutilServiceID(interfaceName)
	if err != nil {
		return M.Socksaddr{}, err
	}
	for _, domain := range []string{"Setup:", "State:"} {
		output, err := scutil("show " + domain + "/Network/Service/" + serviceID + "/DNS")
		if err != nil {
			return M.Socksaddr{}, err
		}
		serverArray := scutilServerArrayRegexp.FindStringSubmatch(output)
		if serverArray == nil {
			continue
		}
		for _, entry := range scutilArrayEntryRegexp.FindAllStringSubmatch(serverArray[1], -1) {
			address, err := netip.ParseAddr(entry[1])
			if err != nil || address.IsLoopback() {
				continue
			}
			if address.IsLinkLocalUnicast() && address.Zone() == "" {
				address = address.WithZone(interfaceName)
			}
			return M.SocksaddrFrom(address, 53), nil
		}
	}
	return M.Socksaddr{}, E.New("no DNS server on the network service of ", interfaceName)
}

func scutilServiceID(interfaceName string) (string, error) {
	output, err := scutil("list State:/Network/Service/[^/]+/IPv[46]")
	if err != nil {
		return "", err
	}
	for _, serviceKey := range scutilServiceKeyRegexp.FindAllStringSubmatch(output, -1) {
		value, err := scutil("show " + serviceKey[1])
		if err != nil {
			return "", err
		}
		name := scutilInterfaceNameRegexp.FindStringSubmatch(value)
		if name != nil && name[1] == interfaceName {
			return serviceKey[2], nil
		}
	}
	return "", E.New("no network service on ", interfaceName)
}

func scutil(command string) (string, error) {
	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader(command + "\n")
	output, err := cmd.Output()
	if err != nil {
		return "", E.Cause(err, "execute scutil")
	}
	return string(output), nil
}
