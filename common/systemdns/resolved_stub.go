//go:build !linux

package systemdns

import M "github.com/sagernet/sing/common/metadata"

func resolvedUplinkServers(stubServers []M.Socksaddr) []M.Socksaddr {
	return stubServers
}
