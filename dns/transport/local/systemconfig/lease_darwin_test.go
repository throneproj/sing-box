//go:build darwin && cgo

package systemconfig

import (
	"net/netip"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestParseLeaseServers(t *testing.T) {
	t.Parallel()
	summary := "<dictionary> {\n  IPv4 : <array> {\n  }\n  domain_name_server (ip_mult): {192.0.2.10, 192.0.2.11}\n  router (ip_mult): {192.0.2.1}\n}\n"
	require.Equal(t, []M.Socksaddr{
		M.SocksaddrFrom(netip.MustParseAddr("192.0.2.10"), 53),
		M.SocksaddrFrom(netip.MustParseAddr("192.0.2.11"), 53),
	}, parseLeaseServers(summary))
	require.Equal(t, []M.Socksaddr{
		M.SocksaddrFrom(netip.MustParseAddr("192.0.2.10"), 53),
	}, parseLeaseServers("  domain_name_server (ip): 192.0.2.10\n"))
	require.Nil(t, parseLeaseServers("  router (ip_mult): {192.0.2.1}\n"))
	require.Nil(t, parseLeaseServers(""))
}
