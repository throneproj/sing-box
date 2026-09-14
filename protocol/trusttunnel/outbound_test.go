package trusttunnel

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"github.com/xchacha20-poly1305/sing-trusttunnel"
)

func TestOutboundStartsHealthCheck(t *testing.T) {
	t.Parallel()
	client, err := trusttunnel.NewClient(trusttunnel.ClientOptions{
		Ctx:         t.Context(),
		Detour:      new(N.DefaultDialer),
		Server:      M.ParseSocksaddr("127.0.0.1:443"),
		Auth:        auth.User{Username: "sekai", Password: "password"},
		TLSConfig:   newTestTLSConfig(t, option.OutboundTLSOptions{}),
		HealthCheck: true,
	})
	require.NoError(t, err)
	outbound := &Outbound{client: client}
	require.NoError(t, outbound.Start(adapter.StartStateStart))
	// Both touch the health check timer, which panics unless the client was started.
	outbound.InterfaceUpdated()
	require.NoError(t, outbound.Close())
}
