package trusttunnel

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trusttunnel"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestOutboundStartsHealthCheck(t *testing.T) {
	t.Parallel()
	client, err := trusttunnel.NewClient(trusttunnel.ClientOptions{
		Context:     t.Context(),
		Logger:      logger.NOP(),
		Dialer:      new(N.DefaultDialer),
		Server:      M.ParseSocksaddr("127.0.0.1:443"),
		Username:    "sekai",
		Password:    "password",
		TLSConfig:   newTestTLSConfig(t, option.OutboundTLSOptions{}),
		HealthCheck: true,
	})
	require.NoError(t, err)
	outbound := &Outbound{client: client}
	scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	require.NoError(t, outbound.Start(adapter.StartStateStart, scope))
	outbound.InterfaceUpdated(t.Context())
	require.NoError(t, scope.Close())
}
