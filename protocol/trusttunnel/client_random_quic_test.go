//go:build with_quic

package trusttunnel

import (
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestClientRandomThroughQUICService(t *testing.T) {
	t.Parallel()
	packetConn, err := N.SystemDialer.ListenPacket(t.Context(), M.ParseSocksaddr("127.0.0.1:0"))
	require.NoError(t, err)
	keyLog := startClientRandomService(t, nil, packetConn)
	client := newClientRandomClient(t, M.ParseSocksaddr(packetConn.LocalAddr().String()), true)
	// Only one connection: ResetConnections closes the client's http3.Transport for good.
	requireEcho(t, client)
	requireServerClientRandoms(t, keyLog, 1)
}
