//go:build with_utls

package trusttunnel

import (
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestClientRandomUTLSClientHello(t *testing.T) {
	t.Parallel()
	prefix, mask, err := parseClientRandom(testClientRandom)
	require.NoError(t, err)
	for _, fingerprint := range []string{"chrome", "firefox", "randomized"} {
		t.Run(fingerprint, func(t *testing.T) {
			t.Parallel()
			tlsOptions := option.OutboundTLSOptions{
				UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
			}
			config, err := newClientRandomConfig(newTestTLSConfig(t, tlsOptions), testClientRandom, tlsOptions)
			require.NoError(t, err)
			randoms := make(map[string]bool)
			for range 4 {
				random := clientHelloRandom(captureClientHello(t, config))
				requireMatchesClientRandom(t, prefix, mask, random)
				randoms[string(random)] = true
			}
			require.Len(t, randoms, 4)
		})
	}
}
