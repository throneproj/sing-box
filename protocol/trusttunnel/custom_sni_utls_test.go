//go:build with_utls

package trusttunnel

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestCustomSNIUTLS(t *testing.T) {
	t.Parallel()
	utlsOptions := option.OutboundTLSOptions{
		UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
	}
	t.Run("client hello", func(t *testing.T) {
		t.Parallel()
		config := newTestTLSConfig(t, utlsOptions)
		require.NoError(t, setCustomSNI(config, testCustomSNI, utlsOptions))
		clientHello := captureClientHello(t, config)
		require.True(t, bytes.Contains(clientHello, []byte(testCustomSNI)))
		require.False(t, bytes.Contains(clientHello, []byte(testServerName)))
	})
	t.Run("verifies server_name", func(t *testing.T) {
		t.Parallel()
		requireCustomSNIHandshake(t, testServerName, utlsOptions, false)
	})
	t.Run("rejects certificate for custom_sni", func(t *testing.T) {
		t.Parallel()
		requireCustomSNIHandshake(t, testCustomSNI, utlsOptions, true)
	})
}
