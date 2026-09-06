package trusttunnel

import (
	"bytes"
	"context"
	stdTLS "crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestClientRandomOptionDecode(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name    string
		content string
		value   string
	}{
		{"absent", `{"server":"example.org","server_port":443}`, ""},
		{"present", `{"server":"example.org","server_port":443,"client_random":"a0b0/f0f0"}`, "a0b0/f0f0"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var options option.TrustTunnelOutboundOptions
			err := json.UnmarshalContextDisallowUnknownFields(context.Background(), []byte(testCase.content), &options)
			require.NoError(t, err)
			require.Equal(t, testCase.value, options.ClientRandom)
		})
	}
}

func TestParseClientRandom(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name   string
		value  string
		prefix string
		mask   string
	}{
		{"prefix", "aabbcc", "aabbcc", "ffffff"},
		{"prefix and mask", "a0b0/f0f0", "a0b0", "f0f0"},
		{"short mask", "aabbcc/ff", "aabbcc", "ffffff"},
		{"long mask", "aabb/f0f0f0", "aabb", "f0f0"},
		{"upper case", "AABB", "aabb", "ffff"},
		{"full length", hex.EncodeToString(bytes.Repeat([]byte{0xAA}, 32)), hex.EncodeToString(bytes.Repeat([]byte{0xAA}, 32)), hex.EncodeToString(bytes.Repeat([]byte{0xFF}, 32))},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			prefix, mask, err := parseClientRandom(testCase.value)
			require.NoError(t, err)
			require.Equal(t, testCase.prefix, hex.EncodeToString(prefix))
			require.Equal(t, testCase.mask, hex.EncodeToString(mask))
		})
	}
}

func TestParseClientRandomInvalid(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name  string
		value string
	}{
		{"odd length prefix", "aab"},
		{"odd length mask", "aabb/ff0"},
		{"not hex", "zzzz"},
		{"mask not hex", "aabb/zzzz"},
		{"empty mask", "aabb/"},
		{"empty prefix", "/ffff"},
		{"empty prefix and mask", "/"},
		{"too long", hex.EncodeToString(bytes.Repeat([]byte{0xAA}, 33))},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := parseClientRandom(testCase.value)
			require.Error(t, err)
		})
	}
}

// TestClientRandomReaderAppliesOnce uses a full length prefix, so that any read
// the prefix was applied to is exactly equal to it.
func TestClientRandomReaderAppliesOnce(t *testing.T) {
	t.Parallel()
	prefix := bytes.Repeat([]byte{0xAA}, clientRandomLength)
	reader := &clientRandomReader{prefix: prefix, mask: bytes.Repeat([]byte{0xFF}, clientRandomLength)}

	shortRead := make([]byte, clientRandomLength/2)
	_, err := io.ReadFull(reader, shortRead)
	require.NoError(t, err)
	require.NotEqual(t, prefix[:len(shortRead)], shortRead)

	clientHelloRandom := make([]byte, clientRandomLength)
	_, err = io.ReadFull(reader, clientHelloRandom)
	require.NoError(t, err)
	require.Equal(t, prefix, clientHelloRandom)

	for range 4 {
		later := make([]byte, clientRandomLength)
		_, err = io.ReadFull(reader, later)
		require.NoError(t, err)
		require.NotEqual(t, prefix, later)
	}
}

func TestClientRandomReaderKeepsUnmaskedBits(t *testing.T) {
	t.Parallel()
	prefix, mask, err := parseClientRandom("a0b0/f0f0")
	require.NoError(t, err)
	values := make(map[string]bool)
	for range 64 {
		reader := &clientRandomReader{prefix: prefix, mask: mask}
		random := make([]byte, clientRandomLength)
		_, err = io.ReadFull(reader, random)
		require.NoError(t, err)
		requireMatchesClientRandom(t, prefix, mask, random)
		values[string(random[:len(prefix)])] = true
	}
	// The four bits of each masked byte that the mask leaves out stay random.
	require.Greater(t, len(values), 1)
}

func TestClientRandomClientHello(t *testing.T) {
	t.Parallel()
	prefix, mask, err := parseClientRandom("a0b0/f0f0")
	require.NoError(t, err)
	tlsConfig := newTestTLSConfig(t)
	config, err := newClientRandomConfig(tlsConfig, option.TrustTunnelOutboundOptions{
		ClientRandom: "a0b0/f0f0",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true},
		},
	})
	require.NoError(t, err)
	randoms := make(map[string]bool)
	for range 8 {
		random := captureClientHelloRandom(t, config)
		requireMatchesClientRandom(t, prefix, mask, random)
		randoms[string(random)] = true
	}
	// Every connection generates its own random.
	require.Len(t, randoms, 8)
	// The entropy source is replaced on a copy, the wrapped config is untouched.
	stdConfig, err := tlsConfig.STDConfig()
	require.NoError(t, err)
	require.Nil(t, stdConfig.Rand)
}

func TestClientRandomQUICClientHello(t *testing.T) {
	t.Parallel()
	prefix, mask, err := parseClientRandom("a0b0/f0f0")
	require.NoError(t, err)
	config, err := newClientRandomConfig(newTestTLSConfig(t), option.TrustTunnelOutboundOptions{
		ClientRandom: "a0b0/f0f0",
		QUIC:         true,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true},
		},
	})
	require.NoError(t, err)
	config.SetNextProtos([]string{"h3"})

	randoms := make(map[string]bool)
	var previousConfig *stdTLS.Config
	for range 8 {
		stdConfig, err := config.STDConfig()
		require.NoError(t, err)
		if previousConfig != nil {
			require.NotSame(t, previousConfig, stdConfig)
		}
		previousConfig = stdConfig
		random := captureQUICClientHelloRandom(t, stdConfig)
		requireMatchesClientRandom(t, prefix, mask, random)
		randoms[string(random)] = true
	}
	require.Len(t, randoms, 8)
}

func TestNewClientRandomConfigECHUnsupported(t *testing.T) {
	t.Parallel()
	_, err := newClientRandomConfig(newTestTLSConfig(t), option.TrustTunnelOutboundOptions{
		ClientRandom: "aabb",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled: true,
				ECH:     &option.OutboundECHOptions{Enabled: true},
			},
		},
	})
	require.Error(t, err)
}

func requireMatchesClientRandom(t *testing.T, prefix []byte, mask []byte, random []byte) {
	t.Helper()
	require.Len(t, random, clientRandomLength)
	for i, prefixByte := range prefix {
		require.Equalf(t, prefixByte&mask[i], random[i]&mask[i], "byte %d of %s", i, hex.EncodeToString(random))
	}
}

func newTestTLSConfig(t *testing.T) tls.Config {
	t.Helper()
	config, err := tls.NewClient(context.Background(), logger.NOP(), "example.org", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.org",
	})
	require.NoError(t, err)
	return config
}

// captureClientHelloRandom runs the client side of a TLS handshake against a
// pipe and returns the random of the ClientHello it sent.
func captureClientHelloRandom(t *testing.T, config tls.Config) []byte {
	t.Helper()
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()
	tlsConn, err := config.Client(clientPipe)
	require.NoError(t, err)
	go func() {
		_ = tlsConn.HandshakeContext(context.Background())
	}()
	// Record header, handshake header, legacy version, random.
	clientHello := make([]byte, 5+4+2+clientRandomLength)
	_, err = io.ReadFull(serverPipe, clientHello)
	require.NoError(t, err)
	require.Equal(t, byte(0x16), clientHello[0], "handshake record")
	require.Equal(t, byte(0x01), clientHello[5], "client hello")
	return clientHello[11:]
}

func captureQUICClientHelloRandom(t *testing.T, config *stdTLS.Config) []byte {
	t.Helper()
	config.MinVersion = stdTLS.VersionTLS13
	conn := stdTLS.QUICClient(&stdTLS.QUICConfig{TLSConfig: config})
	defer conn.Close()
	conn.SetTransportParameters(nil)
	require.NoError(t, conn.Start(context.Background()))

	var clientHello []byte
	for {
		event := conn.NextEvent()
		switch event.Kind {
		case stdTLS.QUICWriteData:
			if event.Level != stdTLS.QUICEncryptionLevelInitial {
				continue
			}
			clientHello = append(clientHello, event.Data...)
			if len(clientHello) >= 4+2+clientRandomLength {
				require.Equal(t, byte(0x01), clientHello[0], "client hello")
				return bytes.Clone(clientHello[6 : 6+clientRandomLength])
			}
		case stdTLS.QUICNoEvent:
			require.FailNow(t, "QUIC ClientHello was not emitted")
		}
	}
}
