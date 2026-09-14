package trusttunnel

import (
	"bytes"
	"context"
	stdTLS "crypto/tls"
	"encoding/hex"
	"io"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

const testClientRandom = "a0b0/f0f0"

func TestClientRandomOptionDecode(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name    string
		content string
		value   string
	}{
		{
			name:    "absent",
			content: `{"server":"example.org","server_port":443}`,
		},
		{
			name:    "present",
			content: `{"server":"example.org","server_port":443,"client_random":"a0b0/f0f0"}`,
			value:   "a0b0/f0f0",
		},
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
		{
			name:   "prefix",
			value:  "aabbcc",
			prefix: "aabbcc",
			mask:   "ffffff",
		},
		{
			name:   "prefix and mask",
			value:  "a0b0/f0f0",
			prefix: "a0b0",
			mask:   "f0f0",
		},
		{
			name:   "upper case",
			value:  "AABB",
			prefix: "aabb",
			mask:   "ffff",
		},
		{
			name:   "full length",
			value:  hex.EncodeToString(bytes.Repeat([]byte{0xAA}, 32)),
			prefix: hex.EncodeToString(bytes.Repeat([]byte{0xAA}, 32)),
			mask:   hex.EncodeToString(bytes.Repeat([]byte{0xFF}, 32)),
		},
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
		{name: "odd length prefix", value: "aab"},
		{name: "odd length mask", value: "aabb/ff0"},
		{name: "not hex", value: "zzzz"},
		{name: "mask not hex", value: "aabb/zzzz"},
		{name: "empty mask", value: "aabb/"},
		{name: "short mask", value: "aabbcc/ff"},
		{name: "long mask", value: "aabb/f0f0f0"},
		{name: "empty prefix", value: "/ffff"},
		{name: "empty prefix and mask", value: "/"},
		{name: "too long", value: hex.EncodeToString(bytes.Repeat([]byte{0xAA}, 33))},
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
	prefix, mask, err := parseClientRandom(testClientRandom)
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
	prefix, mask, err := parseClientRandom(testClientRandom)
	require.NoError(t, err)
	tlsConfig := newTestTLSConfig(t, option.OutboundTLSOptions{})
	config, err := newClientRandomConfig(tlsConfig, testClientRandom, option.OutboundTLSOptions{})
	require.NoError(t, err)
	randoms := make(map[string]bool)
	for range 8 {
		random := clientHelloRandom(captureClientHello(t, config))
		requireMatchesClientRandom(t, prefix, mask, random)
		randoms[string(random)] = true
	}
	require.Len(t, randoms, 8)
	// The entropy source is replaced on a copy, the wrapped config is untouched.
	stdConfig, err := tlsConfig.STDConfig()
	require.NoError(t, err)
	require.Nil(t, stdConfig.Rand)
}

func TestClientRandomKeepsServerNameCase(t *testing.T) {
	t.Parallel()
	tlsConfig := newTestTLSConfig(t, option.OutboundTLSOptions{
		TLSTricks: &option.TLSTricksOptions{MixedCaseSNI: true},
	})
	stdConfig, err := tlsConfig.STDConfig()
	require.NoError(t, err)
	serverName := []byte(stdConfig.ServerName)
	config, err := newClientRandomConfig(tlsConfig, testClientRandom, option.OutboundTLSOptions{})
	require.NoError(t, err)
	for range 8 {
		require.True(t, bytes.Contains(captureClientHello(t, config), serverName))
	}
}

func TestClientRandomQUICClientHello(t *testing.T) {
	t.Parallel()
	prefix, mask, err := parseClientRandom(testClientRandom)
	require.NoError(t, err)
	config, err := newClientRandomConfig(newTestTLSConfig(t, option.OutboundTLSOptions{}), testClientRandom, option.OutboundTLSOptions{})
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

func TestNewClientRandomConfigIncompatible(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name       string
		config     tls.Config
		tlsOptions option.OutboundTLSOptions
	}{
		{
			name:       "ECH",
			config:     newTestTLSConfig(t, option.OutboundTLSOptions{}),
			tlsOptions: option.OutboundTLSOptions{ECH: &option.OutboundECHOptions{Enabled: true}},
		},
		{
			name:       "custom uTLS fingerprint",
			config:     newTestTLSConfig(t, option.OutboundTLSOptions{}),
			tlsOptions: option.OutboundTLSOptions{UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "custom"}},
		},
		{
			name:   "no custom entropy",
			config: struct{ tls.Config }{newTestTLSConfig(t, option.OutboundTLSOptions{})},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := newClientRandomConfig(testCase.config, testClientRandom, testCase.tlsOptions)
			require.Error(t, err)
		})
	}
}

func requireMatchesClientRandom(t *testing.T, prefix []byte, mask []byte, random []byte) {
	t.Helper()
	require.Len(t, random, clientRandomLength)
	for i, prefixByte := range prefix {
		require.Equalf(t, prefixByte&mask[i], random[i]&mask[i], "byte %d of %s", i, hex.EncodeToString(random))
	}
}

func newTestTLSConfig(t *testing.T, options option.OutboundTLSOptions) tls.Config {
	t.Helper()
	options.Enabled = true
	options.ServerName = "example.org"
	config, err := tls.NewClient(context.Background(), logger.NOP(), "example.org", options)
	require.NoError(t, err)
	return config
}

// captureClientHello runs the client side of a handshake against a write-only
// conn and returns the ClientHello record it sent.
func captureClientHello(t *testing.T, config tls.Config) []byte {
	t.Helper()
	var buffer bytes.Buffer
	tlsConn, err := config.Client(bufio.NewWriteOnlyConn(&buffer))
	require.NoError(t, err)
	_ = tlsConn.HandshakeContext(context.Background())
	clientHello := buffer.Bytes()
	require.Greater(t, len(clientHello), 5+4+2+clientRandomLength)
	require.Equal(t, byte(0x16), clientHello[0], "handshake record")
	require.Equal(t, byte(0x01), clientHello[5], "client hello")
	return clientHello
}

// clientHelloRandom skips the record header, handshake header and legacy version.
func clientHelloRandom(clientHello []byte) []byte {
	return clientHello[5+4+2 : 5+4+2+clientRandomLength]
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
