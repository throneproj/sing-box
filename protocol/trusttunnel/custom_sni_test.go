package trusttunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdTLS "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

const (
	testServerName = "example.org"
	testCustomSNI  = "cdn.example.net"
)

func TestCustomSNIOptionDecode(t *testing.T) {
	t.Parallel()
	var options option.TrustTunnelOutboundOptions
	err := json.UnmarshalContextDisallowUnknownFields(context.Background(), []byte(`{"server":"example.org","server_port":443,"custom_sni":"cdn.example.net"}`), &options)
	require.NoError(t, err)
	require.Equal(t, testCustomSNI, options.CustomSNI)
}

func TestCustomSNIClientHello(t *testing.T) {
	t.Parallel()
	config := newTestTLSConfig(t, option.OutboundTLSOptions{})
	require.NoError(t, setCustomSNI(config, testCustomSNI, option.OutboundTLSOptions{}))
	for _, candidate := range []tls.Config{config, config.Clone()} {
		clientHello := captureClientHello(t, candidate)
		require.True(t, bytes.Contains(clientHello, []byte(testCustomSNI)))
		require.False(t, bytes.Contains(clientHello, []byte(testServerName)))
	}
}

func TestCustomSNIWithClientRandom(t *testing.T) {
	t.Parallel()
	prefix, mask, err := parseClientRandom(testClientRandom)
	require.NoError(t, err)
	config := newTestTLSConfig(t, option.OutboundTLSOptions{})
	require.NoError(t, setCustomSNI(config, testCustomSNI, option.OutboundTLSOptions{}))
	config, err = newClientRandomConfig(config, testClientRandom, option.OutboundTLSOptions{})
	require.NoError(t, err)
	clientHello := captureClientHello(t, config)
	require.True(t, bytes.Contains(clientHello, []byte(testCustomSNI)))
	requireMatchesClientRandom(t, prefix, mask, clientHelloRandom(clientHello))
}

func TestCustomSNIQUICConfig(t *testing.T) {
	t.Parallel()
	config := newTestTLSConfig(t, option.OutboundTLSOptions{})
	require.NoError(t, setCustomSNI(config, testCustomSNI, option.OutboundTLSOptions{}))
	stdConfig, err := config.STDConfig()
	require.NoError(t, err)
	require.Equal(t, testCustomSNI, stdConfig.ServerName)
	require.True(t, stdConfig.InsecureSkipVerify)
	require.NotNil(t, stdConfig.VerifyConnection, "the certificate is still verified against server_name")
}

func TestCustomSNIVerifiesServerName(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name       string
		certName   string
		tlsOptions option.OutboundTLSOptions
		wantErr    bool
	}{
		{name: "certificate for server_name", certName: testServerName},
		{name: "certificate for custom_sni", certName: testCustomSNI, wantErr: true},
		{name: "insecure", certName: testCustomSNI, tlsOptions: option.OutboundTLSOptions{Insecure: true}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			requireCustomSNIHandshake(t, testCase.certName, testCase.tlsOptions, testCase.wantErr)
		})
	}
}

func TestSetCustomSNIIncompatible(t *testing.T) {
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
			name:   "disable_sni",
			config: newTestTLSConfig(t, option.OutboundTLSOptions{DisableSNI: true}),
		},
		{
			name:   "no custom SNI support",
			config: struct{ tls.Config }{newTestTLSConfig(t, option.OutboundTLSOptions{})},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			require.Error(t, setCustomSNI(testCase.config, testCustomSNI, testCase.tlsOptions))
		})
	}
}

// requireCustomSNIHandshake connects to a local TLS server whose certificate is
// issued for certName and checks that the server saw custom_sni.
func requireCustomSNIHandshake(t *testing.T, certName string, tlsOptions option.OutboundTLSOptions, wantErr bool) {
	t.Helper()
	certificate, certPEM := newTestCertificate(t, certName)
	listener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	serverName := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serverConn := stdTLS.Server(conn, &stdTLS.Config{
			GetCertificate: func(info *stdTLS.ClientHelloInfo) (*stdTLS.Certificate, error) {
				serverName <- info.ServerName
				return certificate, nil
			},
		})
		_ = serverConn.HandshakeContext(context.Background())
	}()

	tlsOptions.Enabled = true
	tlsOptions.ServerName = testServerName
	tlsOptions.Certificate = badoption.Listable[string]{certPEM}
	config, err := tls.NewClient(context.Background(), logger.NOP(), testServerName, tlsOptions)
	require.NoError(t, err)
	require.NoError(t, setCustomSNI(config, testCustomSNI, tlsOptions))

	conn, err := net.Dial(N.NetworkTCP, listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	tlsConn, err := config.Client(conn)
	require.NoError(t, err)
	err = tlsConn.HandshakeContext(context.Background())
	if wantErr {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
	select {
	case got := <-serverName:
		require.Equal(t, testCustomSNI, got)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "server did not receive a ClientHello")
	}
}

func newTestCertificate(t *testing.T, dnsName string) (*stdTLS.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return &stdTLS.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key},
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}
