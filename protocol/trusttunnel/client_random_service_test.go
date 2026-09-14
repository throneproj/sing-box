package trusttunnel

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"github.com/xchacha20-poly1305/sing-trusttunnel"
)

func TestClientRandomThroughService(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	keyLog := startClientRandomService(t, listener, nil)
	client := newClientRandomClient(t, M.ParseSocksaddr(listener.Addr().String()), false)
	for range 2 {
		requireEcho(t, client)
		// Drop the connection so that the next dial runs a new handshake.
		client.ResetConnections()
	}
	requireServerClientRandoms(t, keyLog, 2)
}

// clientRandomKeyLog collects the ClientHello random of every handshake the
// server completes, from its TLS key log.
type clientRandomKeyLog struct {
	access  sync.Mutex
	randoms [][]byte
}

func (l *clientRandomKeyLog) Write(p []byte) (int, error) {
	fields := strings.Fields(string(p))
	if len(fields) == 3 && fields[0] == "CLIENT_HANDSHAKE_TRAFFIC_SECRET" {
		random, err := hex.DecodeString(fields[1])
		if err == nil {
			l.access.Lock()
			l.randoms = append(l.randoms, random)
			l.access.Unlock()
		}
	}
	return len(p), nil
}

func requireServerClientRandoms(t *testing.T, keyLog *clientRandomKeyLog, count int) {
	t.Helper()
	prefix, mask, err := parseClientRandom(testClientRandom)
	require.NoError(t, err)
	keyLog.access.Lock()
	randoms := slices.Clone(keyLog.randoms)
	keyLog.access.Unlock()
	require.Len(t, randoms, count)
	distinct := make(map[string]bool)
	for _, random := range randoms {
		requireMatchesClientRandom(t, prefix, mask, random)
		distinct[string(random)] = true
	}
	require.Len(t, distinct, count)
}

func startClientRandomService(t *testing.T, listener net.Listener, packetConn net.PacketConn) *clientRandomKeyLog {
	t.Helper()
	privateKey, certificate, err := tls.GenerateCertificate(nil, nil, time.Now, "example.org", time.Now().Add(time.Hour))
	require.NoError(t, err)
	serverConfig, err := tls.NewServer(t.Context(), logger.NOP(), option.InboundTLSOptions{
		Enabled:     true,
		ALPN:        badoption.Listable[string]{"h2"},
		Certificate: badoption.Listable[string]{string(certificate)},
		Key:         badoption.Listable[string]{string(privateKey)},
	})
	require.NoError(t, err)
	require.NoError(t, serverConfig.Start())
	stdConfig, err := serverConfig.STDConfig()
	require.NoError(t, err)
	keyLog := new(clientRandomKeyLog)
	stdConfig.KeyLogWriter = keyLog
	service := trusttunnel.NewService(trusttunnel.ServiceOptions{
		Ctx:     t.Context(),
		Logger:  logger.NOP(),
		Handler: new(echoHandler),
	})
	service.UpdateUsers([]auth.User{{Username: "sekai", Password: "password"}})
	require.NoError(t, service.Start(listener, packetConn, serverConfig))
	t.Cleanup(func() {
		_ = service.Close()
		_ = serverConfig.Close()
	})
	return keyLog
}

func newClientRandomClient(t *testing.T, server M.Socksaddr, quic bool) *trusttunnel.Client {
	t.Helper()
	config, err := newClientRandomConfig(newTestTLSConfig(t, option.OutboundTLSOptions{Insecure: true}), testClientRandom, option.OutboundTLSOptions{})
	require.NoError(t, err)
	client, err := trusttunnel.NewClient(trusttunnel.ClientOptions{
		Ctx:       t.Context(),
		Detour:    new(N.DefaultDialer),
		Server:    server,
		Auth:      auth.User{Username: "sekai", Password: "password"},
		TLSConfig: config,
		QUIC:      quic,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}

func requireEcho(t *testing.T, client *trusttunnel.Client) {
	t.Helper()
	conn, err := client.Dial(t.Context(), M.ParseSocksaddr("example.org:80"))
	require.NoError(t, err)
	defer conn.Close()
	payload := []byte("client_random")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	received := make([]byte, len(payload))
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err)
	require.Equal(t, payload, received)
}

type echoHandler struct{}

func (h *echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer onClose(nil)
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
}

func (h *echoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	onClose(nil)
}
