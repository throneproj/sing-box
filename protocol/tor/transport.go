//go:build with_tor_transports

package tor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/proxybridge"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/meeklite"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/webtunnel"
	sf "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
)

func init() {
	// in-process transports have no managed-proxy parent reading PT protocol lines from stdout
	pt.Stdout = io.Discard
}

type transportListener struct {
	ctx             context.Context
	cancel          context.CancelFunc
	logger          logger.ContextLogger
	dialer          N.Dialer
	bridges         []*bridge
	proxyURL        *url.URL
	secret          string
	factories       map[string]base.ClientFactory
	listener        *pt.SocksListener
	snowflakeAccess sync.Mutex
	snowflakes      map[int]*sf.Transport
	failureAccess   sync.Mutex
	lastFailure     []time.Time
}

func validateTransport(bridge *bridge) error {
	if bridge.transport == "snowflake" {
		_, err := newSnowflakeConfig(bridge.arguments)
		return err
	}
	factory, err := newClientFactory(bridge.transport)
	if err != nil {
		return err
	}
	arguments := pt.Args(bridge.arguments)
	_, err = factory.ParseArgs(&arguments)
	return err
}

func newClientFactory(transport string) (base.ClientFactory, error) {
	// client factories keep no state on disk
	switch transport {
	case "obfs4":
		return new(obfs4.Transport).ClientFactory("")
	case "meek_lite":
		return new(meeklite.Transport).ClientFactory("")
	case "webtunnel":
		return webtunnel.Transport.ClientFactory("")
	default:
		return nil, E.New("unknown transport: ", transport)
	}
}

func newSnowflakeConfig(arguments pt.Args) (sf.ClientConfig, error) {
	var config sf.ClientConfig
	config.BrokerURL, _ = arguments.Get("url")
	config.AmpCacheURL, _ = arguments.Get("ampcache")
	config.SQSQueueURL, _ = arguments.Get("sqsqueue")
	config.SQSCredsStr, _ = arguments.Get("sqscreds")
	if config.SQSQueueURL != "" {
		if config.BrokerURL != "" || config.AmpCacheURL != "" {
			return sf.ClientConfig{}, E.New("sqsqueue cannot be combined with url or ampcache")
		}
		if config.SQSCredsStr == "" {
			return sf.ClientConfig{}, E.New("missing sqscreds")
		}
	} else if config.BrokerURL == "" {
		return sf.ClientConfig{}, E.New("missing url")
	}
	if fronts, loaded := arguments.Get("fronts"); loaded {
		if fronts != "" {
			config.FrontDomains = strings.Split(strings.TrimSpace(fronts), ",")
		}
	} else if front, loaded := arguments.Get("front"); loaded {
		config.FrontDomains = strings.Split(strings.TrimSpace(front), ",")
	}
	if ice, loaded := arguments.Get("ice"); loaded {
		config.ICEAddresses = strings.Split(strings.TrimSpace(ice), ",")
	}
	if maxPeers, loaded := arguments.Get("max"); loaded {
		var err error
		config.Max, err = strconv.Atoi(maxPeers)
		if err != nil {
			return sf.ClientConfig{}, E.New("invalid max: ", maxPeers)
		}
	}
	if removeSNI, loaded := arguments.Get("utls-nosni"); loaded {
		switch strings.ToLower(removeSNI) {
		case "true", "yes":
			config.UTLSRemoveSNI = true
		}
	}
	config.UTLSClientID, _ = arguments.Get("utls-imitate")
	config.BridgeFingerprint, _ = arguments.Get("fingerprint")
	config.CovertDTLSConfig, _ = arguments.Get("covertdtls-config")
	config.CovertDTLSFingerprint, _ = arguments.Get("covertdtls-fingerprint")
	return config, nil
}

func newTransportListener(ctx context.Context, logger logger.ContextLogger, dialer N.Dialer, proxy *proxybridge.Bridge, bridges []*bridge) (*transportListener, error) {
	factories := make(map[string]base.ClientFactory)
	for _, it := range bridges {
		if it.transport == "" || it.transport == "snowflake" || factories[it.transport] != nil {
			continue
		}
		factory, err := newClientFactory(it.transport)
		if err != nil {
			return nil, err
		}
		factories[it.transport] = factory
	}
	listener, err := pt.ListenSocks(N.NetworkTCP, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	transport := &transportListener{
		ctx:     ctx,
		cancel:  cancel,
		logger:  logger,
		dialer:  dialer,
		bridges: bridges,
		proxyURL: &url.URL{
			Scheme: "socks5",
			User:   url.UserPassword(proxy.Username(), proxy.Password()),
			Host:   "127.0.0.1:" + F.ToString(proxy.Port()),
		},
		secret:      rand.Text(),
		factories:   factories,
		listener:    listener,
		snowflakes:  make(map[int]*sf.Transport),
		lastFailure: make([]time.Time, len(bridges)),
	}
	go transport.acceptLoop()
	return transport, nil
}

func (l *transportListener) Port() uint16 {
	return M.SocksaddrFromNet(l.listener.Addr()).Port
}

func (l *transportListener) Secret() string {
	return l.secret
}

func (l *transportListener) Close() error {
	l.cancel()
	return l.listener.Close()
}

func (l *transportListener) acceptLoop() {
	for {
		conn, err := l.listener.AcceptSocks()
		if err != nil {
			return
		}
		go l.handle(conn)
	}
}

func (l *transportListener) handle(conn *pt.SocksConn) {
	ctx, cancel := context.WithCancel(log.ContextWithNewID(l.ctx))
	defer cancel()
	secret, _ := conn.Req.Args.Get("t")
	indexString, _ := conn.Req.Args.Get("i")
	index, err := strconv.Atoi(indexString)
	if subtle.ConstantTimeCompare([]byte(secret), []byte(l.secret)) != 1 || err != nil || index < 0 || index >= len(l.bridges) {
		l.logger.DebugContext(ctx, "rejected unauthenticated transport request from ", conn.RemoteAddr())
		conn.Reject()
		conn.Close()
		return
	}
	bridge := l.bridges[index]
	// cancel closes the raw connections of the bridge, so it also aborts a stalled handshake
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, C.TCPTimeout)
	stopHandshake := context.AfterFunc(handshakeCtx, cancel)
	remoteConn, err := l.dialBridge(ctx, index, bridge)
	if !stopHandshake() {
		common.Close(remoteConn)
		err = E.Cause(handshakeCtx.Err(), "handshake")
	}
	handshakeCancel()
	if err != nil {
		conn.Reject()
		conn.Close()
		l.logFailure(ctx, index, err)
		return
	}
	err = conn.Grant(&net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		remoteConn.Close()
		conn.Close()
		return
	}
	l.logger.InfoContext(ctx, bridge.pluginTransport(), " connection to ", bridge.address)
	err = bufio.CopyConn(ctx, conn.Conn, remoteConn)
	if err != nil && !E.IsClosedOrCanceled(err) {
		l.logger.DebugContext(ctx, E.Cause(err, bridge.pluginTransport(), " connection to ", bridge.address))
	}
}

func (l *transportListener) dialBridge(ctx context.Context, index int, bridge *bridge) (net.Conn, error) {
	switch bridge.transport {
	case "":
		return l.dialer.DialContext(ctx, N.NetworkTCP, M.SocksaddrFromNetIP(bridge.address))
	case "snowflake":
		client, err := l.snowflakeClient(index)
		if err != nil {
			return nil, err
		}
		return client.Dial()
	default:
		factory := l.factories[bridge.transport]
		arguments := pt.Args(bridge.arguments)
		clientArgs, err := factory.ParseArgs(&arguments)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(ctx)
		conn, err := factory.Dial(N.NetworkTCP, bridge.address.String(), l.dialFunc(ctx), clientArgs)
		if err != nil {
			cancel()
			return nil, err
		}
		// a meek read returns only after its worker leaves the round trip, so closing must also close the raw connections
		return &bridgeConn{conn, cancel}, nil
	}
}

func (l *transportListener) dialFunc(ctx context.Context) base.DialFunc {
	return func(network string, address string) (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
		defer cancel()
		conn, err := l.dialer.DialContext(dialCtx, network, M.ParseSocksaddr(address))
		if err != nil {
			return nil, err
		}
		// transports leave raw connections open after a failed handshake, and meek keeps them pooled
		context.AfterFunc(ctx, func() {
			conn.Close()
		})
		return conn, nil
	}
}

type bridgeConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *bridgeConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

func (l *transportListener) snowflakeClient(index int) (*sf.Transport, error) {
	l.snowflakeAccess.Lock()
	defer l.snowflakeAccess.Unlock()
	client := l.snowflakes[index]
	if client != nil {
		return client, nil
	}
	config, err := newSnowflakeConfig(l.bridges[index].arguments)
	if err != nil {
		return nil, err
	}
	config.CommunicationProxy = l.proxyURL
	client, err = sf.NewSnowflakeClient(config)
	if err != nil {
		return nil, err
	}
	client.AddSnowflakeEventListener(&snowflakeEventLogger{l, index})
	l.snowflakes[index] = client
	return client, nil
}

func (l *transportListener) logFailure(ctx context.Context, index int, err error) {
	bridge := l.bridges[index]
	err = E.Cause(err, bridge.pluginTransport(), " bridge ", bridge.address)
	if l.ctx.Err() == nil {
		now := time.Now()
		l.failureAccess.Lock()
		warn := now.Sub(l.lastFailure[index]) >= time.Minute
		if warn {
			l.lastFailure[index] = now
		}
		l.failureAccess.Unlock()
		if warn {
			l.logger.WarnContext(ctx, err)
			return
		}
	}
	l.logger.DebugContext(ctx, err)
}

type snowflakeEventLogger struct {
	listener *transportListener
	index    int
}

func (l *snowflakeEventLogger) OnNewSnowflakeEvent(snowflakeEvent event.SnowflakeEvent) {
	var failed bool
	switch snowflakeEvent := snowflakeEvent.(type) {
	case event.EventOnOfferCreated:
		failed = snowflakeEvent.Error != nil
	case event.EventOnBrokerRendezvous:
		failed = snowflakeEvent.Error != nil
	case event.EventOnSnowflakeConnectionFailed:
		failed = true
	}
	if failed {
		l.listener.logFailure(l.listener.ctx, l.index, E.New(snowflakeEvent.String()))
		return
	}
	bridge := l.listener.bridges[l.index]
	l.listener.logger.DebugContext(l.listener.ctx, bridge.transport, " bridge ", bridge.address, ": ", snowflakeEvent.String())
}
