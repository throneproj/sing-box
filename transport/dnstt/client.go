package dnstt

import (
	"context"
	"encoding/hex"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/smux"
)

const (
	dnsttIdleTimeout        = 2 * time.Minute
	dnsttKeepAliveInterval  = 10 * time.Second
	vaydnsIdleTimeout       = 10 * time.Second
	vaydnsKeepAliveInterval = 2 * time.Second
	defaultHandshakeTimeout = 15 * time.Second
	initRetryDelay          = time.Second
	maxRetryDelay           = 30 * time.Second
)

type ClientOptions struct {
	Context           context.Context
	Logger            logger.ContextLogger
	Dialer            N.Dialer
	Mode              string
	DNSTTCompat       bool
	Domain            string
	PublicKey         string
	RecordType        string
	ClientIDSize      int
	MaxQNameLen       int
	RPS               float64
	IdleTimeout       time.Duration
	KeepAliveInterval time.Duration
	HandshakeTimeout  time.Duration
	Resolvers         []ResolverOptions
	ResolverStrategy  string
	SharedUDPSocket   bool
	SystemResolvers   func() []M.Socksaddr
}

type Client struct {
	ctx               context.Context
	cancel            context.CancelFunc
	logger            logger.ContextLogger
	transportConfig   transportConfig
	wire              *wireFormat
	mtu               int
	publicKey         []byte
	rps               float64
	idleTimeout       time.Duration
	keepAliveInterval time.Duration
	handshakeTimeout  time.Duration
	resolvers         []ResolverOptions
	strategy          string
	systemResolvers   func() []M.Socksaddr
	access            sync.Mutex
	session           *session
	pending           *sessionOffer
	closeIdle         bool
	closed            bool
	retryAt           time.Time
	retryDelay        time.Duration
	lastError         error
	wg                sync.WaitGroup
}

type sessionOffer struct {
	done chan struct{}
	err  error
}

func NewClient(options ClientOptions) (*Client, error) {
	wire, err := newWireFormat(options)
	if err != nil {
		return nil, err
	}
	mtu, err := wire.mtu()
	if err != nil {
		return nil, err
	}
	publicKey, err := parsePublicKey(options.PublicKey)
	if err != nil {
		return nil, err
	}
	idleTimeout := options.IdleTimeout
	keepAliveInterval := options.KeepAliveInterval
	if wire.vaydns && !options.DNSTTCompat {
		if idleTimeout == 0 {
			idleTimeout = vaydnsIdleTimeout
		}
		if keepAliveInterval == 0 {
			keepAliveInterval = vaydnsKeepAliveInterval
		}
	} else {
		if idleTimeout == 0 {
			idleTimeout = dnsttIdleTimeout
		}
		if keepAliveInterval == 0 {
			keepAliveInterval = dnsttKeepAliveInterval
		}
	}
	if keepAliveInterval >= idleTimeout {
		return nil, E.New("keepalive_interval (", keepAliveInterval, ") must be less than idle_timeout (", idleTimeout, ")")
	}
	handshakeTimeout := options.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	if len(options.Resolvers) == 0 {
		return nil, E.New("missing resolvers")
	}
	for _, resolver := range options.Resolvers {
		switch resolver.Type {
		case ResolverTypeUDP, ResolverTypeTCP, ResolverTypeTLS, ResolverTypeHTTPS, ResolverTypeSystem:
		default:
			return nil, E.New("unknown resolver type: ", resolver.Type)
		}
	}
	strategy := options.ResolverStrategy
	switch strategy {
	case "":
		strategy = StrategyRoundRobin
	case StrategyRoundRobin, StrategyFailover, StrategyFanout:
	default:
		return nil, E.New("unknown resolver strategy: ", strategy)
	}
	httpSenders := dnsttHTTPSenders
	if wire.vaydns {
		httpSenders = vaydnsHTTPSenders
	}
	ctx, cancel := context.WithCancel(options.Context)
	return &Client{
		ctx:    ctx,
		cancel: cancel,
		logger: options.Logger,
		transportConfig: transportConfig{
			ctx:         adapter.ContextForMultiplexSession(ctx),
			logger:      options.Logger,
			dialer:      options.Dialer,
			queueSize:   wire.queueSize(),
			sharedUDP:   !wire.vaydns || options.SharedUDPSocket,
			httpSenders: httpSenders,
		},
		wire:              wire,
		mtu:               mtu,
		publicKey:         publicKey,
		rps:               options.RPS,
		idleTimeout:       idleTimeout,
		keepAliveInterval: keepAliveInterval,
		handshakeTimeout:  handshakeTimeout,
		resolvers:         options.Resolvers,
		strategy:          strategy,
		systemResolvers:   options.SystemResolvers,
		retryDelay:        initRetryDelay,
	}, nil
}

func newWireFormat(options ClientOptions) (*wireFormat, error) {
	if options.Domain == "" {
		return nil, E.New("missing domain")
	}
	domain, err := parseName(options.Domain)
	if err != nil {
		return nil, E.Cause(err, "parse domain")
	}
	recordType, err := parseRecordType(options.RecordType)
	if err != nil {
		return nil, err
	}
	switch options.Mode {
	case "", ModeDNSTT:
		if recordType != rrTypeTXT {
			return nil, E.New("record_type ", options.RecordType, " requires vaydns mode")
		}
		return &wireFormat{
			padded:       true,
			clientIDSize: dnsttClientIDSize,
			domain:       domain,
			recordType:   recordType,
		}, nil
	case ModeVayDNS:
	default:
		return nil, E.New("unknown mode: ", options.Mode)
	}
	maxQNameLen := options.MaxQNameLen
	if maxQNameLen <= 0 {
		if options.DNSTTCompat {
			maxQNameLen = vaydnsMaxQNameLen
		} else {
			maxQNameLen = vaydnsDefaultQNameLen
		}
	}
	maxQNameLen = min(maxQNameLen, vaydnsMaxQNameLen)
	if options.DNSTTCompat {
		if recordType != rrTypeTXT {
			return nil, E.New("record_type ", options.RecordType, " is not supported with dnstt_compat")
		}
		return &wireFormat{
			vaydns:       true,
			padded:       true,
			clientIDSize: dnsttClientIDSize,
			domain:       domain,
			recordType:   recordType,
			maxQNameLen:  maxQNameLen,
		}, nil
	}
	clientIDSize := options.ClientIDSize
	if clientIDSize < 0 {
		return nil, E.New("invalid client_id_size: ", clientIDSize)
	} else if clientIDSize == 0 {
		clientIDSize = vaydnsClientIDSize
	}
	return &wireFormat{
		vaydns:       true,
		clientIDSize: clientIDSize,
		domain:       domain,
		recordType:   recordType,
		maxQNameLen:  maxQNameLen,
	}, nil
}

func parsePublicKey(publicKey string) ([]byte, error) {
	if publicKey == "" {
		return nil, E.New("missing public_key")
	}
	key, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, E.Cause(err, "parse public_key")
	}
	if len(key) != noiseKeyLength {
		return nil, E.New("public_key must be ", noiseKeyLength*2, " hex digits")
	}
	return key, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	keepSession := adapter.KeepSessionFromContext(ctx)
	for retried := false; ; retried = true {
		s, err := c.acquireSession(ctx)
		if err != nil {
			return nil, err
		}
		stream, err := s.openStream(ctx)
		if err == nil {
			return &streamConn{Stream: stream, client: c, session: s, keepSession: keepSession}, nil
		}
		c.releaseStream(s, false)
		if retried || ctx.Err() != nil || !s.smux.IsClosed() {
			return nil, err
		}
	}
}

func (c *Client) acquireSession(ctx context.Context) (*session, error) {
	for {
		c.access.Lock()
		if c.closed {
			c.access.Unlock()
			return nil, net.ErrClosed
		}
		if s := c.session; s != nil {
			if s.active() {
				s.streams++
				c.access.Unlock()
				return s, nil
			}
			c.session = nil
		}
		pending := c.pending
		if pending == nil {
			if time.Now().Before(c.retryAt) {
				err := c.lastError
				c.access.Unlock()
				return nil, err
			}
			pending = &sessionOffer{done: make(chan struct{})}
			c.pending = pending
			c.wg.Add(1)
			go c.completeOffer(pending)
		}
		c.access.Unlock()
		select {
		case <-pending.done:
			if pending.err != nil {
				return nil, pending.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// The session is built on the client context, so a caller that stops waiting cannot abort a shared handshake.
func (c *Client) completeOffer(pending *sessionOffer) {
	defer c.wg.Done()
	s, err := c.newSession(c.ctx)
	var discarded *session
	c.access.Lock()
	if err == nil && c.closed {
		discarded, err = s, net.ErrClosed
	}
	if err != nil {
		c.lastError = err
		c.retryAt = time.Now().Add(c.retryDelay)
		c.retryDelay = min(c.retryDelay*2, maxRetryDelay)
	} else {
		c.lastError = nil
		c.retryAt = time.Time{}
		c.retryDelay = initRetryDelay
		c.session = s
		c.wg.Add(1)
		go c.monitorSession(s)
	}
	pending.err = err
	c.pending = nil
	close(pending.done)
	c.access.Unlock()
	if discarded != nil {
		discarded.close()
	}
}

func (c *Client) monitorSession(s *session) {
	defer c.wg.Done()
	s.wait()
	c.access.Lock()
	if c.session == s {
		c.session = nil
	}
	c.access.Unlock()
	s.close()
	select {
	case <-s.failed:
		if s.err != net.ErrClosed {
			c.logger.Debug("session ", s.id(), " closed: ", s.err)
			return
		}
	default:
	}
	c.logger.Debug("session ", s.id(), " closed")
}

func (c *Client) releaseStream(s *session, keepSession bool) {
	c.access.Lock()
	s.streams--
	closeSession := c.closeIdle && !keepSession && s.streams == 0 && c.session == s
	if closeSession {
		c.session = nil
	}
	c.access.Unlock()
	if closeSession {
		s.fail(net.ErrClosed)
	}
}

// InterfaceUpdated replaces the resolver sockets and keeps the KCP session.
func (c *Client) InterfaceUpdated() {
	c.access.Lock()
	s := c.session
	c.retryAt = time.Time{}
	c.retryDelay = initRetryDelay
	c.access.Unlock()
	if s != nil {
		s.resolvers.reset()
	}
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.access.Lock()
	c.closeIdle = !keep
	c.access.Unlock()
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	c.access.Lock()
	s := c.session
	if s == nil || s.streams > 0 {
		c.access.Unlock()
		return
	}
	c.session = nil
	c.access.Unlock()
	s.fail(net.ErrClosed)
}

func (c *Client) Close() error {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	c.closed = true
	s := c.session
	c.session = nil
	c.access.Unlock()
	c.cancel()
	if s != nil {
		s.fail(net.ErrClosed)
	}
	c.wg.Wait()
	return nil
}

type streamConn struct {
	*smux.Stream
	client      *Client
	session     *session
	keepSession bool
	closeOnce   sync.Once
}

func (c *streamConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *streamConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *streamConn) Close() error {
	err := c.Stream.Close()
	c.closeOnce.Do(func() {
		c.client.releaseStream(c.session, c.keepSession)
	})
	return err
}

func (c *streamConn) Upstream() any {
	return c.Stream
}
