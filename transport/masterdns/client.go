package masterdns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/systemdns"
	"github.com/sagernet/sing-box/transport/masterdns/cipher"
	"github.com/sagernet/sing-box/transport/masterdns/compress"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	mtuRetryDelay       = 5 * time.Second
	sessionPollInterval = time.Second
)

// Runtime is the data plane; Run starts it once a session is accepted and stops it before a restart. Stop must be synchronous.
type Runtime interface {
	Start(ctx context.Context, session Session) error
	Stop()
}

type Client struct {
	logger   logger.ContextLogger
	config   Config
	dialer   N.Dialer
	codec    *cipher.Codec
	domains  map[string]wire.Domain
	system   *systemdns.Source
	balancer *Balancer
	pool     resolverPool

	queryID             atomic.Uint32
	probeCode           atomic.Uint32
	restartPending      atomic.Bool
	sessionResetPending atomic.Bool
	resolversChanged    atomic.Bool
	mtuScanned          atomic.Bool
	restartSignal       chan struct{}
	healthWake          chan struct{}
	workers             sync.WaitGroup

	access              sync.Mutex
	runContext          context.Context
	resolvers           []netip.AddrPort
	settings            wire.ClientSettings
	processWorkers      int
	uploadMTU           int
	uploadMTUChars      int
	safeUploadMTU       int
	downloadMTU         int
	maxPackedBlocks     int
	uploadCompression   compress.Type
	downloadCompression compress.Type
	ready               bool
	sessionID           uint8
	sessionCookie       uint8
	base64Response      bool
	initPayload         []byte
	initVerify          [wire.VerifyCodeSize]byte
	initReady           bool
	initCursor          int

	stateAccess  sync.Mutex
	session      *Session
	stateErr     error
	stateChanged chan struct{}
	closed       bool
}

// NewClient does no I/O; with the system resolver entry the context must carry the network manager.
func NewClient(ctx context.Context, logger logger.ContextLogger, config Config, dialer N.Dialer) (*Client, error) {
	client, err := newClient(logger, config, dialer)
	if err != nil {
		return nil, err
	}
	if config.SystemResolver {
		client.system, err = systemdns.NewSource(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		client.resolvers = config.Resolvers
		client.balancer.SetConnections(Connections(config.Domains, config.Resolvers))
	}
	return client, nil
}

func newClient(logger logger.ContextLogger, config Config, dialer N.Dialer) (*Client, error) {
	codec, err := cipher.New(config.EncryptionMethod, config.EncryptionKey)
	if err != nil {
		return nil, err
	}
	domains := make(map[string]wire.Domain, len(config.Domains))
	for _, name := range config.Domains {
		domain, err := wire.NewDomain(name)
		if err != nil {
			return nil, E.Cause(err, "invalid domain: ", name)
		}
		domains[name] = domain
	}
	client := &Client{
		logger:              logger,
		config:              config,
		dialer:              dialer,
		codec:               codec,
		domains:             domains,
		balancer:            NewBalancer(config.BalancingStrategy),
		pool:                resolverPool{pools: make(map[netip.AddrPort]chan pooledConn)},
		restartSignal:       make(chan struct{}, 1),
		healthWake:          make(chan struct{}, 1),
		settings:            defaultClientSettings(config),
		processWorkers:      defaultProcessWorkers,
		maxPackedBlocks:     1,
		uploadCompression:   config.UploadCompression,
		downloadCompression: config.DownloadCompression,
		stateChanged:        make(chan struct{}),
	}
	var seed [4]byte
	rand.Read(seed[:])
	client.queryID.Store(binary.BigEndian.Uint32(seed[:]))
	client.balancer.SetStreamFailover(streamFailoverThreshold, streamFailoverCooldown)
	client.balancer.SetAutoDisable(true, autoDisableWindow)
	client.balancer.SetDisabledHandler(client.resolverDisabled)
	client.balancer.SetDownConfirmHandler(client.confirmResolverDown)
	return client, nil
}

// Run follows the reference client loop; a later Run reuses the last MTU scan unless RecheckResolvers was called since.
func (c *Client) Run(ctx context.Context, runtime Runtime) (runErr error) {
	if c.isClosed() {
		return net.ErrClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	c.access.Lock()
	c.runContext = ctx
	c.access.Unlock()
	c.setState(nil, nil)
	var (
		mtuReady       = c.mtuScanned.Load()
		healthStarted  bool
		runtimeStarted bool
		failures       int
	)
	defer func() {
		cancel()
		c.workers.Wait()
		c.closeResolverPools()
		c.resetSession()
		c.clearRestartRequest()
		c.setState(nil, runErr)
	}()
	stop := func() {
		c.closeSessionBurst(ctx)
		if runtimeStarted {
			runtime.Stop()
		}
	}
	for {
		if ctx.Err() != nil {
			stop()
			return nil
		}
		if !mtuReady {
			c.setState(nil, nil)
			if c.system != nil {
				c.refreshResolvers(ctx, false)
			}
			err := c.runMTUScan(ctx)
			if ctx.Err() != nil {
				stop()
				return nil
			}
			if err == nil {
				if upload, download := c.syncedMTU(); upload <= 0 || download <= 0 {
					err = E.New("MTU tests failed: upload MTU ", upload, ", download MTU ", download)
				}
			}
			if err != nil {
				c.logger.Error("MTU tests failed: ", err)
				c.setState(nil, err)
				if !sleepContext(ctx, mtuRetryDelay) {
					stop()
					return nil
				}
				continue
			}
			mtuReady = true
			c.mtuScanned.Store(true)
		}
		if !healthStarted {
			healthStarted = true
			c.workers.Go(func() {
				c.runHealthLoop(ctx)
			})
		}
		if !c.isReady() {
			c.setState(nil, nil)
			err := c.initializeSession(ctx, c.config.MTU.TestRetries)
			if err != nil {
				if ctx.Err() != nil {
					stop()
					return nil
				}
				failures++
				delay := sessionInitRetryDelay(failures)
				c.logger.Error("session initialization failed: ", err, ", retrying in ", delay)
				c.setState(nil, err)
				if !sleepContext(ctx, delay) {
					stop()
					return nil
				}
				continue
			}
			failures = 0
			c.access.Lock()
			session := c.sessionLocked()
			c.access.Unlock()
			c.logger.Info("session ", session.ID, " initialized, upload MTU ", session.UploadMTU, ", download MTU ", session.DownloadMTU)
			err = runtime.Start(ctx, session)
			if err != nil {
				return E.Cause(err, "start runtime")
			}
			runtimeStarted = true
			c.setState(&session, nil)
		}
		timer := time.NewTimer(sessionPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			stop()
			return nil
		case <-c.restartSignal:
			timer.Stop()
			runtime.Stop()
			runtimeStarted = false
			c.resetSession()
			c.setState(nil, nil)
			c.clearRestartRequest()
			failures++
			delay := sessionInitRetryDelay(failures)
			c.logger.Warn("session reset, retrying in ", delay)
			if !sleepContext(ctx, delay) {
				stop()
				return nil
			}
		case <-timer.C:
		}
	}
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// RequestSessionRestart is how the runtime reports SESSION_REJECT, SESSION_BUSY or ERROR_DROP; repeated calls before the restart are ignored.
func (c *Client) RequestSessionRestart(reason string) {
	if !c.restartPending.CompareAndSwap(false, true) {
		return
	}
	c.logger.Warn("session restart requested: ", reason)
	select {
	case c.restartSignal <- struct{}{}:
	default:
	}
}

func (c *Client) clearRestartRequest() {
	c.restartPending.Store(false)
	for {
		select {
		case <-c.restartSignal:
		default:
			return
		}
	}
}

func (c *Client) isReady() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.ready
}

func (c *Client) setState(session *Session, err error) {
	c.stateAccess.Lock()
	defer c.stateAccess.Unlock()
	if c.closed {
		return
	}
	c.session = session
	c.stateErr = err
	close(c.stateChanged)
	c.stateChanged = make(chan struct{})
}

func (c *Client) isClosed() bool {
	c.stateAccess.Lock()
	defer c.stateAccess.Unlock()
	return c.closed
}

// WaitSession waits for a running session; it fails at once while the client backs off after a failed MTU scan or session init, after Run failed and after Close.
func (c *Client) WaitSession(ctx context.Context) (Session, error) {
	for {
		c.stateAccess.Lock()
		session, err, changed := c.session, c.stateErr, c.stateChanged
		c.stateAccess.Unlock()
		if session != nil {
			return *session, nil
		}
		if err != nil {
			return Session{}, err
		}
		select {
		case <-ctx.Done():
			return Session{}, ctx.Err()
		case <-changed:
		}
	}
}

func (c *Client) Session() (Session, bool) {
	c.stateAccess.Lock()
	defer c.stateAccess.Unlock()
	if c.session == nil {
		return Session{}, false
	}
	return *c.session, true
}

func (c *Client) Balancer() *Balancer {
	return c.balancer
}

func (c *Client) Codec() *cipher.Codec {
	return c.codec
}

func (c *Client) Domain(name string) wire.Domain {
	return c.domains[name]
}

func (c *Client) NextQueryID() uint16 {
	return uint16(c.queryID.Add(1))
}

// RecheckResolvers is for interface changes: pooled sockets are dropped, system resolvers re-read, inactive resolvers probed right away and the next Run scans again.
func (c *Client) RecheckResolvers() {
	c.mtuScanned.Store(false)
	if c.system != nil {
		c.system.Reset()
		c.resolversChanged.Store(true)
	}
	c.closeResolverPools()
	c.balancer.resetHealthChecks()
	select {
	case c.healthWake <- struct{}{}:
	default:
	}
}

// Close fails every WaitSession and later Run; the caller stops Run first.
func (c *Client) Close() error {
	c.stateAccess.Lock()
	if c.closed {
		c.stateAccess.Unlock()
		return nil
	}
	c.closed = true
	c.session = nil
	c.stateErr = net.ErrClosed
	close(c.stateChanged)
	c.stateChanged = make(chan struct{})
	c.stateAccess.Unlock()
	if c.system != nil {
		return c.system.Close()
	}
	return nil
}

func (c *Client) lifetime() context.Context {
	c.access.Lock()
	defer c.access.Unlock()
	if c.runContext == nil {
		return context.Background()
	}
	return c.runContext
}

func (c *Client) resolverDisabled(conn Connection, reason string) {
	c.logger.Warn("resolver ", conn.Resolver, " disabled for ", conn.Domain, " (", reason, "), ", c.balancer.ActiveCount(), " active")
}

// refreshResolvers merges the system DNS servers into the configured resolvers; before the first scan the balancer starts over, later only the changed connections do.
func (c *Client) refreshResolvers(ctx context.Context, keepState bool) {
	resolvers := mergeResolvers(c.config.Resolvers, c.system.Servers())
	c.access.Lock()
	changed := !slices.Equal(c.resolvers, resolvers)
	c.resolvers = resolvers
	c.access.Unlock()
	if !changed {
		return
	}
	c.logger.InfoContext(ctx, "using ", len(resolvers), " resolvers")
	connections := Connections(c.config.Domains, resolvers)
	if keepState {
		c.balancer.updateConnections(connections)
	} else {
		c.balancer.SetConnections(connections)
	}
}

func mergeResolvers(resolvers []netip.AddrPort, system []M.Socksaddr) []netip.AddrPort {
	merged := slices.Clone(resolvers)
	seen := make(map[netip.Addr]bool, len(resolvers)+len(system))
	for _, resolver := range resolvers {
		seen[resolver.Addr()] = true
	}
	for _, server := range system {
		addr := server.Addr.Unmap()
		if !server.IsIP() || seen[addr] {
			continue
		}
		seen[addr] = true
		merged = append(merged, netip.AddrPortFrom(addr, server.Port))
	}
	slices.SortFunc(merged, func(a, b netip.AddrPort) int {
		return strings.Compare(a.Addr().String(), b.Addr().String())
	})
	return merged
}

func (c *Client) buildQuery(domain wire.Domain, packet wire.Packet) ([]byte, error) {
	raw, err := wire.AppendPacket(nil, packet)
	if err != nil {
		return nil, err
	}
	encoded, err := wire.EncodeFrame(nil, c.codec, raw)
	if err != nil {
		return nil, err
	}
	query, err := wire.AppendQuery(nil, 0, domain, encoded)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(query, c.NextQueryID())
	return query, nil
}
