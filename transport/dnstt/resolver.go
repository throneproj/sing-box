package dnstt

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	ResolverTypeUDP    = "udp"
	ResolverTypeTCP    = "tcp"
	ResolverTypeTLS    = "tls"
	ResolverTypeHTTPS  = "https"
	ResolverTypeSystem = "system"

	StrategyRoundRobin = "round_robin"
	StrategyFailover   = "failover"
	StrategyFanout     = "fanout"
)

const (
	unansweredThreshold = 8
	silenceThreshold    = 2 * time.Second
	initDownDelay       = time.Second
	maxDownDelay        = 30 * time.Second
	maxMessageSize      = 4096
)

type ResolverOptions struct {
	Type        string
	Server      M.Socksaddr
	URL         string
	TLSConfig   tls.Config
	TCPFallback bool
}

type resolverTransport interface {
	writeMessage(message []byte)
	close()
}

type resolverHandler interface {
	handleMessage(message []byte)
	handleError(err error)
}

type transportConfig struct {
	ctx         context.Context
	logger      logger.ContextLogger
	dialer      N.Dialer
	queueSize   int
	sharedUDP   bool
	httpSenders int
}

func newResolverTransport(config transportConfig, options ResolverOptions, handler resolverHandler) resolverTransport {
	switch options.Type {
	case ResolverTypeTCP:
		return newStreamTransport(config, options, handler, func(ctx context.Context) (net.Conn, error) {
			return config.dialer.DialContext(ctx, N.NetworkTCP, options.Server)
		})
	case ResolverTypeTLS:
		tlsDialer := tls.NewDialer(config.dialer, options.TLSConfig)
		return newStreamTransport(config, options, handler, func(ctx context.Context) (net.Conn, error) {
			return tlsDialer.DialTLSContext(ctx, options.Server)
		})
	case ResolverTypeHTTPS:
		return newHTTPSTransport(config, options, handler)
	default:
		if config.sharedUDP {
			return newUDPTransport(config, options, handler)
		}
		return newUDPExchangeTransport(config, options, handler)
	}
}

type resolver struct {
	options    ResolverOptions
	transport  resolverTransport
	generation uint64
	unanswered int
	lastActive time.Time
	downUntil  time.Time
	downDelay  time.Duration
	trial      bool
	failed     bool
}

type resolverHandle struct {
	set        *resolverSet
	resolver   *resolver
	generation uint64
}

func (h *resolverHandle) handleMessage(message []byte) {
	if h.set.conn.handleResponse(message) {
		h.set.markActive(h.resolver)
	}
}

func (h *resolverHandle) handleError(err error) {
	h.set.transportFailed(h.resolver, h.generation, err)
}

// With a single resolver every query goes to it, as in the references.
type resolverSet struct {
	config    transportConfig
	options   []ResolverOptions
	system    func() []M.Socksaddr
	strategy  string
	onFailure func(error)
	conn      *packetConn
	access    sync.Mutex
	resolvers []*resolver
	next      int
	closed    bool
}

func newResolverSet(config transportConfig, options []ResolverOptions, system func() []M.Socksaddr, strategy string, onFailure func(error)) *resolverSet {
	return &resolverSet{
		config:    config,
		options:   options,
		system:    system,
		strategy:  strategy,
		onFailure: onFailure,
	}
}

func expandResolvers(options []ResolverOptions, system func() []M.Socksaddr) []ResolverOptions {
	var expanded []ResolverOptions
	for _, resolverOptions := range options {
		if resolverOptions.Type != ResolverTypeSystem {
			expanded = append(expanded, resolverOptions)
			continue
		}
		if system == nil {
			continue
		}
		for _, server := range system() {
			expanded = append(expanded, ResolverOptions{
				Type:        ResolverTypeUDP,
				Server:      server,
				TCPFallback: resolverOptions.TCPFallback,
			})
		}
	}
	return expanded
}

func (s *resolverSet) newResolvers() ([]*resolver, error) {
	expanded := expandResolvers(s.options, s.system)
	if len(expanded) == 0 {
		return nil, E.New("no available resolver")
	}
	now := time.Now()
	resolvers := make([]*resolver, 0, len(expanded))
	for _, options := range expanded {
		resolvers = append(resolvers, &resolver{
			options:    options,
			lastActive: now,
			downDelay:  initDownDelay,
		})
	}
	return resolvers, nil
}

func (s *resolverSet) start(conn *packetConn) error {
	resolvers, err := s.newResolvers()
	if err != nil {
		return err
	}
	s.conn = conn
	s.access.Lock()
	defer s.access.Unlock()
	s.resolvers = resolvers
	for _, r := range resolvers {
		s.openLocked(r)
	}
	return nil
}

func (s *resolverSet) openLocked(r *resolver) {
	r.generation++
	r.transport = newResolverTransport(s.config, r.options, &resolverHandle{
		set:        s,
		resolver:   r,
		generation: r.generation,
	})
}

// reset replaces every resolver socket after a network change; the KCP session keeps running.
func (s *resolverSet) reset() {
	resolvers, err := s.newResolvers()
	if err != nil {
		s.config.logger.Warn(E.Cause(err, "reset resolvers"))
		return
	}
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return
	}
	oldResolvers := s.resolvers
	s.resolvers = resolvers
	for _, r := range resolvers {
		s.openLocked(r)
	}
	s.access.Unlock()
	for _, r := range oldResolvers {
		r.transport.close()
	}
}

func (s *resolverSet) close() {
	s.access.Lock()
	s.closed = true
	resolvers := s.resolvers
	s.resolvers = nil
	s.access.Unlock()
	for _, r := range resolvers {
		r.transport.close()
	}
}

func (s *resolverSet) writeQuery(query []byte) {
	targets, staleTransports := s.selectTransports(time.Now())
	for _, transport := range targets {
		transport.writeMessage(query)
	}
	for _, transport := range staleTransports {
		transport.close()
	}
}

func (s *resolverSet) selectTransports(now time.Time) (targets []resolverTransport, staleTransports []resolverTransport) {
	s.access.Lock()
	defer s.access.Unlock()
	var available, trial []*resolver
	for _, r := range s.resolvers {
		selectable, staleTransport := s.selectableLocked(r, now)
		if staleTransport != nil {
			staleTransports = append(staleTransports, staleTransport)
		}
		if !selectable {
			continue
		}
		if r.trial {
			trial = append(trial, r)
		} else {
			available = append(available, r)
		}
	}
	if len(available) == 0 {
		available, trial = trial, nil
	}
	if len(available) == 0 {
		for _, r := range s.resolvers {
			if !r.failed {
				available = append(available, r)
			}
		}
	}
	if len(available) == 0 {
		return nil, staleTransports
	}
	switch s.strategy {
	case StrategyFailover:
		available = available[:1]
	case StrategyFanout:
	default:
		index := s.next % len(available)
		s.next++
		available = available[index : index+1]
	}
	// A resolver back from a down period gets copies until it answers, so a dead one adds no stall.
	for _, r := range append(available, trial...) {
		r.unanswered++
		targets = append(targets, r.transport)
	}
	return targets, staleTransports
}

func (s *resolverSet) selectableLocked(r *resolver, now time.Time) (bool, resolverTransport) {
	var staleTransport resolverTransport
	if !r.downUntil.IsZero() {
		if now.Before(r.downUntil) {
			return false, nil
		}
		r.downUntil = time.Time{}
		if r.failed {
			r.failed = false
			staleTransport = r.transport
			s.openLocked(r)
		}
		r.trial = true
		// One more unanswered query after a quiet trial window takes it down again.
		r.unanswered = unansweredThreshold - 1
		r.lastActive = now
	}
	if r.unanswered >= unansweredThreshold && now.Sub(r.lastActive) >= silenceThreshold {
		s.markDownLocked(r, now)
		return false, staleTransport
	}
	return true, staleTransport
}

func (s *resolverSet) markDownLocked(r *resolver, now time.Time) {
	r.trial = false
	r.downUntil = now.Add(r.downDelay)
	r.downDelay = min(r.downDelay*2, maxDownDelay)
}

func (s *resolverSet) markActive(r *resolver) {
	s.access.Lock()
	r.unanswered = 0
	r.lastActive = time.Now()
	if !r.failed {
		r.trial = false
		r.downDelay = initDownDelay
		r.downUntil = time.Time{}
	}
	s.access.Unlock()
}

func (s *resolverSet) transportFailed(r *resolver, generation uint64, err error) {
	s.access.Lock()
	if s.closed || r.generation != generation || r.failed {
		s.access.Unlock()
		return
	}
	r.failed = true
	s.markDownLocked(r, time.Now())
	allFailed := true
	for _, it := range s.resolvers {
		if !it.failed {
			allFailed = false
			break
		}
	}
	s.access.Unlock()
	s.config.logger.Debug("resolver ", r.options.Server, ": ", err)
	if allFailed {
		s.onFailure(err)
	}
}
