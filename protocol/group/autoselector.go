package group

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func RegisterAutoSelector(registry *outbound.Registry) {
	outbound.Register[option.AutoSelectorOutboundOptions](registry, C.TypeAutoSelector, NewAutoSelector)
}

var (
	_ adapter.OutboundGroup           = (*AutoSelector)(nil)
	_ adapter.URLTestGroup            = (*AutoSelector)(nil)
	_ adapter.ConnectionHandler       = (*AutoSelector)(nil)
	_ adapter.PacketConnectionHandler = (*AutoSelector)(nil)
)

const (
	BalanceModeRotate     = "rotate"
	BalanceModeConnection = "connection"
)

const (
	defaultAutoInterval      = 1 * time.Minute
	defaultAutoBenchInterval = 10 * time.Minute
	defaultAutoSampling      = 10
	defaultAutoActiveSize    = 10
	defaultAutoTimeout       = 5 * time.Second
	defaultAutoConcurrency   = 16
	defaultAutoTolerance     = 100
	defaultAutoFailTolerance = 0.5
	// The qualified set is the instant-failover pool, so it defaults to more
	// than one: with a set of one, a single working member is enough to stop
	// caring whether any other still works, and its failure means a cold search.
	defaultAutoExpected        = 5
	defaultAutoBalanceInterval = 30 * time.Second
	defaultAutoDialRetries     = 2

	// How often the selected member alone is re-probed. Independent of the tier
	// interval on purpose: a broken exit that still accepts TCP produces no dial
	// error at all, so nothing else would notice it until the next full round.
	defaultAutoWatchInterval = 15 * time.Second
	// Floor between two pulled-forward rounds. A member usually fails several
	// dials in a row and each must not buy its own sweep.
	minKickGap = 5 * time.Second

	// A round of this many probes that all fail is suspicious enough to spend a
	// connectivity check on; below it, the sampling ring absorbs the noise.
	outageProbeQuorum = 4
	// Failure samples and dial cooldowns recorded this long before an outage was
	// confirmed are rolled back — they were the local network, not the servers.
	outageRollbackWindow = 45 * time.Second
	// How often to re-test the local network while suspended.
	recoveryInterval = 5 * time.Second
	// A blocked connectivity URL must delay recovery, not prevent it.
	osResumeGrace = 5 * time.Minute
	// Probes run while neither signal says the link is back; tiny, since most will fail.
	optimisticProbeInterval = 30 * time.Second
	optimisticProbeSize     = 3
	// Distinct members failing back to back in the dial path before we spend an
	// out-of-band connectivity check.
	dialOutageSuspicion = 3
	// How long a connectivity verdict may be reused.
	connectivityTTL = 5 * time.Second
)

// dialBackoff is the cooldown ladder applied to a member after consecutive
// failed dials. The first step is deliberately short: one failure should move
// traffic off a member immediately, but must not exile it for minutes.
var dialBackoff = []time.Duration{
	5 * time.Second,
	15 * time.Second,
	45 * time.Second,
	2 * time.Minute,
	5 * time.Minute,
}

// AutoSelectorMemberStatus is one member's externally visible health. Everything
// the UI needs to explain a decision is here — nothing about the selector's
// state should require guessing from logs.
type AutoSelectorMemberStatus struct {
	Tag           string    `json:"tag"`
	Rank          int       `json:"rank"`
	State         string    `json:"state"`
	Selected      bool      `json:"selected"`
	SelectedUDP   bool      `json:"selected_udp"`
	Qualified     bool      `json:"qualified"`
	Active        bool      `json:"active"`
	AverageMs     int       `json:"average_ms"`
	DeviationMs   int       `json:"deviation_ms"`
	MinMs         int       `json:"min_ms"`
	MaxMs         int       `json:"max_ms"`
	Samples       int       `json:"samples"`
	Failures      int       `json:"failures"`
	Probes        int       `json:"probes"`
	DialTotal     int       `json:"dial_total"`
	DialFail      int       `json:"dial_fail"`
	LastOK        time.Time `json:"last_ok"`
	LastProbe     time.Time `json:"last_probe"`
	CooldownUntil time.Time `json:"cooldown_until"`
	LastError     string    `json:"last_error"`
}

// AutoSelectorStatus is a point-in-time snapshot of a whole group.
type AutoSelectorStatus struct {
	Tag         string `json:"tag"`
	Phase       string `json:"phase"`
	Selected    string `json:"selected"`
	SelectedUDP string `json:"selected_udp"`
	// Pinned is the member a user chose by hand, empty when fully automatic. It
	// is reported separately from Selected because the two differ whenever the
	// pinned member is not currently healthy.
	Pinned           string                     `json:"pinned"`
	Balance          bool                       `json:"balance"`
	BalanceMode      string                     `json:"balance_mode"`
	Suspended        bool                       `json:"suspended"`
	SuspendedSince   time.Time                  `json:"suspended_since"`
	MembersTotal     int                        `json:"members_total"`
	MembersProbed    int                        `json:"members_probed"`
	MembersAlive     int                        `json:"members_alive"`
	MembersQualified int                        `json:"members_qualified"`
	MembersCooldown  int                        `json:"members_cooldown"`
	ProbesInFlight   int                        `json:"probes_in_flight"`
	RoundsCompleted  int                        `json:"rounds_completed"`
	LastRoundAt      time.Time                  `json:"last_round_at"`
	NextRoundAt      time.Time                  `json:"next_round_at"`
	LastSwitchAt     time.Time                  `json:"last_switch_at"`
	LastSwitchReason string                     `json:"last_switch_reason"`
	Members          []AutoSelectorMemberStatus `json:"members"`
}

// AutoSelectorGroup is the contract callers outside this package (the RPC
// layer) assert against: full introspection, plus the two actions a UI needs.
type AutoSelectorGroup interface {
	adapter.OutboundGroup
	Status() AutoSelectorStatus
	CheckOutbounds()
	SelectOutbound(tag string) bool
}

type AutoSelector struct {
	outbound.Adapter
	ctx        context.Context
	cancel     context.CancelFunc
	outbound   adapter.OutboundManager
	connection adapter.ConnectionManager
	network    adapter.NetworkManager
	pause      pause.Manager
	logger     logger.ContextLogger

	tags       []string
	link       string
	connectURL string

	interval        time.Duration
	benchInterval   time.Duration
	watchInterval   time.Duration
	activeSize      int
	sampling        int
	probeTimeout    time.Duration
	concurrency     int
	tolerance       time.Duration
	maxRTT          time.Duration
	failTolerance   float64
	baselines       []time.Duration
	expected        int
	balance         bool
	balanceMode     string
	balanceInterval time.Duration
	dialRetries     int

	interruptGroup               *interrupt.Group
	interruptExternalConnections bool

	access     sync.Mutex
	members    map[string]*memberHealth
	outbounds  map[string]adapter.Outbound
	ranked     []*rankedNode
	qualified  []string
	activeSet  map[string]bool
	benchOrder []string
	benchIdx   int

	selectedTCP common.TypedValue[adapter.Outbound]
	selectedUDP common.TypedValue[adapter.Outbound]

	pinnedTag        string
	suspended        bool
	suspendedSince   time.Time
	optimisticIdx    int
	roundsCompleted  int
	lastRoundAt      time.Time
	nextRoundAt      time.Time
	probesInFlight   int
	lastSwitchAt     time.Time
	lastSwitchReason string
	started          bool
	nextRotateAt     time.Time
	lastKickAt       time.Time
	recentDialFails  map[string]time.Time

	connAccess    sync.Mutex
	connOK        bool
	connCheckedAt time.Time

	pauseCallback *list.Element[pause.Callback]
	kick          chan struct{}
	close         chan struct{}
	closeOnce     sync.Once
}

func NewAutoSelector(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AutoSelectorOutboundOptions) (adapter.Outbound, error) {
	if len(options.Outbounds) == 0 {
		return nil, E.New("missing tags")
	}
	groupCtx, cancel := context.WithCancel(ctx)
	s := &AutoSelector{
		Adapter:                      outbound.NewAdapter(C.TypeAutoSelector, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          groupCtx,
		cancel:                       cancel,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		network:                      service.FromContext[adapter.NetworkManager](ctx),
		pause:                        service.FromContext[pause.Manager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		link:                         options.URL,
		connectURL:                   options.ConnectivityURL,
		interval:                     time.Duration(options.Interval),
		benchInterval:                time.Duration(options.BenchInterval),
		watchInterval:                time.Duration(options.WatchInterval),
		activeSize:                   options.ActiveSize,
		sampling:                     options.Sampling,
		probeTimeout:                 time.Duration(options.Timeout),
		concurrency:                  options.Concurrency,
		maxRTT:                       time.Duration(options.MaxRTT),
		failTolerance:                options.FailTolerance,
		expected:                     options.Expected,
		balance:                      options.Balance,
		balanceMode:                  options.BalanceMode,
		balanceInterval:              time.Duration(options.BalanceInterval),
		dialRetries:                  options.DialRetries,
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,
		members:                      make(map[string]*memberHealth, len(options.Outbounds)),
		outbounds:                    make(map[string]adapter.Outbound, len(options.Outbounds)),
		activeSet:                    make(map[string]bool),
		recentDialFails:              make(map[string]time.Time),
		kick:                         make(chan struct{}, 1),
		close:                        make(chan struct{}),
	}
	if options.Tolerance > 0 {
		s.tolerance = time.Duration(options.Tolerance) * time.Millisecond
	} else {
		s.tolerance = defaultAutoTolerance * time.Millisecond
	}
	for _, baseline := range options.Baselines {
		s.baselines = append(s.baselines, time.Duration(baseline))
	}
	s.applyDefaults()

	validity := s.interval * time.Duration(s.sampling) * 2
	if benchValidity := s.benchInterval * 2; benchValidity > validity {
		// Bench members are probed far less often than active ones; without this
		// their samples would expire before the next probe and they would sink
		// back to "untested" forever.
		validity = benchValidity
	}
	for _, memberTag := range s.tags {
		if _, exists := s.members[memberTag]; exists {
			continue
		}
		s.members[memberTag] = newMemberHealth(memberTag, s.sampling, validity)
	}
	s.restoreWarm(options.Warm, time.Now())
	// Silently dropped when it names a member this build no longer contains —
	// the pool is rebuilt from a ranked list and the pinned server may simply
	// not have made the cut this time.
	if common.Contains(s.tags, options.Pinned) {
		s.pinnedTag = options.Pinned
	}
	s.benchOrder = append(s.benchOrder, s.tags...)
	return s, nil
}

// restoreWarm replays the caller's saved health as a single aged sample per
// member, which is all it takes to start with a real ranking instead of a pool
// of unknowns. Replaying with the original age rather than as fresh data is the
// safeguard: an entry older than the sampling window is already invisible to
// stats(), so a selector that has been stopped for a long time still starts
// cold, and one real probe always outweighs what was restored.
func (s *AutoSelector) restoreWarm(entries []option.AutoSelectorWarmEntry, now time.Time) int {
	restored := 0
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		health, loaded := s.members[entry.Tag]
		if !loaded || seen[entry.Tag] {
			continue
		}
		seen[entry.Tag] = true
		value := rttFailed
		if entry.RTT > 0 {
			value = time.Duration(entry.RTT) * time.Millisecond
		}
		at := now.Add(-time.Duration(entry.Age) * time.Second)
		if now.Sub(at) > health.validity {
			continue
		}
		health.put(value, at)
		restored++
	}
	return restored
}

func (s *AutoSelector) applyDefaults() {
	if s.interval <= 0 {
		s.interval = defaultAutoInterval
	}
	if s.benchInterval <= 0 {
		s.benchInterval = defaultAutoBenchInterval
	}
	if s.benchInterval < s.interval {
		s.benchInterval = s.interval
	}
	if s.sampling <= 0 {
		s.sampling = defaultAutoSampling
	}
	if s.activeSize <= 0 {
		s.activeSize = defaultAutoActiveSize
	}
	if s.expected <= 0 {
		s.expected = defaultAutoExpected
	}
	// The qualified set must sit inside the fast-probed set, or members would be
	// advertised as ready to take over on stale bench-rate measurements.
	if s.activeSize < s.expected {
		s.activeSize = s.expected
	}
	if s.activeSize > len(s.tags) {
		s.activeSize = len(s.tags)
	}
	if s.watchInterval <= 0 {
		s.watchInterval = defaultAutoWatchInterval
	}
	if s.watchInterval > s.interval {
		// Watching slower than the tier itself is probed would make it dead
		// weight; at that point the round already covers the selected member.
		s.watchInterval = s.interval
	}
	if s.probeTimeout <= 0 {
		s.probeTimeout = defaultAutoTimeout
	}
	if s.concurrency <= 0 {
		s.concurrency = defaultAutoConcurrency
	}
	if s.failTolerance <= 0 || s.failTolerance > 1 {
		s.failTolerance = defaultAutoFailTolerance
	}
	if s.balanceMode != BalanceModeConnection {
		s.balanceMode = BalanceModeRotate
	}
	if s.balanceInterval <= 0 {
		s.balanceInterval = defaultAutoBalanceInterval
	}
	if s.dialRetries < 0 {
		s.dialRetries = 0
	} else if s.dialRetries == 0 {
		s.dialRetries = defaultAutoDialRetries
	}
}

func (s *AutoSelector) Start() error {
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		s.outbounds[tag] = detour
	}

	s.access.Lock()
	// The caller's ordering is the ranking prior: seed with it so a selection
	// exists before the first probe lands.
	s.ranked = make([]*rankedNode, 0, len(s.tags))
	for _, tag := range s.tags {
		s.ranked = append(s.ranked, &rankedNode{tag: tag, tier: tierUntested})
	}
	s.refreshActiveSetLocked()
	// Restored health only pays off if it is ranked before the first pick is
	// made — otherwise the selection below still falls back to the prior and the
	// warm data does nothing until the first round lands.
	warmed := 0
	for _, health := range s.members {
		if health.probes > 0 {
			warmed++
		}
	}
	if warmed > 0 {
		s.evaluateLocked(time.Now())
	}
	s.access.Unlock()
	if warmed > 0 {
		s.logger.Info("auto-selector: restored health for ", warmed, " of ", len(s.tags), " members")
	}

	// A warm start has already ranked and chosen on real measurements, which
	// beats both the cached tag and the ordering prior. Only fall back when
	// nothing has been picked.
	if s.selectedFor(N.NetworkTCP) != nil {
		return nil
	}

	var restored adapter.Outbound
	if s.Tag() != "" {
		if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
			if selected := cacheFile.LoadSelected(s.Tag()); selected != "" {
				restored = s.outbounds[selected]
			}
		}
	}
	if restored == nil {
		restored = s.outbounds[s.tags[0]]
	}
	s.setSelected(restored, N.NetworkTCP, "initial")
	if common.Contains(restored.Network(), N.NetworkUDP) {
		s.setSelected(restored, N.NetworkUDP, "initial")
	} else {
		for _, tag := range s.tags {
			if detour := s.outbounds[tag]; common.Contains(detour.Network(), N.NetworkUDP) {
				s.setSelected(detour, N.NetworkUDP, "initial")
				break
			}
		}
	}
	return nil
}

func (s *AutoSelector) PostStart() error {
	s.access.Lock()
	s.started = true
	s.access.Unlock()
	go s.loop()
	go s.watchLoop()
	return nil
}

func (s *AutoSelector) Close() error {
	s.closeOnce.Do(func() {
		close(s.close)
		s.cancel()
	})
	s.access.Lock()
	if s.pauseCallback != nil {
		s.pause.UnregisterCallback(s.pauseCallback)
		s.pauseCallback = nil
	}
	s.access.Unlock()
	return nil
}

func (s *AutoSelector) Now() string {
	if selected := s.selectedTCP.Load(); selected != nil {
		return selected.Tag()
	}
	if selected := s.selectedUDP.Load(); selected != nil {
		return selected.Tag()
	}
	return ""
}

func (s *AutoSelector) All() []string {
	return s.tags
}

// SelectOutbound pins the group to one member, as the clash API's group
// selection does. The prober keeps running and will move off it if it dies.
// SelectOutbound pins the group to one member. An empty tag hands it back to
// automatic selection.
//
// The pin is a preference, not an override of the safety net: it is honoured for
// as long as that member stays healthy, and the moment it stops being healthy
// the ranking takes over exactly as it would otherwise. It resumes on its own
// once the member recovers. Anything stricter would turn an auto selector into a
// manual one — the point is to break a tie between members that measure alike,
// not to sit on a server that has stopped working.
func (s *AutoSelector) SelectOutbound(tag string) bool {
	if tag == "" {
		s.access.Lock()
		s.pinnedTag = ""
		s.evaluateLocked(time.Now())
		s.access.Unlock()
		s.logger.Info("auto-selector: released the pinned member, back to automatic")
		return true
	}
	detour, loaded := s.outbounds[tag]
	if !loaded {
		return false
	}
	s.access.Lock()
	s.pinnedTag = tag
	s.access.Unlock()

	s.setSelected(detour, N.NetworkTCP, "pinned by user")
	if common.Contains(detour.Network(), N.NetworkUDP) {
		s.setSelected(detour, N.NetworkUDP, "pinned by user")
	}
	return true
}

// pinnedFor returns the pinned member when it is currently fit to carry traffic
// on this network. Caller holds s.access.
func (s *AutoSelector) pinnedFor(network string, byTag map[string]*rankedNode) adapter.Outbound {
	if s.pinnedTag == "" {
		return nil
	}
	node, loaded := byTag[s.pinnedTag]
	if !loaded || node.tier != tierHealthy {
		return nil
	}
	detour, loaded := s.outbounds[s.pinnedTag]
	if !loaded || !common.Contains(detour.Network(), network) {
		return nil
	}
	return detour
}

// ---------------------------------------------------------------- probing ---

func (s *AutoSelector) loop() {
	// Probe the active set straight away so the first pick is informed rather
	// than inherited from the ranking prior.
	s.runRound(true)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	s.access.Lock()
	s.pauseCallback = pause.RegisterTicker(s.pause, ticker, s.interval, nil)
	s.nextRoundAt = time.Now().Add(s.interval)
	s.access.Unlock()

	for {
		urgent := false
		select {
		case <-s.close:
			return
		case <-s.kick:
			urgent = true
		case <-ticker.C:
		}
		if s.isSuspended() {
			// The recovery goroutine owns probing while suspended.
			continue
		}
		s.runRound(urgent)
		s.access.Lock()
		s.nextRoundAt = time.Now().Add(s.interval)
		s.access.Unlock()
	}
}

// requestRound pulls the next round forward instead of waiting out the tier
// interval. Debounced, because the events that call for it — a member failing
// its dials, the watchdog losing the exit — arrive in bursts, and each one must
// not buy its own sweep.
func (s *AutoSelector) requestRound() {
	s.access.Lock()
	if !s.lastKickAt.IsZero() && time.Since(s.lastKickAt) < minKickGap {
		s.access.Unlock()
		return
	}
	s.lastKickAt = time.Now()
	s.access.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// watchLoop re-probes the selected member, and only that one, on its own short
// interval. The tier interval is tuned for the cost of sweeping hundreds of
// members, which makes it far too slow for the one member actually carrying
// traffic — and a broken exit does not always announce itself: a server that
// still completes a TCP handshake but tunnels nothing produces no dial error, so
// nothing in the dial path would ever notice.
func (s *AutoSelector) watchLoop() {
	ticker := time.NewTicker(s.watchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.close:
			return
		case <-ticker.C:
		}
		if s.isSuspended() {
			continue
		}
		detour := s.selectedFor(N.NetworkTCP)
		if detour == nil {
			continue
		}
		value, err := s.probe(detour)
		now := time.Now()
		if value != rttFailed {
			s.access.Lock()
			if health, loaded := s.members[detour.Tag()]; loaded {
				health.put(value, now)
				health.lastDialErr = ""
				health.clearCooldown()
			}
			s.access.Unlock()
			continue
		}
		if isLocalNetworkError(err) {
			go s.assessOutage()
			continue
		}
		// One failed probe is a signal, not a verdict — it goes into the ring
		// like any other and the ranking decides what it is worth. What it does
		// buy is an immediate round over the active tier, so the answer comes in
		// seconds rather than at the next tick.
		s.access.Lock()
		if health, loaded := s.members[detour.Tag()]; loaded {
			health.put(rttFailed, now)
			if err != nil {
				health.lastDialErr = err.Error()
			}
		}
		s.evaluateLocked(now)
		s.access.Unlock()
		s.logger.Debug("auto-selector: selected member ", detour.Tag(), " failed its watch probe, checking the active tier")
		s.requestRound()
	}
}

// roundBatch picks the members to probe this round: the whole active tier, plus
// the next slice of the bench rotation so every member is covered once per
// benchInterval. An urgent round — the first one, a recovery check, or a round
// pulled forward because something just broke — takes the active tier only, so
// the answer arrives in one probe time instead of behind a bench sweep.
func (s *AutoSelector) roundBatch(urgent bool) []string {
	s.access.Lock()
	defer s.access.Unlock()

	batch := make([]string, 0, s.activeSize+8)
	seen := make(map[string]bool, s.activeSize+8)
	for i := 0; i < len(s.ranked) && len(batch) < s.activeSize; i++ {
		tag := s.ranked[i].tag
		if seen[tag] {
			continue
		}
		seen[tag] = true
		batch = append(batch, tag)
	}
	if urgent || len(s.benchOrder) == 0 {
		return batch
	}

	benchTotal := len(s.benchOrder)
	roundsPerCycle := int(s.benchInterval / s.interval)
	if roundsPerCycle < 1 {
		roundsPerCycle = 1
	}
	perRound := (benchTotal + roundsPerCycle - 1) / roundsPerCycle
	for i := 0; i < perRound; i++ {
		tag := s.benchOrder[s.benchIdx%benchTotal]
		s.benchIdx = (s.benchIdx + 1) % benchTotal
		if seen[tag] {
			continue
		}
		seen[tag] = true
		batch = append(batch, tag)
	}
	return batch
}

type probeResult struct {
	tag   string
	value time.Duration
	err   error
	at    time.Time
}

func (s *AutoSelector) runRound(urgent bool) {
	batch := s.roundBatch(urgent)
	if len(batch) == 0 {
		return
	}
	startedAt := time.Now()
	results := s.probeBatch(batch, urgent)
	if len(results) == 0 {
		return
	}
	s.commitRound(results, startedAt)
}

func (s *AutoSelector) probeBatch(batch []string, urgent bool) []probeResult {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make([]probeResult, 0, len(batch))
		limiter = make(chan struct{}, s.concurrency)
	)
	// Spread probes over the round so a 300-member group never bursts. Urgent
	// rounds skip the jitter: we want a usable answer immediately.
	spread := s.interval / 2
	for _, tag := range batch {
		detour, loaded := s.outbounds[tag]
		if !loaded {
			continue
		}
		wg.Add(1)
		go func(tag string, detour adapter.Outbound) {
			defer wg.Done()
			if !urgent && spread > 0 {
				delay := time.Duration(rand.Int63n(int64(spread)))
				select {
				case <-time.After(delay):
				case <-s.close:
					return
				}
			}
			select {
			case limiter <- struct{}{}:
			case <-s.close:
				return
			}
			defer func() { <-limiter }()

			s.access.Lock()
			s.probesInFlight++
			s.access.Unlock()
			value, err := s.probe(detour)
			s.access.Lock()
			s.probesInFlight--
			s.access.Unlock()

			mu.Lock()
			results = append(results, probeResult{tag: tag, value: value, err: err, at: time.Now()})
			mu.Unlock()
		}(tag, detour)
	}
	wg.Wait()
	return results
}

func (s *AutoSelector) probe(detour adapter.Outbound) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.probeTimeout)
	defer cancel()
	delay, err := urltest.URLTest(ctx, s.link, detour)
	if err != nil {
		return rttFailed, err
	}
	return time.Duration(delay) * time.Millisecond, nil
}

// commitRound decides whether a round's failures describe the servers or the
// local network, then either records or discards them. Successes always commit:
// one working member proves the network is up.
func (s *AutoSelector) commitRound(results []probeResult, startedAt time.Time) {
	var succeeded, failed, localErrors int
	for _, result := range results {
		if result.value == rttFailed {
			failed++
			if isLocalNetworkError(result.err) {
				localErrors++
			}
		} else {
			succeeded++
		}
	}

	// Members that went into this round with a clean record and came out of it
	// failing. Servers do not break in synchronised batches; a network does, so
	// this is the signal that catches a link dying *during* a round — where
	// probes that already landed keep succeeded above zero and every whole-round
	// rule below stays silent while good members collect failures.
	brokeTogether := 0
	s.access.Lock()
	for _, result := range results {
		if result.value != rttFailed {
			continue
		}
		health, loaded := s.members[result.tag]
		if !loaded {
			continue
		}
		if stats := health.stats(result.at); stats.All > 0 && stats.Fail == 0 {
			brokeTogether++
		}
	}
	s.access.Unlock()

	outage := false
	if failed > 0 {
		switch {
		case s.networkInterfaceDown():
			outage = true
		case succeeded == 0 && localErrors*2 >= failed:
			outage = true
		case succeeded == 0 && failed >= outageProbeQuorum:
			// A whole round failing is suspicious but not proof — a subscription
			// can genuinely expire. Only an independent check may conclude.
			outage = !s.connectivityOK(true)
		case brokeTogether >= outageProbeQuorum:
			outage = !s.connectivityOK(true)
		}
	}

	// A member answering is proof the link is up, and outranks every heuristic above.
	if outage && succeeded > 0 && s.isSuspended() {
		outage = false
	}

	now := time.Now()
	if outage {
		s.enterSuspended(now, startedAt)
		return
	}

	s.access.Lock()
	for _, result := range results {
		health, loaded := s.members[result.tag]
		if !loaded {
			continue
		}
		if result.err != nil && isLocalNetworkError(result.err) {
			// This probe never reached the server, so it says nothing about the
			// member. Recording it would let a flaky local stack bury members it
			// never actually asked anything.
			health.lastDialErr = result.err.Error()
			continue
		}
		health.put(result.value, result.at)
		if result.err != nil {
			health.lastDialErr = result.err.Error()
		} else if result.value != rttFailed {
			health.lastDialErr = ""
			// A probe is a real dial, so it outdates the penalty the member is serving.
			health.clearCooldown()
		}
	}
	s.roundsCompleted++
	s.lastRoundAt = now
	// Reaching here at all means the outage assessment cleared: the local
	// network is demonstrably usable, whatever the members did.
	wasSuspended := s.suspended
	s.suspended = false
	s.suspendedSince = time.Time{}
	s.evaluateLocked(now)
	s.access.Unlock()

	if wasSuspended {
		s.logger.Info("auto-selector: local network recovered, resuming health checks")
	}
}

func (s *AutoSelector) networkInterfaceDown() bool {
	return s.defaultInterfaceIndex() < 0
}

// defaultInterfaceIndex is -1 when the OS reports no route; the index lets recovery spot a
// different network appearing.
func (s *AutoSelector) defaultInterfaceIndex() int {
	if s.network == nil {
		return 0
	}
	iif := s.network.DefaultNetworkInterface()
	if iif == nil {
		return -1
	}
	return iif.Index
}

// connectivityOK probes the configured connectivity URL *without* the proxy.
// Verdicts are cached briefly and concurrent callers share one probe.
func (s *AutoSelector) connectivityOK(force bool) bool {
	if s.connectURL == "" {
		return !s.networkInterfaceDown()
	}
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	age := time.Since(s.connCheckedAt)
	if age < connectivityTTL && !force {
		return s.connOK
	}
	// A verdict that landed while this caller waited for the lock is fresh
	// enough even for a forced check — concurrent callers share one probe.
	if age < time.Second {
		return s.connOK
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.probeTimeout)
	defer cancel()
	_, err := urltest.URLTest(ctx, s.connectURL, N.SystemDialer)
	s.connOK = err == nil
	s.connCheckedAt = time.Now()
	return s.connOK
}

func (s *AutoSelector) isSuspended() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.suspended
}

// enterSuspended freezes the ranking and undoes the damage the outage already
// did: failure samples and dial cooldowns taken from `since` onward are erased,
// so a dropped wifi cannot mark a healthy pool dead.
//
// `since` is the start of the round that raised the alarm, or zero when the
// alarm came from the dial path. A round is the unit that matters: probes are
// deliberately spread over half the interval, so with an interval of minutes the
// fixed rollback window covers only the tail of a round and would leave the
// earlier failures — recorded while the network was already dying — in place.
// The window is still the floor, since it also has to cover the dial path.
func (s *AutoSelector) enterSuspended(now time.Time, since time.Time) {
	s.access.Lock()
	if s.suspended {
		s.access.Unlock()
		return
	}
	s.suspended = true
	s.suspendedSince = now
	since = rollbackSince(now, since)
	rolledSamples := 0
	rolledCooldowns := 0
	for _, health := range s.members {
		rolledSamples += health.rollbackFailuresSince(since)
		if health.clearCooldownSince(since) {
			rolledCooldowns++
		}
	}
	s.access.Unlock()

	s.logger.Warn("auto-selector: local network is down, suspending health checks (rolled back ",
		rolledSamples, " samples, ", rolledCooldowns, " cooldowns)")
	go s.recoveryLoop()
}

// recoveryLoop runs only while suspended, polling the local network far more
// often than the normal probe interval so recovery is not delayed by a minute.
//
// The connectivity URL leads until osResumeGrace, then the OS route alone; an
// optimistic probe answering overrules both.
func (s *AutoSelector) recoveryLoop() {
	ticker := time.NewTicker(recoveryInterval)
	defer ticker.Stop()
	backoff := recoveryInterval
	var (
		lastAttempt    time.Time
		lastOptimistic time.Time
		lastIndex      = -1
	)
	for {
		select {
		case <-s.close:
			return
		case <-ticker.C:
		}
		if !s.isSuspended() {
			return
		}
		index := s.defaultInterfaceIndex()
		if index < 0 {
			backoff = recoveryInterval
			lastAttempt = time.Time{}
			lastIndex = -1
		} else if index != lastIndex {
			// A different default interface is a real change in network state, not just elapsed time.
			lastIndex = index
			backoff = recoveryInterval
			lastAttempt = time.Time{}
		}

		now := time.Now()
		ready := index >= 0
		if ready && s.connectURL != "" && s.suspendedFor(now) < osResumeGrace {
			ready = s.connectivityOK(true)
		}
		if !ready {
			// Both signals can be wrong while a member still works, so keep asking a few.
			if lastOptimistic.IsZero() || now.Sub(lastOptimistic) >= optimisticProbeInterval {
				lastOptimistic = now
				s.optimisticRound()
				if !s.isSuspended() {
					return
				}
			}
			continue
		}

		if !lastAttempt.IsZero() && now.Sub(lastAttempt) < backoff {
			continue
		}
		lastAttempt = now
		s.runRound(true)
		if !s.isSuspended() {
			return
		}
		// Link up but nothing answered: keep asking, just not every five seconds forever.
		if backoff < s.interval {
			backoff = min(backoff*2, s.interval)
		}
	}
}

func (s *AutoSelector) suspendedFor(now time.Time) time.Duration {
	s.access.Lock()
	defer s.access.Unlock()
	if s.suspendedSince.IsZero() {
		return 0
	}
	return now.Sub(s.suspendedSince)
}

// optimisticRound commits only successes: a failure while the link is believed down says
// nothing about the member and would bury a healthy pool.
func (s *AutoSelector) optimisticRound() {
	batch := s.optimisticBatch()
	if len(batch) == 0 {
		return
	}
	startedAt := time.Now()
	succeeded := make([]probeResult, 0, len(batch))
	for _, result := range s.probeBatch(batch, true) {
		if result.value != rttFailed {
			succeeded = append(succeeded, result)
		}
	}
	if len(succeeded) == 0 {
		return
	}
	s.commitRound(succeeded, startedAt)
}

// optimisticBatch rotates through the ranking, so genuinely dead top members do not hide a
// working one further down.
func (s *AutoSelector) optimisticBatch() []string {
	s.access.Lock()
	defer s.access.Unlock()
	if len(s.ranked) == 0 {
		return nil
	}
	size := min(optimisticProbeSize, len(s.ranked))
	batch := make([]string, 0, size)
	for i := 0; i < size; i++ {
		// Modulo on read, since the ranking can shrink between rounds.
		s.optimisticIdx %= len(s.ranked)
		batch = append(batch, s.ranked[s.optimisticIdx].tag)
		s.optimisticIdx++
	}
	return batch
}

// ------------------------------------------------------------- evaluation ---

// evaluateLocked re-ranks every member and updates the selection. Caller holds
// s.access.
func (s *AutoSelector) evaluateLocked(now time.Time) {
	nodes := make([]*rankedNode, 0, len(s.tags))
	byTag := make(map[string]*rankedNode, len(s.tags))
	for _, tag := range s.tags {
		health, loaded := s.members[tag]
		if !loaded {
			continue
		}
		stats := health.stats(now)
		node := &rankedNode{tag: tag, stats: stats}
		switch {
		case health.inCooldown(now):
			node.tier = tierCooldown
		case stats.All == 0:
			node.tier = tierUntested
		case !stats.Alive():
			node.tier = tierDead
		default:
			node.tier = tierHealthy
		}
		nodes = append(nodes, node)
		byTag[tag] = node
	}
	// Preserve the previous ordering as the tie-break prior so equal members do
	// not shuffle between rounds.
	prior := make(map[string]int, len(s.ranked))
	for i, node := range s.ranked {
		prior[node.tag] = i
	}
	ordered := make([]*rankedNode, len(nodes))
	copy(ordered, nodes)
	stableByPrior(ordered, prior)
	sortNodes(ordered)
	s.ranked = ordered

	eligible := make([]*rankedNode, 0, len(ordered))
	for _, node := range ordered {
		if node.tier != tierHealthy {
			continue
		}
		if s.maxRTT > 0 && node.stats.Average >= s.maxRTT {
			continue
		}
		if node.stats.FailRatio() > s.failTolerance {
			continue
		}
		eligible = append(eligible, node)
	}
	qualified := applyBaselines(eligible, s.baselines, s.expected)
	s.qualified = s.qualified[:0]
	for _, node := range qualified {
		s.qualified = append(s.qualified, node.tag)
	}
	s.refreshActiveSetLocked()
	s.updateSelectionLocked(qualified, byTag, now)
}

func (s *AutoSelector) refreshActiveSetLocked() {
	s.activeSet = make(map[string]bool, s.activeSize)
	for i := 0; i < len(s.ranked) && i < s.activeSize; i++ {
		s.activeSet[s.ranked[i].tag] = true
	}
}

func (s *AutoSelector) updateSelectionLocked(qualified []*rankedNode, byTag map[string]*rankedNode, now time.Time) {
	s.updateNetworkSelectionLocked(N.NetworkTCP, qualified, byTag, now)
	s.updateNetworkSelectionLocked(N.NetworkUDP, qualified, byTag, now)
}

func (s *AutoSelector) updateNetworkSelectionLocked(network string, qualified []*rankedNode, byTag map[string]*rankedNode, now time.Time) {
	// A user's pick outranks the measurements while it is healthy — that is the
	// whole point of pinning one of several members that measure alike. It falls
	// through to the ranking the moment it is not, and comes back on its own.
	if pinned := s.pinnedFor(network, byTag); pinned != nil {
		if current := s.selectedFor(network); current == nil || current.Tag() != pinned.Tag() {
			s.setSelectedLocked(pinned, network, "pinned by user", now, true)
		}
		return
	}

	candidates := make([]*rankedNode, 0, len(qualified))
	for _, node := range qualified {
		if detour, loaded := s.outbounds[node.tag]; loaded && common.Contains(detour.Network(), network) {
			candidates = append(candidates, node)
		}
	}
	current := s.selectedFor(network)

	if len(candidates) == 0 {
		// Nothing qualified for this network. Keep whatever we have if it still
		// looks usable, else fall back to the best ranked member that supports
		// it, however poor.
		if current != nil {
			if node, loaded := byTag[current.Tag()]; loaded && node.tier == tierHealthy {
				return
			}
		}
		for _, node := range s.ranked {
			if node.tier == tierCooldown {
				continue
			}
			if detour, loaded := s.outbounds[node.tag]; loaded && common.Contains(detour.Network(), network) {
				s.setSelectedLocked(detour, network, "fallback: no qualified member", now, true)
				return
			}
		}
		// Everything is cooling down, where an outage puts the whole pool: a penalised member
		// still beats none.
		for _, node := range s.ranked {
			if detour, loaded := s.outbounds[node.tag]; loaded && common.Contains(detour.Network(), network) {
				s.setSelectedLocked(detour, network, "fallback: every member is cooling down", now, true)
				return
			}
		}
		return
	}

	// Incumbent stays unless a challenger beats it by more than the tolerance.
	if current != nil {
		for _, node := range candidates {
			if node.tag == current.Tag() {
				if node.stats.Average <= candidates[0].stats.Average+s.tolerance {
					return
				}
				break
			}
		}
	}
	s.setSelectedLocked(s.outbounds[candidates[0].tag], network, "best available", now, true)
}

func (s *AutoSelector) selectedFor(network string) adapter.Outbound {
	if network == N.NetworkUDP {
		return s.selectedUDP.Load()
	}
	return s.selectedTCP.Load()
}

func (s *AutoSelector) setSelected(detour adapter.Outbound, network string, reason string) {
	s.access.Lock()
	s.setSelectedLocked(detour, network, reason, time.Now(), true)
	s.access.Unlock()
}

// setSelectedLocked moves the selection. interruptExisting says whether live
// connections on the old member should be torn down, which is a health decision
// and not something a routine balance rotation has any business doing.
func (s *AutoSelector) setSelectedLocked(detour adapter.Outbound, network string, reason string, now time.Time, interruptExisting bool) {
	if detour == nil {
		return
	}
	var previous adapter.Outbound
	if network == N.NetworkUDP {
		previous = s.selectedUDP.Swap(detour)
	} else {
		previous = s.selectedTCP.Swap(detour)
	}
	if previous == detour {
		return
	}
	s.lastSwitchAt = now
	s.lastSwitchReason = reason
	if network == N.NetworkTCP && s.Tag() != "" {
		if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
			if err := cacheFile.StoreSelected(s.Tag(), detour.Tag()); err != nil {
				s.logger.Debug("auto-selector: store selected: ", err)
			}
		}
	}
	if previous != nil && s.started {
		s.logger.Info("auto-selector: ", network, " ", previous.Tag(), " -> ", detour.Tag(), " (", reason, ")")
		if interruptExisting {
			s.interruptGroup.Interrupt(s.interruptExternalConnections)
		}
	}
}

// --------------------------------------------------------------- dialling ---

// pick returns the outbound to attempt next for a dial, skipping anything
// already tried on this dial. It walks selection -> qualified -> ranked, and
// only as a last resort reaches into members that are in cooldown.
func (s *AutoSelector) pick(network string, tried map[string]bool) adapter.Outbound {
	s.access.Lock()
	defer s.access.Unlock()
	now := time.Now()

	// Balancing and a pinned member are contradictory instructions; the explicit
	// one wins. Spreading traffic resumes by itself once the pin is released or
	// the member stops being healthy.
	balancing := s.balance && s.pinnedTag == ""
	if balancing && s.balanceMode == BalanceModeRotate && now.After(s.nextRotateAt) {
		s.rotateLocked(network, now)
	}
	if balancing && s.balanceMode == BalanceModeConnection && len(s.qualified) > 1 {
		if detour := s.pickRandomQualifiedLocked(network, tried, now); detour != nil {
			return detour
		}
	}

	if current := s.selectedFor(network); current != nil && !tried[current.Tag()] {
		if health, loaded := s.members[current.Tag()]; !loaded || !health.inCooldown(now) {
			return current
		}
	}
	for _, tag := range s.qualified {
		if detour := s.usableLocked(tag, network, tried, now, false); detour != nil {
			return detour
		}
	}
	for _, node := range s.ranked {
		if detour := s.usableLocked(node.tag, network, tried, now, false); detour != nil {
			return detour
		}
	}
	// Everything is cooling down. Better to retry a penalised member than to
	// hand the client a failure.
	for _, node := range s.ranked {
		if detour := s.usableLocked(node.tag, network, tried, now, true); detour != nil {
			return detour
		}
	}
	return nil
}

func (s *AutoSelector) usableLocked(tag string, network string, tried map[string]bool, now time.Time, ignoreCooldown bool) adapter.Outbound {
	if tried[tag] {
		return nil
	}
	detour, loaded := s.outbounds[tag]
	if !loaded || !common.Contains(detour.Network(), network) {
		return nil
	}
	if !ignoreCooldown {
		if health, ok := s.members[tag]; ok && health.inCooldown(now) {
			return nil
		}
	}
	return detour
}

func (s *AutoSelector) pickRandomQualifiedLocked(network string, tried map[string]bool, now time.Time) adapter.Outbound {
	candidates := make([]adapter.Outbound, 0, len(s.qualified))
	for _, tag := range s.qualified {
		if detour := s.usableLocked(tag, network, tried, now, false); detour != nil {
			candidates = append(candidates, detour)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	return candidates[rand.Intn(len(candidates))]
}

// rotateLocked advances balance mode to the next qualified member. Rotating the
// whole selection (rather than picking per connection) keeps session affinity
// and keeps per-member traffic accounting exact.
//
// Nothing is interrupted: every member in the rotation is healthy, so live
// connections are left to finish where they started and only new ones follow the
// rotation. Tearing them down every balance_interval would make balancing far
// more disruptive than the failover it is not.
func (s *AutoSelector) rotateLocked(network string, now time.Time) {
	s.nextRotateAt = now.Add(s.balanceInterval)
	if len(s.qualified) < 2 {
		return
	}
	current := s.selectedFor(network)
	start := 0
	if current != nil {
		for i, tag := range s.qualified {
			if tag == current.Tag() {
				start = i + 1
				break
			}
		}
	}
	for i := 0; i < len(s.qualified); i++ {
		tag := s.qualified[(start+i)%len(s.qualified)]
		if detour := s.usableLocked(tag, network, nil, now, false); detour != nil {
			s.setSelectedLocked(detour, network, "balance rotation", now, false)
			return
		}
	}
}

// noteDialResult feeds the passive health signal. A failure demotes the member
// immediately so the very next attempt goes elsewhere; a success clears the
// penalty and promotes the member that actually worked, so Now() — and with it
// traffic accounting — tracks reality.
func (s *AutoSelector) noteDialResult(detour adapter.Outbound, network string, err error) {
	now := time.Now()
	tag := detour.Tag()

	if err == nil {
		s.access.Lock()
		if health, loaded := s.members[tag]; loaded {
			health.reward(now)
		}
		delete(s.recentDialFails, tag)
		if current := s.selectedFor(network); current == nil || current.Tag() != tag {
			// The member we moved off just failed to dial, so its live
			// connections are already broken; honouring the interrupt setting
			// here gets clients off it instead of leaving them hanging.
			s.setSelectedLocked(detour, network, "failover succeeded", now, true)
		}
		s.access.Unlock()
		return
	}

	if isLocalNetworkError(err) {
		// Nothing to learn about the member; go find out whether we still have
		// a network at all.
		go s.assessOutage()
		return
	}

	s.access.Lock()
	suspended := s.suspended
	if !suspended {
		if health, loaded := s.members[tag]; loaded {
			health.penalize(now, dialBackoff, err)
		}
		s.recentDialFails[tag] = now
		for failedTag, at := range s.recentDialFails {
			if now.Sub(at) > outageRollbackWindow {
				delete(s.recentDialFails, failedTag)
			}
		}
	}
	distinctFailures := len(s.recentDialFails)
	s.access.Unlock()

	if suspended {
		return
	}
	if distinctFailures >= dialOutageSuspicion {
		// Several different members failing at once is more likely to be this
		// machine than all of them dying together — verify out of band.
		go s.assessOutage()
	}
	// A real dial just failed on a member the ranking still rates highly, so the
	// ranking is out of date. Re-measure the active tier now rather than letting
	// traffic keep arriving at a member we already know is bad.
	s.requestRound()
}

func (s *AutoSelector) assessOutage() {
	if s.isSuspended() {
		return
	}
	if s.networkInterfaceDown() || (s.connectURL != "" && !s.connectivityOK(false)) {
		// No round to scope the rollback to; the fixed window covers the dials
		// that raised the alarm.
		s.enterSuspended(time.Now(), time.Time{})
	}
}

func (s *AutoSelector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP, N.NetworkUDP:
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	tried := make(map[string]bool, s.dialRetries+1)
	var lastError error
	for attempt := 0; attempt <= s.dialRetries; attempt++ {
		detour := s.pick(N.NetworkName(network), tried)
		if detour == nil {
			break
		}
		tried[detour.Tag()] = true
		conn, err := detour.DialContext(ctx, network, destination)
		if err == nil {
			s.noteDialResult(detour, N.NetworkName(network), nil)
			return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
		}
		lastError = err
		s.noteDialResult(detour, N.NetworkName(network), err)
		s.logger.DebugContext(ctx, "auto-selector: ", detour.Tag(), " failed: ", err)
		if ctx.Err() != nil {
			break
		}
	}
	if lastError == nil {
		lastError = E.New("no usable outbound")
	}
	return nil, lastError
}

func (s *AutoSelector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	tried := make(map[string]bool, s.dialRetries+1)
	var lastError error
	for attempt := 0; attempt <= s.dialRetries; attempt++ {
		detour := s.pick(N.NetworkUDP, tried)
		if detour == nil {
			break
		}
		tried[detour.Tag()] = true
		conn, err := detour.ListenPacket(ctx, destination)
		if err == nil {
			s.noteDialResult(detour, N.NetworkUDP, nil)
			return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
		}
		lastError = err
		s.noteDialResult(detour, N.NetworkUDP, err)
		if ctx.Err() != nil {
			break
		}
	}
	if lastError == nil {
		lastError = E.New("no usable outbound")
	}
	return nil, lastError
}

func (s *AutoSelector) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *AutoSelector) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

// ------------------------------------------------------------ inspection ---

// URLTest forces a full sweep of every member and reports the delays, satisfying
// adapter.URLTestGroup so the clash API can drive it.
func (s *AutoSelector) URLTest(ctx context.Context) (map[string]uint16, error) {
	startedAt := time.Now()
	results := s.probeBatch(s.tags, true)
	s.commitRound(results, startedAt)
	delays := make(map[string]uint16, len(results))
	for _, result := range results {
		if result.value == rttFailed {
			continue
		}
		delays[result.tag] = uint16(result.value / time.Millisecond)
	}
	return delays, nil
}

// PerformUpdateCheck re-ranks the members and refreshes the selection outside
// the round schedule, so a delay test driven through the clash API takes effect
// immediately instead of waiting for the next round.
func (s *AutoSelector) PerformUpdateCheck() {
	s.access.Lock()
	defer s.access.Unlock()
	s.evaluateLocked(time.Now())
}

func (s *AutoSelector) CheckOutbounds() {
	go func() {
		startedAt := time.Now()
		results := s.probeBatch(s.tags, true)
		s.commitRound(results, startedAt)
	}()
}

func (s *AutoSelector) Status() AutoSelectorStatus {
	s.access.Lock()
	defer s.access.Unlock()
	now := time.Now()

	selectedTCP := ""
	if selected := s.selectedTCP.Load(); selected != nil {
		selectedTCP = selected.Tag()
	}
	selectedUDP := ""
	if selected := s.selectedUDP.Load(); selected != nil {
		selectedUDP = selected.Tag()
	}
	qualified := make(map[string]bool, len(s.qualified))
	for _, tag := range s.qualified {
		qualified[tag] = true
	}

	status := AutoSelectorStatus{
		Tag:              s.Tag(),
		Selected:         selectedTCP,
		SelectedUDP:      selectedUDP,
		Pinned:           s.pinnedTag,
		Balance:          s.balance,
		BalanceMode:      s.balanceMode,
		Suspended:        s.suspended,
		SuspendedSince:   s.suspendedSince,
		MembersTotal:     len(s.tags),
		MembersQualified: len(s.qualified),
		ProbesInFlight:   s.probesInFlight,
		RoundsCompleted:  s.roundsCompleted,
		LastRoundAt:      s.lastRoundAt,
		NextRoundAt:      s.nextRoundAt,
		LastSwitchAt:     s.lastSwitchAt,
		LastSwitchReason: s.lastSwitchReason,
		Members:          make([]AutoSelectorMemberStatus, 0, len(s.ranked)),
	}
	switch {
	case s.suspended:
		status.Phase = "suspended"
	case !s.started:
		status.Phase = "starting"
	case s.roundsCompleted == 0:
		status.Phase = "probing"
	default:
		status.Phase = "ready"
	}

	for rank, node := range s.ranked {
		health, loaded := s.members[node.tag]
		if !loaded {
			continue
		}
		stats := health.stats(now)
		if stats.All > 0 {
			status.MembersProbed++
		}
		if stats.Alive() {
			status.MembersAlive++
		}
		if health.inCooldown(now) {
			status.MembersCooldown++
		}
		status.Members = append(status.Members, AutoSelectorMemberStatus{
			Tag:           node.tag,
			Rank:          rank + 1,
			State:         node.state(),
			Selected:      node.tag == selectedTCP,
			SelectedUDP:   node.tag == selectedUDP,
			Qualified:     qualified[node.tag],
			Active:        s.activeSet[node.tag],
			AverageMs:     int(stats.Average / time.Millisecond),
			DeviationMs:   int(stats.Deviation / time.Millisecond),
			MinMs:         int(stats.Min / time.Millisecond),
			MaxMs:         int(stats.Max / time.Millisecond),
			Samples:       stats.All,
			Failures:      stats.Fail,
			Probes:        health.probes,
			DialTotal:     health.dialTotal,
			DialFail:      health.dialFail,
			LastOK:        health.lastOK,
			LastProbe:     health.lastProbe,
			CooldownUntil: health.cooldownUntil,
			LastError:     health.lastDialErr,
		})
	}
	return status
}
