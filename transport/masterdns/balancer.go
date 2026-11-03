package masterdns

import (
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/wire"
	E "github.com/sagernet/sing/common/exceptions"
)

var ErrNoValidConnections = E.New("no valid connections after mtu testing")

const (
	statsHalfLifeThreshold = 1000
	pendingSoftCap         = 8192
	pendingHardCap         = 12288
	pendingShardCount      = 16
	rngFallbackSeed        = 0x9e3779b97f4a7c15
)

type Connection struct {
	Domain          string
	Resolver        netip.AddrPort
	Key             string
	Valid           bool
	UploadMTU       int
	UploadMTUChars  int
	DownloadMTU     int
	ResolveTime     time.Duration
	LastHealthCheck time.Time
}

// Connections pairs every domain with every resolver, domains outermost, keyed ip|port|domain like the reference.
func Connections(domains []string, resolvers []netip.AddrPort) []Connection {
	connections := make([]Connection, 0, len(domains)*len(resolvers))
	seen := make(map[string]bool, len(domains)*len(resolvers))
	for _, domain := range domains {
		for _, resolver := range resolvers {
			key := resolver.Addr().String() + "|" + strconv.Itoa(int(resolver.Port())) + "|" + domain
			if seen[key] {
				continue
			}
			seen[key] = true
			connections = append(connections, Connection{
				Domain:   domain,
				Resolver: resolver,
				Key:      key,
			})
		}
	}
	return connections
}

type Balancer struct {
	strategy         BalancingStrategy
	timeNow          func() time.Time
	rrCounter        atomic.Uint64
	healthRRCounter  atomic.Uint64
	rngState         atomic.Uint64
	nextPendingSweep atomic.Int64
	pendingOverflow  atomic.Bool
	pendingSize      atomic.Int32
	pendingEvictRR   atomic.Uint32
	pendingShards    [pendingShardCount]pendingShard

	access            sync.RWMutex
	connections       []Connection
	indexByKey        map[string]int
	activeIDs         []int
	inactiveIDs       []int
	stats             []*connectionStats
	streamRoutes      map[uint16]*streamRoute
	failoverThreshold int
	failoverCooldown  time.Duration
	autoDisable       bool
	autoDisableWindow time.Duration
	disabledHandler   func(conn Connection, reason string)
	confirmDown       func(conn Connection, window time.Duration) bool
}

type streamRoute struct {
	access       sync.Mutex
	preferredKey string
	resendStreak int
	lastFailover time.Time
}

type pendingKey struct {
	resolver netip.AddrPort
	local    netip.AddrPort
	id       uint16
}

type pendingSample struct {
	key        string
	sentAt     time.Time
	timedOut   bool
	timedOutAt time.Time
	evictAfter time.Time
}

type timeoutObservation struct {
	key string
	at  time.Time
}

type pendingShard struct {
	access  sync.Mutex
	pending map[pendingKey]pendingSample
}

type connectionStats struct {
	sent            atomic.Uint64
	acked           atomic.Uint64
	lost            atomic.Uint64
	rttMicrosSum    atomic.Uint64
	rttCount        atomic.Uint64
	windowStartedAt atomic.Int64
	windowSent      atomic.Uint32
	windowLost      atomic.Uint32
	windowAccess    sync.Mutex
	halfLifeRunning atomic.Bool
}

type poolPick uint8

const (
	poolPickRandom poolPick = iota
	poolPickRoundRobin
)

func NewBalancer(strategy BalancingStrategy) *Balancer {
	balancer := &Balancer{
		strategy:          strategy,
		timeNow:           time.Now,
		streamRoutes:      make(map[uint16]*streamRoute),
		failoverThreshold: 1,
		failoverCooldown:  time.Second,
	}
	for i := range balancer.pendingShards {
		balancer.pendingShards[i].pending = make(map[pendingKey]pendingSample)
	}
	seed := uint64(time.Now().UnixNano())
	if seed == 0 {
		seed = rngFallbackSeed
	}
	balancer.rngState.Store(seed)
	return balancer
}

func (b *Balancer) SetStreamFailover(threshold int, cooldown time.Duration) {
	if cooldown <= 0 {
		cooldown = time.Second
	}
	b.access.Lock()
	b.failoverThreshold = max(threshold, 1)
	b.failoverCooldown = cooldown
	b.access.Unlock()
}

func (b *Balancer) SetAutoDisable(enabled bool, window time.Duration) {
	b.access.Lock()
	b.autoDisable = enabled
	b.autoDisableWindow = window
	b.access.Unlock()
}

// SetDisabledHandler is called after the balancer lock is released.
func (b *Balancer) SetDisabledHandler(handler func(conn Connection, reason string)) {
	b.access.Lock()
	b.disabledHandler = handler
	b.access.Unlock()
}

func (b *Balancer) SetDownConfirmHandler(handler func(conn Connection, window time.Duration) bool) {
	b.access.Lock()
	b.confirmDown = handler
	b.access.Unlock()
}

func (b *Balancer) SetConnections(connections []Connection) {
	b.access.Lock()
	defer b.access.Unlock()
	b.connections = make([]Connection, 0, len(connections))
	b.indexByKey = make(map[string]int, len(connections))
	b.activeIDs = make([]int, 0, len(connections))
	b.inactiveIDs = make([]int, 0, len(connections))
	b.stats = make([]*connectionStats, 0, len(connections))
	for i := range b.pendingShards {
		shard := &b.pendingShards[i]
		shard.access.Lock()
		clear(shard.pending)
		shard.access.Unlock()
	}
	b.pendingOverflow.Store(false)
	b.pendingSize.Store(0)
	clear(b.streamRoutes)
	for _, conn := range connections {
		if conn.Key == "" {
			continue
		}
		index := len(b.connections)
		b.connections = append(b.connections, Connection{
			Domain:   conn.Domain,
			Resolver: conn.Resolver,
			Key:      conn.Key,
		})
		b.indexByKey[conn.Key] = index
		b.inactiveIDs = append(b.inactiveIDs, index)
		b.stats = append(b.stats, &connectionStats{})
	}
}

// updateConnections swaps in a new connection list, keeping the state of every key that remains; new keys start inactive.
func (b *Balancer) updateConnections(connections []Connection) {
	b.access.Lock()
	defer b.access.Unlock()
	oldConnections, oldStats, oldIndexByKey := b.connections, b.stats, b.indexByKey
	oldActive, oldInactive := b.activeIDs, b.inactiveIDs
	b.connections = make([]Connection, 0, len(connections))
	b.indexByKey = make(map[string]int, len(connections))
	b.activeIDs = make([]int, 0, len(connections))
	b.inactiveIDs = make([]int, 0, len(connections))
	b.stats = make([]*connectionStats, 0, len(connections))
	moved := make(map[int]int, len(oldConnections))
	var added []int
	for _, conn := range connections {
		if conn.Key == "" {
			continue
		}
		index := len(b.connections)
		if previous, loaded := oldIndexByKey[conn.Key]; loaded {
			b.connections = append(b.connections, oldConnections[previous])
			b.stats = append(b.stats, oldStats[previous])
			moved[previous] = index
		} else {
			b.connections = append(b.connections, Connection{
				Domain:   conn.Domain,
				Resolver: conn.Resolver,
				Key:      conn.Key,
			})
			b.stats = append(b.stats, &connectionStats{})
			added = append(added, index)
		}
		b.indexByKey[conn.Key] = index
	}
	for _, previous := range oldActive {
		if index, loaded := moved[previous]; loaded {
			b.activeIDs = append(b.activeIDs, index)
		}
	}
	for _, previous := range oldInactive {
		if index, loaded := moved[previous]; loaded {
			b.inactiveIDs = append(b.inactiveIDs, index)
		}
	}
	b.inactiveIDs = append(b.inactiveIDs, added...)
	for key := range oldIndexByKey {
		if _, loaded := b.indexByKey[key]; !loaded {
			b.clearPreferredResolverReferencesLocked(key)
		}
	}
}

func (b *Balancer) resetHealthChecks() {
	b.access.Lock()
	for _, index := range b.inactiveIDs {
		b.connections[index].LastHealthCheck = time.Time{}
	}
	b.access.Unlock()
}

func (b *Balancer) ActiveCount() int {
	b.access.RLock()
	defer b.access.RUnlock()
	return len(b.activeIDs)
}

func (b *Balancer) TotalCount() int {
	b.access.RLock()
	defer b.access.RUnlock()
	return len(b.connections)
}

func (b *Balancer) Connection(key string) (Connection, bool) {
	b.access.RLock()
	defer b.access.RUnlock()
	index, loaded := b.indexByKey[key]
	if !loaded {
		return Connection{}, false
	}
	return b.connections[index], true
}

func (b *Balancer) SetValid(key string, valid bool) bool {
	b.access.Lock()
	defer b.access.Unlock()
	index, loaded := b.indexByKey[key]
	if !loaded {
		return false
	}
	if b.connections[index].Valid == valid {
		return true
	}
	b.connections[index].Valid = valid
	if valid {
		b.stats[index].resetWindow()
	} else {
		b.clearPreferredResolverReferencesLocked(key)
	}
	b.moveConnectionLocked(index, valid)
	return true
}

func (b *Balancer) SetMTU(key string, upload int, uploadChars int, download int) bool {
	b.access.Lock()
	defer b.access.Unlock()
	index, loaded := b.indexByKey[key]
	if !loaded {
		return false
	}
	conn := &b.connections[index]
	conn.UploadMTU = upload
	conn.UploadMTUChars = uploadChars
	conn.DownloadMTU = download
	return true
}

func (b *Balancer) ApplyProbeResult(key string, upload int, uploadChars int, download int, resolveTime time.Duration, active bool) bool {
	b.access.Lock()
	defer b.access.Unlock()
	index, loaded := b.indexByKey[key]
	if !loaded {
		return false
	}
	conn := &b.connections[index]
	conn.UploadMTU = upload
	conn.UploadMTUChars = uploadChars
	conn.DownloadMTU = download
	conn.ResolveTime = resolveTime
	wasValid := conn.Valid
	conn.Valid = active
	if active {
		b.stats[index].resetWindow()
	} else {
		b.clearPreferredResolverReferencesLocked(key)
	}
	if wasValid != active {
		b.moveConnectionLocked(index, active)
	}
	return true
}

func (b *Balancer) ReportSend(key string) {
	if stats := b.statsForKey(key); stats != nil {
		stats.sent.Add(1)
		stats.applyHalfLife()
	}
}

func (b *Balancer) ReportSuccess(key string, rtt time.Duration) {
	stats := b.statsForKey(key)
	if stats == nil {
		return
	}
	stats.acked.Add(1)
	if rtt > 0 {
		stats.rttMicrosSum.Add(uint64(rtt / time.Microsecond))
		stats.rttCount.Add(1)
	}
	stats.applyHalfLife()
}

// ReportTimeout disables a resolver whose every send in the window timed out, unless too few stay active or a probe still reaches it.
func (b *Balancer) ReportTimeout(key string, now time.Time, window time.Duration, minActive int) bool {
	stats := b.statsForKey(key)
	if stats == nil {
		return false
	}
	stats.lost.Add(1)
	stats.applyHalfLife()
	timedOut, sent := stats.recordWindowTimeout(b.orNow(now), window)
	b.access.Lock()
	conn := b.connectionLocked(key)
	if conn == nil || !conn.Valid {
		b.access.Unlock()
		return false
	}
	activeCount := len(b.activeIDs)
	if int(sent) < autoDisableMinObservations(activeCount, window) || timedOut != sent {
		b.access.Unlock()
		return false
	}
	if activeCount <= max(minActive, 2) {
		b.access.Unlock()
		return false
	}
	confirmDown := b.confirmDown
	if confirmDown != nil && activeCount <= 20 {
		probed := *conn
		b.access.Unlock()
		down := confirmDown(probed, window)
		b.access.Lock()
		conn = b.connectionLocked(key)
		if conn == nil || !conn.Valid {
			b.access.Unlock()
			return false
		}
		if !down {
			stats.resetWindow()
			b.access.Unlock()
			return false
		}
	}
	conn.Valid = false
	stats.resetWindow()
	b.clearPreferredResolverReferencesLocked(key)
	b.moveConnectionLocked(b.indexByKey[key], false)
	disabled := *conn
	handler := b.disabledHandler
	b.access.Unlock()
	if handler != nil {
		handler(disabled, "TIMEOUT")
	}
	return true
}

func (b *Balancer) retractTimeout(key string, now time.Time, window time.Duration) {
	stats := b.statsForKey(key)
	if stats == nil {
		return
	}
	if stats.lost.Load() > 0 {
		stats.lost.Add(^uint64(0))
	}
	stats.applyHalfLife()
	stats.retractWindowTimeout(b.orNow(now), window)
}

func (b *Balancer) TrackSend(dnsID uint16, resolver netip.AddrPort, local netip.AddrPort, key string, sentAt time.Time, packetTimeout time.Duration) {
	if !resolver.IsValid() || key == "" {
		return
	}
	b.access.RLock()
	window := b.autoDisableWindow
	activeCount := len(b.activeIDs)
	b.access.RUnlock()
	requestTimeout := resolverRequestTimeout(packetTimeout, autoDisableCheckInterval(activeCount, window), window)
	if size := b.pendingSize.Load(); size >= pendingHardCap {
		b.evictPending(int(size) - pendingHardCap + 1)
	}
	sampleKey := newPendingKey(dnsID, resolver, local)
	shard := &b.pendingShards[sampleKey.shard()]
	shard.access.Lock()
	_, exists := shard.pending[sampleKey]
	if b.pendingSize.Load() >= pendingSoftCap {
		b.pendingOverflow.Store(true)
		b.setNextPendingSweep(sentAt)
	}
	shard.pending[sampleKey] = pendingSample{
		key:    key,
		sentAt: sentAt,
	}
	if !exists {
		b.pendingSize.Add(1)
	}
	b.schedulePendingSweep(sentAt.Add(requestTimeout))
	shard.access.Unlock()
	b.ReportSend(key)
	if stats := b.statsForKey(key); stats != nil {
		stats.recordWindowSend(b.orNow(sentAt), window)
	}
}

func (b *Balancer) TrackSuccess(dnsID uint16, resolver netip.AddrPort, local netip.AddrPort, receivedAt time.Time) {
	if !resolver.IsValid() {
		return
	}
	b.access.RLock()
	window := b.autoDisableWindow
	b.access.RUnlock()
	sample, loaded := b.takePending(newPendingKey(dnsID, resolver, local))
	if !loaded || sample.key == "" {
		return
	}
	if sample.timedOut && !sample.timedOutAt.IsZero() {
		b.retractTimeout(sample.key, receivedAt, window)
	}
	if !sample.sentAt.IsZero() && !receivedAt.Before(sample.sentAt) {
		if rtt := receivedAt.Sub(sample.sentAt); rtt > 0 {
			b.ReportSuccess(sample.key, rtt)
		}
	}
}

func (b *Balancer) TrackFailure(dnsID uint16, resolver netip.AddrPort, local netip.AddrPort, failedAt time.Time) {
	if !resolver.IsValid() {
		return
	}
	b.access.RLock()
	autoDisable := b.autoDisable
	window := b.autoDisableWindow
	b.access.RUnlock()
	sample, loaded := b.takePending(newPendingKey(dnsID, resolver, local))
	if !loaded || sample.key == "" || sample.timedOut || !autoDisable {
		return
	}
	b.ReportTimeout(sample.key, failedAt, window, 1)
}

func (b *Balancer) CollectExpiredTimeouts(now time.Time, packetTimeout time.Duration) {
	b.access.RLock()
	autoDisable := b.autoDisable
	window := b.autoDisableWindow
	activeCount := len(b.activeIDs)
	b.access.RUnlock()
	if !autoDisable {
		return
	}
	if !b.pendingOverflow.Load() && !b.pendingSweepDue(now) {
		return
	}
	requestTimeout := resolverRequestTimeout(packetTimeout, autoDisableCheckInterval(activeCount, window), window)
	ttl := resolverSampleTTL(packetTimeout)
	var (
		observations []timeoutObservation
		nextDue      time.Time
	)
	for i := range b.pendingShards {
		shard := &b.pendingShards[i]
		shard.access.Lock()
		shardObservations, shardNextDue, removed := prunePending(shard.pending, now, requestTimeout, ttl)
		if removed > 0 {
			b.pendingSize.Add(int32(-removed))
		}
		observations = append(observations, shardObservations...)
		if nextDue.IsZero() || !shardNextDue.IsZero() && shardNextDue.Before(nextDue) {
			nextDue = shardNextDue
		}
		shard.access.Unlock()
	}
	if overflow := int(b.pendingSize.Load()) - pendingHardCap; overflow >= 0 {
		b.evictPending(overflow + 1)
	}
	b.setNextPendingSweep(nextDue)
	b.pendingOverflow.Store(false)
	for _, observation := range observations {
		b.ReportTimeout(observation.key, observation.at, window, 1)
	}
}

func (b *Balancer) SeedConservativeStats(key string) {
	stats := b.statsForKey(key)
	if stats == nil {
		return
	}
	stats.sent.Store(10)
	stats.acked.Store(8)
	stats.lost.Store(0)
	stats.rttMicrosSum.Store(0)
	stats.rttCount.Store(0)
}

func (b *Balancer) BestConnection() (Connection, bool) {
	b.access.RLock()
	defer b.access.RUnlock()
	if len(b.activeIDs) == 0 {
		return Connection{}, false
	}
	if b.strategy == BalancingRandom {
		return b.connections[b.activeIDs[b.nextRandom()%uint64(len(b.activeIDs))]], true
	}
	if pool, pick, handled := b.strategyCandidatePoolLocked(""); handled {
		if len(pool) == 0 {
			return b.roundRobinBestLocked()
		}
		return b.pickFromPoolLocked(pool, pick)
	}
	scorer, hasSignal := b.strategyScorerLocked()
	if scorer == nil || !hasSignal {
		return b.roundRobinBestLocked()
	}
	return b.bestScoredLocked(scorer, "")
}

func (b *Balancer) UniqueConnections(count int) []Connection {
	b.access.RLock()
	defer b.access.RUnlock()
	return b.uniqueConnectionsLocked(count)
}

func (b *Balancer) ActiveConnections() []Connection {
	b.access.RLock()
	defer b.access.RUnlock()
	return b.connectionsByIndexLocked(b.activeIDs)
}

func (b *Balancer) AllConnections() []Connection {
	b.access.RLock()
	defer b.access.RUnlock()
	connections := make([]Connection, len(b.connections))
	copy(connections, b.connections)
	return connections
}

func (b *Balancer) NextInactiveForHealthCheck(now time.Time, minInterval time.Duration) (Connection, bool) {
	b.access.Lock()
	defer b.access.Unlock()
	count := len(b.inactiveIDs)
	if count == 0 {
		return Connection{}, false
	}
	minInterval = max(minInterval, 0)
	start := int((b.healthRRCounter.Add(1) - 1) % uint64(count))
	for i := range count {
		conn := &b.connections[b.inactiveIDs[(start+i)%count]]
		if !conn.LastHealthCheck.IsZero() && now.Sub(conn.LastHealthCheck) < minInterval {
			continue
		}
		conn.LastHealthCheck = now
		return *conn, true
	}
	return Connection{}, false
}

func (b *Balancer) EnsureStream(streamID uint16) {
	if streamID == 0 {
		return
	}
	b.access.Lock()
	if b.streamRoutes[streamID] == nil {
		b.streamRoutes[streamID] = &streamRoute{}
	}
	b.access.Unlock()
}

func (b *Balancer) CleanupStream(streamID uint16) {
	if streamID == 0 {
		return
	}
	b.access.Lock()
	delete(b.streamRoutes, streamID)
	b.access.Unlock()
}

func (b *Balancer) NoteStreamProgress(streamID uint16) {
	if streamID == 0 {
		return
	}
	b.access.RLock()
	route := b.streamRoutes[streamID]
	b.access.RUnlock()
	if route != nil {
		route.access.Lock()
		route.resendStreak = 0
		route.access.Unlock()
	}
}

// SelectTargets keeps data and resends of a stream on a sticky resolver and fills the duplicates from the strategy.
func (b *Balancer) SelectTargets(packetType uint8, streamID uint16, count int) ([]Connection, error) {
	b.access.RLock()
	defer b.access.RUnlock()
	count = normalizeRequiredCount(len(b.activeIDs), count)
	if count <= 0 {
		return nil, ErrNoValidConnections
	}
	if count == 1 || streamID == 0 || packetType != wire.PacketStreamData && packetType != wire.PacketStreamResend {
		selected := b.uniqueConnectionsLocked(count)
		if len(selected) == 0 {
			return nil, ErrNoValidConnections
		}
		return selected, nil
	}
	route := b.streamRoutes[streamID]
	if route == nil {
		return b.uniqueConnectionsLocked(count), nil
	}
	route.access.Lock()
	defer route.access.Unlock()
	preferred, loaded := b.preferredConnectionLocked(packetType, route)
	if !loaded {
		return b.uniqueConnectionsLocked(count), nil
	}
	selected := make([]Connection, 0, count)
	selected = append(selected, preferred)
	return append(selected, b.uniqueConnectionsExcludingLocked(count-1, preferred.Key)...), nil
}

func (b *Balancer) preferredConnectionLocked(packetType uint8, route *streamRoute) (Connection, bool) {
	if packetType == wire.PacketStreamResend {
		route.resendStreak++
		if current, loaded := b.validPreferredLocked(route); loaded {
			now := b.timeNow()
			if route.resendStreak < b.failoverThreshold || now.Sub(route.lastFailover) < b.failoverCooldown {
				return current, true
			}
			if replacement, loaded := b.alternateConnectionLocked(current.Key); loaded {
				route.preferredKey = replacement.Key
				route.resendStreak = 0
				route.lastFailover = now
				return replacement, true
			}
			return current, true
		}
	}
	if current, loaded := b.validPreferredLocked(route); loaded {
		return current, true
	}
	var (
		replacement Connection
		loaded      bool
	)
	if route.preferredKey == "" {
		replacement, loaded = b.initialPreferredLocked()
	} else {
		replacement, loaded = b.alternateConnectionLocked(route.preferredKey)
	}
	if !loaded {
		return Connection{}, false
	}
	route.preferredKey = replacement.Key
	route.resendStreak = 0
	return replacement, true
}

func (b *Balancer) validPreferredLocked(route *streamRoute) (Connection, bool) {
	if route.preferredKey == "" {
		return Connection{}, false
	}
	conn := b.connectionLocked(route.preferredKey)
	if conn == nil || !conn.Valid {
		return Connection{}, false
	}
	return *conn, true
}

func (b *Balancer) alternateConnectionLocked(excludeKey string) (Connection, bool) {
	if excludeKey != "" {
		if replacement, loaded := b.bestExcludingLocked(excludeKey); loaded {
			return replacement, true
		}
	}
	selected := b.uniqueConnectionsLocked(1)
	if len(selected) == 0 {
		return Connection{}, false
	}
	if excludeKey == "" || selected[0].Key != excludeKey {
		return selected[0], true
	}
	return b.bestExcludingLocked(excludeKey)
}

func (b *Balancer) initialPreferredLocked() (Connection, bool) {
	if len(b.activeIDs) == 0 {
		return Connection{}, false
	}
	switch b.strategy {
	case BalancingRandom, BalancingRoundRobin, BalancingRoundRobinDefault:
		return b.targetByStrategyLocked()
	}
	if pool, pick, handled := b.strategyCandidatePoolLocked(""); handled {
		if len(pool) == 0 {
			return b.targetByStrategyLocked()
		}
		return b.pickFromPoolLocked(pool, pick)
	}
	scorer, hasSignal := b.strategyScorerLocked()
	if scorer == nil || !hasSignal {
		return b.targetByStrategyLocked()
	}
	pool := b.lowestScoreLocked(min(10, len(b.activeIDs)), scorer)
	if len(pool) == 0 {
		return b.targetByStrategyLocked()
	}
	return b.pickFromPoolLocked(pool, poolPickRandom)
}

func (b *Balancer) targetByStrategyLocked() (Connection, bool) {
	selected := b.uniqueConnectionsLocked(1)
	if len(selected) == 0 {
		return Connection{}, false
	}
	return selected[0], true
}

func (b *Balancer) clearPreferredResolverReferencesLocked(key string) {
	if key == "" {
		return
	}
	for _, route := range b.streamRoutes {
		if route.preferredKey != key {
			continue
		}
		route.preferredKey = ""
		route.resendStreak = 0
	}
}

func (b *Balancer) moveConnectionLocked(index int, valid bool) {
	if valid {
		b.inactiveIDs = removeIndex(b.inactiveIDs, index)
		b.activeIDs = addIndex(b.activeIDs, index)
	} else {
		b.activeIDs = removeIndex(b.activeIDs, index)
		b.inactiveIDs = addIndex(b.inactiveIDs, index)
	}
}

func addIndex(indices []int, index int) []int {
	for _, existing := range indices {
		if existing == index {
			return indices
		}
	}
	return append(indices, index)
}

func removeIndex(indices []int, index int) []int {
	for i, existing := range indices {
		if existing == index {
			indices[i] = indices[len(indices)-1]
			return indices[:len(indices)-1]
		}
	}
	return indices
}

func (b *Balancer) statsForKey(key string) *connectionStats {
	b.access.RLock()
	defer b.access.RUnlock()
	index, loaded := b.indexByKey[key]
	if !loaded {
		return nil
	}
	return b.stats[index]
}

func (b *Balancer) connectionLocked(key string) *Connection {
	index, loaded := b.indexByKey[key]
	if !loaded {
		return nil
	}
	return &b.connections[index]
}

func (b *Balancer) connectionsByIndexLocked(indices []int) []Connection {
	if len(indices) == 0 {
		return nil
	}
	connections := make([]Connection, len(indices))
	for i, index := range indices {
		connections[i] = b.connections[index]
	}
	return connections
}

func (b *Balancer) orNow(now time.Time) time.Time {
	if now.IsZero() {
		return b.timeNow()
	}
	return now
}

func (b *Balancer) uniqueConnectionsLocked(count int) []Connection {
	count = normalizeRequiredCount(len(b.activeIDs), count)
	if count <= 0 {
		return nil
	}
	if b.strategy == BalancingRandom {
		return b.randomLocked(count)
	}
	if pool, pick, handled := b.strategyCandidatePoolLocked(""); handled {
		if len(pool) == 0 {
			return b.roundRobinLocked(count)
		}
		return b.limitPoolLocked(pool, count, pick)
	}
	scorer, hasSignal := b.strategyScorerLocked()
	if scorer == nil || !hasSignal {
		return b.roundRobinLocked(count)
	}
	return b.lowestScoreLocked(count, scorer)
}

func (b *Balancer) uniqueConnectionsExcludingLocked(count int, excludeKey string) []Connection {
	if count <= 0 || len(b.activeIDs) == 0 {
		return nil
	}
	all := b.uniqueConnectionsLocked(count + 1)
	selected := make([]Connection, 0, count)
	for _, conn := range all {
		if conn.Key == excludeKey {
			continue
		}
		selected = append(selected, conn)
		if len(selected) >= count {
			break
		}
	}
	return selected
}

func (b *Balancer) bestExcludingLocked(excludeKey string) (Connection, bool) {
	if b.strategy == BalancingRandom {
		return b.roundRobinBestExcludingLocked(excludeKey)
	}
	if pool, pick, handled := b.strategyCandidatePoolLocked(excludeKey); handled {
		if len(pool) == 0 {
			return b.roundRobinBestExcludingLocked(excludeKey)
		}
		return b.pickFromPoolLocked(pool, pick)
	}
	scorer, hasSignal := b.strategyScorerLocked()
	if scorer == nil || !hasSignal {
		return b.roundRobinBestExcludingLocked(excludeKey)
	}
	return b.bestScoredLocked(scorer, excludeKey)
}

func (b *Balancer) roundRobinLocked(count int) []Connection {
	total := len(b.activeIDs)
	start := int((b.rrCounter.Add(uint64(count)) - uint64(count)) % uint64(total))
	selected := make([]Connection, count)
	for i := range count {
		selected[i] = b.connections[b.activeIDs[(start+i)%total]]
	}
	return selected
}

func (b *Balancer) randomLocked(count int) []Connection {
	total := len(b.activeIDs)
	if count <= 0 || total == 0 {
		return nil
	}
	if count == 1 {
		return []Connection{b.connections[b.activeIDs[b.nextRandom()%uint64(total)]]}
	}
	indices := append([]int(nil), b.activeIDs...)
	for i := range count {
		j := i + int(b.nextRandom()%uint64(total-i))
		indices[i], indices[j] = indices[j], indices[i]
	}
	return b.connectionsByIndexLocked(indices[:count])
}

func (b *Balancer) lowestScoreLocked(count int, scorer func(int) uint64) []Connection {
	total := len(b.activeIDs)
	if count <= 0 || total == 0 {
		return nil
	}
	if count == 1 {
		conn, loaded := b.bestScoredLocked(scorer, "")
		if !loaded {
			return nil
		}
		return []Connection{conn}
	}
	type scoredIndex struct {
		index int
		score uint64
	}
	ordered := b.rotatedActiveLocked(count)
	scored := make([]scoredIndex, total)
	for i, index := range ordered {
		scored[i] = scoredIndex{index: index, score: scorer(index)}
	}
	for i := 0; i < count && i < total; i++ {
		minimum := i
		for j := i + 1; j < total; j++ {
			if scored[j].score < scored[minimum].score {
				minimum = j
			}
		}
		scored[i], scored[minimum] = scored[minimum], scored[i]
	}
	selected := make([]Connection, count)
	for i := range count {
		selected[i] = b.connections[scored[i].index]
	}
	return selected
}

func (b *Balancer) bestScoredLocked(scorer func(int) uint64, excludeKey string) (Connection, bool) {
	best := -1
	var bestScore uint64
	for _, index := range b.rotatedActiveLocked(1) {
		if excludeKey != "" && b.connections[index].Key == excludeKey {
			continue
		}
		score := scorer(index)
		if best == -1 || score < bestScore {
			best = index
			bestScore = score
		}
	}
	if best < 0 {
		return Connection{}, false
	}
	return b.connections[best], true
}

func (b *Balancer) roundRobinBestLocked() (Connection, bool) {
	if len(b.activeIDs) == 0 {
		return Connection{}, false
	}
	return b.connections[b.activeIDs[(b.rrCounter.Add(1)-1)%uint64(len(b.activeIDs))]], true
}

func (b *Balancer) roundRobinBestExcludingLocked(excludeKey string) (Connection, bool) {
	for _, index := range b.rotatedActiveLocked(1) {
		if b.connections[index].Key == excludeKey {
			continue
		}
		return b.connections[index], true
	}
	return Connection{}, false
}

func (b *Balancer) rotatedActiveLocked(step int) []int {
	total := len(b.activeIDs)
	if total == 0 {
		return nil
	}
	step = max(step, 1)
	start := int((b.rrCounter.Add(uint64(step)) - uint64(step)) % uint64(total))
	ordered := make([]int, total)
	for i := range total {
		ordered[i] = b.activeIDs[(start+i)%total]
	}
	return ordered
}

func (b *Balancer) hasLossSignalLocked() bool {
	for _, index := range b.activeIDs {
		if b.stats[index].sent.Load() > 0 {
			return true
		}
	}
	return false
}

func (b *Balancer) hasLatencySignalLocked() bool {
	for _, index := range b.activeIDs {
		if b.stats[index].rttCount.Load() > 0 {
			return true
		}
	}
	return false
}

func (b *Balancer) strategyScorerLocked() (func(int) uint64, bool) {
	switch b.strategy {
	case BalancingLeastLoss:
		return b.lossScoreLocked, b.hasLossSignalLocked()
	case BalancingLowestLatency:
		return b.latencyScoreLocked, b.hasLatencySignalLocked()
	case BalancingHybrid:
		return b.hybridScoreLocked, b.hasLossSignalLocked() || b.hasLatencySignalLocked()
	default:
		return nil, false
	}
}

func (b *Balancer) strategyCandidatePoolLocked(excludeKey string) ([]Connection, poolPick, bool) {
	switch b.strategy {
	case BalancingLossThenLatency:
		if !b.hasLossSignalLocked() && !b.hasLatencySignalLocked() {
			return nil, poolPickRandom, true
		}
		return b.lossThenLatencyCandidatesLocked(excludeKey), poolPickRandom, true
	case BalancingLeastLossTopRandom:
		if !b.hasLossSignalLocked() {
			return nil, poolPickRandom, true
		}
		return b.leastLossTopTierLocked(excludeKey), poolPickRandom, true
	case BalancingLeastLossTopRoundRobin:
		if !b.hasLossSignalLocked() {
			return nil, poolPickRoundRobin, true
		}
		return b.leastLossTopTierLocked(excludeKey), poolPickRoundRobin, true
	default:
		return nil, poolPickRandom, false
	}
}

func (b *Balancer) pickFromPoolLocked(pool []Connection, pick poolPick) (Connection, bool) {
	if len(pool) == 0 {
		return Connection{}, false
	}
	if pick == poolPickRoundRobin {
		return pool[(b.rrCounter.Add(1)-1)%uint64(len(pool))], true
	}
	return pool[b.nextRandom()%uint64(len(pool))], true
}

func (b *Balancer) limitPoolLocked(pool []Connection, count int, pick poolPick) []Connection {
	if len(pool) == 0 || count <= 0 {
		return nil
	}
	if count >= len(pool) {
		return pool
	}
	if pick == poolPickRoundRobin {
		start := int((b.rrCounter.Add(uint64(count)) - uint64(count)) % uint64(len(pool)))
		ordered := make([]Connection, len(pool))
		for i := range pool {
			ordered[i] = pool[(start+i)%len(pool)]
		}
		return ordered[:count]
	}
	if count == 1 {
		pool[0] = pool[b.nextRandom()%uint64(len(pool))]
		return pool[:1:1]
	}
	for i := range count {
		j := i + int(b.nextRandom()%uint64(len(pool)-i))
		pool[i], pool[j] = pool[j], pool[i]
	}
	return pool[:count:count]
}

func (b *Balancer) lossThenLatencyCandidatesLocked(excludeKey string) []Connection {
	type candidate struct {
		index   int
		loss    uint64
		latency uint64
		hasRTT  bool
	}
	candidates := make([]candidate, 0, len(b.activeIDs))
	bestLoss := ^uint64(0)
	for _, index := range b.activeIDs {
		if excludeKey != "" && b.connections[index].Key == excludeKey {
			continue
		}
		loss := b.lossScoreLocked(index)
		bestLoss = min(bestLoss, loss)
		candidates = append(candidates, candidate{
			index:   index,
			loss:    loss,
			latency: b.hybridLatencyPenaltyLocked(index),
			hasRTT:  b.stats[index].rttCount.Load() > 0,
		})
	}
	if len(candidates) == 0 {
		return nil
	}
	lossCutoff := bestLoss + 25
	if bestLoss >= 200 {
		lossCutoff = bestLoss
	}
	shortlist := make([]candidate, 0, len(candidates))
	bestLatency := ^uint64(0)
	for _, candidate := range candidates {
		if candidate.loss > lossCutoff {
			continue
		}
		shortlist = append(shortlist, candidate)
		if candidate.hasRTT && candidate.latency < bestLatency {
			bestLatency = candidate.latency
		}
	}
	selected := make([]Connection, 0, len(shortlist))
	if bestLatency == ^uint64(0) {
		for _, candidate := range shortlist {
			selected = append(selected, b.connections[candidate.index])
		}
		return selected
	}
	latencyCutoff := bestLatency + latencyToleranceForTier(bestLatency)
	for _, candidate := range shortlist {
		if !candidate.hasRTT || candidate.latency <= latencyCutoff {
			selected = append(selected, b.connections[candidate.index])
		}
	}
	if len(selected) > 0 {
		return selected
	}
	return []Connection{b.connections[shortlist[0].index]}
}

func latencyToleranceForTier(bestLatency uint64) uint64 {
	if bestLatency >= 200 {
		return 0
	}
	return min(max(bestLatency/4, 2), 25)
}

func (b *Balancer) leastLossTopTierLocked(excludeKey string) []Connection {
	type candidate struct {
		index int
		loss  uint64
	}
	candidates := make([]candidate, 0, len(b.activeIDs))
	for _, index := range b.activeIDs {
		if excludeKey != "" && b.connections[index].Key == excludeKey {
			continue
		}
		candidates = append(candidates, candidate{index: index, loss: b.lossScoreLocked(index)})
	}
	if len(candidates) == 0 {
		return nil
	}
	topCount := min(max(2, (len(candidates)+9)/10), len(candidates))
	for i := range topCount {
		minimum := i
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].loss < candidates[minimum].loss {
				minimum = j
			}
		}
		candidates[i], candidates[minimum] = candidates[minimum], candidates[i]
	}
	selected := make([]Connection, topCount)
	for i := range topCount {
		selected[i] = b.connections[candidates[i].index]
	}
	return selected
}

func (b *Balancer) lossScoreLocked(index int) uint64 {
	stats := b.stats[index]
	sent, lost := stats.sent.Load(), stats.lost.Load()
	if sent == 0 || lost == 0 {
		return 0
	}
	return lost * 1000 / sent
}

func (b *Balancer) latencyScoreLocked(index int) uint64 {
	stats := b.stats[index]
	sum, count := stats.rttMicrosSum.Load(), stats.rttCount.Load()
	if count == 0 {
		return 999000
	}
	return sum / count
}

func (b *Balancer) hybridScoreLocked(index int) uint64 {
	return b.lossScoreLocked(index)*8 + b.hybridLatencyPenaltyLocked(index)
}

func (b *Balancer) hybridLatencyPenaltyLocked(index int) uint64 {
	latency := b.latencyScoreLocked(index)
	if latency == 999000 {
		return 200
	}
	return min(latency/1000, 1000)
}

func (b *Balancer) nextRandom() uint64 {
	for {
		current := b.rngState.Load()
		next := xorshift64(current)
		if b.rngState.CompareAndSwap(current, next) {
			return next
		}
	}
}

func xorshift64(value uint64) uint64 {
	if value == 0 {
		value = rngFallbackSeed
	}
	value ^= value << 13
	value ^= value >> 7
	value ^= value << 17
	return value
}

func normalizeRequiredCount(validCount int, count int) int {
	if validCount <= 0 {
		return 0
	}
	if count <= 0 {
		count = 1
	}
	return min(count, validCount)
}

func newPendingKey(id uint16, resolver netip.AddrPort, local netip.AddrPort) pendingKey {
	return pendingKey{
		resolver: netip.AddrPortFrom(resolver.Addr().Unmap(), resolver.Port()),
		local:    netip.AddrPortFrom(local.Addr().Unmap(), local.Port()),
		id:       id,
	}
}

func (k pendingKey) shard() int {
	hash := uint32(k.id)
	for _, addrPort := range [2]netip.AddrPort{k.resolver, k.local} {
		for _, value := range addrPort.Addr().As16() {
			hash = hash*33 + uint32(value)
		}
		hash = hash*33 + uint32(addrPort.Port())
	}
	return int(hash % pendingShardCount)
}

func (b *Balancer) takePending(key pendingKey) (pendingSample, bool) {
	shard := &b.pendingShards[key.shard()]
	shard.access.Lock()
	defer shard.access.Unlock()
	sample, loaded := shard.pending[key]
	if loaded {
		delete(shard.pending, key)
		b.pendingSize.Add(-1)
	}
	return sample, loaded
}

func (b *Balancer) pendingCount() int {
	return int(b.pendingSize.Load())
}

func (b *Balancer) pendingSweepDue(now time.Time) bool {
	next := b.nextPendingSweep.Load()
	return next == 0 || now.UnixNano() >= next
}

func (b *Balancer) schedulePendingSweep(next time.Time) {
	if next.IsZero() {
		return
	}
	nextUnix := next.UnixNano()
	for {
		current := b.nextPendingSweep.Load()
		if current != 0 && current <= nextUnix {
			return
		}
		if b.nextPendingSweep.CompareAndSwap(current, nextUnix) {
			return
		}
	}
}

func (b *Balancer) setNextPendingSweep(next time.Time) {
	if next.IsZero() {
		b.nextPendingSweep.Store(0)
		return
	}
	b.nextPendingSweep.Store(next.UnixNano())
}

// prunePending marks samples past the request timeout as lost once and keeps them for a grace period, so a late answer can retract the loss.
func prunePending(pending map[pendingKey]pendingSample, now time.Time, requestTimeout time.Duration, ttl time.Duration) ([]timeoutObservation, time.Time, int) {
	if len(pending) == 0 {
		return nil, time.Time{}, 0
	}
	var (
		observations []timeoutObservation
		nextDue      time.Time
		removed      int
	)
	timeoutBefore := now.Add(-requestTimeout)
	absoluteCutoff := now.Add(-ttl)
	lateGrace := resolverLateResponseGrace(requestTimeout, ttl)
	for key, sample := range pending {
		if !sample.timedOut {
			timeoutAt := sample.sentAt.Add(requestTimeout)
			if !sample.sentAt.After(timeoutBefore) {
				sample.timedOut = true
				sample.timedOutAt = timeoutAt
				if sample.timedOutAt.After(now) {
					sample.timedOutAt = now
				}
				sample.evictAfter = sample.timedOutAt.Add(lateGrace)
				pending[key] = sample
				if sample.key != "" {
					observations = append(observations, timeoutObservation{key: sample.key, at: sample.timedOutAt})
				}
			} else if nextDue.IsZero() || timeoutAt.Before(nextDue) {
				nextDue = timeoutAt
			}
			if sample.sentAt.Before(absoluteCutoff) {
				delete(pending, key)
				removed++
			}
			continue
		}
		if !sample.evictAfter.IsZero() && !sample.evictAfter.After(now) || sample.sentAt.Before(absoluteCutoff) {
			delete(pending, key)
			removed++
			continue
		}
		evictAt := sample.evictAfter
		if evictAt.IsZero() {
			evictAt = sample.sentAt.Add(ttl)
		}
		if nextDue.IsZero() || evictAt.Before(nextDue) {
			nextDue = evictAt
		}
	}
	return observations, nextDue, removed
}

func (b *Balancer) evictPending(count int) {
	for count > 0 {
		removedAny := false
		start := int((b.pendingEvictRR.Add(1) - 1) % pendingShardCount)
		for i := 0; i < pendingShardCount && count > 0; i++ {
			shard := &b.pendingShards[(start+i)%pendingShardCount]
			shard.access.Lock()
			for key := range shard.pending {
				delete(shard.pending, key)
				b.pendingSize.Add(-1)
				count--
				removedAny = true
				break
			}
			shard.access.Unlock()
		}
		if !removedAny {
			return
		}
	}
}

func resolverSampleTTL(packetTimeout time.Duration) time.Duration {
	return min(max(packetTimeout*3, 10*time.Second), 45*time.Second)
}

func resolverRequestTimeout(packetTimeout time.Duration, checkInterval time.Duration, window time.Duration) time.Duration {
	timeout := packetTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if checkInterval > 0 && checkInterval < timeout {
		timeout = checkInterval
	}
	if window > 0 && window < timeout {
		timeout = window
	}
	return max(timeout, 500*time.Millisecond)
}

func resolverLateResponseGrace(requestTimeout time.Duration, ttl time.Duration) time.Duration {
	if requestTimeout <= 0 {
		requestTimeout = 5 * time.Second
	}
	grace := max(requestTimeout*3, time.Second)
	if ttl > 0 && grace > ttl {
		grace = ttl
	}
	return grace
}

func autoDisableMinObservations(active int, window time.Duration) int {
	var base int
	switch {
	case active <= 3:
		return 1000000
	case active <= 5:
		base = 48
	case active <= 8:
		base = 40
	case active <= 10:
		base = 34
	case active <= 15:
		base = 26
	case active <= 20:
		base = 22
	case active <= 30:
		base = 18
	case active <= 40:
		base = 15
	case active <= 50:
		base = 13
	case active <= 75:
		base = 10
	case active <= 100:
		base = 8
	case active <= 150:
		base = 7
	default:
		base = 6
	}
	switch {
	case window >= 60*time.Second:
		return base * 3
	case window >= 30*time.Second:
		return base * 2
	default:
		return base
	}
}

func autoDisableCheckInterval(active int, window time.Duration) time.Duration {
	interval := window / 30
	if interval <= 0 {
		interval = 3 * time.Second
	}
	interval = max(interval, time.Second)
	maxInterval := 5 * time.Second
	if window >= 60*time.Second {
		maxInterval = 12 * time.Second
	} else if window >= 30*time.Second {
		maxInterval = 8 * time.Second
	}
	interval = min(interval, maxInterval)
	var floor time.Duration
	switch {
	case active <= 5:
		floor = 5 * time.Second
	case active <= 8:
		floor = 4500 * time.Millisecond
	case active <= 10:
		floor = 4 * time.Second
	case active <= 15:
		floor = 3500 * time.Millisecond
	case active <= 20:
		floor = 3 * time.Second
	case active <= 30:
		floor = 2500 * time.Millisecond
	case active <= 50:
		floor = 2 * time.Second
	case active <= 75:
		floor = 1500 * time.Millisecond
	}
	return max(interval, floor)
}

func (s *connectionStats) ensureWindowLocked(now time.Time, window time.Duration) {
	if window <= 0 {
		s.windowStartedAt.CompareAndSwap(0, now.UnixNano())
		return
	}
	nowUnix := now.UnixNano()
	startedAt := s.windowStartedAt.Load()
	if startedAt == 0 || nowUnix-startedAt >= window.Nanoseconds() {
		if s.windowStartedAt.CompareAndSwap(startedAt, nowUnix) {
			s.windowSent.Store(0)
			s.windowLost.Store(0)
		}
	}
}

func (s *connectionStats) recordWindowSend(now time.Time, window time.Duration) {
	s.windowAccess.Lock()
	s.ensureWindowLocked(now, window)
	s.windowSent.Add(1)
	s.windowAccess.Unlock()
}

func (s *connectionStats) recordWindowTimeout(now time.Time, window time.Duration) (timedOut uint32, sent uint32) {
	s.windowAccess.Lock()
	defer s.windowAccess.Unlock()
	s.ensureWindowLocked(now, window)
	return s.windowLost.Add(1), s.windowSent.Load()
}

func (s *connectionStats) retractWindowTimeout(now time.Time, window time.Duration) {
	s.windowAccess.Lock()
	defer s.windowAccess.Unlock()
	s.ensureWindowLocked(now, window)
	if lost := s.windowLost.Load(); lost > 0 {
		s.windowLost.Store(lost - 1)
	}
}

func (s *connectionStats) resetWindow() {
	s.windowAccess.Lock()
	s.windowStartedAt.Store(0)
	s.windowSent.Store(0)
	s.windowLost.Store(0)
	s.windowAccess.Unlock()
}

func (s *connectionStats) applyHalfLife() {
	if s.sent.Load() <= statsHalfLifeThreshold &&
		s.acked.Load() <= statsHalfLifeThreshold &&
		s.lost.Load() <= statsHalfLifeThreshold &&
		s.rttCount.Load() <= statsHalfLifeThreshold {
		return
	}
	if !s.halfLifeRunning.CompareAndSwap(false, true) {
		return
	}
	defer s.halfLifeRunning.Store(false)
	for _, counter := range []*atomic.Uint64{&s.sent, &s.acked, &s.lost, &s.rttMicrosSum, &s.rttCount} {
		for {
			current := counter.Load()
			if current == 0 || counter.CompareAndSwap(current, current/2) {
				break
			}
		}
	}
}
