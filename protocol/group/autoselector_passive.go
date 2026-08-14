package group

import (
	"context"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/publicsuffix"
)

const (
	// How long a connection outcome takes to lose half its weight.
	passiveHalfLife = time.Minute
	// Recent failures that make a member suspect, once they also outnumber its recent answers.
	passiveSuspectFailures = 3
	passiveReplyTimeout    = 3 * time.Second
	// A slower first byte is a server holding the request open, not the member's latency.
	passiveFirstByteCeiling = 10 * time.Second
	// The least weight a first-byte sample gets, so a burst of connections still moves the average.
	passiveMinWeight = 0.05
	// Real traffic stands in for a member's round probes for up to this many intervals.
	passiveProbeStretch = 3

	defaultAutoSiteMemory = time.Hour
	maxRememberedSites    = 4096
	sitePruneInterval     = time.Minute
)

// passiveSuspectBackoff is how long a suspect member is held out of the selection. Each repeat takes the next step,
// and a member that stays clear of suspicion for the longest step starts over.
var passiveSuspectBackoff = []time.Duration{
	1 * time.Minute,
	2 * time.Minute,
	4 * time.Minute,
	8 * time.Minute,
	16 * time.Minute,
}

// decayed is a count whose every unit loses half its weight per passiveHalfLife.
type decayed struct {
	value float64
	at    time.Time
}

func (d decayed) valueAt(now time.Time) float64 {
	if d.value == 0 || !now.After(d.at) {
		return d.value
	}
	return d.value * math.Exp2(-float64(now.Sub(d.at))/float64(passiveHalfLife))
}

func (d *decayed) add(now time.Time) {
	d.value = d.valueAt(now) + 1
	d.at = now
}

// passiveHealth is what real connections say about a member. Guarded by AutoSelector.access.
type passiveHealth struct {
	answered     int
	failed       int
	recentOK     decayed
	recentFail   decayed
	lastAnswered time.Time
	lastFailed   time.Time

	// A time-weighted moving average: a sample weighs more the longer it has been since the previous one, so a
	// burst of connections counts about as much as one, and an average left alone gives way to the next sample.
	firstByte   time.Duration
	firstByteAt time.Time

	suspectAt    time.Time
	suspectUntil time.Time
	suspectStep  int
}

func (p *passiveHealth) noteAnswered(firstByte time.Duration, now time.Time) {
	p.answered++
	p.lastAnswered = now
	p.recentOK.add(now)
	if firstByte > passiveFirstByteCeiling {
		return
	}
	if p.firstByteAt.IsZero() {
		p.firstByte = firstByte
	} else {
		weight := max(1-math.Exp2(-float64(now.Sub(p.firstByteAt))/float64(passiveHalfLife)), passiveMinWeight)
		p.firstByte += time.Duration(weight * float64(firstByte-p.firstByte))
	}
	p.firstByteAt = now
}

// noteFailed records a failure, counting it towards suspicion only when counted, and reports whether the member
// just turned suspect.
func (p *passiveHealth) noteFailed(now time.Time, counted bool) bool {
	p.failed++
	p.lastFailed = now
	if !counted {
		return false
	}
	p.recentFail.add(now)
	if p.suspect(now) {
		return false
	}
	failures := p.recentFail.valueAt(now)
	if failures < passiveSuspectFailures || failures < p.recentOK.valueAt(now) {
		return false
	}
	if now.Sub(p.suspectUntil) > passiveSuspectBackoff[len(passiveSuspectBackoff)-1] {
		p.suspectStep = 0
	}
	p.suspectAt = now
	p.suspectUntil = now.Add(passiveSuspectBackoff[p.suspectStep])
	if p.suspectStep < len(passiveSuspectBackoff)-1 {
		p.suspectStep++
	}
	return true
}

func (p *passiveHealth) suspect(now time.Time) bool {
	return now.Before(p.suspectUntil)
}

// fresh reports whether the member answered a real connection within the window, with nothing failing since. A
// failure on the same clock tick wins: Windows clocks tick coarsely enough for the two to tie.
func (p *passiveHealth) fresh(now time.Time, window time.Duration) bool {
	return !p.lastAnswered.IsZero() && now.Sub(p.lastAnswered) < window && p.lastAnswered.After(p.lastFailed) && !p.suspect(now)
}

// recent rounds the decayed counts for display.
func (p *passiveHealth) recent(now time.Time) (answered int, failed int) {
	return int(math.Round(p.recentOK.valueAt(now))), int(math.Round(p.recentFail.valueAt(now)))
}

// rollbackSince forgets the failures a local outage caused. The decayed count cannot be split by time, so it goes
// whole; a suspicion raised since is lifted and does not count as a repeat.
func (p *passiveHealth) rollbackSince(since time.Time) {
	if p.lastFailed.Before(since) {
		return
	}
	p.recentFail = decayed{}
	if !p.suspectAt.IsZero() && !p.suspectAt.Before(since) {
		p.suspectAt = time.Time{}
		p.suspectUntil = time.Time{}
		if p.suspectStep > 0 {
			p.suspectStep--
		}
	}
}

// siteRecord is what the group remembers about one site: the member that last answered it, and when each member
// that failed it did.
type siteRecord struct {
	member   string
	answered time.Time
	failed   map[string]time.Time
}

func (r *siteRecord) expired(now time.Time, memory time.Duration) bool {
	if r.member != "" && now.Sub(r.answered) < memory {
		return false
	}
	for _, at := range r.failed {
		if now.Sub(at) < memory {
			return false
		}
	}
	return true
}

// siteOf names what a connection is for: the registrable domain when there is a name, the address otherwise.
func siteOf(ctx context.Context, destination M.Socksaddr) string {
	var domain string
	if destination.IsFqdn() {
		domain = destination.Fqdn
	} else if metadata := adapter.ContextFrom(ctx); metadata != nil {
		domain = metadata.Domain
	}
	if domain == "" {
		if destination.IsIP() {
			return destination.Addr.Unmap().String()
		}
		return ""
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if site, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
		return site
	}
	return domain
}

// notePassive records how a connection on tag went. It must not be called with s.access held: an interrupt closes
// connections under it, which is why the close path reports from a goroutine of its own.
func (s *AutoSelector) notePassive(tag string, site string, firstByte time.Duration, failed bool) {
	now := time.Now()
	s.access.Lock()
	defer s.access.Unlock()
	health, loaded := s.members[tag]
	if !loaded {
		return
	}
	if !failed {
		health.passive.noteAnswered(firstByte, now)
		if site != "" {
			s.rememberSiteLocked(site, tag, now)
		}
		return
	}
	if s.suspended {
		return
	}
	if s.notePassiveFailureLocked(health, site, now) {
		s.evaluateLocked(now)
	}
}

// notePassiveFailureLocked reports whether the failure made the member suspect.
func (s *AutoSelector) notePassiveFailureLocked(health *memberHealth, site string, now time.Time) bool {
	counted := site == "" || s.avoidSiteLocked(site, health.tag, now)
	if !health.passive.noteFailed(now, counted) {
		return false
	}
	// Moving back up to it waits out the fail-back gate, as after any failure.
	health.noteFailure(now)
	s.logger.Info("auto-selector: ", health.tag, " fails most real connections, held out for ", health.passive.suspectUntil.Sub(now))
	return true
}

// rememberSiteLocked notes that tag answered site: the site keeps it, and stops avoiding it.
func (s *AutoSelector) rememberSiteLocked(site string, tag string, now time.Time) {
	record := s.siteRecordLocked(site, now)
	if record == nil {
		return
	}
	record.member = tag
	record.answered = now
	delete(record.failed, tag)
}

// avoidSiteLocked notes that tag failed site, and reports whether that is news: a site failing again on the same
// member is the same problem, so it counts against the member once per memory window.
func (s *AutoSelector) avoidSiteLocked(site string, tag string, now time.Time) bool {
	record := s.siteRecordLocked(site, now)
	if record == nil {
		return true
	}
	if record.member == tag {
		record.member = ""
	}
	if record.failed == nil {
		record.failed = make(map[string]time.Time)
	}
	at, loaded := record.failed[tag]
	record.failed[tag] = now
	return !loaded || now.Sub(at) >= s.siteMemory
}

// siteRecordLocked returns the site's record, making one when there is room. Expired records are dropped only once
// the table is full, and at most once per sitePruneInterval.
func (s *AutoSelector) siteRecordLocked(site string, now time.Time) *siteRecord {
	if record, loaded := s.sites[site]; loaded {
		return record
	}
	if len(s.sites) >= maxRememberedSites {
		if now.Sub(s.sitesPrunedAt) < sitePruneInterval {
			return nil
		}
		s.sitesPrunedAt = now
		for name, record := range s.sites {
			if record.expired(now, s.siteMemory) {
				delete(s.sites, name)
			}
		}
		if len(s.sites) >= maxRememberedSites {
			return nil
		}
	}
	record := &siteRecord{}
	s.sites[site] = record
	return record
}

// steerSiteLocked moves a dial off a routine pick that already failed its site: to the member that last answered
// the site, else to the best ranked healthy member the site has not failed on. Nil keeps the routine pick.
func (s *AutoSelector) steerSiteLocked(network string, site string, routine adapter.Outbound, tried map[string]bool, now time.Time) adapter.Outbound {
	record := s.sites[site]
	if record == nil {
		return nil
	}
	avoid := make(map[string]bool, len(record.failed))
	for tag, at := range record.failed {
		if now.Sub(at) < s.siteMemory {
			avoid[tag] = true
		}
	}
	if !avoid[routine.Tag()] {
		return nil
	}
	var remembered string
	if record.member != "" && now.Sub(record.answered) < s.siteMemory {
		remembered = record.member
	}
	var fallback adapter.Outbound
	for _, node := range s.ranked {
		if avoid[node.tag] || node.tier != tierHealthy || node.suspect {
			continue
		}
		detour := s.usableLocked(node.tag, network, tried, now, false)
		if detour == nil {
			continue
		}
		if node.tag == remembered {
			return detour
		}
		if fallback == nil {
			fallback = detour
		}
	}
	return fallback
}

// rollbackPassiveLocked undoes what a local outage did to the passive record.
func (s *AutoSelector) rollbackPassiveLocked(since time.Time) {
	for _, health := range s.members {
		health.passive.rollbackSince(since)
	}
	for _, record := range s.sites {
		for tag, at := range record.failed {
			if !at.Before(since) {
				delete(record.failed, tag)
			}
		}
	}
}

// serving reports whether the member answered real traffic within the watch interval, with nothing failing since.
func (s *AutoSelector) serving(tag string) bool {
	if !s.passive {
		return false
	}
	s.access.Lock()
	defer s.access.Unlock()
	health, loaded := s.members[tag]
	return loaded && health.passive.fresh(time.Now(), s.watchInterval)
}

// passiveCoveredLocked reports whether real traffic stands in for a member's round probe: it answered within the
// interval with nothing failing since, and its last probe is recent enough to keep the ring from running dry.
func (s *AutoSelector) passiveCoveredLocked(tag string, now time.Time) bool {
	if !s.passive {
		return false
	}
	health, loaded := s.members[tag]
	return loaded && health.passive.fresh(now, s.interval) && now.Sub(health.lastProbe) < passiveProbeStretch*s.interval
}

// passiveFlow turns one connection into one outcome: answered at its first byte back, or failed when it closes
// after sending with nothing back. A UDP flow fails when its first reply misses the reply timeout instead, since
// closing one says nothing.
type passiveFlow struct {
	selector *AutoSelector
	tag      string
	site     string
	packet   bool
	openedAt time.Time

	sent    atomic.Bool
	settled atomic.Bool
	access  sync.Mutex
	sentAt  time.Time
	timer   *time.Timer
}

func (s *AutoSelector) newPassiveFlow(tag string, site string, packet bool) *passiveFlow {
	return &passiveFlow{selector: s, tag: tag, site: site, packet: packet, openedAt: time.Now()}
}

func (f *passiveFlow) wrote(int64) {
	if f.sent.Load() {
		return
	}
	f.access.Lock()
	defer f.access.Unlock()
	if f.sent.Load() || f.settled.Load() {
		return
	}
	f.sentAt = time.Now()
	f.sent.Store(true)
	if f.packet {
		f.timer = time.AfterFunc(f.selector.replyTimeout, f.unanswered)
	}
}

func (f *passiveFlow) read(int64) {
	if f.settled.Load() {
		return
	}
	f.access.Lock()
	if !f.settleLocked() {
		f.access.Unlock()
		return
	}
	start := f.sentAt
	if start.IsZero() {
		// The server spoke first.
		start = f.openedAt
	}
	f.access.Unlock()
	f.selector.notePassive(f.tag, f.site, time.Since(start), false)
}

func (f *passiveFlow) unanswered() {
	f.access.Lock()
	settled := f.settleLocked()
	f.access.Unlock()
	if settled {
		f.selector.notePassive(f.tag, f.site, 0, true)
	}
}

func (f *passiveFlow) closed() {
	if f.settled.Load() {
		return
	}
	f.access.Lock()
	failed := f.settleLocked() && !f.packet && !f.sentAt.IsZero() && !f.selector.interrupting.Load()
	f.access.Unlock()
	if failed {
		go f.selector.notePassive(f.tag, f.site, 0, true)
	}
}

// settleLocked claims the flow's one outcome.
func (f *passiveFlow) settleLocked() bool {
	if f.settled.Load() {
		return false
	}
	f.settled.Store(true)
	if f.timer != nil {
		f.timer.Stop()
	}
	return true
}

// passiveConn watches a connection through counters, so the copy loop still reads and writes the connection
// underneath directly.
type passiveConn struct {
	*bufio.CounterConn
	flow *passiveFlow
}

func (s *AutoSelector) passiveConn(conn net.Conn, tag string, site string, packet bool) net.Conn {
	flow := s.newPassiveFlow(tag, site, packet)
	return &passiveConn{bufio.NewCounterConn(conn, []N.CountFunc{flow.read}, []N.CountFunc{flow.wrote}), flow}
}

func (c *passiveConn) Close() error {
	c.flow.closed()
	return c.CounterConn.Close()
}

type passivePacketConn struct {
	N.NetPacketConn
	flow *passiveFlow
}

func (s *AutoSelector) passivePacketConn(conn net.PacketConn, tag string, site string) net.PacketConn {
	return &passivePacketConn{bufio.NewPacketConn(conn), s.newPassiveFlow(tag, site, true)}
}

func (c *passivePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.NetPacketConn.ReadFrom(p)
	if n > 0 {
		c.flow.read(int64(n))
	}
	return
}

func (c *passivePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.NetPacketConn.WriteTo(p, addr)
	if n > 0 {
		c.flow.wrote(int64(n))
	}
	return
}

func (c *passivePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.NetPacketConn.ReadPacket(buffer)
	if err == nil && buffer.Len() > 0 {
		c.flow.read(int64(buffer.Len()))
	}
	return destination, err
}

func (c *passivePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	dataLen := buffer.Len()
	err := c.NetPacketConn.WritePacket(buffer, destination)
	if err == nil && dataLen > 0 {
		c.flow.wrote(int64(dataLen))
	}
	return err
}

func (c *passivePacketConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	return c.NetPacketConn, []N.CountFunc{c.flow.read}
}

func (c *passivePacketConn) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	return c.NetPacketConn, []N.CountFunc{c.flow.wrote}
}

func (c *passivePacketConn) Upstream() any {
	return c.NetPacketConn
}

func (c *passivePacketConn) Close() error {
	c.flow.closed()
	return c.NetPacketConn.Close()
}
