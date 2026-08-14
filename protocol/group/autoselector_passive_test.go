package group

import (
	"context"
	"io"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func passiveSelector(t *testing.T, members ...string) *AutoSelector {
	t.Helper()
	s := dialSelector(members...)
	s.strategy = StrategyLatency
	s.sampling = 10
	s.activeSize = len(members)
	s.expected = 3
	s.failTolerance = defaultAutoFailTolerance
	s.tolerance = defaultAutoTolerance * time.Millisecond
	s.interval = time.Minute
	s.watchInterval = 15 * time.Second
	s.passive = true
	s.siteMemory = time.Hour
	s.replyTimeout = 20 * time.Millisecond
	s.sites = make(map[string]*siteRecord)
	s.interruptGroup = interrupt.NewGroup()
	s.attachedGroup = interrupt.NewGroup()
	s.logger = logger.NOP()
	return s
}

func waitFor(t *testing.T, s *AutoSelector, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.access.Lock()
		met := condition()
		s.access.Unlock()
		if met {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDecayedHalvesEveryHalfLife(t *testing.T) {
	now := time.Now()
	var d decayed
	d.add(now)
	d.add(now)
	if got := d.valueAt(now.Add(passiveHalfLife)); math.Abs(got-1) > 1e-9 {
		t.Fatalf("after one half-life = %v, want 1", got)
	}
	if got := d.valueAt(now.Add(-time.Second)); got != 2 {
		t.Fatalf("before the last update = %v, want 2", got)
	}
}

func TestFirstByteAverageWeighsByTime(t *testing.T) {
	now := time.Now()
	var p passiveHealth
	p.noteAnswered(100*time.Millisecond, now)
	// A burst barely moves it: the second sample lands at the same instant.
	p.noteAnswered(500*time.Millisecond, now)
	if p.firstByte != 120*time.Millisecond {
		t.Fatalf("after a burst = %v, want 120ms", p.firstByte)
	}
	// After a long quiet spell the next sample all but replaces it.
	p.noteAnswered(500*time.Millisecond, now.Add(10*passiveHalfLife))
	if p.firstByte < 499*time.Millisecond {
		t.Fatalf("after a quiet spell = %v, want about 500ms", p.firstByte)
	}
	// A server holding the request open is an answer, not a latency.
	p.noteAnswered(time.Minute, now.Add(11*passiveHalfLife))
	if p.firstByte > 500*time.Millisecond || p.answered != 4 {
		t.Fatalf("after a held request = %v (%d answered), want the average kept", p.firstByte, p.answered)
	}
}

func TestSuspectNeedsFailuresToOutnumberAnswers(t *testing.T) {
	now := time.Now()
	var p passiveHealth
	if p.noteFailed(now, true) || p.noteFailed(now, true) {
		t.Fatal("two failures are not enough")
	}
	if !p.noteFailed(now, true) || !p.suspect(now) || !p.suspectUntil.Equal(now.Add(passiveSuspectBackoff[0])) {
		t.Fatalf("after three failures suspect until %v, want %v", p.suspectUntil, now.Add(passiveSuspectBackoff[0]))
	}

	var busy passiveHealth
	for range 5 {
		busy.noteAnswered(50*time.Millisecond, now)
	}
	for range 4 {
		if busy.noteFailed(now, true) {
			t.Fatal("a member answering more than it fails is not suspect")
		}
	}
	if !busy.noteFailed(now, true) {
		t.Fatal("failures matching the answers make it suspect")
	}

	var repeated passiveHealth
	for range 10 {
		if repeated.noteFailed(now, false) {
			t.Fatal("uncounted failures cannot make a member suspect")
		}
	}
	if repeated.failed != 10 || repeated.recentFail.valueAt(now) != 0 {
		t.Fatalf("failed = %d, recent = %v; want every failure listed and none counted", repeated.failed, repeated.recentFail.valueAt(now))
	}
}

func TestSuspectHoldOutDoublesOnRepeat(t *testing.T) {
	var p passiveHealth
	heldOutAt := func(at time.Time) time.Duration {
		t.Helper()
		for range 10 {
			if p.noteFailed(at, true) {
				return p.suspectUntil.Sub(at)
			}
		}
		t.Fatalf("still not suspect at %v", at)
		return 0
	}
	if got := heldOutAt(time.Now()); got != passiveSuspectBackoff[0] {
		t.Fatalf("first hold-out = %v, want %v", got, passiveSuspectBackoff[0])
	}
	// Back from the first hold-out with half its failures still on record: two more repeat it, for twice as long.
	at := p.suspectUntil.Add(time.Second)
	if p.noteFailed(at, true) {
		t.Fatal("one failure on top of the decayed ones is not enough yet")
	}
	if !p.noteFailed(at, true) || !p.suspectUntil.Equal(at.Add(passiveSuspectBackoff[1])) {
		t.Fatalf("repeat suspect until %v, want %v", p.suspectUntil, at.Add(passiveSuspectBackoff[1]))
	}
	for i := 2; i < len(passiveSuspectBackoff)+2; i++ {
		want := passiveSuspectBackoff[min(i, len(passiveSuspectBackoff)-1)]
		if got := heldOutAt(p.suspectUntil.Add(time.Second)); got != want {
			t.Fatalf("repeat %d held out for %v, want %v", i, got, want)
		}
	}
	// A member clear of suspicion for the longest step starts over.
	if got := heldOutAt(p.suspectUntil.Add(passiveSuspectBackoff[len(passiveSuspectBackoff)-1] + time.Second)); got != passiveSuspectBackoff[0] {
		t.Fatalf("after a long clean spell held out for %v, want %v", got, passiveSuspectBackoff[0])
	}
}

func TestSiteFailureCountsOncePerMember(t *testing.T) {
	s := passiveSelector(t, "a", "b")
	now := time.Now()
	if !s.avoidSiteLocked("example.com", "a", now) {
		t.Fatal("a first failure counts")
	}
	if s.avoidSiteLocked("example.com", "a", now.Add(time.Minute)) {
		t.Fatal("the same site failing again on the same member counts once")
	}
	if !s.avoidSiteLocked("example.com", "b", now) {
		t.Fatal("another member failing the site counts")
	}
	if !s.avoidSiteLocked("example.com", "a", now.Add(time.Minute+s.siteMemory)) {
		t.Fatal("a failure after the memory window counts again")
	}
	s.rememberSiteLocked("example.com", "a", now)
	if record := s.sites["example.com"]; record.member != "a" || record.failed["a"] != (time.Time{}) {
		t.Fatalf("record = %+v, want a remembered and no longer avoided", record)
	}
}

func TestPassiveSuspectLosesTheSelection(t *testing.T) {
	now := time.Now()
	s := passiveSelector(t, "a", "b")
	fill(s.members["a"], now, 50*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond)
	fill(s.members["b"], now, 80*time.Millisecond, 80*time.Millisecond, 80*time.Millisecond)
	s.evaluateLocked(now)
	if got := selectedTag(s); got != "a" {
		t.Fatalf("selected = %q, want a", got)
	}

	// One site failing over and over is one problem.
	for range 5 {
		s.notePassive("a", "one.example", 0, true)
	}
	if got := selectedTag(s); got != "a" {
		t.Fatalf("after one failing site selected = %q, want a", got)
	}
	s.notePassive("a", "two.example", 0, true)
	s.notePassive("a", "three.example", 0, true)
	if got := selectedTag(s); got != "b" {
		t.Fatalf("after three failing sites selected = %q, want b", got)
	}
	if s.ranked[len(s.ranked)-1].tag != "a" || s.members["a"].lastFailure.IsZero() {
		t.Fatal("a suspect member ranks last among the healthy, and counts as failed for fail-back")
	}
	status := s.Status()
	for _, member := range status.Members {
		if member.Tag != "a" {
			continue
		}
		if member.State != "suspect" || member.SuspectUntil.IsZero() || member.PassiveFailed != 7 || member.RecentFailed != 3 {
			t.Fatalf("status = %+v, want suspect with 7 failures, 3 of them counted", member)
		}
	}
	if !status.Passive || status.SitesRemembered != 0 {
		t.Fatalf("status passive = %v, sites = %d", status.Passive, status.SitesRemembered)
	}

	// Pinned or not, a suspect member is not used while there is another.
	s.pinnedTag = "a"
	s.evaluateLocked(time.Now())
	if got := selectedTag(s); got != "b" {
		t.Fatalf("pinned to a suspect member, selected = %q, want b", got)
	}
}

func TestPassiveSiteSteersOffAMemberThatFailedIt(t *testing.T) {
	now := time.Now()
	s := passiveSelector(t, "a", "b", "c")
	fill(s.members["a"], now, 50*time.Millisecond, 50*time.Millisecond)
	fill(s.members["b"], now, 80*time.Millisecond, 80*time.Millisecond)
	fill(s.members["c"], now, 90*time.Millisecond, 90*time.Millisecond)
	s.evaluateLocked(now)

	pick := func(site string) (string, bool) {
		detour, steered := s.pick(N.NetworkTCP, site, map[string]bool{})
		if detour == nil {
			return "", steered
		}
		return detour.Tag(), steered
	}
	s.avoidSiteLocked("blocked.example", "a", now)
	// Nothing has answered the site yet: the best member it has not failed on.
	if tag, steered := pick("blocked.example"); tag != "b" || !steered {
		t.Fatalf("pick = %s (steered %v), want b steered", tag, steered)
	}
	s.rememberSiteLocked("blocked.example", "c", now)
	if tag, steered := pick("blocked.example"); tag != "c" || !steered {
		t.Fatalf("pick = %s (steered %v), want the member that answered", tag, steered)
	}
	if tag, steered := pick("other.example"); tag != "a" || steered {
		t.Fatalf("other site pick = %s (steered %v), want the selection", tag, steered)
	}
	// A remembered member cooling down is passed over.
	s.members["c"].penalize(now, dialBackoff, nil)
	if tag, _ := pick("blocked.example"); tag != "b" {
		t.Fatalf("pick = %s, want b while c cools down", tag)
	}
	// Once every member has failed the site, the routine pick stands.
	s.avoidSiteLocked("blocked.example", "b", now)
	s.avoidSiteLocked("blocked.example", "c", now)
	if tag, steered := pick("blocked.example"); tag != "a" || steered {
		t.Fatalf("pick = %s (steered %v), want the selection", tag, steered)
	}
}

func TestSteeredDialSuccessKeepsTheSelection(t *testing.T) {
	now := time.Now()
	s := passiveSelector(t, "a", "b")
	fill(s.members["a"], now, 50*time.Millisecond, 50*time.Millisecond)
	fill(s.members["b"], now, 80*time.Millisecond, 80*time.Millisecond)
	s.evaluateLocked(now)
	s.started = true
	live := &closeFlag{}
	s.interruptGroup.Add(live, false)

	s.noteDialResult(s.outbounds["b"], N.NetworkTCP, "steered.example", true, nil)
	if got := selectedTag(s); got != "a" || live.closed {
		t.Fatalf("after a steered dial selected = %q, interrupted = %v; want a, untouched", got, live.closed)
	}
	s.noteDialResult(s.outbounds["b"], N.NetworkTCP, "", false, nil)
	if got := selectedTag(s); got != "b" || !live.closed {
		t.Fatalf("after a failover selected = %q, interrupted = %v; want b, interrupted", got, live.closed)
	}

	// A balanced pick is steered too, so it promotes nothing either.
	s.balance = true
	s.balanceMode = BalanceModeConnection
	if _, steered := s.pick(N.NetworkTCP, "", map[string]bool{}); !steered {
		t.Fatal("a balanced pick must be steered")
	}
}

func TestPassiveFlowOutcomes(t *testing.T) {
	s := passiveSelector(t, "a")
	health := s.members["a"]

	flow := s.newPassiveFlow("a", "one.example", false)
	flow.wrote(10)
	flow.read(20)
	flow.read(20)
	flow.closed()
	if health.passive.answered != 1 || health.passive.failed != 0 || s.sites["one.example"].member != "a" {
		t.Fatalf("answered = %d, failed = %d; want one answer remembered for the site", health.passive.answered, health.passive.failed)
	}

	// Sent and closed with nothing back.
	flow = s.newPassiveFlow("a", "two.example", false)
	flow.wrote(10)
	flow.closed()
	waitFor(t, s, func() bool { return health.passive.failed == 1 })

	// Closed before sending anything, or by the selector itself: no outcome.
	s.newPassiveFlow("a", "three.example", false).closed()
	flow = s.newPassiveFlow("a", "three.example", false)
	flow.wrote(10)
	s.interrupting.Store(true)
	flow.closed()
	s.interrupting.Store(false)

	// UDP: a flow left unanswered fails on its own; closing one says nothing.
	flow = s.newPassiveFlow("a", "four.example", true)
	flow.wrote(10)
	waitFor(t, s, func() bool { return health.passive.failed == 2 })
	flow = s.newPassiveFlow("a", "five.example", true)
	flow.wrote(10)
	flow.read(10)
	flow.closed()
	flow = s.newPassiveFlow("a", "six.example", true)
	flow.wrote(10)
	flow.closed()
	time.Sleep(3 * s.replyTimeout)
	s.access.Lock()
	defer s.access.Unlock()
	if health.passive.answered != 2 || health.passive.failed != 2 {
		t.Fatalf("answered = %d, failed = %d; want 2 and 2", health.passive.answered, health.passive.failed)
	}
}

func TestPassiveConnsKeepTheCopyPathDirect(t *testing.T) {
	s := passiveSelector(t, "a")
	client, server := net.Pipe()
	defer server.Close()
	conn := s.interruptGroup.NewConn(s.passiveConn(client, "a", "pipe.example", false), true)
	reader, readCounters := N.UnwrapCountReader(conn, nil)
	writer, writeCounters := N.UnwrapCountWriter(conn, nil)
	if reader == io.Reader(conn) || writer == io.Writer(conn) || len(readCounters) != 1 || len(writeCounters) != 1 {
		t.Fatalf("unwrapped to %T/%T with %d/%d counters, want the inner conn with one each", reader, writer, len(readCounters), len(writeCounters))
	}
	go func() {
		request := make([]byte, 4)
		_, _ = io.ReadFull(server, request)
		_, _ = server.Write([]byte("pong"))
	}()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if health := s.members["a"]; health.passive.answered != 1 || health.passive.failed != 0 {
		t.Fatalf("answered = %d, failed = %d; want one answer", health.passive.answered, health.passive.failed)
	}

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packetConn := s.interruptGroup.NewPacketConn(s.passivePacketConn(udp, "a", ""), true).(N.NetPacketConn)
	defer packetConn.Close()
	if _, counters := N.UnwrapCountPacketReader(packetConn, nil); len(counters) != 1 {
		t.Fatalf("packet reader has %d counters, want 1", len(counters))
	}
	if _, counters := N.UnwrapCountPacketWriter(packetConn, nil); len(counters) != 1 {
		t.Fatalf("packet writer has %d counters, want 1", len(counters))
	}
}

func TestPassiveTrafficStandsInForProbes(t *testing.T) {
	now := time.Now()
	s := passiveSelector(t, "a", "b")
	fill(s.members["a"], now, 50*time.Millisecond, 50*time.Millisecond)
	fill(s.members["b"], now, 80*time.Millisecond, 80*time.Millisecond)
	s.evaluateLocked(now)
	if s.serving("a") {
		t.Fatal("no traffic yet")
	}
	s.members["a"].passive.noteAnswered(40*time.Millisecond, time.Now())
	if !s.serving("a") {
		t.Fatal("an answer within the watch interval stands in for the watch probe")
	}
	if batch := s.roundBatch(false); len(batch) != 1 || batch[0] != "b" {
		t.Fatalf("batch = %v, want only b", batch)
	}
	if batch := s.roundBatch(true); len(batch) != 2 {
		t.Fatalf("urgent batch = %v, want every active member", batch)
	}
	// However busy, a member is probed every few intervals so its ring keeps real samples.
	s.members["a"].lastProbe = time.Now().Add(-passiveProbeStretch * s.interval)
	if batch := s.roundBatch(false); len(batch) != 2 {
		t.Fatalf("batch = %v, want a probed again", batch)
	}
	s.members["a"].lastProbe = time.Now()
	s.members["a"].passive.noteFailed(time.Now(), false)
	if s.serving("a") || len(s.roundBatch(false)) != 2 {
		t.Fatal("a failure since the last answer means the traffic no longer vouches for it")
	}
}

func TestOutageRollbackForgetsPassiveFailures(t *testing.T) {
	s := passiveSelector(t, "a")
	since := time.Now()
	s.avoidSiteLocked("old.example", "a", since.Add(-time.Minute))
	for range 3 {
		s.members["a"].passive.noteFailed(since.Add(time.Second), true)
	}
	s.avoidSiteLocked("new.example", "a", since.Add(time.Second))
	s.rollbackPassiveLocked(since)
	p := s.members["a"].passive
	if p.suspect(since.Add(2*time.Second)) || p.suspectStep != 0 || p.recentFail.valueAt(since) != 0 {
		t.Fatalf("after rollback suspect until %v, step %d; want neither", p.suspectUntil, p.suspectStep)
	}
	if _, kept := s.sites["old.example"].failed["a"]; !kept {
		t.Fatal("a site failure from before the outage stays")
	}
	if _, kept := s.sites["new.example"].failed["a"]; kept {
		t.Fatal("a site failure during the outage goes")
	}

	// While suspended, failing connections are the local network's.
	s.suspended = true
	failed := s.members["a"].passive.failed
	for _, site := range []string{"x.example", "y.example", "z.example"} {
		s.notePassive("a", site, 0, true)
	}
	if p := s.members["a"].passive; p.failed != failed || p.suspect(time.Now()) {
		t.Fatalf("while suspended failed = %d (was %d), suspect = %v; want nothing recorded", p.failed, failed, p.suspect(time.Now()))
	}
}

func TestSiteOf(t *testing.T) {
	sniffed := adapter.WithContext(context.Background(), &adapter.InboundContext{Domain: "api.GitHub.com"})
	for _, test := range []struct {
		ctx         context.Context
		destination M.Socksaddr
		want        string
	}{
		{context.Background(), M.Socksaddr{Fqdn: "WWW.Example.co.uk", Port: 443}, "example.co.uk"},
		{sniffed, M.SocksaddrFrom(netip.MustParseAddr("192.0.2.1"), 443), "github.com"},
		{context.Background(), M.SocksaddrFrom(netip.MustParseAddr("::ffff:192.0.2.1"), 53), "192.0.2.1"},
		{context.Background(), M.Socksaddr{Fqdn: "router", Port: 80}, "router"},
	} {
		if got := siteOf(test.ctx, test.destination); got != test.want {
			t.Fatalf("siteOf(%s) = %q, want %q", test.destination, got, test.want)
		}
	}
}

func TestNewAutoSelectorPassiveOptions(t *testing.T) {
	newSelector := func(passive *option.AutoSelectorPassiveOptions) *AutoSelector {
		detour, err := NewAutoSelector(context.Background(), nil, logger.NOP(), "auto", option.AutoSelectorOutboundOptions{
			Outbounds: []string{"a"},
			Passive:   passive,
		})
		if err != nil {
			t.Fatal(err)
		}
		return detour.(*AutoSelector)
	}
	if s := newSelector(nil); s.passive || s.sites != nil {
		t.Fatal("passive scoring is off by default")
	}
	if s := newSelector(&option.AutoSelectorPassiveOptions{}); s.passive {
		t.Fatal("passive scoring needs enabled")
	}
	s := newSelector(&option.AutoSelectorPassiveOptions{Enabled: true})
	if !s.passive || s.sites == nil || s.siteMemory != defaultAutoSiteMemory || s.replyTimeout != passiveReplyTimeout {
		t.Fatalf("defaults = %v/%v/%v", s.passive, s.siteMemory, s.replyTimeout)
	}
	s = newSelector(&option.AutoSelectorPassiveOptions{Enabled: true, SiteMemory: badoption.Duration(10 * time.Minute)})
	if s.siteMemory != 10*time.Minute {
		t.Fatalf("site memory = %v, want 10m", s.siteMemory)
	}
}
