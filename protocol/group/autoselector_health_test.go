package group

import (
	"errors"

	"github.com/sagernet/sing-box/option"
	"net"
	"syscall"
	"testing"
	"time"
)

func fill(h *memberHealth, now time.Time, values ...time.Duration) {
	for i, value := range values {
		h.put(value, now.Add(time.Duration(i)*time.Millisecond))
	}
}

func TestStatsAveragesOnlySuccesses(t *testing.T) {
	now := time.Now()
	h := newMemberHealth("a", 10, time.Minute)
	fill(h, now, 100*time.Millisecond, rttFailed, 200*time.Millisecond, 300*time.Millisecond)

	stats := h.stats(now)
	if stats.All != 4 {
		t.Fatalf("All = %d, want 4", stats.All)
	}
	if stats.Fail != 1 {
		t.Fatalf("Fail = %d, want 1", stats.Fail)
	}
	if stats.Average != 200*time.Millisecond {
		t.Fatalf("Average = %v, want 200ms", stats.Average)
	}
	if stats.Min != 100*time.Millisecond || stats.Max != 300*time.Millisecond {
		t.Fatalf("Min/Max = %v/%v, want 100ms/300ms", stats.Min, stats.Max)
	}
	if !stats.Alive() {
		t.Fatal("member with successful samples must be alive")
	}
	if stats.FailRatio() != 0.25 {
		t.Fatalf("FailRatio = %v, want 0.25", stats.FailRatio())
	}
}

func TestStatsSingleSampleGetsSyntheticDeviation(t *testing.T) {
	now := time.Now()
	h := newMemberHealth("a", 10, time.Minute)
	fill(h, now, 100*time.Millisecond)

	// A lone sample has zero real deviation, which would let it outrank every
	// well-measured member forever.
	if got := h.stats(now).Deviation; got != 50*time.Millisecond {
		t.Fatalf("Deviation = %v, want 50ms", got)
	}
}

func TestStatsIgnoresExpiredSamples(t *testing.T) {
	now := time.Now()
	h := newMemberHealth("a", 10, time.Minute)
	fill(h, now.Add(-2*time.Minute), 100*time.Millisecond, 100*time.Millisecond)
	fill(h, now, 300*time.Millisecond)

	stats := h.stats(now)
	if stats.All != 1 {
		t.Fatalf("All = %d, want 1 (expired samples must not count)", stats.All)
	}
	if stats.Average != 300*time.Millisecond {
		t.Fatalf("Average = %v, want 300ms", stats.Average)
	}
}

func TestAllFailedMemberIsNotAlive(t *testing.T) {
	now := time.Now()
	h := newMemberHealth("a", 10, time.Minute)
	fill(h, now, rttFailed, rttFailed)

	stats := h.stats(now)
	if stats.Alive() {
		t.Fatal("member with only failures must not be alive")
	}
	// Average stays zero here, which is exactly why tiering must run before the
	// least-load comparators.
	if stats.Average != 0 {
		t.Fatalf("Average = %v, want 0", stats.Average)
	}
}

func TestSortTiersDeadBelowUntested(t *testing.T) {
	healthy := &rankedNode{tag: "healthy", tier: tierHealthy, stats: memberStats{All: 5, Average: 400 * time.Millisecond, Deviation: 40 * time.Millisecond}}
	dead := &rankedNode{tag: "dead", tier: tierDead, stats: memberStats{All: 5, Fail: 5}}
	untested := &rankedNode{tag: "untested", tier: tierUntested}
	cooldown := &rankedNode{tag: "cooldown", tier: tierCooldown}

	nodes := []*rankedNode{dead, cooldown, untested, healthy}
	sortNodes(nodes)

	want := []string{"healthy", "untested", "dead", "cooldown"}
	for i, node := range nodes {
		if node.tag != want[i] {
			t.Fatalf("position %d = %q, want %q (order: %v)", i, node.tag, want[i], tags(nodes))
		}
	}
}

func TestSortPrefersStabilityOverRawSpeed(t *testing.T) {
	jittery := &rankedNode{tag: "jittery", tier: tierHealthy, stats: memberStats{All: 10, Average: 90 * time.Millisecond, Deviation: 200 * time.Millisecond}}
	steady := &rankedNode{tag: "steady", tier: tierHealthy, stats: memberStats{All: 10, Average: 150 * time.Millisecond, Deviation: 10 * time.Millisecond}}

	nodes := []*rankedNode{jittery, steady}
	sortNodes(nodes)
	if nodes[0].tag != "steady" {
		t.Fatalf("first = %q, want steady", nodes[0].tag)
	}
}

func TestApplyBaselinesWalksUntilExpected(t *testing.T) {
	nodes := []*rankedNode{
		{tag: "a", stats: memberStats{Deviation: 10 * time.Millisecond}},
		{tag: "b", stats: memberStats{Deviation: 20 * time.Millisecond}},
		{tag: "c", stats: memberStats{Deviation: 250 * time.Millisecond}},
		{tag: "d", stats: memberStats{Deviation: 900 * time.Millisecond}},
	}
	baselines := []time.Duration{50 * time.Millisecond, 300 * time.Millisecond, time.Second}

	// The first baseline admits a and b; that already meets expected=2.
	if got := tags(applyBaselines(nodes, baselines, 2)); len(got) != 2 {
		t.Fatalf("expected=2 gave %v, want 2 members", got)
	}
	// expected=3 forces the walk on to the next baseline, which admits c.
	if got := tags(applyBaselines(nodes, baselines, 3)); len(got) != 3 {
		t.Fatalf("expected=3 gave %v, want 3 members", got)
	}
	// With no baselines it degrades to a plain top-N cut.
	if got := tags(applyBaselines(nodes, nil, 2)); len(got) != 2 || got[0] != "a" {
		t.Fatalf("no baselines gave %v, want [a b]", got)
	}
}

func TestRollbackClearsOutageFailuresOnly(t *testing.T) {
	now := time.Now()
	h := newMemberHealth("a", 10, time.Hour)
	h.put(100*time.Millisecond, now.Add(-10*time.Minute))
	h.put(rttFailed, now.Add(-10*time.Minute)) // long before the outage
	h.put(rttFailed, now.Add(-5*time.Second))  // during the outage
	h.put(rttFailed, now.Add(-2*time.Second))  // during the outage

	if rolled := h.rollbackFailuresSince(now.Add(-30 * time.Second)); rolled != 2 {
		t.Fatalf("rolled = %d, want 2", rolled)
	}
	stats := h.stats(now)
	if stats.Fail != 1 {
		t.Fatalf("Fail = %d, want 1 (only the pre-outage failure survives)", stats.Fail)
	}
	if !stats.Alive() {
		t.Fatal("member must stay alive after its outage failures are rolled back")
	}
}

func TestCooldownBackoffAndRollback(t *testing.T) {
	now := time.Now()
	h := newMemberHealth("a", 10, time.Hour)

	h.penalize(now, dialBackoff, errors.New("refused"))
	if !h.inCooldown(now.Add(time.Second)) {
		t.Fatal("member must be in cooldown right after a failed dial")
	}
	if h.inCooldown(now.Add(dialBackoff[0] + time.Second)) {
		t.Fatal("first cooldown step must be short")
	}

	h.penalize(now, dialBackoff, errors.New("refused"))
	if !h.inCooldown(now.Add(dialBackoff[0] + time.Second)) {
		t.Fatal("consecutive failures must extend the backoff")
	}

	// An outage detected moments later must undo the penalty entirely.
	if !h.clearCooldownSince(now.Add(-time.Second)) {
		t.Fatal("clearCooldownSince must report a rollback")
	}
	if h.inCooldown(now) || h.cooldownStep != 0 || h.dialFail != 0 {
		t.Fatal("rollback must fully reset the penalty state")
	}
}

func TestCooldownRollbackIgnoresOlderPenalties(t *testing.T) {
	now := time.Now()
	h := newMemberHealth("a", 10, time.Hour)
	h.penalize(now.Add(-5*time.Minute), dialBackoff, errors.New("refused"))

	if h.clearCooldownSince(now.Add(-30 * time.Second)) {
		t.Fatal("a penalty from before the outage window must not be rolled back")
	}
}

func TestRewardClearsPenalty(t *testing.T) {
	now := time.Now()
	h := newMemberHealth("a", 10, time.Hour)
	h.penalize(now, dialBackoff, errors.New("refused"))
	h.reward(now)

	if h.inCooldown(now) || h.dialFail != 0 || h.lastDialErr != "" {
		t.Fatal("a successful dial must clear the penalty state")
	}
}

func TestIsLocalNetworkError(t *testing.T) {
	local := []error{
		syscall.ENETUNREACH,
		syscall.EHOSTUNREACH,
		errors.New("dial tcp: connect: network is unreachable"),
		&net.DNSError{Err: "server misbehaving", IsNotFound: false},
	}
	for _, err := range local {
		if !isLocalNetworkError(err) {
			t.Fatalf("%v should be classified as a local network error", err)
		}
	}

	remote := []error{
		nil,
		errors.New("connection reset by peer"),
		errors.New("EOF"),
		errors.New("tls: handshake failure"),
		&net.DNSError{Err: "no such host", IsNotFound: true},
	}
	for _, err := range remote {
		if isLocalNetworkError(err) {
			t.Fatalf("%v should not be classified as a local network error", err)
		}
	}
}

func TestStableByPriorKeepsEqualMembersInPlace(t *testing.T) {
	prior := map[string]int{"b": 0, "a": 1}
	nodes := []*rankedNode{
		{tag: "a", tier: tierHealthy, stats: memberStats{All: 5, Average: 100 * time.Millisecond, Deviation: 10 * time.Millisecond}},
		{tag: "b", tier: tierHealthy, stats: memberStats{All: 5, Average: 100 * time.Millisecond, Deviation: 10 * time.Millisecond}},
		{tag: "c", tier: tierHealthy, stats: memberStats{All: 5, Average: 100 * time.Millisecond, Deviation: 10 * time.Millisecond}},
	}
	stableByPrior(nodes, prior)
	sortNodes(nodes)

	// b ranked above a last round and is exactly as good this round, so it must
	// stay ahead; c has no prior and sorts last.
	if got := tags(nodes); got[0] != "b" || got[1] != "a" || got[2] != "c" {
		t.Fatalf("order = %v, want [b a c]", got)
	}
}

func tags(nodes []*rankedNode) []string {
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, node.tag)
	}
	return out
}

// --------------------------------------------------------------- warm start ---

func warmSelector(tags ...string) *AutoSelector {
	s := &AutoSelector{members: make(map[string]*memberHealth, len(tags))}
	for _, tag := range tags {
		s.members[tag] = newMemberHealth(tag, 10, time.Hour)
	}
	return s
}

func TestRestoreWarmSeedsRankableHealth(t *testing.T) {
	now := time.Now()
	s := warmSelector("good", "broken")
	restored := s.restoreWarm([]option.AutoSelectorWarmEntry{
		{Tag: "good", RTT: 120, Age: 30},
		{Tag: "broken", RTT: 0, Age: 30},
	}, now)
	if restored != 2 {
		t.Fatalf("restored = %d, want 2", restored)
	}

	good := s.members["good"].stats(now)
	if !good.Alive() || good.Average != 120*time.Millisecond {
		t.Fatalf("good = %+v, want one live 120ms sample", good)
	}
	// A member that was failing must come back failing, or a restart would hand
	// traffic straight back to the server we already knew was down.
	if broken := s.members["broken"].stats(now); broken.Alive() || broken.Fail != 1 {
		t.Fatalf("broken = %+v, want a single failure and not alive", broken)
	}
}

func TestRestoreWarmDropsEntriesOlderThanValidity(t *testing.T) {
	now := time.Now()
	s := warmSelector("stale")
	// Two hours old against a one hour window: a selector that has been stopped
	// this long has to start cold rather than trust what it remembers.
	if restored := s.restoreWarm([]option.AutoSelectorWarmEntry{
		{Tag: "stale", RTT: 120, Age: 7200},
	}, now); restored != 0 {
		t.Fatalf("restored = %d, want 0", restored)
	}
	if stats := s.members["stale"].stats(now); stats.All != 0 {
		t.Fatalf("stats = %+v, want nothing restored", stats)
	}
}

func TestRestoreWarmIgnoresUnknownAndRepeatedTags(t *testing.T) {
	now := time.Now()
	s := warmSelector("a")
	restored := s.restoreWarm([]option.AutoSelectorWarmEntry{
		{Tag: "a", RTT: 100, Age: 5},
		{Tag: "a", RTT: 900, Age: 5}, // a repeat must not stack onto the ring
		{Tag: "gone", RTT: 100, Age: 5},
	}, now)
	if restored != 1 {
		t.Fatalf("restored = %d, want 1", restored)
	}
	if stats := s.members["a"].stats(now); stats.All != 1 || stats.Average != 100*time.Millisecond {
		t.Fatalf("stats = %+v, want a single 100ms sample", stats)
	}
}

// ------------------------------------------------------------ outage window ---

func TestRollbackCoversTheWholeRoundNotJustTheWindow(t *testing.T) {
	now := time.Now()
	// Probes spread over half a 5 minute interval, so the round began well
	// before the fixed window opened.
	roundStart := now.Add(-3 * time.Minute)
	if since := rollbackSince(now, roundStart); !since.Equal(roundStart) {
		t.Fatalf("since = %v, want the round start %v", since, roundStart)
	}
}

func TestRollbackNeverShrinksBelowTheFixedWindow(t *testing.T) {
	now := time.Now()
	window := now.Add(-outageRollbackWindow)
	// A short round must not narrow the rollback: the dial failures that raised
	// the alarm can predate it.
	if since := rollbackSince(now, now.Add(-time.Second)); !since.Equal(window) {
		t.Fatalf("since = %v, want the fixed window %v", since, window)
	}
	// The dial path has no round at all.
	if since := rollbackSince(now, time.Time{}); !since.Equal(window) {
		t.Fatalf("since = %v, want the fixed window %v", since, window)
	}
}
