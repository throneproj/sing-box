package group

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func prioritySelector(t *testing.T, tiers [][]string, members ...string) *AutoSelector {
	t.Helper()
	s := dialSelector(members...)
	priority, err := memberPriority(members, tiers)
	if err != nil {
		t.Fatal(err)
	}
	s.strategy = StrategyPriority
	s.priority = priority
	s.sampling = 10
	s.activeSize = len(members)
	s.expected = 3
	s.failTolerance = defaultAutoFailTolerance
	s.tolerance = defaultAutoTolerance * time.Millisecond
	s.failbackChecks = defaultAutoFailbackChecks
	s.failbackDelay = defaultAutoFailbackDelay
	s.interruptGroup = interrupt.NewGroup()
	s.attachedGroup = interrupt.NewGroup()
	s.logger = logger.NOP()
	return s
}

func selectedTag(s *AutoSelector) string {
	if detour := s.selectedFor(N.NetworkTCP); detour != nil {
		return detour.Tag()
	}
	return ""
}

func putAt(h *memberHealth, at time.Time, values ...time.Duration) {
	for i, value := range values {
		h.put(value, at.Add(time.Duration(i)*time.Second))
	}
}

type closeFlag struct {
	closed bool
}

func (c *closeFlag) Close() error {
	c.closed = true
	return nil
}

func TestMemberPriorityFromTiers(t *testing.T) {
	priority, err := memberPriority([]string{"a", "b", "c", "d"}, [][]string{{"b"}, {"c", "a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	// b keeps its first tier, d is in none and lands after the last.
	for tag, want := range map[string]int{"b": 0, "c": 1, "a": 1, "d": 2} {
		if priority[tag] != want {
			t.Fatalf("priority[%s] = %d, want %d", tag, priority[tag], want)
		}
	}

	priority, err = memberPriority([]string{"x", "y"}, nil)
	if err != nil || priority["x"] != 0 || priority["y"] != 1 {
		t.Fatalf("without tiers = %v (%v), want the member order", priority, err)
	}

	if _, err = memberPriority([]string{"a"}, [][]string{{"z"}}); err == nil {
		t.Fatal("a tier naming no member must be rejected")
	}
}

func TestNewAutoSelectorStrategyOptions(t *testing.T) {
	newSelector := func(options option.AutoSelectorOutboundOptions) (*AutoSelector, error) {
		detour, err := NewAutoSelector(context.Background(), nil, logger.NOP(), "auto", options)
		if err != nil {
			return nil, err
		}
		return detour.(*AutoSelector), nil
	}
	if _, err := newSelector(option.AutoSelectorOutboundOptions{Outbounds: []string{"a"}, Strategy: "fastest"}); err == nil {
		t.Fatal("an unknown strategy must be rejected")
	}
	if _, err := newSelector(option.AutoSelectorOutboundOptions{
		Outbounds: []string{"a"}, Strategy: StrategyPriority, Tiers: [][]string{{"b"}},
	}); err == nil {
		t.Fatal("a tier naming no member must be rejected")
	}

	s, err := newSelector(option.AutoSelectorOutboundOptions{Outbounds: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.strategy != StrategyLatency || s.failbackChecks != defaultAutoFailbackChecks || s.failbackDelay != defaultAutoFailbackDelay {
		t.Fatalf("defaults = %s/%d/%v", s.strategy, s.failbackChecks, s.failbackDelay)
	}

	s, err = newSelector(option.AutoSelectorOutboundOptions{
		Outbounds: []string{"a", "b"}, Strategy: StrategyPriority, Tiers: [][]string{{"b"}},
		Sampling: 2, FailbackChecks: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.priority["b"] != 0 || s.priority["a"] != 1 {
		t.Fatalf("priority = %v, want b before a", s.priority)
	}
	if s.failbackChecks != 2 {
		t.Fatalf("failbackChecks = %d, want it capped at the 2 samples kept", s.failbackChecks)
	}
}

func TestStreakCountsChecksSinceLastFailure(t *testing.T) {
	t0 := time.Now().Add(-time.Hour)
	h := newMemberHealth("a", 10, 2*time.Hour)
	if !h.settled(t0, 3, time.Minute) {
		t.Fatal("a member that never failed has nothing to prove")
	}

	putAt(h, t0, 100*time.Millisecond, rttFailed, 100*time.Millisecond, 100*time.Millisecond)
	if got := h.streak(); got != 2 {
		t.Fatalf("streak = %d, want 2", got)
	}
	// A failed dial breaks the run just like a failed check.
	h.penalize(t0.Add(10*time.Second), dialBackoff, syscall.ECONNREFUSED)
	if got := h.streak(); got != 0 {
		t.Fatalf("streak = %d after a failed dial, want 0", got)
	}
	putAt(h, t0.Add(20*time.Second), 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	if h.settled(t0.Add(30*time.Second), 3, time.Minute) {
		t.Fatal("three checks are not enough while the delay since the failure runs")
	}
	if !h.settled(t0.Add(70*time.Second), 3, time.Minute) {
		t.Fatal("three checks and the delay must settle the member")
	}
}

func TestOutageRollbackForgetsFailbackFailures(t *testing.T) {
	now := time.Now()
	h := newMemberHealth("a", 10, time.Hour)
	h.put(100*time.Millisecond, now.Add(-10*time.Minute))
	h.put(rttFailed, now.Add(-5*time.Minute))
	h.put(rttFailed, now.Add(-10*time.Second))

	h.rollbackFailuresSince(now.Add(-30 * time.Second))
	if !h.lastFailure.Equal(now.Add(-5 * time.Minute)) {
		t.Fatalf("lastFailure = %v, want the failure from before the outage", h.lastFailure)
	}
	h.rollbackFailuresSince(now.Add(-6 * time.Minute))
	if !h.lastFailure.IsZero() || !h.settled(now, 3, time.Minute) {
		t.Fatalf("lastFailure = %v, want nothing left to recover from", h.lastFailure)
	}
}

func TestPriorityPrefersHigherTierOverFaster(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	s := prioritySelector(t, [][]string{{"primary"}, {"backup"}}, "backup", "primary")
	putAt(s.members["primary"], past, 300*time.Millisecond, 300*time.Millisecond)
	putAt(s.members["backup"], past, 50*time.Millisecond, 50*time.Millisecond)

	s.evaluateLocked(time.Now())
	if got := selectedTag(s); got != "primary" {
		t.Fatalf("selected = %q, want primary", got)
	}
	if got := tags(s.ranked); got[0] != "primary" {
		t.Fatalf("ranked = %v, want primary first", got)
	}
}

func TestPriorityDropsToNextTierOnFailedDial(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	s := prioritySelector(t, [][]string{{"primary"}, {"backup"}, {"spare"}}, "primary", "backup", "spare")
	for _, tag := range s.tags {
		putAt(s.members[tag], past, 100*time.Millisecond, 100*time.Millisecond)
	}
	s.evaluateLocked(time.Now())
	if got := selectedTag(s); got != "primary" {
		t.Fatalf("selected = %q, want primary", got)
	}

	s.noteDialResult(s.outbounds["primary"], N.NetworkTCP, "", false, syscall.ECONNREFUSED)
	s.evaluateLocked(time.Now())
	if got := selectedTag(s); got != "backup" {
		t.Fatalf("selected = %q, want the next tier down", got)
	}
	// The failover order follows the tiers too: backup is tried before spare.
	if detour, _ := s.pick(N.NetworkTCP, "", map[string]bool{}); detour == nil || detour.Tag() != "backup" {
		t.Fatalf("pick = %v, want backup", detour)
	}
}

func TestPriorityFailbackWaitsForChecksAndDelay(t *testing.T) {
	t0 := time.Now().Add(-10 * time.Minute)
	s := prioritySelector(t, [][]string{{"primary"}, {"backup"}}, "primary", "backup")
	putAt(s.members["primary"], t0, 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	putAt(s.members["backup"], t0, 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	s.evaluateLocked(t0.Add(5 * time.Second))

	primary := s.members["primary"]
	for i := 1; i <= 4; i++ {
		primary.put(rttFailed, t0.Add(time.Duration(i)*10*time.Second))
	}
	s.evaluateLocked(t0.Add(40 * time.Second))
	if got := selectedTag(s); got != "backup" {
		t.Fatalf("selected = %q, want backup once primary fails most checks", got)
	}

	steps := []struct {
		at   time.Duration
		want string
	}{
		{60 * time.Second, "backup"}, // 1 check passed
		{75 * time.Second, "backup"}, // 2 checks passed
		{90 * time.Second, "backup"}, // 3 checks, but only 50s since the last failure
	}
	for _, step := range steps {
		at := t0.Add(step.at)
		primary.put(100*time.Millisecond, at)
		s.evaluateLocked(at)
		if got := selectedTag(s); got != step.want {
			t.Fatalf("at +%v selected = %q, want %q", step.at, got, step.want)
		}
	}
	s.evaluateLocked(t0.Add(100 * time.Second))
	if got := selectedTag(s); got != "primary" {
		t.Fatalf("selected = %q, want primary back after 3 checks and 60s", got)
	}
	if s.lastSwitchReason != "back to a higher priority" {
		t.Fatalf("reason = %q", s.lastSwitchReason)
	}
}

func TestPriorityFlappingPrimaryDoesNotChurn(t *testing.T) {
	t0 := time.Now().Add(-10 * time.Minute)
	s := prioritySelector(t, [][]string{{"primary"}, {"backup"}}, "primary", "backup")
	for _, tag := range s.tags {
		for i := 0; i < 8; i++ {
			s.members[tag].put(100*time.Millisecond, t0.Add(-time.Duration(8-i)*time.Second))
		}
	}
	s.evaluateLocked(t0)
	s.members["primary"].penalize(t0, dialBackoff, syscall.ECONNREFUSED)
	s.evaluateLocked(t0)
	if got := selectedTag(s); got != "backup" {
		t.Fatalf("selected = %q, want backup after the failed dial", got)
	}

	// Primary answers every other check for five minutes: never long enough to earn its place back.
	switches := s.lastSwitchAt
	for i := 1; i <= 10; i++ {
		at := t0.Add(time.Duration(i) * 30 * time.Second)
		value := 100 * time.Millisecond
		if i%2 == 0 {
			value = rttFailed
		}
		s.members["primary"].put(value, at)
		s.members["backup"].put(100*time.Millisecond, at)
		s.evaluateLocked(at)
		if got := selectedTag(s); got != "backup" {
			t.Fatalf("check %d selected = %q, want backup", i, got)
		}
	}
	if !s.lastSwitchAt.Equal(switches) {
		t.Fatal("a flapping primary must not move the selection")
	}
}

func TestPriorityIncumbentRidesOutASingleFailure(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	s := prioritySelector(t, [][]string{{"a", "b"}, {"backup"}}, "a", "b", "backup")
	for _, tag := range s.tags {
		putAt(s.members[tag], past, 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
	}
	s.evaluateLocked(time.Now())
	incumbent := selectedTag(s)

	s.members[incumbent].put(rttFailed, time.Now())
	s.evaluateLocked(time.Now())
	if got := selectedTag(s); got != incumbent {
		t.Fatalf("selected = %q, want %q to stay: one failed check is not a verdict", got, incumbent)
	}
	// Nor does it rank the member carrying traffic below a lower tier.
	if order := tags(s.ranked); order[len(order)-1] != "backup" {
		t.Fatalf("ranked = %v, want backup last", order)
	}
}

func TestPriorityInterruptsOnlyOnTheWayDown(t *testing.T) {
	for _, failbackInterrupt := range []bool{false, true} {
		t0 := time.Now().Add(-10 * time.Minute)
		s := prioritySelector(t, [][]string{{"primary"}, {"backup"}}, "primary", "backup")
		s.started = true
		s.interruptExternalConnections = true
		s.failbackInterrupt = failbackInterrupt
		putAt(s.members["primary"], t0, 100*time.Millisecond, 100*time.Millisecond)
		putAt(s.members["backup"], t0, 100*time.Millisecond, 100*time.Millisecond)
		s.evaluateLocked(t0.Add(5 * time.Second))

		onPrimary := &closeFlag{}
		s.interruptGroup.Add(onPrimary, true)
		s.members["primary"].penalize(t0.Add(10*time.Second), dialBackoff, syscall.ECONNREFUSED)
		s.evaluateLocked(t0.Add(10 * time.Second))
		if !onPrimary.closed {
			t.Fatal("dropping off a failed member must interrupt its connections")
		}

		onBackup := &closeFlag{}
		s.interruptGroup.Add(onBackup, true)
		putAt(s.members["primary"], t0.Add(20*time.Second), 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
		s.evaluateLocked(t0.Add(2 * time.Minute))
		if got := selectedTag(s); got != "primary" {
			t.Fatalf("selected = %q, want primary back", got)
		}
		if onBackup.closed != failbackInterrupt {
			t.Fatalf("failback_interrupt = %v closed the backup's connections = %v", failbackInterrupt, onBackup.closed)
		}
	}
}

func TestPriorityBalanceStaysInTier(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	s := prioritySelector(t, [][]string{{"a", "b"}, {"c", "d"}}, "a", "b", "c", "d")
	s.expected = 4
	s.balance = true
	s.balanceMode = BalanceModeRotate
	s.balanceInterval = time.Minute
	for _, tag := range s.tags {
		putAt(s.members[tag], past, 100*time.Millisecond, 100*time.Millisecond)
	}
	s.evaluateLocked(time.Now())
	if len(s.qualified) != 4 {
		t.Fatalf("qualified = %v, want all four", s.qualified)
	}
	if got := s.balanceSetLocked(N.NetworkTCP); len(got) != 2 || s.priority[got[0]] != 0 || s.priority[got[1]] != 0 {
		t.Fatalf("balance set = %v, want only the top tier", got)
	}

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		s.rotateLocked(N.NetworkTCP, time.Now())
		seen[selectedTag(s)] = true
	}
	if seen["c"] || seen["d"] || !seen["a"] || !seen["b"] {
		t.Fatalf("rotation visited %v, want a and b only", seen)
	}
}

func TestPriorityProbesHigherTiersWhileBelow(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	s := prioritySelector(t, [][]string{{"p1", "p2", "p3"}, {"backup"}}, "p1", "p2", "p3", "backup", "spare")
	s.activeSize = 1
	for _, tag := range []string{"p1", "p2", "p3"} {
		putAt(s.members[tag], past, rttFailed, rttFailed)
	}
	putAt(s.members["backup"], past, 100*time.Millisecond, 100*time.Millisecond)
	putAt(s.members["spare"], past, 100*time.Millisecond, 100*time.Millisecond)
	s.evaluateLocked(time.Now())
	if got := selectedTag(s); got != "backup" {
		t.Fatalf("selected = %q, want backup", got)
	}

	batch := s.roundBatch(true)
	want := map[string]bool{"backup": true, "p1": true, "p2": true, "p3": true}
	if len(batch) != len(want) {
		t.Fatalf("batch = %v, want %v", batch, want)
	}
	for _, tag := range batch {
		if !want[tag] {
			t.Fatalf("batch = %v, want %v", batch, want)
		}
	}
}

func TestPriorityConfirmsRecoveryOnlyWhileItAnswers(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	s := prioritySelector(t, [][]string{{"primary"}, {"backup"}}, "primary", "backup")
	putAt(s.members["primary"], past, rttFailed, rttFailed)
	putAt(s.members["backup"], past, 100*time.Millisecond, 100*time.Millisecond)
	s.evaluateLocked(time.Now())
	if s.recoveringLocked() != nil {
		t.Fatal("a member that keeps failing is left to the tier interval")
	}

	s.members["primary"].put(100*time.Millisecond, time.Now())
	s.evaluateLocked(time.Now())
	if detour := s.recoveringLocked(); detour == nil || detour.Tag() != "primary" {
		t.Fatalf("recovering = %v, want primary once it answers", detour)
	}

	s.members["primary"].put(rttFailed, time.Now().Add(time.Second))
	s.evaluateLocked(time.Now().Add(time.Second))
	if s.recoveringLocked() != nil {
		t.Fatal("a failed check stops the fast confirmation until the member answers again")
	}

	s.members["primary"].put(100*time.Millisecond, time.Now().Add(2*time.Second))
	s.evaluateLocked(time.Now().Add(2 * time.Second))
	s.pinnedTag = "backup"
	if s.recoveringLocked() != nil {
		t.Fatal("a pinned selection does not follow the tiers")
	}
}

func TestLatencyStrategyIgnoresPriority(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	s := prioritySelector(t, [][]string{{"slow"}, {"fast"}}, "slow", "fast")
	s.strategy = StrategyLatency
	putAt(s.members["slow"], past, 300*time.Millisecond, 310*time.Millisecond)
	putAt(s.members["fast"], past, 50*time.Millisecond, 60*time.Millisecond)
	s.evaluateLocked(time.Now())
	if got := selectedTag(s); got != "fast" {
		t.Fatalf("selected = %q, want fast", got)
	}
}
