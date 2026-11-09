package group

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type refusingDialer struct{}

func (refusingDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, syscall.ECONNREFUSED
}

func (refusingDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, syscall.ECONNREFUSED
}

var upstreamMembers = []string{"a", "b", "c", "d", "e", "f"}

// upstreamSelector gives every member a clean record; a nil upstream configures none.
func upstreamSelector(t *testing.T, upstream N.Dialer) *AutoSelector {
	s := dialSelector(upstreamMembers...)
	ctx, cancel := context.WithCancel(pause.WithDefaultManager(context.Background()))
	s.ctx = ctx
	s.cancel = cancel
	s.pause = service.FromContext[pause.Manager](ctx)
	s.logger = logger.NOP()
	s.probeTimeout = time.Second
	s.close = make(chan struct{})
	t.Cleanup(func() {
		close(s.close)
		cancel()
	})
	if upstream != nil {
		s.upstream = &stubOutbound{Adapter: outbound.NewAdapter(C.TypeSOCKS, "relay", []string{N.NetworkTCP}, nil), Dialer: upstream}
	}
	past := time.Now().Add(-time.Minute)
	for _, health := range s.members {
		fill(health, past, 100*time.Millisecond, 100*time.Millisecond)
	}
	return s
}

func roundResults(at time.Time, failed []string, succeeded []string) []probeResult {
	results := make([]probeResult, 0, len(failed)+len(succeeded))
	for _, tag := range failed {
		results = append(results, probeResult{tag: tag, value: rttFailed, err: io.EOF, at: at})
	}
	for _, tag := range succeeded {
		results = append(results, probeResult{tag: tag, value: 100 * time.Millisecond, at: at})
	}
	return results
}

func TestCorrelatedFailureBehindDeadUpstreamSuspends(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		failed    []string
		succeeded []string
	}{
		{"whole round failed", upstreamMembers, nil},
		{"clean members broke together", upstreamMembers[:5], upstreamMembers[5:]},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			s := upstreamSelector(t, refusingDialer{})
			startedAt := time.Now()
			// The watchdog lost member a while the round was in flight.
			watched := s.members["a"]
			watched.put(rttFailed, startedAt)
			watched.penalize(startedAt, dialBackoff, io.EOF)

			s.commitRound(roundResults(time.Now(), testCase.failed, testCase.succeeded), startedAt)
			if !s.isSuspended() {
				t.Fatal("a round lost behind a dead upstream must suspend")
			}
			now := time.Now()
			for _, tag := range upstreamMembers {
				health := s.members[tag]
				if stats := health.stats(now); stats.Fail != 0 || !stats.Alive() {
					t.Fatalf("%s = %+v, want the round's failures rolled back", tag, stats)
				}
				if health.inCooldown(now) {
					t.Fatalf("%s is cooling down until %v, want the penalty rolled back", tag, health.cooldownUntil)
				}
			}
		})
	}
}

func TestCorrelatedFailureBehindWorkingUpstreamCommits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	s := upstreamSelector(t, N.SystemDialer)
	s.link = server.URL

	startedAt := time.Now()
	s.commitRound(roundResults(time.Now(), upstreamMembers, nil), startedAt)
	if s.isSuspended() {
		t.Fatal("a working upstream puts the failures on the members, not the network")
	}
	assertRoundCommitted(t, s)
}

func TestCorrelatedFailureWithoutUpstreamCommits(t *testing.T) {
	s := upstreamSelector(t, nil)
	if !s.upstreamOK(true) {
		t.Fatal("no upstream must never veto a verdict")
	}

	startedAt := time.Now()
	s.commitRound(roundResults(time.Now(), upstreamMembers, nil), startedAt)
	if s.isSuspended() {
		t.Fatal("without an upstream, a passing connectivity check must commit")
	}
	assertRoundCommitted(t, s)
}

func TestDialPathOutageChecksUpstream(t *testing.T) {
	s := upstreamSelector(t, refusingDialer{})
	s.assessOutage()
	if !s.isSuspended() {
		t.Fatal("a dead upstream found from the dial path must suspend")
	}
}

func assertRoundCommitted(t *testing.T, s *AutoSelector) {
	t.Helper()
	now := time.Now()
	for _, tag := range upstreamMembers {
		if stats := s.members[tag].stats(now); stats.Fail != 1 {
			t.Fatalf("%s = %+v, want the round's failure recorded", tag, stats)
		}
	}
	if s.roundsCompleted != 1 {
		t.Fatalf("roundsCompleted = %d, want 1", s.roundsCompleted)
	}
}
