package group

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type stubOutbound struct {
	outbound.Adapter
	N.Dialer
}

func dialSelector(tags ...string) *AutoSelector {
	s := warmSelector(tags...)
	s.tags = tags
	s.outbounds = make(map[string]adapter.Outbound, len(tags))
	s.recentDialFails = make(map[string]time.Time)
	s.kick = make(chan struct{}, 1)
	for _, tag := range tags {
		s.outbounds[tag] = &stubOutbound{Adapter: outbound.NewAdapter(C.TypeWireGuard, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil)}
	}
	return s
}

func roundRequested(s *AutoSelector) bool {
	select {
	case <-s.kick:
		return true
	default:
		return false
	}
}

func TestRoutedDialFailureMovesSelectionOff(t *testing.T) {
	now := time.Now()
	s := dialSelector("flow", "spare")
	fill(s.members["flow"], now, 80*time.Millisecond, 80*time.Millisecond)
	fill(s.members["spare"], now, 120*time.Millisecond, 120*time.Millisecond)
	s.evaluateLocked(now)
	if selected := s.selectedFor(N.NetworkTCP); selected == nil || selected.Tag() != "flow" {
		t.Fatalf("selected = %v, want flow", selected)
	}

	err := E.Cause(syscall.ECONNREFUSED, "open connection to 192.0.2.1:443 using outbound/wireguard[flow]")
	s.DialFailed(s.outbounds["flow"], N.NetworkTCP, err)
	if health := s.members["flow"]; !health.inCooldown(time.Now()) || health.dialFail != 1 {
		t.Fatalf("flow dialFail = %d, cooldown until %v; want a penalty", health.dialFail, health.cooldownUntil)
	}
	if !roundRequested(s) {
		t.Fatal("a routed failure must pull the next round forward")
	}

	// The probe round settles whether the member is really down; until it lands,
	// the cooldown alone has to keep new connections off it.
	s.evaluateLocked(time.Now())
	if selected := s.selectedFor(N.NetworkTCP); selected == nil || selected.Tag() != "spare" {
		t.Fatalf("selected = %v, want spare", selected)
	}
}

func TestRoutedDialFailureSkipsMemberHandles(t *testing.T) {
	s := dialSelector("plain")
	// A handle's dial ran through DialContext, which recorded every attempt.
	handle := &memberHandle{Outbound: s.outbounds["plain"], selector: s}
	s.DialFailed(handle, N.NetworkTCP, syscall.ECONNREFUSED)
	if health := s.members["plain"]; health.dialFail != 0 || health.inCooldown(time.Now()) {
		t.Fatalf("plain dialFail = %d, want no second penalty", health.dialFail)
	}
	if roundRequested(s) {
		t.Fatal("no round may be requested for an already recorded failure")
	}
}

func TestRoutedDialFailureIgnoresUnrelatedErrors(t *testing.T) {
	for _, err := range []error{
		E.Cause(context.Canceled, "open connection to example.com:443"),
		E.Cause(net.ErrClosed, "open packet connection to 192.0.2.1:53"),
		E.Cause(syscall.ENETUNREACH, "open connection to 192.0.2.1:443"),
	} {
		s := dialSelector("flow")
		s.DialFailed(s.outbounds["flow"], N.NetworkTCP, err)
		if health := s.members["flow"]; health.dialFail != 0 || health.inCooldown(time.Now()) {
			t.Fatalf("%v: dialFail = %d, want no penalty", err, health.dialFail)
		}
		if roundRequested(s) {
			t.Fatalf("%v: no round may be requested", err)
		}
	}
}
