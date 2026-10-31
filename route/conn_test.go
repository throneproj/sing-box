package route

import (
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type testOutbound struct {
	outbound.Adapter
	N.Dialer
}

func newTestOutbound(tag string) *testOutbound {
	return &testOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil)}
}

type testDialFailureListener struct {
	*testOutbound
	failed []string
}

func (l *testDialFailureListener) DialFailed(detour adapter.Outbound, network string, err error) {
	l.failed = append(l.failed, network+"/"+detour.Tag())
}

func TestNotifyDialFailure(t *testing.T) {
	t.Parallel()
	outer := &testDialFailureListener{testOutbound: newTestOutbound("outer")}
	inner := &testDialFailureListener{testOutbound: newTestOutbound("inner")}
	notifyDialFailure([]adapter.Outbound{outer, inner, newTestOutbound("leaf")}, N.NetworkUDP, os.ErrDeadlineExceeded)
	require.Equal(t, []string{"udp/inner"}, outer.failed)
	require.Equal(t, []string{"udp/leaf"}, inner.failed)

	notifyDialFailure(nil, N.NetworkTCP, os.ErrDeadlineExceeded)
	notifyDialFailure([]adapter.Outbound{outer}, N.NetworkTCP, os.ErrDeadlineExceeded)
	require.Len(t, outer.failed, 1)
}
