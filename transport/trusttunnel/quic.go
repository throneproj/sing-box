//go:build with_quic

package trusttunnel

import (
	"context"
	"time"

	"github.com/sagernet/quic-go"
	C "github.com/sagernet/sing-box/constant"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common/ntp"
)

// Chrome's initial stream window.
const quicStreamReceiveWindow = 131072

const disablePathMTUDiscovery = !(C.IsLinux || C.IsWindows || C.IsDarwin)

func setCongestionControl(ctx context.Context, conn *quic.Conn, name string) {
	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}
	switch name {
	case "cubic":
		conn.SetCongestionControl(congestion_meta1.NewCubicSender(
			congestion_meta1.DefaultClock{TimeFunc: timeFunc},
			conn.InitialPacketSize(),
			false,
		))
	case "reno":
		conn.SetCongestionControl(congestion_meta1.NewCubicSender(
			congestion_meta1.DefaultClock{TimeFunc: timeFunc},
			conn.InitialPacketSize(),
			true,
		))
	default:
		conn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard))
	}
}
