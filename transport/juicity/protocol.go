package juicity

import (
	"github.com/sagernet/quic-go"
	C "github.com/sagernet/sing-box/constant"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
)

const (
	Version = 0
)

const (
	CommandAuthenticate = 0
)

const (
	NetworkTCP = 1
	NetworkUDP = 3
)

const AuthenticateLen = 2 + 16 + 32

const (
	initialStreamReceiveWindow     = 2 * 1024 * 1024
	maxStreamReceiveWindow         = 32 * 1024 * 1024
	initialConnectionReceiveWindow = 32 * 1024 * 1024
	maxConnectionReceiveWindow     = 64 * 1024 * 1024
)

const disablePathMTUDiscovery = !(C.IsLinux || C.IsWindows || C.IsDarwin)

func setCongestion(connection *quic.Conn) {
	connection.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(connection.InitialPacketSize(), congestion_meta2.ProfileStandard))
}
