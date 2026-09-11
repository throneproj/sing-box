package masque

import (
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common/buf"
)

const (
	connectHost     = "cloudflareaccess.com"
	connectProtocol = "cf-connect-ip"

	settingH3Datagram00                   = 0x276
	capsuleTypeDatagram http3.CapsuleType = 0
	contextIDIP                           = 0
)

type Conn interface {
	// ReadPacket appends one IP packet to buffer.
	ReadPacket(buffer *buf.Buffer) error
	// WritePacket sends one IP packet without retaining it.
	WritePacket(packet []byte) error
	Close() error
}
