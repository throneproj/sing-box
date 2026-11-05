package warpmasque

import (
	"strconv"

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

// PacketTooLargeError reports the largest IP packet the carrier can send at the moment.
type PacketTooLargeError struct {
	MTU int
}

func (e *PacketTooLargeError) Error() string {
	return "packet too large for the carrier (maximum: " + strconv.Itoa(e.MTU) + " bytes)"
}
