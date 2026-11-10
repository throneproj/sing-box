package dialer

import (
	"crypto/rand"
	"encoding/binary"
	"net"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	quicOpenerLength  = 1200
	quicOpenerVersion = 0x6b3343cf
	quicOpenerCIDLen  = 8
)

// DPI that keys a UDP flow on its first packet's QUIC version lets the flow through after a v2 decoy.
func newQUICOpener() []byte {
	packet := make([]byte, quicOpenerLength)
	rand.Read(packet)
	packet[0] = 0xc0 | 0x10 | packet[0]&0x0f
	binary.BigEndian.PutUint32(packet[1:], quicOpenerVersion)
	offset := 5
	packet[offset] = quicOpenerCIDLen
	offset += 1 + quicOpenerCIDLen
	packet[offset] = quicOpenerCIDLen
	offset += 1 + quicOpenerCIDLen
	packet[offset] = 0
	offset++
	binary.BigEndian.PutUint16(packet[offset:], 0x4000|uint16(quicOpenerLength-offset-2))
	return packet
}

func writeQUICOpener(conn net.Conn) {
	_, _ = conn.Write(newQUICOpener())
}

func writeQUICOpenerTo(conn net.PacketConn, destination M.Socksaddr) {
	if !destination.IsIP() || destination.Addr.IsUnspecified() || destination.Port == 0 {
		return
	}
	_, _ = conn.WriteTo(newQUICOpener(), destination.UDPAddr())
}
