package wire

import (
	"github.com/sagernet/sing-box/transport/masterdns/compress"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	PacketMTUUpRequest                    uint8 = 0x01
	PacketMTUUpResponse                   uint8 = 0x02
	PacketMTUDownRequest                  uint8 = 0x03
	PacketMTUDownResponse                 uint8 = 0x04
	PacketSessionInit                     uint8 = 0x05
	PacketSessionAccept                   uint8 = 0x06
	PacketPing                            uint8 = 0x07
	PacketPong                            uint8 = 0x08
	PacketStreamSYN                       uint8 = 0x09
	PacketStreamSYNAck                    uint8 = 0x0A
	PacketStreamConnected                 uint8 = 0x0B
	PacketStreamConnectedAck              uint8 = 0x0C
	PacketStreamConnectFail               uint8 = 0x0D
	PacketStreamConnectFailAck            uint8 = 0x0E
	PacketStreamData                      uint8 = 0x0F
	PacketStreamDataAck                   uint8 = 0x10
	PacketStreamDataNack                  uint8 = 0x11
	PacketStreamResend                    uint8 = 0x12
	PacketPackedControlBlocks             uint8 = 0x13
	PacketStreamCloseWrite                uint8 = 0x14
	PacketStreamCloseWriteAck             uint8 = 0x15
	PacketStreamCloseRead                 uint8 = 0x16
	PacketStreamCloseReadAck              uint8 = 0x17
	PacketStreamRST                       uint8 = 0x18
	PacketStreamRSTAck                    uint8 = 0x19
	PacketSOCKS5SYN                       uint8 = 0x1A
	PacketSOCKS5SYNAck                    uint8 = 0x1B
	PacketSOCKS5ConnectFail               uint8 = 0x1C
	PacketSOCKS5ConnectFailAck            uint8 = 0x1D
	PacketSOCKS5RulesetDenied             uint8 = 0x1E
	PacketSOCKS5RulesetDeniedAck          uint8 = 0x1F
	PacketSOCKS5NetworkUnreachable        uint8 = 0x20
	PacketSOCKS5NetworkUnreachableAck     uint8 = 0x21
	PacketSOCKS5HostUnreachable           uint8 = 0x22
	PacketSOCKS5HostUnreachableAck        uint8 = 0x23
	PacketSOCKS5ConnectionRefused         uint8 = 0x24
	PacketSOCKS5ConnectionRefusedAck      uint8 = 0x25
	PacketSOCKS5TTLExpired                uint8 = 0x26
	PacketSOCKS5TTLExpiredAck             uint8 = 0x27
	PacketSOCKS5CommandUnsupported        uint8 = 0x28
	PacketSOCKS5CommandUnsupportedAck     uint8 = 0x29
	PacketSOCKS5AddressTypeUnsupported    uint8 = 0x2A
	PacketSOCKS5AddressTypeUnsupportedAck uint8 = 0x2B
	PacketSOCKS5AuthFailed                uint8 = 0x2C
	PacketSOCKS5AuthFailedAck             uint8 = 0x2D
	PacketSOCKS5UpstreamUnavailable       uint8 = 0x2E
	PacketSOCKS5UpstreamUnavailableAck    uint8 = 0x2F
	PacketSOCKS5Connected                 uint8 = 0x30
	PacketSOCKS5ConnectedAck              uint8 = 0x31
	PacketDNSQueryRequest                 uint8 = 0x32
	PacketDNSQueryResponse                uint8 = 0x33
	PacketDNSQueryRequestAck              uint8 = 0x34
	PacketDNSQueryResponseAck             uint8 = 0x35
	PacketSessionClose                    uint8 = 0x36
	PacketSessionBusy                     uint8 = 0x37
	PacketErrorDrop                       uint8 = 0xFF
)

const (
	MinHeaderSize = 4
	MaxHeaderSize = 11
	// MaxHeaderType is the first packet type with the largest header; capacity probes are sized with it.
	MaxHeaderType = PacketMTUUpRequest
)

var (
	ErrPacketTooShort        = E.New("packet too short")
	ErrInvalidPacketType     = E.New("invalid packet type")
	ErrInvalidHeaderCheck    = E.New("invalid packet header check")
	ErrInvalidCompressedData = E.New("invalid compressed packet payload")
)

const (
	flagValid uint8 = 1 << iota
	flagStream
	flagSequence
	flagFragment
	flagCompression
)

var packetFlags = buildPacketFlags()

type Packet struct {
	SessionID      uint8
	Type           uint8
	SessionCookie  uint8
	StreamID       uint16
	SequenceNum    uint16
	FragmentID     uint8
	TotalFragments uint8
	// Compression is the raw header byte; values above compress.ZLIB carry an uncompressed payload.
	Compression compress.Type
	Payload     []byte
}

func Valid(packetType uint8) bool {
	return packetFlags[packetType]&flagValid != 0
}

func HasStream(packetType uint8) bool {
	return packetFlags[packetType]&flagStream != 0
}

func HasSequence(packetType uint8) bool {
	return packetFlags[packetType]&flagSequence != 0
}

func HasFragment(packetType uint8) bool {
	return packetFlags[packetType]&flagFragment != 0
}

func HasCompression(packetType uint8) bool {
	return packetFlags[packetType]&flagCompression != 0
}

func HeaderSize(packetType uint8) int {
	flags := packetFlags[packetType]
	if flags&flagValid == 0 {
		return 0
	}
	size := MinHeaderSize
	if flags&flagStream != 0 {
		size += 2
	}
	if flags&flagSequence != 0 {
		size += 2
	}
	if flags&flagFragment != 0 {
		size += 2
	}
	if flags&flagCompression != 0 {
		size++
	}
	return size
}

func AppendPacket(dst []byte, packet Packet) ([]byte, error) {
	flags := packetFlags[packet.Type]
	if flags&flagValid == 0 {
		return nil, ErrInvalidPacketType
	}
	start := len(dst)
	dst = append(dst, packet.SessionID, packet.Type)
	if flags&flagStream != 0 {
		dst = append(dst, byte(packet.StreamID>>8), byte(packet.StreamID))
	}
	if flags&flagSequence != 0 {
		dst = append(dst, byte(packet.SequenceNum>>8), byte(packet.SequenceNum))
	}
	if flags&flagFragment != 0 {
		dst = append(dst, packet.FragmentID, packet.TotalFragments)
	}
	if flags&flagCompression != 0 {
		dst = append(dst, uint8(packet.Compression))
	}
	dst = append(dst, packet.SessionCookie)
	dst = append(dst, headerCheck(dst[start:]))
	return append(dst, packet.Payload...), nil
}

// AppendCompressedPacket compresses the payload with packet.Compression where the type allows it, like the reference BuildRawAuto.
func AppendCompressedPacket(dst []byte, packet Packet, minSize int) ([]byte, error) {
	packet.Payload, packet.Compression = CompressPayload(packet.Type, packet.Payload, packet.Compression, minSize)
	return AppendPacket(dst, packet)
}

func CompressPayload(packetType uint8, payload []byte, t compress.Type, minSize int) ([]byte, compress.Type) {
	if compress.Normalize(uint8(t)) == compress.Off || !HasCompression(packetType) || len(payload) == 0 {
		return payload, compress.Off
	}
	return compress.Compress(payload, t, minSize)
}

// ParsePacket parses a raw frame; the payload aliases data and is still compressed.
func ParsePacket(data []byte) (Packet, error) {
	if len(data) < MinHeaderSize {
		return Packet{}, ErrPacketTooShort
	}
	packetType := data[1]
	flags := packetFlags[packetType]
	if flags&flagValid == 0 {
		return Packet{}, ErrInvalidPacketType
	}
	if len(data) < HeaderSize(packetType) {
		return Packet{}, ErrPacketTooShort
	}
	packet := Packet{
		SessionID: data[0],
		Type:      packetType,
	}
	offset := 2
	if flags&flagStream != 0 {
		packet.StreamID = uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2
	}
	if flags&flagSequence != 0 {
		packet.SequenceNum = uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2
	}
	if flags&flagFragment != 0 {
		packet.FragmentID = data[offset]
		packet.TotalFragments = data[offset+1]
		offset += 2
	}
	if flags&flagCompression != 0 {
		packet.Compression = compress.Type(data[offset])
		offset++
	}
	packet.SessionCookie = data[offset]
	if data[offset+1] != headerCheck(data[:offset+1]) {
		return Packet{}, ErrInvalidHeaderCheck
	}
	packet.Payload = data[offset+2:]
	return packet, nil
}

// Inflate decompresses the payload in place of a parsed packet.
func (p *Packet) Inflate() error {
	if !HasCompression(p.Type) || p.Compression == compress.Off {
		return nil
	}
	payload, err := compress.Decompress(p.Payload, p.Compression)
	if err != nil {
		return ErrInvalidCompressedData
	}
	p.Payload = payload
	return nil
}

func headerCheck(header []byte) byte {
	check := byte(len(header)*17 + 0x5D)
	for index, value := range header {
		check += value + byte(index)
		check ^= value << (index & 0x03)
	}
	return check
}

func buildPacketFlags() [256]uint8 {
	var flags [256]uint8
	for _, packetType := range []uint8{
		PacketMTUUpResponse, PacketMTUDownRequest, PacketSessionInit, PacketSessionAccept,
		PacketSessionBusy, PacketSessionClose, PacketPing, PacketPong, PacketErrorDrop,
	} {
		flags[packetType] |= flagValid
	}
	for packetType := PacketStreamSYN; packetType <= PacketDNSQueryResponseAck; packetType++ {
		if packetType != PacketPackedControlBlocks {
			flags[packetType] |= flagValid | flagStream | flagSequence
		}
	}
	flags[PacketMTUUpRequest] |= flagValid | flagStream | flagSequence
	flags[PacketMTUDownResponse] |= flagValid | flagStream | flagSequence
	for _, packetType := range []uint8{
		PacketStreamData, PacketStreamResend, PacketSOCKS5SYN,
		PacketDNSQueryRequest, PacketDNSQueryResponse, PacketDNSQueryRequestAck, PacketDNSQueryResponseAck,
		PacketMTUUpRequest, PacketMTUDownResponse,
	} {
		flags[packetType] |= flagFragment
	}
	for _, packetType := range []uint8{
		PacketStreamData, PacketStreamResend, PacketPackedControlBlocks,
		PacketDNSQueryRequest, PacketDNSQueryResponse, PacketMTUUpRequest, PacketMTUDownResponse,
	} {
		flags[packetType] |= flagValid | flagCompression
	}
	return flags
}
