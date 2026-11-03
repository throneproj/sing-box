package wire

import (
	"encoding/binary"
	"strings"

	"github.com/sagernet/sing-box/transport/masterdns/cipher"
)

const (
	ProbeCodeSize = 4
	// MinUploadProbe and MinDownloadProbe are the smallest sizes the reference client probes.
	MinUploadProbe   = 1 + ProbeCodeSize
	MinDownloadProbe = SessionAcceptSize
	// MaxDownloadProbe is the largest download size a reference server answers.
	MaxDownloadProbe = 4096

	probeMetaSize         = ProbeCodeSize + 2
	downloadProbeHeadSize = MinUploadProbe + 2
	probeSessionID        = 255
)

// ProbePacket wraps an MTU probe payload in the header the reference client uses.
func ProbePacket(packetType uint8, payload []byte) Packet {
	return Packet{
		SessionID:      probeSessionID,
		Type:           packetType,
		StreamID:       1,
		SequenceNum:    1,
		TotalFragments: 1,
		Payload:        payload,
	}
}

// NewUploadProbe builds an MTU_UP_REQ payload of exactly size bytes, or nil below MinUploadProbe.
func NewUploadProbe(size int, base64Response bool, code uint32) []byte {
	if size < MinUploadProbe {
		return nil
	}
	payload := make([]byte, size)
	if base64Response {
		payload[0] = ResponseModeBase64
	}
	binary.BigEndian.PutUint32(payload[1:], code)
	return payload
}

// NewDownloadProbe builds an MTU_DOWN_REQ payload asking for downloadSize bytes, padded to the synced upload MTU.
func NewDownloadProbe(uploadMTU int, downloadSize int, base64Response bool, code uint32) []byte {
	payload := NewUploadProbe(max(downloadProbeHeadSize, uploadMTU), base64Response, code)
	binary.BigEndian.PutUint16(payload[MinUploadProbe:], uint16(downloadSize))
	return payload
}

func CheckUploadProbe(packet Packet, code uint32, size int) bool {
	return packet.Type == PacketMTUUpResponse &&
		len(packet.Payload) == probeMetaSize &&
		binary.BigEndian.Uint32(packet.Payload) == code &&
		int(binary.BigEndian.Uint16(packet.Payload[ProbeCodeSize:])) == size
}

func CheckDownloadProbe(packet Packet, code uint32, size int) bool {
	return packet.Type == PacketMTUDownResponse &&
		len(packet.Payload) == size &&
		len(packet.Payload) >= probeMetaSize &&
		binary.BigEndian.Uint32(packet.Payload) == code &&
		int(binary.BigEndian.Uint16(packet.Payload[ProbeCodeSize:])) == size
}

// UploadProbeReply is the MTU_UP_RES payload a reference server returns, or false when it drops the request.
func UploadProbeReply(request []byte) ([]byte, bool) {
	if len(request) < MinUploadProbe || request[0] > ResponseModeBase64 {
		return nil, false
	}
	reply := append(make([]byte, 0, probeMetaSize), request[1:MinUploadProbe]...)
	return binary.BigEndian.AppendUint16(reply, uint16(len(request))), true
}

// DownloadProbeReply is the MTU_DOWN_RES payload a reference server returns; minSize is 20 for MasterDnsVPN and 30 for StormDNS.
func DownloadProbeReply(request []byte, minSize int) ([]byte, bool) {
	if len(request) < downloadProbeHeadSize || request[0] > ResponseModeBase64 {
		return nil, false
	}
	size := int(binary.BigEndian.Uint16(request[MinUploadProbe:]))
	if size < minSize || size > MaxDownloadProbe {
		return nil, false
	}
	reply := make([]byte, size)
	copy(reply, request[1:MinUploadProbe])
	binary.BigEndian.PutUint16(reply[ProbeCodeSize:], uint16(size))
	return reply, true
}

// EncodedChars is the query label length of a max-header frame carrying payloadLength bytes.
func EncodedChars(payloadLength int, method cipher.Method) int {
	if payloadLength <= 0 {
		return 0
	}
	return Base36Len(MaxHeaderSize + payloadLength + method.Overhead())
}

// MaxUploadPayload is the largest probe payload whose query still fits under domain.
func MaxUploadPayload(domain string, method cipher.Method) int {
	maxChars := MaxEncodedChars(domain)
	domainLength := len(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if maxChars <= 0 || domainLength == 0 {
		return 0
	}
	low, high, best := 0, maxChars, 0
	for low <= high {
		middle := (low + high) / 2
		if middle <= 0 || queryNameLength(Base36Len(MaxHeaderSize+middle+method.Overhead()), domainLength) <= MaxNameLength {
			best = middle
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	return best
}

// SafeUploadMTU leaves room for the cipher overhead, keeping at least 64 bytes.
func SafeUploadMTU(uploadMTU int, method cipher.Method) int {
	if uploadMTU <= 0 {
		return 0
	}
	return min(max(uploadMTU-method.Overhead(), 64), uploadMTU)
}
