package wire

import (
	"bytes"
	"encoding/binary"
	"math"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/compress"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ResponseModeRaw    = 0
	ResponseModeBase64 = 1

	VerifyCodeSize          = 4
	SessionInitSize         = 10
	SessionAcceptBaseSize   = 7
	SessionAcceptPolicySize = 13
	SessionAcceptSize       = SessionAcceptBaseSize + SessionAcceptPolicySize
	PingPayloadSize         = 7
	ErrorDropPayloadSize    = 8

	scaledMin = 50 * time.Millisecond
	scaledMax = time.Second
)

type SessionInit struct {
	Base64Response      bool
	UploadCompression   compress.Type
	DownloadCompression compress.Type
	UploadMTU           uint16
	DownloadMTU         uint16
	VerifyCode          [VerifyCodeSize]byte
}

func AppendSessionInit(dst []byte, init SessionInit) []byte {
	mode := byte(ResponseModeRaw)
	if init.Base64Response {
		mode = ResponseModeBase64
	}
	dst = append(dst, mode, compress.PackPair(init.UploadCompression, init.DownloadCompression))
	dst = binary.BigEndian.AppendUint16(dst, init.UploadMTU)
	dst = binary.BigEndian.AppendUint16(dst, init.DownloadMTU)
	return append(dst, init.VerifyCode[:]...)
}

// ParseSessionInit decodes a SESSION_INIT payload with the checks of the reference server.
func ParseSessionInit(payload []byte) (SessionInit, error) {
	if len(payload) != SessionInitSize {
		return SessionInit{}, E.New("invalid session init size: ", len(payload))
	}
	if payload[0] > ResponseModeBase64 {
		return SessionInit{}, E.New("invalid session response mode: ", payload[0])
	}
	init := SessionInit{
		Base64Response: payload[0] == ResponseModeBase64,
		UploadMTU:      binary.BigEndian.Uint16(payload[2:4]),
		DownloadMTU:    binary.BigEndian.Uint16(payload[4:6]),
	}
	init.UploadCompression, init.DownloadCompression = compress.SplitPair(payload[1])
	copy(init.VerifyCode[:], payload[6:10])
	return init, nil
}

type SessionAccept struct {
	SessionID           uint8
	SessionCookie       uint8
	UploadCompression   compress.Type
	DownloadCompression compress.Type
	VerifyCode          [VerifyCodeSize]byte
	// HasPolicy is false for the 7-byte form sent by StormDNS and older servers.
	HasPolicy bool
	Policy    SessionPolicy
}

type SessionPolicy struct {
	MaxPacketDuplication      int
	MaxSetupDuplication       int
	MaxUploadMTU              int
	MaxDownloadMTU            int
	MaxRXTXWorkers            int
	MinPingAggressiveInterval time.Duration
	MaxPacketsPerBatch        int
	MaxARQWindowSize          int
	MaxARQDataNackMaxGap      int
	MinCompressionMinSize     int
	MinARQInitialRTO          time.Duration
}

func AppendSessionAccept(dst []byte, accept SessionAccept) []byte {
	dst = append(dst, accept.SessionID, accept.SessionCookie, compress.PackPair(accept.UploadCompression, accept.DownloadCompression))
	dst = append(dst, accept.VerifyCode[:]...)
	if !accept.HasPolicy {
		return dst
	}
	policy := accept.Policy
	dst = append(dst,
		byte(clamp(policy.MaxSetupDuplication, 0, 15)<<4|clamp(policy.MaxPacketDuplication, 0, 15)),
		byte(clamp(policy.MaxUploadMTU, 0, 0xFF)),
	)
	dst = binary.BigEndian.AppendUint16(dst, uint16(clamp(policy.MaxDownloadMTU, 0, 0xFFFF)))
	dst = append(dst,
		byte(clamp(policy.MaxRXTXWorkers, 0, 0xFF)),
		encodeScaled(policy.MinPingAggressiveInterval),
		byte(clamp(policy.MaxPacketsPerBatch, 0, 0xFF)),
	)
	dst = binary.BigEndian.AppendUint16(dst, uint16(clamp(policy.MaxARQWindowSize, 0, 0xFFFF)))
	dst = append(dst, byte(clamp(policy.MaxARQDataNackMaxGap, 0, 0xFF)))
	dst = binary.BigEndian.AppendUint16(dst, uint16(clamp(policy.MinCompressionMinSize, 0, 0xFFFF)))
	return append(dst, encodeScaled(policy.MinARQInitialRTO))
}

// ParseSessionAccept reads the 7-byte prefix and, when at least 20 bytes are present, the client policy.
func ParseSessionAccept(payload []byte) (SessionAccept, error) {
	if len(payload) < SessionAcceptBaseSize {
		return SessionAccept{}, E.New("session accept too short: ", len(payload))
	}
	accept := SessionAccept{
		SessionID:     payload[0],
		SessionCookie: payload[1],
	}
	accept.UploadCompression, accept.DownloadCompression = compress.SplitPair(payload[2])
	copy(accept.VerifyCode[:], payload[3:7])
	if len(payload) < SessionAcceptSize {
		return accept, nil
	}
	policy := payload[SessionAcceptBaseSize:SessionAcceptSize]
	accept.HasPolicy = true
	accept.Policy = SessionPolicy{
		MaxPacketDuplication:      int(policy[0] & 0x0F),
		MaxSetupDuplication:       int(policy[0] >> 4),
		MaxUploadMTU:              int(policy[1]),
		MaxDownloadMTU:            int(binary.BigEndian.Uint16(policy[2:4])),
		MaxRXTXWorkers:            int(policy[4]),
		MinPingAggressiveInterval: decodeScaled(policy[5]),
		MaxPacketsPerBatch:        int(policy[6]),
		MaxARQWindowSize:          int(binary.BigEndian.Uint16(policy[7:9])),
		MaxARQDataNackMaxGap:      int(policy[9]),
		MinCompressionMinSize:     int(binary.BigEndian.Uint16(policy[10:12])),
		MinARQInitialRTO:          decodeScaled(policy[12]),
	}
	return accept, nil
}

// ClientSettings are the client values a server policy may cap.
type ClientSettings struct {
	PacketDuplication      int
	SetupPacketDuplication int
	MaxUploadMTU           int
	MaxDownloadMTU         int
	RXTXWorkers            int
	PingAggressiveInterval time.Duration
	MaxPacketsPerBatch     int
	ARQWindowSize          int
	ARQDataNackMaxGap      int
	CompressionMinSize     int
	ARQInitialRTO          time.Duration
	ARQControlInitialRTO   time.Duration
	ARQMaxRTO              time.Duration
	ARQControlMaxRTO       time.Duration
}

func (s ClientSettings) Apply(policy SessionPolicy) ClientSettings {
	s.PacketDuplication = clamp(s.PacketDuplication, 1, max(policy.MaxPacketDuplication, 1))
	s.SetupPacketDuplication = clamp(s.SetupPacketDuplication, s.PacketDuplication, max(policy.MaxSetupDuplication, s.PacketDuplication))
	s.MaxUploadMTU = clamp(s.MaxUploadMTU, 1, max(policy.MaxUploadMTU, 1))
	s.MaxDownloadMTU = clamp(s.MaxDownloadMTU, 1, max(policy.MaxDownloadMTU, 1))
	s.RXTXWorkers = clamp(s.RXTXWorkers, 1, max(policy.MaxRXTXWorkers, 1))
	s.PingAggressiveInterval = clamp(s.PingAggressiveInterval, policy.MinPingAggressiveInterval, 30*time.Second)
	s.MaxPacketsPerBatch = clamp(s.MaxPacketsPerBatch, 1, max(policy.MaxPacketsPerBatch, 1))
	s.ARQWindowSize = clamp(s.ARQWindowSize, 1, max(policy.MaxARQWindowSize, 1))
	s.ARQDataNackMaxGap = clamp(s.ARQDataNackMaxGap, 0, max(policy.MaxARQDataNackMaxGap, 0))
	s.CompressionMinSize = max(s.CompressionMinSize, policy.MinCompressionMinSize, 1)
	s.ARQInitialRTO = clamp(s.ARQInitialRTO, policy.MinARQInitialRTO, s.ARQMaxRTO)
	s.ARQControlInitialRTO = clamp(s.ARQControlInitialRTO, policy.MinARQInitialRTO, s.ARQControlMaxRTO)
	return s
}

func SessionBusyMatches(payload []byte, verifyCode [VerifyCodeSize]byte) bool {
	return len(payload) >= VerifyCodeSize && bytes.Equal(payload[:VerifyCodeSize], verifyCode[:])
}

func AppendPingPayload(dst []byte, nonce [4]byte) []byte {
	return append(append(dst, 'P', 'O', ':'), nonce[:]...)
}

// AppendErrorDropPayload is the ERROR_DROP body of the reference server; clients ignore its content.
func AppendErrorDropPayload(dst []byte, nonce uint32) []byte {
	dst = binary.BigEndian.AppendUint32(append(dst, 'I', 'N', 'V'), nonce)
	return append(dst, byte(nonce))
}

// clamp checks the lower bound first, so a minimum above the maximum wins, as in the reference.
func clamp[T int | time.Duration](value T, minValue T, maxValue T) T {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

// encodeScaled maps 50ms..1s onto a byte.
func encodeScaled(value time.Duration) byte {
	seconds := clamp(value, scaledMin, scaledMax).Seconds()
	return byte(math.Round((seconds - scaledMin.Seconds()) / (scaledMax.Seconds() - scaledMin.Seconds()) * 255))
}

func decodeScaled(value byte) time.Duration {
	seconds := scaledMin.Seconds() + float64(value)/255*(scaledMax.Seconds()-scaledMin.Seconds())
	return time.Duration(seconds * float64(time.Second))
}
