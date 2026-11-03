package wire

const (
	PriorityCritical = 0
	PriorityRetry    = 1
	PriorityHigh     = 2
	PriorityNormal   = 3
	PriorityLow      = 4
	PriorityIdle     = 5
)

var (
	controlAcks = map[uint8]uint8{
		PacketDNSQueryRequest:              PacketDNSQueryRequestAck,
		PacketDNSQueryResponse:             PacketDNSQueryResponseAck,
		PacketStreamSYN:                    PacketStreamSYNAck,
		PacketStreamConnected:              PacketStreamConnectedAck,
		PacketStreamConnectFail:            PacketStreamConnectFailAck,
		PacketStreamCloseWrite:             PacketStreamCloseWriteAck,
		PacketStreamCloseRead:              PacketStreamCloseReadAck,
		PacketStreamRST:                    PacketStreamRSTAck,
		PacketSOCKS5SYN:                    PacketSOCKS5SYNAck,
		PacketSOCKS5ConnectFail:            PacketSOCKS5ConnectFailAck,
		PacketSOCKS5RulesetDenied:          PacketSOCKS5RulesetDeniedAck,
		PacketSOCKS5NetworkUnreachable:     PacketSOCKS5NetworkUnreachableAck,
		PacketSOCKS5HostUnreachable:        PacketSOCKS5HostUnreachableAck,
		PacketSOCKS5ConnectionRefused:      PacketSOCKS5ConnectionRefusedAck,
		PacketSOCKS5TTLExpired:             PacketSOCKS5TTLExpiredAck,
		PacketSOCKS5CommandUnsupported:     PacketSOCKS5CommandUnsupportedAck,
		PacketSOCKS5AddressTypeUnsupported: PacketSOCKS5AddressTypeUnsupportedAck,
		PacketSOCKS5AuthFailed:             PacketSOCKS5AuthFailedAck,
		PacketSOCKS5UpstreamUnavailable:    PacketSOCKS5UpstreamUnavailableAck,
		PacketSOCKS5Connected:              PacketSOCKS5ConnectedAck,
	}
	controlAcked    = reverseMap(controlAcks)
	closeStreamAcks = map[uint8]uint8{
		PacketStreamRST:                    PacketStreamRSTAck,
		PacketStreamCloseWrite:             PacketStreamCloseWriteAck,
		PacketStreamCloseRead:              PacketStreamCloseReadAck,
		PacketSOCKS5RulesetDenied:          PacketSOCKS5RulesetDeniedAck,
		PacketSOCKS5NetworkUnreachable:     PacketSOCKS5NetworkUnreachableAck,
		PacketSOCKS5HostUnreachable:        PacketSOCKS5HostUnreachableAck,
		PacketSOCKS5ConnectionRefused:      PacketSOCKS5ConnectionRefusedAck,
		PacketSOCKS5TTLExpired:             PacketSOCKS5TTLExpiredAck,
		PacketSOCKS5CommandUnsupported:     PacketSOCKS5CommandUnsupportedAck,
		PacketSOCKS5AddressTypeUnsupported: PacketSOCKS5AddressTypeUnsupportedAck,
		PacketSOCKS5AuthFailed:             PacketSOCKS5AuthFailedAck,
		PacketSOCKS5UpstreamUnavailable:    PacketSOCKS5UpstreamUnavailableAck,
		PacketStreamConnectFail:            PacketStreamConnectFailAck,
		PacketSOCKS5ConnectFail:            PacketSOCKS5ConnectFailAck,
	}
)

// ControlAck returns the acknowledgement type the receiver of packetType queues.
func ControlAck(packetType uint8) (uint8, bool) {
	ackType, loaded := controlAcks[packetType]
	return ackType, loaded
}

// AckedControl returns the control type that ackType acknowledges.
func AckedControl(ackType uint8) (uint8, bool) {
	packetType, loaded := controlAcked[ackType]
	return packetType, loaded
}

// CloseStreamAck returns the acknowledgement of a stream-terminating packet type.
func CloseStreamAck(packetType uint8) (uint8, bool) {
	ackType, loaded := closeStreamAcks[packetType]
	return ackType, loaded
}

func IsPackable(packetType uint8, payloadLength int) bool {
	if payloadLength != 0 {
		return false
	}
	switch packetType {
	case PacketStreamDataAck, PacketStreamDataNack, PacketStreamSYNAck,
		PacketStreamCloseWriteAck, PacketStreamCloseReadAck, PacketStreamRSTAck, PacketSOCKS5SYNAck,
		PacketStreamConnected, PacketStreamConnectedAck, PacketStreamConnectFail, PacketStreamConnectFailAck,
		PacketDNSQueryRequestAck, PacketDNSQueryResponseAck:
		return true
	}
	return IsSOCKSResult(packetType)
}

// IsSOCKSResult reports the SOCKS5 connect results and their acknowledgements.
func IsSOCKSResult(packetType uint8) bool {
	return packetType >= PacketSOCKS5ConnectFail && packetType <= PacketSOCKS5ConnectedAck
}

func DefaultPriority(packetType uint8) int {
	switch packetType {
	case PacketStreamDataAck, PacketStreamDataNack, PacketStreamSYN, PacketStreamSYNAck,
		PacketStreamConnected, PacketStreamConnectedAck, PacketStreamConnectFail, PacketStreamConnectFailAck,
		PacketStreamCloseWriteAck, PacketStreamCloseRead, PacketStreamCloseReadAck, PacketStreamRST, PacketStreamRSTAck,
		PacketSOCKS5SYN, PacketSOCKS5SYNAck, PacketDNSQueryRequestAck, PacketDNSQueryResponseAck:
		return PriorityCritical
	case PacketStreamResend, PacketDNSQueryResponse, PacketDNSQueryRequest:
		return PriorityRetry
	case PacketStreamData:
		return PriorityNormal
	case PacketStreamCloseWrite, PacketSessionClose:
		return PriorityLow
	case PacketPing, PacketPong:
		return PriorityIdle
	}
	if IsSOCKSResult(packetType) {
		return PriorityCritical
	}
	return PriorityNormal
}

func NormalizePriority(packetType uint8, priority int) int {
	if priority >= PriorityCritical && priority <= PriorityIdle {
		return priority
	}
	return DefaultPriority(packetType)
}

// IdentityKey is the queue de-duplication key of a packet, keyed by fragment, sequence or stream depending on the type.
func IdentityKey(streamID uint16, packetType uint8, sequenceNum uint16, fragmentID uint8) uint64 {
	switch packetType {
	case PacketStreamCloseWrite, PacketStreamCloseWriteAck, PacketStreamCloseRead, PacketStreamCloseReadAck,
		PacketStreamRST, PacketStreamRSTAck, PacketStreamConnected, PacketStreamConnectedAck,
		PacketStreamConnectFail, PacketStreamConnectFailAck, PacketPackedControlBlocks, PacketErrorDrop,
		PacketPing, PacketPong:
		return StreamTypeKey(streamID, packetType) | uint64(sequenceNum)<<8
	case PacketSessionClose, PacketSessionBusy:
		return StreamTypeKey(streamID, packetType)
	}
	if IsSOCKSResult(packetType) {
		return StreamTypeKey(streamID, packetType) | uint64(sequenceNum)<<8
	}
	return StreamTypeKey(streamID, packetType) | uint64(sequenceNum)<<8 | uint64(fragmentID)
}

func StreamTypeKey(streamID uint16, packetType uint8) uint64 {
	return uint64(streamID)<<40 | uint64(packetType)<<32
}

func reverseMap(source map[uint8]uint8) map[uint8]uint8 {
	reversed := make(map[uint8]uint8, len(source))
	for key, value := range source {
		reversed[value] = key
	}
	return reversed
}
