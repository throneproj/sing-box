package wire

import (
	"encoding/binary"
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	socksAddressIPv4   = 0x01
	socksAddressDomain = 0x03
	socksAddressIPv6   = 0x04
)

const (
	SOCKSReplyGeneralFailure     = 0x01
	SOCKSReplyRulesetDenied      = 0x02
	SOCKSReplyNetworkUnreachable = 0x03
	SOCKSReplyHostUnreachable    = 0x04
	SOCKSReplyConnectionRefused  = 0x05
	SOCKSReplyTTLExpired         = 0x06
	SOCKSReplyCommandUnsupported = 0x07
	SOCKSReplyAddressUnsupported = 0x08
)

// AppendSOCKSTarget encodes the SOCKS5_SYN payload [ATYP][address][port].
func AppendSOCKSTarget(dst []byte, destination M.Socksaddr) ([]byte, error) {
	destination = destination.Unwrap()
	switch {
	case destination.IsIPv4():
		dst = append(append(dst, socksAddressIPv4), destination.Addr.AsSlice()...)
	case destination.IsIPv6():
		dst = append(append(dst, socksAddressIPv6), destination.Addr.AsSlice()...)
	case destination.IsDomain():
		if len(destination.Fqdn) > 255 {
			return nil, E.New("domain too long: ", destination.Fqdn)
		}
		dst = append(append(dst, socksAddressDomain, byte(len(destination.Fqdn))), destination.Fqdn...)
	default:
		return nil, E.New("invalid destination: ", destination)
	}
	return binary.BigEndian.AppendUint16(dst, destination.Port), nil
}

// ParseSOCKSTarget decodes a SOCKS5_SYN payload with the checks of the reference server.
func ParseSOCKSTarget(payload []byte) (M.Socksaddr, error) {
	if len(payload) < 3 {
		return M.Socksaddr{}, E.New("socks target too short")
	}
	var (
		destination M.Socksaddr
		offset      = 1
	)
	switch payload[0] {
	case socksAddressIPv4:
		if len(payload) < offset+4+2 {
			return M.Socksaddr{}, E.New("socks target too short")
		}
		destination.Addr = netip.AddrFrom4([4]byte(payload[offset : offset+4]))
		offset += 4
	case socksAddressDomain:
		length := int(payload[offset])
		offset++
		if length < 1 || len(payload) < offset+length+2 {
			return M.Socksaddr{}, E.New("invalid socks domain length")
		}
		destination = M.ParseSocksaddrHostPort(string(payload[offset:offset+length]), 0)
		offset += length
	case socksAddressIPv6:
		if len(payload) < offset+16+2 {
			return M.Socksaddr{}, E.New("socks target too short")
		}
		destination.Addr = netip.AddrFrom16([16]byte(payload[offset : offset+16])).Unmap()
		offset += 16
	default:
		return M.Socksaddr{}, E.New("unsupported socks address type: ", payload[0])
	}
	destination.Port = binary.BigEndian.Uint16(payload[offset:])
	return destination, nil
}

// SOCKSReply maps a SOCKS5 failure packet to its SOCKS5 reply code; ok is false for anything else.
func SOCKSReply(packetType uint8) (reply byte, ok bool) {
	switch packetType {
	case PacketSOCKS5ConnectFail, PacketSOCKS5AuthFailed, PacketSOCKS5UpstreamUnavailable:
		return SOCKSReplyGeneralFailure, true
	case PacketSOCKS5RulesetDenied:
		return SOCKSReplyRulesetDenied, true
	case PacketSOCKS5NetworkUnreachable:
		return SOCKSReplyNetworkUnreachable, true
	case PacketSOCKS5HostUnreachable:
		return SOCKSReplyHostUnreachable, true
	case PacketSOCKS5ConnectionRefused:
		return SOCKSReplyConnectionRefused, true
	case PacketSOCKS5TTLExpired:
		return SOCKSReplyTTLExpired, true
	case PacketSOCKS5CommandUnsupported:
		return SOCKSReplyCommandUnsupported, true
	case PacketSOCKS5AddressTypeUnsupported:
		return SOCKSReplyAddressUnsupported, true
	default:
		return 0, false
	}
}
