package dnstt

import (
	"bytes"
	"encoding/binary"
	"io"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ModeDNSTT  = "dnstt"
	ModeVayDNS = "vaydns"
)

const (
	dnsttClientIDSize  = 8
	vaydnsClientIDSize = 2

	dataPaddingLength = 3
	pollPaddingLength = 8
	pollNonceLength   = 4
	paddingPrefix     = 224

	vaydnsMaxQNameLen       = 253
	vaydnsDefaultQNameLen   = 101
	dnsttMinimumMTU         = 80
	vaydnsMinimumMTU        = 25
	dnsttQueueSize          = 128
	vaydnsQueueSize         = 512
	vaydnsMaxDataLength     = 255
	paddedMaxDataLength     = paddingPrefix - 1
	encodedLabelLength      = maxLabelLength
	encodedLabelWireLength  = encodedLabelLength + 1
	base32BlockLength       = 8
	base32BlockDecodeLength = 5
)

type wireFormat struct {
	vaydns       bool
	padded       bool
	clientIDSize int
	domain       dnsName
	recordType   uint16
	maxQNameLen  int
}

func (w *wireFormat) encodedCapacity() (int, error) {
	if !w.vaydns {
		return 0, nil
	}
	available := w.maxQNameLen - w.domain.wireLength()
	if available <= 0 {
		return 0, E.New("domain ", w.domain, " is too long for max_qname_len ", w.maxQNameLen)
	}
	return available * encodedLabelLength / encodedLabelWireLength, nil
}

// See dnsNameCapacity in dnstt-client and DNSNameCapacity in VayDNS.
func (w *wireFormat) mtu() (int, error) {
	var capacity int
	if w.vaydns {
		encodedCapacity, err := w.encodedCapacity()
		if err != nil {
			return 0, err
		}
		capacity = encodedCapacity * base32BlockDecodeLength / base32BlockLength
	} else {
		capacity = (maxNameLength - 1 - w.domain.wireLength()) * encodedLabelLength / encodedLabelWireLength * base32BlockDecodeLength / base32BlockLength
	}
	var overhead int
	if w.padded {
		overhead = w.clientIDSize + 1 + dataPaddingLength + 1
	} else {
		overhead = w.clientIDSize + 1
	}
	mtu := capacity - overhead
	if w.vaydns {
		if mtu < vaydnsMinimumMTU {
			return 0, E.New("MTU ", mtu, " is too small (minimum ", vaydnsMinimumMTU, "), increase max_qname_len, use a shorter domain or decrease client_id_size")
		}
	} else if mtu < dnsttMinimumMTU {
		return 0, E.New("domain ", w.domain, " leaves only ", mtu, " bytes for payload")
	}
	return mtu, nil
}

func (w *wireFormat) queueSize() int {
	if w.vaydns {
		return vaydnsQueueSize
	}
	return dnsttQueueSize
}

func (w *wireFormat) appendPayload(buffer []byte, clientID []byte, packet []byte, random io.Reader) ([]byte, error) {
	buffer = append(buffer, clientID...)
	switch {
	case w.padded:
		if len(packet) > paddedMaxDataLength {
			return nil, E.New("packet too long: ", len(packet))
		}
		paddingLength := pollPaddingLength
		if len(packet) > 0 {
			paddingLength = dataPaddingLength
		}
		buffer = append(buffer, byte(paddingPrefix+paddingLength))
		padding := make([]byte, paddingLength)
		_, err := io.ReadFull(random, padding)
		if err != nil {
			return nil, err
		}
		buffer = append(buffer, padding...)
		if len(packet) > 0 {
			buffer = append(buffer, byte(len(packet)))
			buffer = append(buffer, packet...)
		}
	case len(packet) > 0:
		if len(packet) > vaydnsMaxDataLength {
			return nil, E.New("packet too long: ", len(packet))
		}
		buffer = append(buffer, byte(len(packet)))
		buffer = append(buffer, packet...)
	default:
		nonce := make([]byte, pollNonceLength)
		_, err := io.ReadFull(random, nonce)
		if err != nil {
			return nil, err
		}
		buffer = append(buffer, nonce...)
	}
	return buffer, nil
}

func (w *wireFormat) encodeName(payload []byte) (dnsName, error) {
	encoded := make([]byte, base32Encoding.EncodedLen(len(payload)))
	base32Encoding.Encode(encoded, payload)
	encoded = bytes.ToLower(encoded)
	if w.vaydns {
		capacity, err := w.encodedCapacity()
		if err != nil {
			return nil, err
		}
		if len(encoded) > capacity {
			encoded = encoded[:capacity]
		}
	}
	labels := make([][]byte, 0, len(encoded)/encodedLabelLength+1+len(w.domain))
	for len(encoded) > 0 {
		length := min(len(encoded), encodedLabelLength)
		labels = append(labels, encoded[:length])
		encoded = encoded[length:]
	}
	return newName(append(labels, w.domain...))
}

func (w *wireFormat) queryType() uint16 {
	if w.vaydns {
		return w.recordType
	}
	return rrTypeTXT
}

// Randomness is consumed in reference order: padding or nonce first, then the message ID.
func (w *wireFormat) encodeQuery(clientID []byte, packet []byte, random io.Reader) ([]byte, error) {
	payload, err := w.appendPayload(nil, clientID, packet, random)
	if err != nil {
		return nil, err
	}
	name, err := w.encodeName(payload)
	if err != nil {
		return nil, err
	}
	var id [2]byte
	_, err = io.ReadFull(random, id[:])
	if err != nil {
		return nil, err
	}
	return appendQuery(nil, binary.BigEndian.Uint16(id[:]), name, w.queryType()), nil
}

// Any RCODE other than NOERROR voids the response, as in both references.
func (w *wireFormat) responsePayload(message *dnsMessage) (payload []byte, loaded bool) {
	if message.Flags&0x8000 == 0 || message.rcode() != rcodeNoError || len(message.Answer) == 0 {
		return nil, false
	}
	recordType := w.queryType()
	if recordType == rrTypeA || recordType == rrTypeAAAA {
		var data []byte
		for _, answer := range message.Answer {
			if answer.Type != recordType {
				return nil, false
			}
			data = append(data, answer.Data...)
		}
		payload, err := decodeMultiRR(data)
		if err != nil {
			return nil, false
		}
		return payload, true
	}
	if len(message.Answer) != 1 {
		return nil, false
	}
	answer := message.Answer[0]
	_, loaded = answer.Name.trimSuffix(w.domain)
	if !loaded || answer.Type != recordType {
		return nil, false
	}
	var err error
	switch recordType {
	case rrTypeNULL:
		payload = answer.Data
	case rrTypeCAA:
		payload, err = decodeCAA(answer.Data)
	case rrTypeCNAME, rrTypeNS:
		payload, err = decodeNameData(answer.Data, w.domain)
	case rrTypeMX:
		if len(answer.Data) < 2 {
			return nil, false
		}
		payload, err = decodeNameData(answer.Data[2:], w.domain)
	case rrTypeSRV:
		if len(answer.Data) < 6 {
			return nil, false
		}
		payload, err = decodeNameData(answer.Data[6:], w.domain)
	default:
		payload, err = decodeTXT(answer.Data)
	}
	if err != nil {
		return nil, false
	}
	return payload, true
}

func nextPacket(bundle []byte) (packet []byte, remaining []byte, loaded bool) {
	if len(bundle) < 2 {
		return nil, nil, false
	}
	length := int(binary.BigEndian.Uint16(bundle))
	bundle = bundle[2:]
	if len(bundle) < length {
		return nil, nil, false
	}
	return bundle[:length], bundle[length:], true
}
