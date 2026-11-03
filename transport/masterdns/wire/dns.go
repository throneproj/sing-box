package wire

import (
	"encoding/binary"
	"strings"

	"github.com/sagernet/sing-box/transport/masterdns/cipher"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	MaxNameLength  = 253
	MaxLabelLength = 63
	EDNSUDPSize    = 4096

	dnsHeaderSize     = 12
	dnsTypeTXT        = 16
	dnsTypeOPT        = 41
	dnsClassIN        = 1
	maxNameJumps      = 10
	maxNameWireLength = 255
)

var (
	ErrInvalidName     = E.New("invalid dns name")
	ErrInvalidQuestion = E.New("invalid dns question section")
	ErrInvalidRecord   = E.New("invalid dns resource record section")
	ErrMessageTooShort = E.New("dns message too short")
)

// Domain is a normalized tunnel domain with its wire form.
type Domain struct {
	name  string
	qname []byte
}

func NewDomain(name string) (Domain, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || name == "." {
		return Domain{}, ErrInvalidName
	}
	qname, err := appendName(nil, name)
	if err != nil {
		return Domain{}, err
	}
	return Domain{name: name, qname: qname}, nil
}

func (d Domain) String() string {
	return d.name
}

// EncodeFrame encrypts a raw frame and appends its lower-case base36 form to dst.
func EncodeFrame(dst []byte, codec *cipher.Codec, raw []byte) ([]byte, error) {
	encrypted, err := codec.Encrypt(nil, raw)
	if err != nil {
		return nil, err
	}
	return AppendBase36(dst, encrypted), nil
}

func DecodeFrame(dst []byte, codec *cipher.Codec, encoded []byte) ([]byte, error) {
	encrypted, err := DecodeBase36(nil, encoded)
	if err != nil {
		return nil, err
	}
	return codec.Decrypt(dst, encrypted)
}

// AppendQuery appends a TXT query for the encoded frame under domain with an EDNS0 record advertising 4096 bytes.
func AppendQuery(dst []byte, id uint16, domain Domain, encoded []byte) ([]byte, error) {
	if len(domain.qname) == 0 {
		return nil, ErrInvalidName
	}
	if len(encoded) > 0 && queryNameLength(len(encoded), len(domain.name)) > MaxNameLength {
		return nil, ErrInvalidName
	}
	dst = binary.BigEndian.AppendUint16(dst, id)
	dst = append(dst, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	for start := 0; start < len(encoded); start += MaxLabelLength {
		label := encoded[start:min(start+MaxLabelLength, len(encoded))]
		dst = append(append(dst, byte(len(label))), label...)
	}
	dst = append(dst, domain.qname...)
	dst = binary.BigEndian.AppendUint16(dst, dnsTypeTXT)
	dst = binary.BigEndian.AppendUint16(dst, dnsClassIN)
	dst = append(dst, 0x00)
	dst = binary.BigEndian.AppendUint16(dst, dnsTypeOPT)
	dst = binary.BigEndian.AppendUint16(dst, EDNSUDPSize)
	return append(dst, 0, 0, 0, 0, 0, 0), nil
}

// MaxEncodedChars is how many encoded characters fit in a query name under domain.
func MaxEncodedChars(domain string) int {
	domainLength := len(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domainLength <= 0 {
		return MaxNameLength
	}
	low, high, best := 0, MaxNameLength, 0
	for low <= high {
		middle := (low + high) / 2
		if queryNameLength(middle, domainLength) <= MaxNameLength {
			best = middle
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	return best
}

// queryNameLength is the presentation length of encoded characters split into 63-byte labels under a domain.
func queryNameLength(encodedChars int, domainLength int) int {
	if encodedChars <= 0 {
		return domainLength
	}
	return encodedChars + (encodedChars-1)/MaxLabelLength + 1 + domainLength
}

// SplitName returns the encoded labels of a query name under the longest matching domain, without dots.
func SplitName(name string, domains []string) (labels string, domain string, ok bool) {
	name = strings.TrimSuffix(name, ".")
	for _, candidate := range domains {
		if len(candidate) > len(domain) && (name == candidate || strings.HasSuffix(name, "."+candidate)) {
			domain = candidate
			ok = true
		}
	}
	if !ok || name == domain {
		return "", domain, ok
	}
	return strings.ReplaceAll(name[:len(name)-len(domain)-1], ".", ""), domain, true
}

type header struct {
	id      uint16
	flags   uint16
	qdCount uint16
	anCount uint16
	nsCount uint16
	arCount uint16
}

func parseHeader(message []byte) header {
	return header{
		id:      binary.BigEndian.Uint16(message[0:2]),
		flags:   binary.BigEndian.Uint16(message[2:4]),
		qdCount: binary.BigEndian.Uint16(message[4:6]),
		anCount: binary.BigEndian.Uint16(message[6:8]),
		nsCount: binary.BigEndian.Uint16(message[8:10]),
		arCount: binary.BigEndian.Uint16(message[10:12]),
	}
}

func appendName(dst []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return append(dst, 0), nil
	}
	if len(name) > MaxNameLength {
		return nil, ErrInvalidName
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > MaxLabelLength {
			return nil, ErrInvalidName
		}
		dst = append(append(dst, byte(len(label))), label...)
	}
	return append(dst, 0), nil
}

// walkName follows a possibly compressed name, writing its lower-cased labels to name when set.
func walkName(message []byte, offset int, name *strings.Builder) (next int, hasLabel bool, err error) {
	if offset >= len(message) {
		return offset, false, ErrInvalidName
	}
	var (
		jumped     bool
		jumps      int
		wireLength = 1
	)
	next = offset
	for {
		if offset >= len(message) {
			return next, hasLabel, ErrInvalidName
		}
		length := int(message[offset])
		if length == 0 {
			if !jumped {
				next = offset + 1
			}
			return next, hasLabel, nil
		}
		if length >= 0xC0 {
			if offset+1 >= len(message) || jumps >= maxNameJumps {
				return next, hasLabel, ErrInvalidName
			}
			// Pointers may only go backwards, which also rules out loops.
			pointer := int(binary.BigEndian.Uint16(message[offset:]) & 0x3FFF)
			if pointer < dnsHeaderSize || pointer >= offset || pointer >= len(message) {
				return next, hasLabel, ErrInvalidName
			}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = pointer
			jumps++
			continue
		}
		if length > MaxLabelLength || wireLength+length+1 > maxNameWireLength {
			return next, hasLabel, ErrInvalidName
		}
		wireLength += length + 1
		offset++
		end := offset + length
		if end > len(message) {
			return next, hasLabel, ErrInvalidName
		}
		if name != nil {
			if hasLabel {
				name.WriteByte('.')
			}
			for _, char := range message[offset:end] {
				if char >= 'A' && char <= 'Z' {
					char += 'a' - 'A'
				}
				name.WriteByte(char)
			}
		}
		hasLabel = true
		offset = end
		if !jumped {
			next = offset
		}
	}
}

func parseName(message []byte, offset int) (string, int, error) {
	var name strings.Builder
	next, hasLabel, err := walkName(message, offset, &name)
	if err != nil {
		return "", next, err
	}
	if !hasLabel {
		return ".", next, nil
	}
	return name.String(), next, nil
}

func skipQuestions(message []byte, offset int, count int) (int, error) {
	for range count {
		next, _, err := walkName(message, offset, nil)
		if err != nil || next+4 > len(message) {
			return offset, ErrInvalidQuestion
		}
		offset = next + 4
	}
	return offset, nil
}

type record struct {
	recordType uint16
	start      int
	data       []byte
}

// nextRecord reads the resource record at offset.
func nextRecord(message []byte, offset int) (record, int, error) {
	next, _, err := walkName(message, offset, nil)
	if err != nil || next+10 > len(message) {
		return record{}, offset, ErrInvalidRecord
	}
	end := next + 10 + int(binary.BigEndian.Uint16(message[next+8:]))
	if end > len(message) {
		return record{}, offset, ErrInvalidRecord
	}
	return record{
		recordType: binary.BigEndian.Uint16(message[next:]),
		start:      offset,
		data:       message[next+10 : end],
	}, end, nil
}

func skipRecords(message []byte, offset int, count int) (int, error) {
	for range count {
		_, next, err := nextRecord(message, offset)
		if err != nil {
			return offset, err
		}
		offset = next
	}
	return offset, nil
}
