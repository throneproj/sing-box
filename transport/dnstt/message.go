package dnstt

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"io"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	rrTypeA     uint16 = 1
	rrTypeNS    uint16 = 2
	rrTypeCNAME uint16 = 5
	rrTypeNULL  uint16 = 10
	rrTypeMX    uint16 = 15
	rrTypeTXT   uint16 = 16
	rrTypeAAAA  uint16 = 28
	rrTypeSRV   uint16 = 33
	rrTypeOPT   uint16 = 41
	rrTypeCAA   uint16 = 257

	classIN uint16 = 1

	rcodeNoError = 0

	compressionPointerLimit = 10
	maxNameLength           = 255
	maxLabelLength          = 63
	ednsPayloadSize         = 4096
)

var (
	base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

	errZeroLengthLabel = E.New("name contains a zero-length label")
	errLabelTooLong    = E.New("name contains a label longer than 63 octets")
	errNameTooLong     = E.New("name is longer than 255 octets")
	errReservedLabel   = E.New("reserved label type")
	errTooManyPointers = E.New("too many compression pointers")
	errTrailingBytes   = E.New("trailing bytes after message")
)

func parseRecordType(recordType string) (uint16, error) {
	switch strings.ToLower(recordType) {
	case "", "txt":
		return rrTypeTXT, nil
	case "null":
		return rrTypeNULL, nil
	case "cname":
		return rrTypeCNAME, nil
	case "a":
		return rrTypeA, nil
	case "aaaa":
		return rrTypeAAAA, nil
	case "mx":
		return rrTypeMX, nil
	case "ns":
		return rrTypeNS, nil
	case "srv":
		return rrTypeSRV, nil
	case "caa":
		return rrTypeCAA, nil
	default:
		return 0, E.New("unknown record type: ", recordType)
	}
}

type dnsName [][]byte

func newName(labels [][]byte) (dnsName, error) {
	length := 1
	for _, label := range labels {
		if len(label) == 0 {
			return nil, errZeroLengthLabel
		}
		if len(label) > maxLabelLength {
			return nil, errLabelTooLong
		}
		length += len(label) + 1
	}
	if length > maxNameLength {
		return nil, errNameTooLong
	}
	return labels, nil
}

func parseName(name string) (dnsName, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return newName(nil)
	}
	return newName(bytes.Split([]byte(name), []byte(".")))
}

// wireLength excludes the root label, matching how VayDNS counts QNAME length.
func (n dnsName) wireLength() int {
	var length int
	for _, label := range n {
		length += len(label) + 1
	}
	return length
}

func (n dnsName) trimSuffix(suffix dnsName) (dnsName, bool) {
	if len(n) < len(suffix) {
		return nil, false
	}
	split := len(n) - len(suffix)
	for i, label := range n[split:] {
		if !bytes.Equal(bytes.ToLower(label), bytes.ToLower(suffix[i])) {
			return nil, false
		}
	}
	return n[:split], true
}

func (n dnsName) appendWire(buffer []byte) []byte {
	for _, label := range n {
		buffer = append(buffer, byte(len(label)))
		buffer = append(buffer, label...)
	}
	return append(buffer, 0)
}

func (n dnsName) String() string {
	if len(n) == 0 {
		return "."
	}
	return string(bytes.Join(n, []byte(".")))
}

type dnsQuestion struct {
	Name  dnsName
	Type  uint16
	Class uint16
}

type dnsRR struct {
	Name  dnsName
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

type dnsMessage struct {
	ID         uint16
	Flags      uint16
	Question   []dnsQuestion
	Answer     []dnsRR
	Authority  []dnsRR
	Additional []dnsRR
}

func (m *dnsMessage) rcode() int {
	return int(m.Flags & 0x000f)
}

type messageReader struct {
	data   []byte
	offset int
}

func (r *messageReader) read(n int) ([]byte, error) {
	if r.offset > len(r.data) || len(r.data)-r.offset < n {
		return nil, io.ErrUnexpectedEOF
	}
	content := r.data[r.offset : r.offset+n]
	r.offset += n
	return content, nil
}

func (r *messageReader) readUint16() (uint16, error) {
	content, err := r.read(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(content), nil
}

func (r *messageReader) readUint32() (uint32, error) {
	content, err := r.read(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(content), nil
}

func (r *messageReader) readName() (dnsName, error) {
	var (
		labels   [][]byte
		pointers int
		resume   int
	)
	for {
		prefix, err := r.read(1)
		if err != nil {
			return nil, err
		}
		switch prefix[0] & 0xc0 {
		case 0x00:
			length := int(prefix[0] & 0x3f)
			if length == 0 {
				if pointers > 0 {
					r.offset = resume
				}
				return newName(labels)
			}
			label, err := r.read(length)
			if err != nil {
				return nil, err
			}
			labels = append(labels, bytes.Clone(label))
		case 0xc0:
			lower, err := r.read(1)
			if err != nil {
				return nil, err
			}
			if pointers == 0 {
				resume = r.offset
			}
			pointers++
			if pointers > compressionPointerLimit {
				return nil, errTooManyPointers
			}
			r.offset = int(prefix[0]&0x3f)<<8 | int(lower[0])
		default:
			return nil, errReservedLabel
		}
	}
}

func (r *messageReader) readQuestion() (dnsQuestion, error) {
	var (
		question dnsQuestion
		err      error
	)
	question.Name, err = r.readName()
	if err != nil {
		return question, err
	}
	question.Type, err = r.readUint16()
	if err != nil {
		return question, err
	}
	question.Class, err = r.readUint16()
	return question, err
}

func (r *messageReader) readRR() (dnsRR, error) {
	var (
		rr  dnsRR
		err error
	)
	rr.Name, err = r.readName()
	if err != nil {
		return rr, err
	}
	rr.Type, err = r.readUint16()
	if err != nil {
		return rr, err
	}
	rr.Class, err = r.readUint16()
	if err != nil {
		return rr, err
	}
	rr.TTL, err = r.readUint32()
	if err != nil {
		return rr, err
	}
	dataLength, err := r.readUint16()
	if err != nil {
		return rr, err
	}
	switch {
	case dataLength > 0 && (rr.Type == rrTypeCNAME || rr.Type == rrTypeNS):
		rr.Data, err = r.readDataName(int(dataLength), 0)
	case dataLength > 2 && rr.Type == rrTypeMX:
		rr.Data, err = r.readDataName(int(dataLength), 2)
	case dataLength > 6 && rr.Type == rrTypeSRV:
		rr.Data, err = r.readDataName(int(dataLength), 6)
	default:
		var data []byte
		data, err = r.read(int(dataLength))
		rr.Data = bytes.Clone(data)
	}
	return rr, err
}

// Names in RDATA are decompressed as VayDNS does, else kept raw; either way the reader ends at RDATA end.
func (r *messageReader) readDataName(dataLength int, headerLength int) ([]byte, error) {
	start := r.offset
	header, err := r.read(headerLength)
	if err != nil {
		return nil, err
	}
	name, err := r.readName()
	if err != nil {
		r.offset = start
		data, err := r.read(dataLength)
		return bytes.Clone(data), err
	}
	data := append(bytes.Clone(header), name.appendWire(nil)...)
	r.offset = start + dataLength
	return data, nil
}

func parseMessage(content []byte) (*dnsMessage, error) {
	reader := &messageReader{data: content}
	var (
		message dnsMessage
		err     error
	)
	message.ID, err = reader.readUint16()
	if err != nil {
		return nil, err
	}
	message.Flags, err = reader.readUint16()
	if err != nil {
		return nil, err
	}
	var counts [4]uint16
	for i := range counts {
		counts[i], err = reader.readUint16()
		if err != nil {
			return nil, err
		}
	}
	for range counts[0] {
		question, err := reader.readQuestion()
		if err != nil {
			return nil, err
		}
		message.Question = append(message.Question, question)
	}
	for i, section := range []*[]dnsRR{&message.Answer, &message.Authority, &message.Additional} {
		for range counts[i+1] {
			rr, err := reader.readRR()
			if err != nil {
				return nil, err
			}
			*section = append(*section, rr)
		}
	}
	if reader.offset < len(content) {
		return nil, errTrailingBytes
	}
	return &message, nil
}

// As in both references: RD only, one question and an empty EDNS(0) OPT advertising 4096 bytes.
func appendQuery(buffer []byte, id uint16, name dnsName, qType uint16) []byte {
	buffer = binary.BigEndian.AppendUint16(buffer, id)
	buffer = binary.BigEndian.AppendUint16(buffer, 0x0100)
	buffer = binary.BigEndian.AppendUint16(buffer, 1)
	buffer = binary.BigEndian.AppendUint16(buffer, 0)
	buffer = binary.BigEndian.AppendUint16(buffer, 0)
	buffer = binary.BigEndian.AppendUint16(buffer, 1)
	buffer = name.appendWire(buffer)
	buffer = binary.BigEndian.AppendUint16(buffer, qType)
	buffer = binary.BigEndian.AppendUint16(buffer, classIN)
	buffer = append(buffer, 0)
	buffer = binary.BigEndian.AppendUint16(buffer, rrTypeOPT)
	buffer = binary.BigEndian.AppendUint16(buffer, ednsPayloadSize)
	buffer = binary.BigEndian.AppendUint32(buffer, 0)
	return binary.BigEndian.AppendUint16(buffer, 0)
}

func decodeTXT(data []byte) ([]byte, error) {
	var payload []byte
	for {
		if len(data) == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(data[0])
		data = data[1:]
		if len(data) < length {
			return nil, io.ErrUnexpectedEOF
		}
		payload = append(payload, data[:length]...)
		data = data[length:]
		if len(data) == 0 {
			return payload, nil
		}
	}
}

func decodeCAA(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	tagLength := int(data[1])
	data = data[2:]
	if len(data) < tagLength {
		return nil, io.ErrUnexpectedEOF
	}
	return data[tagLength:], nil
}

func decodeNameData(data []byte, domain dnsName) ([]byte, error) {
	var labels dnsName
	for i := 0; ; {
		if i >= len(data) {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(data[i])
		i++
		if length == 0 {
			break
		}
		if length > maxLabelLength {
			return nil, errLabelTooLong
		}
		if i+length > len(data) {
			return nil, io.ErrUnexpectedEOF
		}
		labels = append(labels, data[i:i+length])
		i += length
	}
	prefix, loaded := labels.trimSuffix(domain)
	if !loaded {
		return nil, E.New("name does not end with domain ", domain)
	}
	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		return nil, err
	}
	return payload[:n], nil
}

func decodeMultiRR(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	length := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	if len(data) < length {
		return nil, io.ErrUnexpectedEOF
	}
	return data[:length], nil
}
