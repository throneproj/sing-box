package wire

import (
	"encoding/base64"
	"encoding/binary"
	"strings"

	"github.com/sagernet/sing-box/transport/masterdns/compress"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	maxTXTChunk       = 255
	maxTXTBase64Chunk = 191
)

var (
	ErrNoTXTAnswer        = E.New("dns txt answer missing")
	ErrMalformedTXTAnswer = E.New("dns txt answer malformed")
	ErrTXTAnswerTooLarge  = E.New("dns txt answer too large")
)

// ParseResponse extracts and inflates the packet carried by the TXT answers of a DNS response.
// The payload may alias message.
func ParseResponse(message []byte, base64Response bool) (Packet, error) {
	if len(message) < dnsHeaderSize {
		return Packet{}, ErrMessageTooShort
	}
	header := parseHeader(message)
	offset, err := skipQuestions(message, dnsHeaderSize, int(header.qdCount))
	if err != nil {
		return Packet{}, err
	}
	var answers [][]byte
	for range header.anCount {
		var answer record
		answer, offset, err = nextRecord(message, offset)
		if err != nil {
			return Packet{}, err
		}
		if answer.recordType != dnsTypeTXT {
			continue
		}
		data := txtData(answer.data)
		if len(data) > 0 {
			answers = append(answers, data)
		}
	}
	// The reference parses every section before looking at the answers.
	_, err = skipRecords(message, offset, int(header.nsCount)+int(header.arCount))
	if err != nil {
		return Packet{}, err
	}
	if len(answers) == 0 {
		return Packet{}, ErrNoTXTAnswer
	}
	if len(answers) == 1 {
		frame := answers[0]
		if base64Response {
			frame, err = base64.RawStdEncoding.AppendDecode(nil, frame)
			if err != nil {
				return Packet{}, err
			}
		}
		packet, err := ParsePacket(frame)
		if err != nil {
			return Packet{}, err
		}
		err = packet.Inflate()
		if err != nil {
			return Packet{}, err
		}
		return packet, nil
	}
	return assembleChunks(answers, base64Response)
}

// ResponseRCode returns the RCODE of a message whose header and questions parse.
func ResponseRCode(message []byte) (uint8, bool) {
	if len(message) < dnsHeaderSize {
		return 0, false
	}
	header := parseHeader(message)
	_, err := skipQuestions(message, dnsHeaderSize, int(header.qdCount))
	if err != nil {
		return 0, false
	}
	return uint8(header.flags & 0x0F), true
}

// txtData joins the character strings of TXT record data, keeping a truncated last string.
func txtData(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	if int(data[0])+1 == len(data) {
		return data[1:]
	}
	var joined []byte
	for offset := 0; offset < len(data); {
		size := int(data[offset])
		offset++
		end := min(offset+size, len(data))
		joined = append(joined, data[offset:end]...)
		offset = end
	}
	return joined
}

func assembleChunks(answers [][]byte, base64Response bool) (Packet, error) {
	var (
		chunks     [256][]byte
		present    [256]bool
		total      int
		seen       int
		header     Packet
		headerSeen bool
	)
	for _, chunk := range answers {
		if base64Response {
			var err error
			chunk, err = base64.RawStdEncoding.AppendDecode(nil, chunk)
			if err != nil {
				return Packet{}, err
			}
		}
		if len(chunk) == 0 {
			continue
		}
		index := int(chunk[0])
		if index == 0 {
			if len(chunk) < 3 || chunk[1] == 0 {
				return Packet{}, ErrMalformedTXTAnswer
			}
			total = int(chunk[1])
			parsed, err := ParsePacket(chunk[2:])
			if err != nil {
				return Packet{}, err
			}
			header = parsed
			headerSeen = true
			chunk = parsed.Payload
		} else {
			chunk = chunk[1:]
		}
		if !present[index] {
			present[index] = true
			seen++
		}
		chunks[index] = chunk
	}
	if !headerSeen || seen != total {
		return Packet{}, ErrMalformedTXTAnswer
	}
	var payload []byte
	for index := range chunks {
		if present[index] != (index < total) {
			return Packet{}, ErrMalformedTXTAnswer
		}
		payload = append(payload, chunks[index]...)
	}
	header.Payload = payload
	err := header.Inflate()
	if err != nil {
		return Packet{}, err
	}
	return header, nil
}

// Query is the first question of a tunnel request.
type Query struct {
	ID   uint16
	Name string
	Type uint16
}

// ParseQuery reads the ID and first question of a request; the name is lower-cased without the trailing dot.
func ParseQuery(message []byte) (Query, error) {
	if len(message) < dnsHeaderSize {
		return Query{}, ErrMessageTooShort
	}
	header := parseHeader(message)
	if header.qdCount == 0 {
		return Query{}, ErrInvalidQuestion
	}
	name, next, err := parseName(message, dnsHeaderSize)
	if err != nil || next+4 > len(message) {
		return Query{}, ErrInvalidQuestion
	}
	return Query{
		ID:   header.id,
		Name: strings.TrimSuffix(name, "."),
		Type: binary.BigEndian.Uint16(message[next:]),
	}, nil
}

// AppendResponse appends the TXT response a reference server sends for packet, splitting large frames into chunks.
func AppendResponse(dst []byte, query []byte, answerName string, packet Packet, base64Response bool) ([]byte, error) {
	frame, err := AppendCompressedPacket(nil, packet, compress.DefaultMinSize)
	if err != nil {
		return nil, err
	}
	maxChunk := maxTXTChunk
	if base64Response {
		maxChunk = maxTXTBase64Chunk
	}
	if len(frame) <= maxChunk {
		return appendTXTResponse(dst, query, answerName, [][]byte{appendTXTString(nil, frame, base64Response)})
	}
	answers, err := txtChunks(frame, base64Response, maxChunk)
	if err != nil {
		return nil, err
	}
	return appendTXTResponse(dst, query, answerName, answers)
}

// txtChunks splits a frame into answers: chunk 0 is [0][total][header][data], chunk n is [n][data].
func txtChunks(frame []byte, base64Response bool, maxChunk int) ([][]byte, error) {
	packet, err := ParsePacket(frame)
	if err != nil {
		return [][]byte{appendTXTString(nil, frame, base64Response)}, nil
	}
	headerSize := len(frame) - len(packet.Payload)
	firstData := max(maxChunk-2-headerSize, 0)
	chunkData := maxChunk - 1
	total := 1
	if remaining := len(packet.Payload) - firstData; remaining > 0 {
		total += (remaining + chunkData - 1) / chunkData
	}
	if total > 255 {
		return nil, ErrTXTAnswerTooLarge
	}
	firstData = min(firstData, len(packet.Payload))
	first := append([]byte{0, byte(total)}, frame[:headerSize+firstData]...)
	answers := [][]byte{appendTXTString(nil, first, base64Response)}
	for index, offset := 1, firstData; offset < len(packet.Payload); index++ {
		end := min(offset+chunkData, len(packet.Payload))
		chunk := append([]byte{byte(index)}, packet.Payload[offset:end]...)
		answers = append(answers, appendTXTString(nil, chunk, base64Response))
		offset = end
	}
	return answers, nil
}

// appendTXTString appends data as TXT record data, raw in 255-byte strings or as one unpadded base64 string.
func appendTXTString(dst []byte, data []byte, base64Response bool) []byte {
	if base64Response {
		dst = append(dst, byte(base64.RawStdEncoding.EncodedLen(len(data))))
		return base64.RawStdEncoding.AppendEncode(dst, data)
	}
	if len(data) == 0 {
		return append(dst, 0)
	}
	for start := 0; start < len(data); start += 255 {
		end := min(start+255, len(data))
		dst = append(append(dst, byte(end-start)), data[start:end]...)
	}
	return dst
}

func appendTXTResponse(dst []byte, query []byte, answerName string, answers [][]byte) ([]byte, error) {
	if len(query) < dnsHeaderSize {
		return nil, ErrMessageTooShort
	}
	header := parseHeader(query)
	questionEnd := dnsHeaderSize
	questionCount := header.qdCount
	if questionCount > 0 {
		var err error
		questionEnd, err = skipQuestions(query, dnsHeaderSize, int(questionCount))
		if err != nil {
			questionEnd, questionCount = 0, 0
		}
	}
	var opt []byte
	if questionEnd >= dnsHeaderSize {
		opt = findOPT(query, header, questionEnd)
	}
	name, err := answerNameBytes(query, answerName)
	if err != nil {
		return nil, err
	}
	dst = binary.BigEndian.AppendUint16(dst, header.id)
	dst = binary.BigEndian.AppendUint16(dst, responseFlags(header.flags))
	dst = binary.BigEndian.AppendUint16(dst, questionCount)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(answers)))
	dst = binary.BigEndian.AppendUint16(dst, 0)
	if len(opt) > 0 {
		dst = binary.BigEndian.AppendUint16(dst, 1)
	} else {
		dst = binary.BigEndian.AppendUint16(dst, 0)
	}
	start := len(dst)
	if questionEnd >= dnsHeaderSize {
		dst = append(dst, query[dnsHeaderSize:questionEnd]...)
	}
	firstAnswer := len(dst) - start + dnsHeaderSize
	for index, answer := range answers {
		if len(answers) > 1 && index > 0 && firstAnswer <= 0x3FFF {
			dst = binary.BigEndian.AppendUint16(dst, uint16(0xC000|firstAnswer))
		} else {
			dst = append(dst, name...)
		}
		dst = binary.BigEndian.AppendUint16(dst, dnsTypeTXT)
		dst = binary.BigEndian.AppendUint16(dst, dnsClassIN)
		dst = append(dst, 0, 0, 0, 0)
		dst = binary.BigEndian.AppendUint16(dst, uint16(len(answer)))
		dst = append(dst, answer...)
	}
	return append(dst, opt...), nil
}

// answerNameBytes reuses the wire form of the first question when it names the answer.
func answerNameBytes(query []byte, answerName string) ([]byte, error) {
	if binary.BigEndian.Uint16(query[4:6]) > 0 {
		name, next, err := parseName(query, dnsHeaderSize)
		if err == nil && next > dnsHeaderSize && strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(answerName, ".")) {
			return query[dnsHeaderSize:next], nil
		}
	}
	return appendName(nil, answerName)
}

func findOPT(query []byte, header header, offset int) []byte {
	if header.arCount == 0 || offset > len(query) {
		return nil
	}
	offset, err := skipRecords(query, offset, int(header.anCount)+int(header.nsCount))
	if err != nil {
		return nil
	}
	for range header.arCount {
		var current record
		current, offset, err = nextRecord(query, offset)
		if err != nil {
			return nil
		}
		if current.recordType == dnsTypeOPT {
			return query[current.start:offset]
		}
	}
	return nil
}

// responseFlags answers like a recursive resolver: QR and RA set, opcode, RD and CD copied, AA and TC cleared.
func responseFlags(requestFlags uint16) uint16 {
	return 0x8080 | requestFlags&(0x7800|0x0100|0x0010)
}
