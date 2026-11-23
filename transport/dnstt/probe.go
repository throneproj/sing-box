package dnstt

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	ProbeStagePoll  = "poll"
	ProbeStageQName = "qname"
)

const (
	ProbeReasonTimeout = "timeout"
	ProbeReasonRcode   = "rcode"
	ProbeReasonAnswer  = "answer"
	ProbeReasonQName   = "qname"
)

const (
	probeExchangeTimeout = 3 * time.Second
	probeBurstSize       = 8
	probeBurstInterval   = 20 * time.Millisecond
	probeShortQNameLen   = 60
	paddingBlockLength   = 32
	dnsttMaxQNameLen     = maxNameLength - 1
)

type ProbeResult struct {
	Passed         bool
	Stage          string
	Reason         string
	Rcode          int
	FirstReply     time.Duration
	ShortNamesOnly bool
	BurstSent      int
	BurstAnswered  int
}

// Probe returns only option errors; a failed probe sets Stage and Reason instead.
func Probe(ctx context.Context, options ClientOptions) (ProbeResult, error) {
	result := ProbeResult{Rcode: -1}
	if len(options.Resolvers) != 1 {
		return result, E.New("probe requires exactly one resolver")
	}
	client, err := NewClient(options)
	if err != nil {
		return result, err
	}
	defer client.Close()
	resolver := options.Resolvers[0]
	if resolver.Type == ResolverTypeSystem {
		resolvers := expandResolvers(options.Resolvers, options.SystemResolvers)
		if len(resolvers) == 0 {
			return result, E.New("no system resolver available")
		}
		resolver = resolvers[0]
	}
	clientID := make([]byte, client.wire.clientIDSize)
	_, err = rand.Read(clientID)
	if err != nil {
		return result, err
	}
	prober := newProber(client, resolver, clientID)
	defer prober.close()
	polls, err := prober.polls(2)
	if err != nil {
		return result, err
	}
	// The server holds a lone query for up to a second and releases it when the next one arrives, so queries go in pairs.
	replies := prober.exchangeAll(ctx, polls, 0, func(_ int, reply probeReply) bool {
		return reply.reason == ""
	})
	first := firstReply(replies)
	result.FirstReply = first.rtt
	if !common.Any(replies, func(it probeReply) bool { return it.reason == "" }) {
		result.Stage = ProbeStagePoll
		result.Reason = first.reason
		result.Rcode = first.rcode
		return result, nil
	}
	result.Rcode = rcodeNoError
	qNameLen := dnsttMaxQNameLen
	if client.wire.vaydns {
		qNameLen = client.wire.maxQNameLen
	}
	reply, err := prober.checkQName(ctx, qNameLen)
	if err != nil {
		return result, err
	}
	if reply.reason != "" {
		result.Stage = ProbeStageQName
		result.Reason = ProbeReasonQName
		result.Rcode = reply.rcode
		if qNameLen > probeShortQNameLen && probePayloadLength(client.wire, probeShortQNameLen) > len(clientID) {
			reply, err = prober.checkQName(ctx, probeShortQNameLen)
			if err != nil {
				return result, err
			}
			result.ShortNamesOnly = reply.reason == ""
		}
		return result, nil
	}
	polls, err = prober.polls(probeBurstSize)
	if err != nil {
		return result, err
	}
	replies = prober.exchangeAll(ctx, polls, probeBurstInterval, nil)
	result.BurstSent = len(replies)
	result.BurstAnswered = len(common.Filter(replies, func(it probeReply) bool { return it.reason == "" }))
	result.Passed = true
	return result, nil
}

// probeReply has a zero rtt when nothing came back and an empty reason for a valid empty answer.
type probeReply struct {
	rtt    time.Duration
	rcode  int
	reason string
}

func firstReply(replies []probeReply) probeReply {
	first := probeReply{rcode: -1, reason: ProbeReasonTimeout}
	for _, reply := range replies {
		if reply.rtt > 0 && (first.rtt == 0 || reply.rtt < first.rtt) {
			first = reply
		}
	}
	return first
}

type prober struct {
	client     *Client
	resolver   ResolverOptions
	clientID   []byte
	httpClient *http.Client
	transport  *dnsTransport.HTTPSTransportWrapper
}

func newProber(client *Client, resolver ResolverOptions, clientID []byte) *prober {
	p := &prober{
		client:   client,
		resolver: resolver,
		clientID: clientID,
	}
	if resolver.Type == ResolverTypeHTTPS {
		p.transport = dnsTransport.NewHTTPSTransportWrapper(tls.NewDialer(client.transportConfig.dialer, resolver.TLSConfig), resolver.Server, new(atomic.Bool))
		p.httpClient = &http.Client{Transport: p.transport}
	}
	return p
}

func (p *prober) close() {
	if p.transport != nil {
		p.transport.Close()
	}
}

func (p *prober) polls(count int) ([][]byte, error) {
	queries := make([][]byte, count)
	for i := range queries {
		query, err := p.client.wire.encodeQuery(p.clientID, nil, rand.Reader)
		if err != nil {
			return nil, err
		}
		queries[i] = query
	}
	return queries, nil
}

// checkQName sends a name of the given length with a poll behind it that releases it from the server's hold.
func (p *prober) checkQName(ctx context.Context, maxQNameLen int) (probeReply, error) {
	query, err := probeQNameQuery(p.client.wire, p.clientID, maxQNameLen)
	if err != nil {
		return probeReply{}, err
	}
	polls, err := p.polls(1)
	if err != nil {
		return probeReply{}, err
	}
	replies := p.exchangeAll(ctx, [][]byte{query, polls[0]}, 0, func(index int, _ probeReply) bool {
		return index == 0
	})
	return replies[0], nil
}

// exchangeAll sends the queries interval apart, each over its own connection, and returns the replies to those sent;
// settled ends the wait once the replies so far decide the result.
func (p *prober) exchangeAll(ctx context.Context, queries [][]byte, interval time.Duration, settled func(index int, reply probeReply) bool) []probeReply {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type indexedReply struct {
		index int
		reply probeReply
	}
	replyChan := make(chan indexedReply, len(queries))
	var sent int
	for index, query := range queries {
		if index > 0 && interval > 0 {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
			if ctx.Err() != nil {
				break
			}
		}
		go func() {
			replyChan <- indexedReply{index, p.exchange(ctx, query)}
		}()
		sent++
	}
	replies := make([]probeReply, sent)
	for range sent {
		received := <-replyChan
		replies[received.index] = received.reply
		if settled != nil && settled(received.index, received.reply) {
			cancel()
		}
	}
	return replies
}

func (p *prober) isEmptyAnswer(response *dnsMessage) bool {
	if len(response.Answer) != 1 || response.Answer[0].Type != p.client.wire.queryType() {
		return false
	}
	payload, loaded := p.client.wire.responsePayload(response)
	return loaded && len(payload) == 0
}

// The filler parses as padding or as a truncated packet, so the server queues nothing.
func probeQNameQuery(wire *wireFormat, clientID []byte, maxQNameLen int) ([]byte, error) {
	payload := make([]byte, probePayloadLength(wire, maxQNameLen))
	_, err := rand.Read(payload)
	if err != nil {
		return nil, err
	}
	copy(payload, clientID)
	for i := len(clientID); i < len(payload); i += paddingBlockLength {
		payload[i] = 0xff
		if !wire.padded {
			break
		}
	}
	encoded := make([]byte, base32Encoding.EncodedLen(len(payload)))
	base32Encoding.Encode(encoded, payload)
	encoded = bytes.ToLower(encoded)
	var labels [][]byte
	for len(encoded) > 0 {
		length := min(len(encoded), encodedLabelLength)
		labels = append(labels, encoded[:length])
		encoded = encoded[length:]
	}
	name, err := newName(append(labels, wire.domain...))
	if err != nil {
		return nil, err
	}
	var id [2]byte
	_, err = rand.Read(id[:])
	if err != nil {
		return nil, err
	}
	return appendQuery(nil, binary.BigEndian.Uint16(id[:]), name, wire.queryType()), nil
}

func probePayloadLength(wire *wireFormat, maxQNameLen int) int {
	available := maxQNameLen - wire.domain.wireLength()
	return available * encodedLabelLength / encodedLabelWireLength * base32BlockDecodeLength / base32BlockLength
}

func (p *prober) exchange(ctx context.Context, query []byte) probeReply {
	ctx, cancel := context.WithTimeout(ctx, probeExchangeTimeout)
	defer cancel()
	var (
		response []byte
		rtt      time.Duration
		err      error
	)
	switch p.resolver.Type {
	case ResolverTypeTCP, ResolverTypeTLS:
		response, rtt, err = p.exchangeStream(ctx, query)
	case ResolverTypeHTTPS:
		response, rtt, err = p.exchangeHTTPS(ctx, query)
	default:
		response, rtt, err = p.exchangeUDP(ctx, query)
	}
	if err != nil {
		return probeReply{rcode: -1, reason: ProbeReasonTimeout}
	}
	// A reply faster than the clock resolution must not read as none.
	reply := probeReply{rtt: max(rtt, time.Nanosecond), rcode: -1, reason: ProbeReasonAnswer}
	message, err := parseMessage(response)
	if err != nil {
		return reply
	}
	reply.rcode = message.rcode()
	if reply.rcode != rcodeNoError {
		reply.reason = ProbeReasonRcode
	} else if p.isEmptyAnswer(message) {
		reply.reason = ""
	}
	return reply
}

func isResponseTo(response []byte, query []byte) bool {
	return len(response) >= 12 && response[2]&0x80 != 0 && binary.BigEndian.Uint16(response) == binary.BigEndian.Uint16(query)
}

func (p *prober) exchangeUDP(ctx context.Context, query []byte) ([]byte, time.Duration, error) {
	config := p.client.transportConfig
	conn, err := config.dialer.ListenPacket(ctx, p.resolver.Server)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	defer stopClose()
	start := time.Now()
	_, err = conn.WriteTo(query, udpDestination(p.resolver.Server))
	if err != nil {
		return nil, 0, err
	}
	server := p.resolver.Server.Unwrap()
	buffer := make([]byte, maxMessageSize)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			return nil, 0, err
		}
		if M.SocksaddrFromNet(addr).Unwrap() != server || !isResponseTo(buffer[:n], query) {
			continue
		}
		rtt := time.Since(start)
		if isTruncated(buffer[:n]) && p.resolver.TCPFallback {
			response, err := exchangeTCP(ctx, config, p.resolver.Server, query)
			if err == nil {
				return response, rtt, nil
			}
		}
		return buffer[:n], rtt, nil
	}
}

func (p *prober) exchangeStream(ctx context.Context, query []byte) ([]byte, time.Duration, error) {
	var (
		conn net.Conn
		err  error
	)
	if p.resolver.Type == ResolverTypeTLS {
		conn, err = tls.NewDialer(p.client.transportConfig.dialer, p.resolver.TLSConfig).DialTLSContext(ctx, p.resolver.Server)
	} else {
		conn, err = p.client.transportConfig.dialer.DialContext(ctx, N.NetworkTCP, p.resolver.Server)
	}
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	defer stopClose()
	start := time.Now()
	err = writeStreamMessage(conn, query)
	if err != nil {
		return nil, 0, err
	}
	for {
		response, err := readStreamMessage(conn)
		if err != nil {
			return nil, 0, err
		}
		if isResponseTo(response, query) {
			return response, time.Since(start), nil
		}
	}
}

func (p *prober) exchangeHTTPS(ctx context.Context, query []byte) ([]byte, time.Duration, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.resolver.URL, bytes.NewReader(query))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Accept", dnsMessageMimeType)
	request.Header.Set("Content-Type", dnsMessageMimeType)
	request.Header.Set("User-Agent", "")
	start := time.Now()
	response, err := p.httpClient.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != dnsMessageMimeType {
		// Not a DNS message, but still the resolver's reply.
		return nil, time.Since(start), nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, httpMaxResponseSize))
	if err != nil {
		return nil, 0, err
	}
	return body, time.Since(start), nil
}
