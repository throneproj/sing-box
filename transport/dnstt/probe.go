package dnstt

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ProbeLevel uint8

const (
	ProbeLevelPoll ProbeLevel = iota
	ProbeLevelQName
	ProbeLevelHandshake
)

const (
	ProbeStagePoll      = "poll"
	ProbeStageQName     = "qname"
	ProbeStageHandshake = "handshake"
)

const (
	probeExchangeTimeout = 5 * time.Second
	probeAttempts        = 2
	paddingBlockLength   = 32
	dnsttMaxQNameLen     = maxNameLength - 1
)

type ProbeResult struct {
	Passed       bool
	Stage        string
	Rcode        int
	Latency      time.Duration
	MaxQNameLen  int
	HandshakeRTT time.Duration
}

// Levels are cumulative; on failure Stage names the failed stage and stays empty for option errors.
func Probe(ctx context.Context, options ClientOptions, level ProbeLevel) (ProbeResult, error) {
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
	prober := newProber(client, resolver)
	defer prober.close()
	clientID := make([]byte, client.wire.clientIDSize)
	_, err = rand.Read(clientID)
	if err != nil {
		return result, err
	}
	err = prober.probePoll(ctx, clientID, &result)
	if err != nil {
		result.Stage = ProbeStagePoll
		return result, err
	}
	if level >= ProbeLevelQName {
		err = prober.probeQName(ctx, clientID, &result)
		if err != nil {
			result.Stage = ProbeStageQName
			return result, err
		}
	}
	if level >= ProbeLevelHandshake {
		client.resolvers = []ResolverOptions{resolver}
		start := time.Now()
		var s *session
		s, err = client.newSession(ctx)
		if err != nil {
			result.Stage = ProbeStageHandshake
			return result, err
		}
		result.HandshakeRTT = time.Since(start)
		s.close()
	}
	result.Passed = true
	return result, nil
}

type prober struct {
	client     *Client
	resolver   ResolverOptions
	httpClient *http.Client
	transport  *dnsTransport.HTTPSTransportWrapper
}

func newProber(client *Client, resolver ResolverOptions) *prober {
	p := &prober{
		client:   client,
		resolver: resolver,
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

func (p *prober) probePoll(ctx context.Context, clientID []byte, result *ProbeResult) error {
	var response *dnsMessage
	for attempt := 1; ; attempt++ {
		query, err := p.client.wire.encodeQuery(clientID, nil, rand.Reader)
		if err != nil {
			return err
		}
		response, result.Latency, err = p.exchange(ctx, query)
		if err == nil {
			break
		}
		if attempt == probeAttempts || ctx.Err() != nil {
			return err
		}
	}
	result.Rcode = response.rcode()
	return p.checkEmptyAnswer(response)
}

func (p *prober) checkEmptyAnswer(response *dnsMessage) error {
	if response.rcode() != rcodeNoError {
		return E.New("resolver answered with RCODE ", response.rcode())
	}
	if len(response.Answer) != 1 {
		return E.New("expected one answer record, got ", len(response.Answer))
	}
	if response.Answer[0].Type != p.client.wire.queryType() {
		return E.New("expected answer type ", p.client.wire.queryType(), ", got ", response.Answer[0].Type)
	}
	payload, loaded := p.client.wire.responsePayload(response)
	if !loaded {
		return E.New("undecodable answer")
	}
	if len(payload) != 0 {
		return E.New("unexpected downstream data for a new client")
	}
	return nil
}

// The filler parses as padding or as a truncated packet, so the server queues nothing.
func (p *prober) probeQName(ctx context.Context, clientID []byte, result *ProbeResult) error {
	wire := p.client.wire
	upper := dnsttMaxQNameLen
	required := dnsttMaxQNameLen
	if wire.vaydns {
		upper = vaydnsMaxQNameLen
		required = wire.maxQNameLen
	}
	lower := wire.domain.wireLength() + 1
	for lower <= upper && probePayloadLength(wire, lower) <= len(clientID) {
		lower++
	}
	if lower > upper {
		return E.New("domain ", wire.domain, " leaves no room for payload")
	}
	passed := func(maxQNameLen int) (bool, error) {
		var lastErr error
		for range probeAttempts {
			query, err := probeQNameQuery(wire, clientID, maxQNameLen)
			if err != nil {
				return false, err
			}
			response, _, err := p.exchange(ctx, query)
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if err == nil {
				err = p.checkEmptyAnswer(response)
				if err == nil {
					return true, nil
				}
			}
			lastErr = err
		}
		p.client.logger.Debug("probe max_qname_len ", maxQNameLen, ": ", lastErr)
		return false, nil
	}
	ok, err := passed(upper)
	if err != nil {
		return err
	}
	if ok {
		result.MaxQNameLen = upper
		return nil
	}
	ok, err = passed(lower)
	if err != nil {
		return err
	}
	if !ok {
		return E.New("resolver does not forward queries with max_qname_len ", lower)
	}
	low, high := lower, upper
	for high-low > 1 {
		middle := low + (high-low)/2
		ok, err = passed(middle)
		if err != nil {
			return err
		}
		if ok {
			low = middle
		} else {
			high = middle
		}
	}
	result.MaxQNameLen = low
	if low < required {
		return E.New("resolver forwards queries up to max_qname_len ", low, ", ", required, " required")
	}
	return nil
}

func probePayloadLength(wire *wireFormat, maxQNameLen int) int {
	available := maxQNameLen - wire.domain.wireLength()
	return available * encodedLabelLength / encodedLabelWireLength * base32BlockDecodeLength / base32BlockLength
}

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

func (p *prober) exchange(ctx context.Context, query []byte) (*dnsMessage, time.Duration, error) {
	exchangeCtx, cancel := context.WithTimeout(ctx, probeExchangeTimeout)
	defer cancel()
	var (
		response []byte
		latency  time.Duration
		err      error
	)
	switch p.resolver.Type {
	case ResolverTypeTCP, ResolverTypeTLS:
		response, latency, err = p.exchangeStream(exchangeCtx, query)
	case ResolverTypeHTTPS:
		response, latency, err = p.exchangeHTTPS(exchangeCtx, query)
	default:
		response, latency, err = p.exchangeUDP(exchangeCtx, query)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		} else if exchangeCtx.Err() != nil {
			return nil, 0, E.New("no response within ", probeExchangeTimeout)
		}
		return nil, 0, err
	}
	message, err := parseMessage(response)
	if err != nil {
		return nil, 0, E.Cause(err, "parse response")
	}
	return message, latency, nil
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
		if isTruncated(buffer[:n]) && p.resolver.TCPFallback {
			response, err := exchangeTCP(ctx, config, p.resolver.Server, query)
			return response, time.Since(start), err
		}
		return buffer[:n], time.Since(start), nil
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
	if response.StatusCode != http.StatusOK {
		return nil, 0, E.New("unexpected HTTP status ", response.Status)
	}
	contentType := response.Header.Get("Content-Type")
	if contentType != dnsMessageMimeType {
		return nil, 0, E.New("unknown HTTP response Content-Type ", strconv.Quote(contentType))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, httpMaxResponseSize))
	if err != nil {
		return nil, 0, err
	}
	return body, time.Since(start), nil
}
