package warpmasque

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	masquetransport "github.com/sagernet/sing-box/transport/warpmasque"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

const (
	minReconnectDelay   = time.Second
	maxReconnectDelay   = time.Minute
	stableConnectionAge = 30 * time.Second
	http3WaitFactor     = 2
	// Before it has an RTT sample, quic-go resends a lost Initial only after about 300 ms.
	minHTTP3Wait = 500 * time.Millisecond
	// A silently dropped UDP path would otherwise hold the race open for the whole connect budget.
	http3HandshakeTimeout = 5 * time.Second
	// A CONNECT that stalls after its handshake must not hold back the other carrier.
	carrierOpenTimeout = 3 * time.Second
	packetBufferSlack  = 256
)

func (e *Endpoint) loop(done chan struct{}) {
	defer close(done)
	var reconnectDelay time.Duration
	for {
		ctx, cancel := context.WithCancel(e.loopContext)
		e.access.Lock()
		e.cancelConnect = cancel
		e.access.Unlock()
		connectionAge, err := e.serve(ctx)
		if e.loopContext.Err() != nil {
			cancel()
			return
		}
		if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
			e.logger.Debug(err)
		} else {
			e.logger.Error(err)
		}
		if connectionAge >= stableConnectionAge {
			reconnectDelay = 0
		}
		if reconnectDelay == 0 {
			reconnectDelay = minReconnectDelay
		} else {
			reconnectDelay = min(reconnectDelay*2, maxReconnectDelay)
		}
		timer := time.NewTimer(reconnectDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			reconnectDelay = 0
		case <-timer.C:
		}
		cancel()
		if e.loopContext.Err() != nil {
			return
		}
	}
}

func (e *Endpoint) serve(ctx context.Context) (time.Duration, error) {
	conn, err := e.connect(ctx)
	if err != nil {
		return 0, err
	}
	e.access.Lock()
	if ctx.Err() != nil {
		e.access.Unlock()
		conn.Close()
		return 0, ctx.Err()
	}
	e.setConnLocked(conn)
	e.access.Unlock()
	connectedAt := time.Now()
	err = e.readPackets(conn)
	e.access.Lock()
	if e.conn == conn {
		e.clearConnLocked()
	}
	e.access.Unlock()
	conn.Close()
	return time.Since(connectedAt), E.Cause(annotateError(err), "connection lost")
}

func (e *Endpoint) connect(ctx context.Context) (masquetransport.Conn, error) {
	if e.versionFallback {
		return e.connectEitherCarrier(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	handshake, err := e.handshake(ctx, e.http2Only)
	if err != nil {
		return nil, connectError(err, e.http2Only)
	}
	return e.open(ctx, handshake, e.http2Only)
}

// connectEitherCarrier races the handshakes but opens one carrier at a time until a tunnel opens, HTTP/3 first: an
// HTTP/2 handshake done first, after t, waits for HTTP/3 until max(http3WaitFactor*t, minHTTP3Wait) has passed.
func (e *Endpoint) connectEitherCarrier(ctx context.Context) (masquetransport.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	type handshakeResult struct {
		useHTTP2  bool
		handshake carrierHandshake
		err       error
	}
	results := make(chan handshakeResult, 2)
	runHandshake := func(ctx context.Context, useHTTP2 bool) {
		handshake, err := e.handshake(ctx, useHTTP2)
		results <- handshakeResult{useHTTP2, handshake, err}
	}
	start := time.Now()
	http3Ctx, cancelHTTP3 := context.WithTimeout(ctx, http3HandshakeTimeout)
	defer cancelHTTP3()
	go runHandshake(http3Ctx, false)
	go runHandshake(ctx, true)
	var (
		pending        = 2
		http3Handshake carrierHandshake
		http2Handshake carrierHandshake
		http3Err       error
		http2Err       error
		http3Deadline  <-chan time.Time
	)
	defer func() {
		common.Close(http3Handshake, http2Handshake)
		for range pending {
			go func() {
				result := <-results
				common.Close(result.handshake)
			}()
		}
	}()
	// fail records a carrier's error and reports whether the other carrier is still in the race.
	fail := func(useHTTP2 bool, err error) bool {
		if useHTTP2 {
			http2Err = err
		} else {
			http3Err = err
		}
		return http3Err == nil || http2Err == nil
	}
	// open caps the CONNECT only while the other carrier is still in the race.
	open := func(handshake carrierHandshake, useHTTP2 bool) (masquetransport.Conn, error) {
		if http3Err != nil || http2Err != nil {
			return e.open(ctx, handshake, useHTTP2)
		}
		ctx, cancel := context.WithTimeout(ctx, carrierOpenTimeout)
		defer cancel()
		return e.open(ctx, handshake, useHTTP2)
	}
	for {
		var (
			handshake carrierHandshake
			useHTTP2  bool
		)
		switch {
		case http3Handshake != nil:
			handshake, http3Handshake = http3Handshake, nil
		case http2Handshake != nil && http3Err != nil:
			handshake, http2Handshake, useHTTP2 = http2Handshake, nil, true
		default:
			select {
			case result := <-results:
				pending--
				switch {
				case result.err != nil:
					err := connectError(result.err, result.useHTTP2)
					if !fail(result.useHTTP2, err) {
						return nil, E.Errors(http3Err, http2Err)
					}
					if ctx.Err() == nil {
						e.logger.Debug(err, ", trying ", carrierName(!result.useHTTP2))
					}
				case !result.useHTTP2:
					http3Handshake = result.handshake
				default:
					http2Handshake = result.handshake
					if http3Err == nil {
						elapsed := time.Since(start)
						http3Deadline = time.After(max(http3WaitFactor*elapsed, minHTTP3Wait) - elapsed)
					}
				}
				continue
			case <-http3Deadline:
				e.logger.Debug("HTTP/3 handshake not completed in ", time.Since(start).Round(time.Millisecond), ", trying HTTP/2")
				handshake, http2Handshake, useHTTP2 = http2Handshake, nil, true
			}
		}
		if ctx.Err() != nil {
			handshake.Close()
			return nil, ctx.Err()
		}
		conn, err := open(handshake, useHTTP2)
		if err == nil {
			return conn, nil
		}
		if !fail(useHTTP2, err) {
			return nil, E.Errors(http3Err, http2Err)
		}
		if ctx.Err() == nil {
			e.logger.Warn(err, ", trying ", carrierName(!useHTTP2))
		}
	}
}

func (e *Endpoint) open(ctx context.Context, handshake carrierHandshake, useHTTP2 bool) (masquetransport.Conn, error) {
	conn, err := handshake.Open(ctx)
	if err != nil {
		return nil, connectError(err, useHTTP2)
	}
	e.logger.Info("connected via ", carrierName(useHTTP2), " to ", e.serverAddr)
	return conn, nil
}

// carrierHandshake is a completed handshake: Open consumes it into a tunnel, Close discards it.
type carrierHandshake interface {
	Open(ctx context.Context) (masquetransport.Conn, error)
	Close() error
}

type http2Handshake struct {
	*masquetransport.HTTP2Handshake
	lifetime    context.Context
	h2Transport *http2.Transport
}

func (h *http2Handshake) Open(ctx context.Context) (masquetransport.Conn, error) {
	return h.HTTP2Handshake.Open(ctx, h.lifetime, h.h2Transport)
}

func (e *Endpoint) handshake(ctx context.Context, useHTTP2 bool) (carrierHandshake, error) {
	tlsOptions, err := clientTLSOptions(e.tlsOptions, e.privateKey, e.privateKeyPEM, e.timeFunc())
	if err != nil {
		return nil, err
	}
	if useHTTP2 {
		tlsConfig, err := tls.NewClient(e.ctx, e.logger, e.serverName, tlsOptions)
		if err != nil {
			return nil, err
		}
		handshake, err := masquetransport.HandshakeHTTP2(ctx, e.outboundDialer, e.serverAddr, tlsConfig)
		if err != nil {
			return nil, err
		}
		return &http2Handshake{HTTP2Handshake: handshake, lifetime: e.loopContext, h2Transport: e.h2Transport}, nil
	}
	tlsConfig, err := tls.NewSTDClient(e.ctx, e.logger, e.serverName, tlsOptions)
	if err != nil {
		return nil, err
	}
	stdConfig, err := tlsConfig.STDConfig()
	if err != nil {
		return nil, err
	}
	packetConn, serverAddr, err := e.listenPacket(ctx)
	if err != nil {
		return nil, err
	}
	handshake, err := masquetransport.HandshakeHTTP3(ctx, packetConn, serverAddr, stdConfig, e.quicConfig)
	if err != nil {
		return nil, err
	}
	return handshake, nil
}

// listenPacket resolves the server itself: the resolve dialer would hide the socket behind a NAT wrapper.
func (e *Endpoint) listenPacket(ctx context.Context) (net.PacketConn, M.Socksaddr, error) {
	if !e.serverAddr.IsDomain() {
		packetConn, err := e.outboundDialer.ListenPacket(ctx, e.serverAddr)
		return packetConn, e.serverAddr, err
	}
	var queryOptions adapter.DNSQueryOptions
	if resolveDialer, isResolveDialer := e.outboundDialer.(dialer.ResolveDialer); isResolveDialer {
		queryOptions = resolveDialer.QueryOptions()
	}
	addresses, err := e.dnsRouter.Lookup(log.ContextWithOverrideLevel(ctx, log.LevelDebug), e.serverAddr.Fqdn, queryOptions)
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	packetConn, address, err := N.ListenSerial(ctx, e.outboundDialer, e.serverAddr, addresses)
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	return packetConn, M.SocksaddrFrom(address, e.serverAddr.Port), nil
}

func clientTLSOptions(tlsOptions option.OutboundTLSOptions, privateKey *ecdsa.PrivateKey, privateKeyPEM string, now time.Time) (option.OutboundTLSOptions, error) {
	certificate, err := newClientCertificate(privateKey, now)
	if err != nil {
		return option.OutboundTLSOptions{}, E.Cause(err, "create client certificate")
	}
	tlsOptions.ClientCertificate = badoption.Listable[string]{certificate}
	tlsOptions.ClientKey = badoption.Listable[string]{privateKeyPEM}
	return tlsOptions, nil
}

func (e *Endpoint) readPackets(conn masquetransport.Conn) error {
	packetBuffers := make([]*buf.Buffer, 1)
	for {
		headroom := e.device.FrontHeadroom()
		packetBuffer := buf.NewSize(headroom + int(e.mtu) + packetBufferSlack)
		packetBuffer.Resize(headroom, 0)
		err := conn.ReadPacket(packetBuffer)
		if err != nil {
			packetBuffer.Release()
			return err
		}
		packetBuffers[0] = packetBuffer
		err = e.device.WriteInboundBuffers(packetBuffers)
		buf.ReleaseMulti(packetBuffers)
		if err != nil {
			e.logger.Debug(E.Cause(err, "write packet to device"))
		}
	}
}

func (e *Endpoint) currentConn() masquetransport.Conn {
	e.access.Lock()
	defer e.access.Unlock()
	return e.conn
}

func (e *Endpoint) setConnLocked(conn masquetransport.Conn) {
	e.conn = conn
	close(e.ready)
}

func (e *Endpoint) clearConnLocked() {
	if e.conn == nil {
		return
	}
	e.conn = nil
	e.ready = make(chan struct{})
}

// Best effort: a packet sent before the carrier is up is dropped, costing a TCP retransmit backoff.
func (e *Endpoint) waitReady(ctx context.Context) {
	e.access.Lock()
	ready := e.ready
	e.access.Unlock()
	timer := time.NewTimer(C.TCPConnectTimeout)
	defer timer.Stop()
	select {
	case <-ready:
	case <-ctx.Done():
	case <-e.loopContext.Done():
	case <-timer.C:
	}
}

func (e *Endpoint) WritePackets(packets [][]byte) error {
	err := e.ensureStarted()
	if err != nil {
		return err
	}
	conn := e.currentConn()
	if conn == nil {
		return E.New("endpoint is not ready yet")
	}
	for _, packet := range packets {
		err := e.writePacket(conn, packet)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Endpoint) writePacketBuffers(packetBuffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(packetBuffers)
	conn := e.currentConn()
	if conn == nil {
		return nil
	}
	for _, packetBuffer := range packetBuffers {
		if e.writePacket(conn, packetBuffer.Bytes()) != nil {
			return nil
		}
	}
	return nil
}

func (e *Endpoint) writePacket(conn masquetransport.Conn, packet []byte) error {
	err := conn.WritePacket(packet)
	if err == nil {
		return nil
	}
	var tooLargeErr *masquetransport.PacketTooLargeError
	if errors.As(err, &tooLargeErr) {
		e.replyPacketTooBig(packet, tooLargeErr.MTU)
		return nil
	}
	e.access.Lock()
	isCurrent := e.conn == conn
	if isCurrent {
		e.clearConnLocked()
	}
	e.access.Unlock()
	if isCurrent {
		e.logger.Error(E.Cause(err, "write packet"))
		conn.Close()
	}
	return err
}

// replyPacketTooBig makes the sender shrink its packets, as a router would. Dropping the packet silently makes TCP
// retransmit the same segment until the connection stalls.
func (e *Endpoint) replyPacketTooBig(packet []byte, mtu int) {
	minimumMTU := header.IPv4MinimumProcessableDatagramSize
	if header.IPVersion(packet) == header.IPv6Version {
		minimumMTU = header.IPv6MinimumMTU
	}
	if mtu < minimumMTU {
		// The sender cannot go below the protocol minimum; path MTU discovery may still raise the limit.
		e.logger.Debug("drop packet: carrier fits only ", mtu, " bytes")
		return
	}
	headroom := e.device.FrontHeadroom()
	reply, built := tun.BuildICMPError(packet, tun.ICMPErrorPacketTooBig, netip.Addr{}, uint32(mtu), headroom)
	if !built {
		return
	}
	replyBuffer := buf.As(reply)
	replyBuffer.Advance(headroom)
	err := e.device.WriteInboundBuffers([]*buf.Buffer{replyBuffer})
	if err != nil {
		e.logger.Debug(E.Cause(err, "write packet too big"))
	}
}

func annotateError(err error) error {
	if err != nil && (strings.Contains(err.Error(), "tls: access denied") || strings.Contains(err.Error(), "tls: unknown certificate")) {
		return E.Cause(err, "private key is not enrolled or was revoked")
	}
	return err
}

func connectError(err error, useHTTP2 bool) error {
	return E.Cause(annotateError(err), "connect via ", carrierName(useHTTP2))
}

func carrierName(useHTTP2 bool) string {
	if useHTTP2 {
		return "HTTP/2"
	}
	return "HTTP/3"
}
