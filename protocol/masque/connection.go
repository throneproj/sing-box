package masque

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	masquetransport "github.com/sagernet/sing-box/transport/masque"
	ovpntransport "github.com/sagernet/sing-box/transport/openvpn"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

const (
	minReconnectDelay    = time.Second
	maxReconnectDelay    = time.Minute
	stableConnectionAge  = 30 * time.Second
	http3FallbackTimeout = 5 * time.Second
	packetBufferSlack    = 256
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
	e.conn = conn
	e.access.Unlock()
	connectedAt := time.Now()
	err = e.readPackets(conn)
	e.access.Lock()
	if e.conn == conn {
		e.conn = nil
	}
	e.access.Unlock()
	conn.Close()
	return time.Since(connectedAt), E.Cause(annotateError(err), "connection lost")
}

func (e *Endpoint) connect(ctx context.Context) (masquetransport.Conn, error) {
	useHTTP2 := e.preferHTTP2
	conn, err := e.dial(ctx, useHTTP2)
	if err == nil || !e.versionFallback || ctx.Err() != nil {
		return conn, err
	}
	e.logger.Warn(err, ", trying ", carrierName(!useHTTP2))
	conn, fallbackErr := e.dial(ctx, !useHTTP2)
	if fallbackErr != nil {
		return nil, E.Errors(err, fallbackErr)
	}
	e.preferHTTP2 = !useHTTP2
	return conn, nil
}

func (e *Endpoint) dial(ctx context.Context, useHTTP2 bool) (masquetransport.Conn, error) {
	conn, err := e.dialCarrier(ctx, useHTTP2)
	if err != nil {
		return nil, E.Cause(annotateError(err), "connect via ", carrierName(useHTTP2))
	}
	e.logger.Info("connected via ", carrierName(useHTTP2), " to ", e.serverAddr)
	return conn, nil
}

func (e *Endpoint) dialCarrier(ctx context.Context, useHTTP2 bool) (masquetransport.Conn, error) {
	tlsOptions, err := clientTLSOptions(e.tlsOptions, e.privateKey, e.privateKeyPEM, e.timeFunc())
	if err != nil {
		return nil, err
	}
	timeout := C.TCPTimeout
	if !useHTTP2 && e.versionFallback {
		// A silently dropped UDP path would otherwise hold back the HTTP/2 fallback for the whole handshake timeout.
		timeout = http3FallbackTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if useHTTP2 {
		tlsConfig, err := tls.NewClient(e.ctx, e.logger, e.serverName, tlsOptions)
		if err != nil {
			return nil, err
		}
		return masquetransport.DialHTTP2(ctx, e.loopContext, e.outboundDialer, e.serverAddr, tlsConfig, e.h2Transport)
	}
	tlsConfig, err := tls.NewSTDClient(e.ctx, e.logger, e.serverName, tlsOptions)
	if err != nil {
		return nil, err
	}
	stdConfig, err := tlsConfig.STDConfig()
	if err != nil {
		return nil, err
	}
	return masquetransport.DialHTTP3(ctx, e.outboundDialer, e.serverAddr, stdConfig, e.quicConfig)
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
	bufferSize := ovpntransport.PacketHeadroom + int(e.mtu) + packetBufferSlack
	packetBuffers := make([]*buf.Buffer, 1)
	for {
		packetBuffer := buf.NewSize(bufferSize)
		packetBuffer.Resize(ovpntransport.PacketHeadroom, 0)
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

func (e *Endpoint) WritePackets(packets [][]byte) error {
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
	var tooLargeErr *quic.DatagramTooLargeError
	if errors.As(err, &tooLargeErr) {
		e.logger.Debug("drop packet: ", err)
		return nil
	}
	e.access.Lock()
	isCurrent := e.conn == conn
	if isCurrent {
		e.conn = nil
	}
	e.access.Unlock()
	if isCurrent {
		e.logger.Error(E.Cause(err, "write packet"))
		conn.Close()
	}
	return err
}

func annotateError(err error) error {
	if err != nil && strings.Contains(err.Error(), "tls: access denied") {
		return E.Cause(err, "private key is not enrolled or was revoked")
	}
	return err
}

func carrierName(useHTTP2 bool) string {
	if useHTTP2 {
		return "HTTP/2"
	}
	return "HTTP/3"
}
