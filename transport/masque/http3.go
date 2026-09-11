package masque

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ Conn = (*http3Conn)(nil)

type http3Conn struct {
	ctx       context.Context
	cancel    context.CancelCauseFunc
	transport *quic.Transport
	quicConn  *quic.Conn
	stream    *http3.RequestStream
	closeOnce sync.Once
}

func DialHTTP3(ctx context.Context, dialer N.Dialer, destination M.Socksaddr, tlsConfig *tls.Config, quicConfig *quic.Config) (Conn, error) {
	udpConn, err := dialer.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	transport := &quic.Transport{
		Conn:               bufio.NewUnbindPacketConn(udpConn),
		ConnectionIDLength: 20,
	}
	// The connection owns the transport and the UDP socket, so its death releases both.
	transport.SetSingleUse(true)
	transport.SetCreatedConn(true)
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	quicConn, err := transport.DialEarly(ctx, udpConn.RemoteAddr(), tlsConfig, quicConfig)
	if err != nil {
		transport.Close()
		return nil, err
	}
	stream, err := openHTTP3Stream(ctx, quicConn)
	if err != nil {
		quicConn.CloseWithError(0, "")
		transport.Close()
		return nil, err
	}
	connCtx, cancel := context.WithCancelCause(quicConn.Context())
	conn := &http3Conn{
		ctx:       connCtx,
		cancel:    cancel,
		transport: transport,
		quicConn:  quicConn,
		stream:    stream,
	}
	go conn.drainCapsules()
	return conn, nil
}

func openHTTP3Stream(ctx context.Context, quicConn *quic.Conn) (*http3.RequestStream, error) {
	// Waiting for SETTINGS and the response ignores ctx, so cancellation closes the connection instead.
	stopClose := context.AfterFunc(ctx, func() {
		quicConn.CloseWithError(0, "")
	})
	stream, err := requestHTTP3Stream(ctx, quicConn)
	if !stopClose() {
		return nil, context.Cause(ctx)
	}
	return stream, err
}

func requestHTTP3Stream(ctx context.Context, quicConn *quic.Conn) (*http3.RequestStream, error) {
	h3Transport := &http3.Transport{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{settingH3Datagram00: 1},
		DisableCompression: true,
	}
	clientConn := h3Transport.NewClientConn(quicConn)
	select {
	case <-clientConn.ReceivedSettings():
	case <-quicConn.Context().Done():
		return nil, context.Cause(quicConn.Context())
	}
	if !clientConn.Settings().EnableDatagrams {
		return nil, E.New("server did not enable HTTP/3 datagrams")
	}
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		return nil, E.Cause(err, "open request stream")
	}
	err = stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  connectProtocol,
		Host:   connectHost,
		URL:    &url.URL{Scheme: "https", Host: connectHost, Path: "/"},
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{"?1"},
			"User-Agent":                []string{""},
		},
	})
	if err != nil {
		return nil, E.Cause(err, "send request")
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, E.Cause(err, "read response")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, E.New("unexpected status: ", response.Status)
	}
	return stream, nil
}

func (c *http3Conn) drainCapsules() {
	parser := http3.NewCapsuleParser(c.stream)
	for {
		_, reader, err := parser.Next()
		if err == nil {
			err = reader.Discard()
		}
		if err != nil {
			if err == io.EOF {
				err = E.New("stream closed by server")
			}
			c.closeWithError(err)
			return
		}
	}
}

func (c *http3Conn) ReadPacket(buffer *buf.Buffer) error {
	for {
		datagram, err := c.stream.ReceiveDatagram(c.ctx)
		if err != nil {
			if c.ctx.Err() != nil {
				return context.Cause(c.ctx)
			}
			return err
		}
		contextID, n, err := quicvarint.Parse(datagram)
		if err != nil || contextID != contextIDIP {
			continue
		}
		packet := datagram[n:]
		if len(packet) == 0 || len(packet) > buffer.FreeLen() {
			continue
		}
		_, err = buffer.Write(packet)
		return err
	}
}

func (c *http3Conn) WritePacket(packet []byte) error {
	buffer := buf.NewSize(1 + len(packet))
	defer buffer.Release()
	err := buffer.WriteByte(contextIDIP)
	if err != nil {
		return err
	}
	_, err = buffer.Write(packet)
	if err != nil {
		return err
	}
	return c.stream.SendDatagram(buffer.Bytes())
}

func (c *http3Conn) Close() error {
	c.closeWithError(net.ErrClosed)
	return nil
}

func (c *http3Conn) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.cancel(err)
		c.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		c.stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		c.quicConn.CloseWithError(0, "")
		c.transport.Close()
	})
}
