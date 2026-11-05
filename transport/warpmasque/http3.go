package warpmasque

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// The limit quic-go reports for a datagram leaves out the packet number, which takes up to 4 bytes.
const packetNumberSlack = 4

var _ Conn = (*http3Conn)(nil)

type http3Conn struct {
	ctx       context.Context
	cancel    context.CancelCauseFunc
	transport *quic.Transport
	quicConn  *quic.Conn
	stream    *http3.RequestStream
	// The quarter stream ID and context ID in front of every IP packet.
	datagramPrefixLen int
	closeOnce         sync.Once
}

// DialHTTP3 takes ownership of packetConn. It should be an unconnected socket: quic-go then drives the file
// descriptor itself (GSO, ECN, batched reads, DF), which a connected one only allows through quic.DialConn,
// and that cannot set the connection ID length.
func DialHTTP3(ctx context.Context, packetConn net.PacketConn, destination M.Socksaddr, tlsConfig *tls.Config, quicConfig *quic.Config) (Conn, error) {
	transport := &quic.Transport{
		Conn: packetConn,
		// Cloudflare closes connections with PROTOCOL_VIOLATION now and then on the default length.
		ConnectionIDLength: 20,
	}
	// The connection owns the transport and the UDP socket, so its death releases both.
	transport.SetSingleUse(true)
	transport.SetCreatedConn(true)
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	quicConn, err := transport.DialEarly(ctx, destination.UDPAddr(), tlsConfig, quicConfig)
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
		ctx:               connCtx,
		cancel:            cancel,
		transport:         transport,
		quicConn:          quicConn,
		stream:            stream,
		datagramPrefixLen: quicvarint.Len(uint64(stream.StreamID()/4)) + quicvarint.Len(contextIDIP),
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
	err = c.stream.SendDatagram(buffer.Bytes())
	var tooLargeErr *quic.DatagramTooLargeError
	if errors.As(err, &tooLargeErr) {
		return &PacketTooLargeError{MTU: int(tooLargeErr.MaxDatagramPayloadSize) - c.datagramPrefixLen - packetNumberSlack}
	}
	return err
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
