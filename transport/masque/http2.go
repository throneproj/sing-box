package masque

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	"github.com/sagernet/sing-box/common/streamctx"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

var _ Conn = (*http2Conn)(nil)

type http2Conn struct {
	ctx        context.Context
	tlsConn    tls.Conn
	clientConn *http2.ClientConn
	cancel     context.CancelCauseFunc
	pipeWriter *io.PipeWriter
	response   *http.Response
	parser     *http3.CapsuleParser
	closeOnce  sync.Once
}

func DialHTTP2(ctx context.Context, lifetime context.Context, dialer N.Dialer, destination M.Socksaddr, tlsConfig tls.Config, h2Transport *http2.Transport) (Conn, error) {
	tlsConfig = tlsConfig.Clone()
	tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
	tcpConn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return nil, err
	}
	tlsConn, err := tls.ClientHandshake(ctx, tcpConn, tlsConfig)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}
	// Cloudflare's MASQUE edge completes TLS without selecting any ALPN protocol.
	if protocol := tlsConn.ConnectionState().NegotiatedProtocol; protocol != "" && protocol != http2.NextProtoTLS {
		tlsConn.Close()
		return nil, E.New("server negotiated ", protocol, " instead of HTTP/2")
	}
	clientConn, err := h2Transport.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	pipeReader, pipeWriter := io.Pipe()
	// The stream is the tunnel: ctx only governs the dial, or its deadline would reset the tunnel.
	streamCtx, cancel, dialed := streamctx.New(lifetime, ctx)
	conn := &http2Conn{
		ctx:        streamCtx,
		tlsConn:    tlsConn,
		clientConn: clientConn,
		cancel:     cancel,
		pipeWriter: pipeWriter,
	}
	authority := net.JoinHostPort(connectHost, "443")
	request := &http.Request{
		Method: http.MethodConnect,
		Host:   authority,
		URL:    &url.URL{Scheme: "https", Host: authority},
		Header: http.Header{
			"Cf-Connect-Proto": []string{connectProtocol},
			"Pq-Enabled":       []string{"false"},
			"User-Agent":       []string{""},
		},
		Body:          pipeReader,
		ContentLength: -1,
	}
	response, err := clientConn.RoundTrip(request.WithContext(streamCtx))
	dialed()
	if err != nil {
		conn.closeWithError(err)
		return nil, err
	}
	conn.response = response
	if response.StatusCode < 200 || response.StatusCode > 299 {
		err = E.New("unexpected status: ", response.Status)
		conn.closeWithError(err)
		return nil, err
	}
	conn.parser = http3.NewCapsuleParser(response.Body)
	return conn, nil
}

func (c *http2Conn) ReadPacket(buffer *buf.Buffer) error {
	for {
		capsuleType, reader, err := c.parser.Next()
		if err != nil {
			return c.readError(err)
		}
		length := reader.Remaining()
		if capsuleType != capsuleTypeDatagram || length == 0 || length > int64(buffer.FreeLen()) {
			err = reader.Discard()
			if err != nil {
				return c.readError(err)
			}
			continue
		}
		_, err = buffer.ReadFullFrom(reader, int(length))
		if err != nil {
			return c.readError(err)
		}
		return nil
	}
}

func (c *http2Conn) readError(err error) error {
	if c.ctx.Err() != nil {
		return context.Cause(c.ctx)
	}
	return err
}

func (c *http2Conn) WritePacket(packet []byte) error {
	buffer := buf.NewSize(quicvarint.Len(uint64(capsuleTypeDatagram)) + quicvarint.Len(uint64(len(packet))) + len(packet))
	defer buffer.Release()
	err := http3.WriteCapsule(buffer, capsuleTypeDatagram, packet)
	if err != nil {
		return err
	}
	_, err = c.pipeWriter.Write(buffer.Bytes())
	return err
}

func (c *http2Conn) Close() error {
	c.closeWithError(net.ErrClosed)
	return nil
}

func (c *http2Conn) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.cancel(err)
		c.pipeWriter.CloseWithError(err)
		if c.response != nil {
			c.response.Body.Close()
		}
		common.Close(c.clientConn, c.tlsConn)
	})
}
