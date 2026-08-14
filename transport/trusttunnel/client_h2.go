package trusttunnel

import (
	"context"
	"net"
	"net/http"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/pipe"

	"golang.org/x/net/http2"
)

func (c *Client) dialHTTP2(ctx context.Context) (clientConn, error) {
	conn, err := c.tlsDialer.DialTLSContext(ctx, c.server)
	if err != nil {
		return nil, err
	}
	if conn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
		conn.Close()
		return nil, E.New("server does not support HTTP/2")
	}
	clientConn, err := c.http2Transport.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "create HTTP/2 connection")
	}
	return &http2ClientConn{ClientConn: clientConn}, nil
}

type http2ClientConn struct {
	*http2.ClientConn
}

func (c *http2ClientConn) reserveNewRequest() bool {
	return c.ReserveNewRequest()
}

func (c *http2ClientConn) isClosed() bool {
	return c.State().Closed
}

func (c *http2ClientConn) openStream(ctx context.Context, request *http.Request, remoteAddr net.Addr) (net.Conn, error) {
	pipeReader, pipeWriter := pipe.Pipe()
	streamCtx, cancel := context.WithCancel(context.Background())
	request.Body = pipeReader
	request = request.WithContext(streamCtx)
	stop := context.AfterFunc(ctx, cancel)
	response, err := c.RoundTrip(request)
	stopped := stop()
	if err == nil && !stopped {
		response.Body.Close()
		err = ctx.Err()
	}
	if err != nil {
		cancel()
		pipeWriter.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, E.Cause(err, "HTTP/2 CONNECT")
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		cancel()
		pipeWriter.Close()
		return nil, statusError(response)
	}
	return &http2StreamConn{
		reader:     response.Body,
		writer:     pipeWriter,
		cancel:     cancel,
		remoteAddr: remoteAddr,
	}, nil
}

func (c *http2ClientConn) healthCheck(ctx context.Context, request *http.Request) error {
	response, err := c.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return statusError(response)
	}
	return nil
}
