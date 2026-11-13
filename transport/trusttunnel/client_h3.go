//go:build with_quic

package trusttunnel

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (c *Client) dialHTTP3(ctx context.Context) (clientConn, error) {
	rawConn, err := c.dialer.DialContext(ctx, N.NetworkUDP, c.server)
	if err != nil {
		return nil, err
	}
	quicConn, err := qtls.DialEarly(ctx, rawConn, c.tlsConfig, &quic.Config{
		Versions:                   []quic.Version{quic.Version1},
		MaxIdleTimeout:             idleTimeout,
		InitialStreamReceiveWindow: quicStreamReceiveWindow,
		DisablePathMTUDiscovery:    disablePathMTUDiscovery,
	})
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	setCongestionControl(c.ctx, quicConn, c.quicCongestionControl)
	return &http3ClientConn{
		ClientConn: (&http3.Transport{DisableCompression: true}).NewClientConn(quicConn),
		rawConn:    rawConn,
	}, nil
}

type http3ClientConn struct {
	*http3.ClientConn
	rawConn  net.Conn
	draining atomic.Bool
}

func (c *http3ClientConn) reserveNewRequest() bool {
	return !c.draining.Load() && !c.isClosed()
}

func (c *http3ClientConn) isClosed() bool {
	return c.Context().Err() != nil
}

func (c *http3ClientConn) openStream(ctx context.Context, request *http.Request, remoteAddr net.Addr) (net.Conn, error) {
	stream, err := c.roundTrip(ctx, request, false)
	if err != nil {
		return nil, err
	}
	return &http3StreamConn{stream: stream, remoteAddr: remoteAddr}, nil
}

func (c *http3ClientConn) healthCheck(ctx context.Context, request *http.Request) error {
	stream, err := c.roundTrip(ctx, request, true)
	if err != nil {
		return err
	}
	stream.CancelRead(0)
	return nil
}

func (c *http3ClientConn) roundTrip(ctx context.Context, request *http.Request, closeWrite bool) (*http3.RequestStream, error) {
	stream, err := c.OpenRequestStream(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Opening fails once the server sent GOAWAY, while streams already open keep running.
		c.draining.Store(true)
		return nil, E.Cause(err, "HTTP/3 CONNECT")
	}
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	var response *http.Response
	err = stream.SendRequestHeader(request)
	if err == nil && closeWrite {
		err = stream.Close()
	}
	if err == nil {
		response, err = stream.ReadResponse()
	}
	if !stop() {
		err = ctx.Err()
	}
	if err != nil {
		stream.CancelRead(0)
		stream.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, E.Cause(err, "HTTP/3 CONNECT")
	}
	if response.StatusCode != http.StatusOK {
		stream.CancelRead(0)
		stream.Close()
		return nil, statusError(response)
	}
	return stream, nil
}

func (c *http3ClientConn) Close() error {
	c.CloseWithError(0, "")
	return c.rawConn.Close()
}

type http3StreamConn struct {
	stream      *http3.RequestStream
	remoteAddr  net.Addr
	writeAccess sync.Mutex
	closed      atomic.Bool
}

func (c *http3StreamConn) Read(p []byte) (int, error) {
	n, err := c.stream.Read(p)
	return n, c.wrapError(err)
}

func (c *http3StreamConn) Write(p []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	n, err := c.stream.Write(p)
	return n, c.wrapError(err)
}

func (c *http3StreamConn) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	return qtls.WrapError(err)
}

func (c *http3StreamConn) CloseWrite() error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return c.stream.Close()
}

func (c *http3StreamConn) Close() error {
	c.closed.Store(true)
	c.stream.SetWriteDeadline(time.Now())
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	c.stream.CancelRead(0)
	return c.stream.Close()
}

func (c *http3StreamConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *http3StreamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http3StreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *http3StreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *http3StreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (c *http3StreamConn) NeedAdditionalReadDeadline() bool {
	return true
}

var (
	_ net.Conn      = (*http3StreamConn)(nil)
	_ N.WriteCloser = (*http3StreamConn)(nil)
)
