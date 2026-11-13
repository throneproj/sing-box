package trusttunnel

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type http2StreamConn struct {
	reader     io.ReadCloser
	writer     net.Conn
	cancel     context.CancelFunc
	remoteAddr net.Addr
	closed     atomic.Bool
}

func (c *http2StreamConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	return n, c.wrapError(err)
}

func (c *http2StreamConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	return n, c.wrapError(err)
}

func (c *http2StreamConn) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if c.closed.Load() || strings.Contains(err.Error(), "client connection force closed") {
		return net.ErrClosed
	}
	return baderror.WrapH2(err)
}

func (c *http2StreamConn) CloseWrite() error {
	return c.writer.Close()
}

func (c *http2StreamConn) Close() error {
	c.closed.Store(true)
	c.writer.Close()
	c.reader.Close()
	c.cancel()
	return nil
}

func (c *http2StreamConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *http2StreamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http2StreamConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *http2StreamConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *http2StreamConn) SetWriteDeadline(t time.Time) error {
	return c.writer.SetWriteDeadline(t)
}

func (c *http2StreamConn) NeedAdditionalReadDeadline() bool {
	return true
}

type tunnelConn struct {
	N.ExtendedConn
	streamConn net.Conn
}

func newTunnelConn(streamConn net.Conn) *tunnelConn {
	return &tunnelConn{ExtendedConn: deadline.NewConn(streamConn), streamConn: streamConn}
}

func (c *tunnelConn) CloseWrite() error {
	return N.CloseWrite(c.streamConn)
}

func (c *tunnelConn) SetDeadline(t time.Time) error {
	return E.Errors(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *tunnelConn) Upstream() any {
	return c.ExtendedConn
}

var (
	_ net.Conn      = (*http2StreamConn)(nil)
	_ N.WriteCloser = (*http2StreamConn)(nil)
	_ N.WriteCloser = (*tunnelConn)(nil)
)
