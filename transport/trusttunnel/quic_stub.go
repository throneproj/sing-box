//go:build !with_quic

package trusttunnel

import (
	"context"
	"io"
	"net"

	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
)

func (c *Client) dialHTTP3(ctx context.Context) (clientConn, error) {
	return nil, C.ErrQUICNotIncluded
}

func (s *Server) ListenHTTP3(packetConn net.PacketConn, handler Handler, tlsConfig tls.ServerConfig) (io.Closer, error) {
	return nil, C.ErrQUICNotIncluded
}
