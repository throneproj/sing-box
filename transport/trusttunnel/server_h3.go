//go:build with_quic

package trusttunnel

import (
	"context"
	"io"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

func (s *Server) ListenHTTP3(packetConn net.PacketConn, handler Handler, tlsConfig tls.ServerConfig) (io.Closer, error) {
	if !common.Contains(tlsConfig.NextProtos(), http3.NextProtoH3) {
		tlsConfig.SetNextProtos(append([]string{http3.NextProtoH3}, tlsConfig.NextProtos()...))
	}
	err := qtls.ConfigureHTTP3(tlsConfig)
	if err != nil {
		return nil, err
	}
	quicListener, err := qtls.ListenEarly(packetConn, tlsConfig, &quic.Config{
		Versions:           []quic.Version{quic.Version1},
		MaxIdleTimeout:     idleTimeout,
		MaxIncomingStreams: 1 << 60,
		Allow0RTT:          true,
		DisablePathManager: true,
	})
	if err != nil {
		return nil, err
	}
	http3Server := &http3.Server{
		Handler: &httpHandler{
			server:  s,
			handler: handler,
		},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			setCongestionControl(s.ctx, conn, s.quicCongestionControl)
			return ctx
		},
	}
	go func() {
		serveErr := http3Server.ServeListener(quicListener)
		if serveErr != nil && !E.IsClosedOrCanceled(serveErr) {
			s.logger.Error("HTTP/3 server closed: ", serveErr)
		}
	}()
	return quicListener, nil
}
