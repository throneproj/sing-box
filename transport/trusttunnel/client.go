package trusttunnel

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

type ClientOptions struct {
	Context               context.Context
	Logger                logger.ContextLogger
	Dialer                N.Dialer
	Server                M.Socksaddr
	TLSConfig             tls.Config
	Username              string
	Password              string
	QUIC                  bool
	QUICCongestionControl string
	HealthCheck           bool
}

type clientConn interface {
	reserveNewRequest() bool
	isClosed() bool
	openStream(ctx context.Context, request *http.Request, remoteAddr net.Addr) (net.Conn, error)
	healthCheck(ctx context.Context, request *http.Request) error
	Close() error
}

type Client struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	logger                logger.ContextLogger
	dialer                N.Dialer
	tlsDialer             tls.Dialer
	server                M.Socksaddr
	tlsConfig             tls.Config
	authorization         string
	quic                  bool
	quicCongestionControl string
	healthCheck           bool
	http2Transport        *http2.Transport
	access                sync.Mutex
	conns                 []clientConn
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.QUIC && !C.WithQUIC {
		return nil, C.ErrQUICNotIncluded
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		if options.QUIC {
			options.TLSConfig.SetNextProtos([]string{"h3"})
		} else {
			options.TLSConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
	}
	ctx, cancel := context.WithCancel(options.Context)
	return &Client{
		ctx:                   ctx,
		cancel:                cancel,
		logger:                options.Logger,
		dialer:                options.Dialer,
		tlsDialer:             tls.NewDialer(options.Dialer, options.TLSConfig),
		server:                options.Server,
		tlsConfig:             options.TLSConfig,
		authorization:         "Basic " + base64.StdEncoding.EncodeToString([]byte(options.Username+":"+options.Password)),
		quic:                  options.QUIC,
		quicCongestionControl: options.QUICCongestionControl,
		healthCheck:           options.HealthCheck,
		http2Transport: &http2.Transport{
			DisableCompression: true,
			IdleConnTimeout:    idleTimeout,
		},
	}, nil
}

func (c *Client) Start() error {
	if c.healthCheck {
		go c.loopHealthCheck()
	}
	return nil
}

func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.openStream(ctx, c.newRequest(destination.String(), userAgent), destination)
	if err != nil {
		return nil, err
	}
	return newTunnelConn(conn), nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := c.openStream(ctx, c.newRequest(udpAuthority, udpUserAgent), M.Socksaddr{})
	if err != nil {
		return nil, err
	}
	return deadline.NewPacketConn(bufio.NewNetPacketConn(newClientPacketConn(conn))), nil
}

func (c *Client) ResetConnections() {
	c.access.Lock()
	defer c.access.Unlock()
	for _, conn := range c.conns {
		conn.Close()
	}
	c.conns = nil
}

func (c *Client) Close() error {
	c.cancel()
	c.ResetConnections()
	return nil
}

func (c *Client) newRequest(authority string, userAgent string) *http.Request {
	return &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: http.Header{
			"User-Agent":          []string{userAgent},
			"Proxy-Authorization": []string{c.authorization},
		},
	}
}

func (c *Client) openStream(ctx context.Context, request *http.Request, remoteAddr net.Addr) (net.Conn, error) {
	conn, err := c.acquire(ctx)
	if err != nil {
		return nil, err
	}
	return conn.openStream(ctx, request, remoteAddr)
}

func (c *Client) acquire(ctx context.Context) (clientConn, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	c.conns = slices.DeleteFunc(c.conns, func(it clientConn) bool { return it.isClosed() })
	for _, conn := range c.conns {
		if conn.reserveNewRequest() {
			return conn, nil
		}
	}
	var (
		conn clientConn
		err  error
	)
	if c.quic {
		conn, err = c.dialHTTP3(adapter.ContextForMultiplexSession(ctx))
	} else {
		conn, err = c.dialHTTP2(adapter.ContextForMultiplexSession(ctx))
	}
	if err != nil {
		return nil, err
	}
	conn.reserveNewRequest()
	c.conns = append(c.conns, conn)
	return conn, nil
}

func (c *Client) loopHealthCheck() {
	ticker := time.NewTicker(connectionTimeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-c.ctx.Done():
			return
		}
		c.access.Lock()
		conns := slices.Clone(c.conns)
		c.access.Unlock()
		for _, conn := range conns {
			if !conn.isClosed() {
				c.checkConnection(conn)
			}
		}
	}
}

func (c *Client) checkConnection(conn clientConn) {
	ctx, cancel := context.WithTimeout(c.ctx, healthCheckTimeout)
	defer cancel()
	err := conn.healthCheck(ctx, c.newRequest(healthCheckAuthority, userAgent))
	if err != nil && c.ctx.Err() == nil {
		c.logger.Debug(E.Cause(err, "health check"))
		conn.Close()
	}
}
