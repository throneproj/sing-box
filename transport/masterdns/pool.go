package masterdns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/wire"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	maxResponseSize        = 65535
	maxMismatchedResponses = 64
	drainGrace             = time.Millisecond
	pooledConnMaxAge       = 90 * time.Second
)

var pastDeadline = time.Unix(1, 0)

type resolverPool struct {
	access sync.Mutex
	pools  map[netip.AddrPort]chan pooledConn
}

type pooledConn struct {
	conn     net.Conn
	pooledAt time.Time
}

func resolverPoolSize(settings wire.ClientSettings, resolvers int) int {
	duplication := max(settings.PacketDuplication, settings.SetupPacketDuplication, 1)
	size := max(8, settings.RXTXWorkers*duplication*2)
	resolvers = max(resolvers, 1)
	switch {
	case resolvers <= 4:
		size *= 2
	case resolvers <= 8:
		size = size * 3 / 2
	case resolvers >= 64:
		size = max(8, size/2)
	case resolvers >= 32:
		size = max(8, size*3/4)
	}
	return min(max(size, 8), 128)
}

func (c *Client) dialResolver(ctx context.Context, resolver netip.AddrPort) (net.Conn, error) {
	return c.dialer.DialContext(ctx, N.NetworkUDP, M.SocksaddrFromNetIP(resolver))
}

func (c *Client) getResolverConn(ctx context.Context, resolver netip.AddrPort) (net.Conn, error) {
	c.access.Lock()
	size := resolverPoolSize(c.settings, len(c.resolvers))
	c.access.Unlock()
	c.pool.access.Lock()
	pool := c.pool.pools[resolver]
	if pool == nil {
		pool = make(chan pooledConn, size)
		c.pool.pools[resolver] = pool
	}
	c.pool.access.Unlock()
	now := time.Now()
	for {
		select {
		case pooled := <-pool:
			if now.Sub(pooled.pooledAt) > pooledConnMaxAge {
				pooled.conn.Close()
				continue
			}
			return pooled.conn, nil
		default:
			return c.dialResolver(ctx, resolver)
		}
	}
}

func (c *Client) putResolverConn(resolver netip.AddrPort, conn net.Conn) {
	c.pool.access.Lock()
	pool := c.pool.pools[resolver]
	c.pool.access.Unlock()
	if pool == nil {
		conn.Close()
		return
	}
	select {
	case pool <- pooledConn{conn: conn, pooledAt: time.Now()}:
	default:
		conn.Close()
	}
}

func (c *Client) closeResolverPools() {
	c.pool.access.Lock()
	pools := c.pool.pools
	c.pool.pools = make(map[netip.AddrPort]chan pooledConn)
	c.pool.access.Unlock()
	for _, pool := range pools {
		for drained := false; !drained; {
			select {
			case pooled := <-pool:
				pooled.conn.Close()
			default:
				drained = true
			}
		}
	}
}

func (c *Client) exchangeResolver(ctx context.Context, resolver netip.AddrPort, query []byte, base64Response bool, timeout time.Duration) (wire.Packet, error) {
	conn, err := c.getResolverConn(ctx, resolver)
	if err != nil {
		return wire.Packet{}, err
	}
	response, err := exchange(ctx, conn, query, timeout)
	if err != nil {
		conn.Close()
		return wire.Packet{}, err
	}
	c.putResolverConn(resolver, conn)
	return wire.ParseResponse(response, base64Response)
}

func (c *Client) sendOneWay(ctx context.Context, resolver netip.AddrPort, query []byte, deadline time.Time) error {
	conn, err := c.getResolverConn(ctx, resolver)
	if err != nil {
		return err
	}
	err = conn.SetWriteDeadline(deadline)
	if err == nil {
		_, err = conn.Write(query)
	}
	if err != nil {
		conn.Close()
		return err
	}
	c.putResolverConn(resolver, conn)
	return nil
}

// exchange drops stale datagrams, then waits for the answer carrying the query's DNS ID on a connected socket.
func exchange(ctx context.Context, conn net.Conn, query []byte, timeout time.Duration) ([]byte, error) {
	if len(query) < 2 {
		return nil, E.New("malformed dns query")
	}
	expectedID := binary.BigEndian.Uint16(query)
	buffer := buf.Get(maxResponseSize)
	defer buf.Put(buffer)
	stop := context.AfterFunc(ctx, func() {
		conn.SetDeadline(pastDeadline)
	})
	defer func() {
		stop()
		conn.SetDeadline(time.Time{})
	}()
	err := drainResponses(conn, buffer)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	err = conn.SetWriteDeadline(deadline)
	if err != nil {
		return nil, err
	}
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	_, err = conn.Write(query)
	if err != nil {
		return nil, contextError(ctx, err)
	}
	for mismatched := 0; ; {
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, contextError(ctx, err)
		}
		if n >= 2 && binary.BigEndian.Uint16(buffer) == expectedID {
			return append([]byte(nil), buffer[:n]...), nil
		}
		mismatched++
		if mismatched >= maxMismatchedResponses {
			return nil, E.New("too many mismatched dns responses")
		}
	}
}

func drainResponses(conn net.Conn, buffer []byte) error {
	for range maxMismatchedResponses * 2 {
		err := conn.SetReadDeadline(time.Now().Add(drainGrace))
		if err != nil {
			return err
		}
		_, err = conn.Read(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil
			}
			return err
		}
	}
	return nil
}

func contextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
