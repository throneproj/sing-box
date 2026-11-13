package juicity

import (
	"encoding/binary"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

var (
	_ N.NetPacketConn = (*udpPacketConn)(nil)
	_ N.FrontHeadroom = (*udpPacketConn)(nil)
)

type udpPacketConn struct {
	net.Conn
	isServer bool
	// Serializes packet writes so the client request header is sent exactly once.
	writeAccess     sync.Mutex
	readWaitOptions N.ReadWaitOptions
}

func newUDPPacketConn(conn net.Conn, isServer bool) *udpPacketConn {
	return &udpPacketConn{
		Conn:     conn,
		isServer: isServer,
	}
}

func (c *udpPacketConn) readPacketHeader() (M.Socksaddr, int, error) {
	destination, err := M.SocksaddrSerializer.ReadAddrPort(c.Conn)
	if err != nil {
		return M.Socksaddr{}, 0, E.Cause(err, "read destination")
	}
	var length uint16
	err = binary.Read(c.Conn, binary.BigEndian, &length)
	if err != nil {
		return M.Socksaddr{}, 0, E.Cause(err, "read payload length")
	}
	return destination, int(length), nil
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, length, err := c.readPacketHeader()
	if err != nil {
		return M.Socksaddr{}, err
	}
	_, err = buffer.ReadFullFrom(c.Conn, length)
	if err != nil {
		return M.Socksaddr{}, E.Cause(err, "read payload")
	}
	return destination, nil
}

func (c *udpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	bufferLen := buffer.Len()
	if bufferLen > math.MaxUint16 {
		return E.New("packet too large")
	}
	if destination.IsDomain() && len(destination.Fqdn) > 255 {
		return E.New("fqdn too long")
	}
	if c.isServer && destination.IsIPv4() {
		// The official server replies with IPv4-mapped IPv6 source addresses.
		destination = M.Socksaddr{Addr: netip.AddrFrom16(destination.Addr.As16()), Port: destination.Port}
	}
	header := buf.With(buffer.ExtendHeader(M.SocksaddrSerializer.AddrPortLen(destination) + 2))
	err := M.SocksaddrSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return err
	}
	common.Must(binary.Write(header, binary.BigEndian, uint16(bufferLen)))
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return common.Error(c.Conn.Write(buffer.Bytes()))
}

func (c *udpPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	destination, length, err := c.readPacketHeader()
	if err != nil {
		return
	}
	if length <= len(p) {
		n, err = io.ReadFull(c.Conn, p[:length])
	} else {
		n, err = io.ReadFull(c.Conn, p)
		if err == nil {
			err = rw.SkipN(c.Conn, length-len(p))
		}
	}
	if err != nil {
		return 0, nil, E.Cause(err, "read payload")
	}
	if destination.IsDomain() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	return
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return bufio.WritePacket(c, p, addr)
}

func (c *udpPacketConn) Read(p []byte) (n int, err error) {
	n, _, err = c.ReadFrom(p)
	return
}

func (c *udpPacketConn) Write(p []byte) (n int, err error) {
	return 0, os.ErrInvalid
}

func (c *udpPacketConn) FrontHeadroom() int {
	return M.MaxSocksaddrLength + 2
}

func (c *udpPacketConn) Upstream() any {
	return c.Conn
}
