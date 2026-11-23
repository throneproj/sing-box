//go:build with_psiphon

package psiphon

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

// Framing as served by psiphon/server/udp.go.
const (
	udpgwFlagKeepalive = 1 << 0
	udpgwFlagRebind    = 1 << 1
	udpgwFlagDNS       = 1 << 2
	udpgwFlagIPv6      = 1 << 3

	udpgwMaxPreambleSize = 23
	udpgwMaxPayloadSize  = 32768
)

// The server keeps one udpgw channel per tunnel and closes the previous one when another opens, so packet conns share a stream.
type udpgwStream struct {
	conn        net.Conn
	writeAccess sync.Mutex
	access      sync.Mutex
	bindings    map[uint16]udpgwBinding
	nextID      uint16
	done        chan struct{}
	err         error
}

type udpgwBinding struct {
	conn        *udpgwPacketConn
	destination netip.AddrPort
}

func newUDPGWStream(conn net.Conn) *udpgwStream {
	stream := &udpgwStream{
		conn:     conn,
		bindings: make(map[uint16]udpgwBinding),
		done:     make(chan struct{}),
	}
	go stream.loopRead()
	return stream
}

func (s *udpgwStream) loopRead() {
	buffer := make([]byte, udpgwMaxPreambleSize+udpgwMaxPayloadSize)
	for {
		_, err := io.ReadFull(s.conn, buffer[:2])
		if err != nil {
			s.close(err)
			return
		}
		size := int(binary.LittleEndian.Uint16(buffer))
		if size < 3 || size > len(buffer)-2 {
			s.close(E.New("invalid udpgw message size: ", size))
			return
		}
		message := buffer[2 : 2+size]
		_, err = io.ReadFull(s.conn, message)
		if err != nil {
			s.close(err)
			return
		}
		if message[0]&udpgwFlagKeepalive != 0 {
			continue
		}
		s.access.Lock()
		binding, loaded := s.bindings[binary.LittleEndian.Uint16(message[1:])]
		s.access.Unlock()
		if !loaded {
			continue
		}
		// Replies never set the IPv6 flag, the address length follows from the binding.
		addressLength := binding.destination.Addr().BitLen() / 8
		if size < 5+addressLength {
			continue
		}
		address, _ := netip.AddrFromSlice(message[3 : 3+addressLength])
		// A recycled connection ID may still receive replies for its previous destination.
		if netip.AddrPortFrom(address, binary.BigEndian.Uint16(message[3+addressLength:])) != binding.destination {
			continue
		}
		binding.conn.enqueue(message[5+addressLength:], binding.destination)
	}
}

func (s *udpgwStream) bind(conn *udpgwPacketConn, destination netip.AddrPort) (uint16, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	if len(s.bindings) == 1<<16 {
		return 0, E.New("udpgw connection IDs exhausted")
	}
	for {
		connID := s.nextID
		s.nextID++
		_, loaded := s.bindings[connID]
		if !loaded {
			s.bindings[connID] = udpgwBinding{conn: conn, destination: destination}
			return connID, nil
		}
	}
}

func (s *udpgwStream) unbind(connIDs map[netip.AddrPort]uint16) {
	s.access.Lock()
	defer s.access.Unlock()
	for _, connID := range connIDs {
		delete(s.bindings, connID)
	}
}

func (s *udpgwStream) writePacket(connID uint16, destination netip.AddrPort, rebind bool, payload []byte) error {
	address := destination.Addr().AsSlice()
	var flags byte
	if rebind {
		flags |= udpgwFlagRebind
	}
	if destination.Port() == 53 {
		flags |= udpgwFlagDNS
	}
	if len(address) == 16 {
		flags |= udpgwFlagIPv6
	}
	preambleSize := 7 + len(address)
	buffer := buf.NewSize(preambleSize + len(payload))
	defer buffer.Release()
	preamble := buffer.Extend(preambleSize)
	binary.LittleEndian.PutUint16(preamble, uint16(preambleSize-2+len(payload)))
	preamble[2] = flags
	binary.LittleEndian.PutUint16(preamble[3:], connID)
	copy(preamble[5:], address)
	binary.BigEndian.PutUint16(preamble[5+len(address):], destination.Port())
	common.Must1(buffer.Write(payload))
	s.writeAccess.Lock()
	_, err := s.conn.Write(buffer.Bytes())
	s.writeAccess.Unlock()
	if err != nil {
		s.close(err)
		return err
	}
	return nil
}

func (s *udpgwStream) close(err error) {
	s.access.Lock()
	if s.err != nil {
		s.access.Unlock()
		return
	}
	s.err = err
	close(s.done)
	s.access.Unlock()
	s.conn.Close()
}

func (s *udpgwStream) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

var _ net.PacketConn = (*udpgwPacketConn)(nil)

type udpgwPacketConn struct {
	stream       *udpgwStream
	access       sync.Mutex
	connIDs      map[netip.AddrPort]uint16
	packets      chan *N.PacketBuffer
	done         chan struct{}
	readDeadline pipe.Deadline
}

func newUDPGWPacketConn(stream *udpgwStream) *udpgwPacketConn {
	return &udpgwPacketConn{
		stream:       stream,
		connIDs:      make(map[netip.AddrPort]uint16),
		packets:      make(chan *N.PacketBuffer, 64),
		done:         make(chan struct{}),
		readDeadline: pipe.MakeDeadline(),
	}
}

func (c *udpgwPacketConn) enqueue(payload []byte, source netip.AddrPort) {
	packet := N.NewPacketBuffer()
	packet.Buffer = buf.NewSize(len(payload))
	common.Must1(packet.Buffer.Write(payload))
	packet.Destination = M.SocksaddrFromNetIP(source)
	select {
	case c.packets <- packet:
	default:
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
	}
}

func (c *udpgwPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case packet := <-c.packets:
		n = copy(p, packet.Buffer.Bytes())
		addr = packet.Destination.UDPAddr()
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
		return
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-c.stream.done:
		return 0, nil, c.stream.err
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *udpgwPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	destination := M.SocksaddrFromNet(addr).Unwrap()
	if !destination.IsIP() {
		return 0, E.New("udpgw only supports IP destinations: ", destination)
	}
	if len(p) > udpgwMaxPayloadSize {
		return 0, E.New("packet too large: ", len(p))
	}
	connID, rebind, err := c.bind(destination.AddrPort())
	if err != nil {
		return 0, err
	}
	err = c.stream.writePacket(connID, destination.AddrPort(), rebind, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpgwPacketConn) bind(destination netip.AddrPort) (uint16, bool, error) {
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.done:
		return 0, false, net.ErrClosed
	default:
	}
	connID, loaded := c.connIDs[destination]
	if loaded {
		return connID, false, nil
	}
	connID, err := c.stream.bind(c, destination)
	if err != nil {
		return 0, false, err
	}
	c.connIDs[destination] = connID
	return connID, true, nil
}

func (c *udpgwPacketConn) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.done:
		return nil
	default:
	}
	close(c.done)
	c.stream.unbind(c.connIDs)
	return nil
}

func (c *udpgwPacketConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *udpgwPacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpgwPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *udpgwPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}
