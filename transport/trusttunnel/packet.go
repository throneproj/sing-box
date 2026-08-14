package trusttunnel

import (
	std_bufio "bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat2"
)

type clientPacketConn struct {
	conn        net.Conn
	reader      *std_bufio.Reader
	writeAccess sync.Mutex
}

func newClientPacketConn(conn net.Conn) *clientPacketConn {
	return &clientPacketConn{
		conn:   conn,
		reader: std_bufio.NewReader(conn),
	}
}

func (c *clientPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	var header [serverPacketHeaderLength]byte
	for {
		_, err := io.ReadFull(c.reader, header[:])
		if err != nil {
			return M.Socksaddr{}, err
		}
		length := int(binary.BigEndian.Uint32(header[:4]))
		if length < serverPacketHeaderLength-4 {
			return M.Socksaddr{}, E.New("invalid packet length: ", length)
		}
		payloadLength := length - (serverPacketHeaderLength - 4)
		if payloadLength > buffer.FreeLen() {
			_, err = c.reader.Discard(payloadLength)
			if err != nil {
				return M.Socksaddr{}, err
			}
			continue
		}
		_, err = buffer.ReadFullFrom(c.reader, payloadLength)
		if err != nil {
			return M.Socksaddr{}, err
		}
		return M.SocksaddrFrom(readPaddedAddress(header[4:20]), binary.BigEndian.Uint16(header[20:22])), nil
	}
}

func (c *clientPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	destination = destination.Unwrap()
	if !destination.IsIP() {
		buffer.Release()
		return E.New("only IP destinations are supported: ", destination)
	}
	packet, header := extendHeader(buffer, clientPacketHeaderLength)
	defer packet.Release()
	binary.BigEndian.PutUint32(header, uint32(packet.Len()-4))
	clear(header[4:22])
	putPaddedAddress(header[22:], destination.Addr)
	binary.BigEndian.PutUint16(header[38:], destination.Port)
	header[40] = 0
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	_, err := c.conn.Write(packet.Bytes())
	return err
}

func (c *clientPacketConn) Close() error {
	return c.conn.Close()
}

func (c *clientPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *clientPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *clientPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *clientPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *clientPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *clientPacketConn) FrontHeadroom() int {
	return clientPacketHeaderLength
}

func (c *clientPacketConn) Upstream() any {
	return c.conn
}

var _ N.PacketConn = (*clientPacketConn)(nil)

type udpSession struct {
	ctx     context.Context
	handler Handler
	source  M.Socksaddr
	writer  http.ResponseWriter
	access  sync.Mutex
	closed  bool
}

func (s *udpSession) loopInput(reader *std_bufio.Reader, service *udpnat.Service) error {
	var header [clientPacketHeaderLength]byte
	for {
		_, err := io.ReadFull(reader, header[:4])
		if err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint32(header[:4]))
		// Malformed packets are skipped like the official endpoint does, the stream stays open.
		if length < clientPacketHeaderLength-4 {
			_, err = reader.Discard(length)
			if err != nil {
				return err
			}
			continue
		}
		_, err = io.ReadFull(reader, header[4:])
		if err != nil {
			return err
		}
		appNameLength := int(header[40])
		payloadLength := length - (clientPacketHeaderLength - 4) - appNameLength
		if payloadLength < 0 || length > maxUDPPayloadLength-(clientPacketHeaderLength-4)-appNameLength {
			_, err = reader.Discard(length - (clientPacketHeaderLength - 4))
			if err != nil {
				return err
			}
			continue
		}
		_, err = reader.Discard(appNameLength)
		if err != nil {
			return err
		}
		buffer := buf.NewSize(payloadLength)
		_, err = buffer.ReadFullFrom(reader, payloadLength)
		if err != nil {
			buffer.Release()
			return err
		}
		source := M.SocksaddrFrom(readPaddedAddress(header[4:20]), binary.BigEndian.Uint16(header[20:22]))
		destination := M.SocksaddrFrom(readPaddedAddress(header[22:38]), binary.BigEndian.Uint16(header[38:40]))
		service.NewPacket([][]byte{buffer.Bytes()}, source, destination, nil)
		buffer.Release()
	}
}

func (s *udpSession) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _ M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	s.handler.NewPacketConnectionEx(ctx, conn, s.source, destination, onClose)
}

func (s *udpSession) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	return true, log.ContextWithNewID(s.ctx), &udpSessionWriter{session: s, destination: source}, nil
}

func (s *udpSession) writePacket(buffer *buf.Buffer, source M.Socksaddr, destination M.Socksaddr) error {
	if !source.IsIP() {
		buffer.Release()
		return E.New("only IP sources are supported: ", source)
	}
	packet, header := extendHeader(buffer, serverPacketHeaderLength)
	defer packet.Release()
	binary.BigEndian.PutUint32(header, uint32(packet.Len()-4))
	putPaddedAddress(header[4:], source.Addr)
	binary.BigEndian.PutUint16(header[20:], source.Port)
	putPaddedAddress(header[22:], destination.Addr)
	binary.BigEndian.PutUint16(header[38:], destination.Port)
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	_, err := s.writer.Write(packet.Bytes())
	if err != nil {
		return err
	}
	s.writer.(http.Flusher).Flush()
	return nil
}

func (s *udpSession) close() {
	s.access.Lock()
	defer s.access.Unlock()
	s.closed = true
}

type udpSessionWriter struct {
	session     *udpSession
	destination M.Socksaddr
}

func (w *udpSessionWriter) WritePacket(buffer *buf.Buffer, source M.Socksaddr) error {
	return w.session.writePacket(buffer, source.Unwrap(), w.destination)
}

func (w *udpSessionWriter) FrontHeadroom() int {
	return serverPacketHeaderLength
}

func extendHeader(buffer *buf.Buffer, headerLength int) (*buf.Buffer, []byte) {
	if buffer.Start() >= headerLength {
		return buffer, buffer.ExtendHeader(headerLength)
	}
	packet := buf.NewSize(headerLength + buffer.Len())
	header := packet.Extend(headerLength)
	common.Must1(packet.Write(buffer.Bytes()))
	buffer.Release()
	return packet, header
}
