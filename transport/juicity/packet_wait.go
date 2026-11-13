package juicity

import (
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ N.PacketReadWaiter = (*udpPacketConn)(nil)

func (c *udpPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return false
}

func (c *udpPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	destination, length, err := c.readPacketHeader()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	buffer = c.readWaitOptions.NewPacketBuffer()
	_, err = buffer.ReadFullFrom(c.Conn, length)
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, E.Cause(err, "read payload")
	}
	c.readWaitOptions.PostReturn(buffer)
	return
}
