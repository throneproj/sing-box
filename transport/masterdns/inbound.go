package masterdns

import (
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/arq"
	"github.com/sagernet/sing-box/transport/masterdns/compress"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
)

const maxClosedStreams = 2000

// handleResponse is the reference handleInboundPacket: resolver health, ping activity, immediate acknowledgements, then the handler table.
func (r *tunnelRuntime) handleResponse(packet inboundPacket) {
	now := time.Now()
	dnsID := binary.BigEndian.Uint16(packet.data)
	response, err := wire.ParseResponse(packet.data, r.session.Base64Response)
	if err != nil {
		if errors.Is(err, wire.ErrNoTXTAnswer) {
			if rcode, loaded := wire.ResponseRCode(packet.data); loaded && rcode != 0 {
				r.balancer.TrackFailure(dnsID, packet.source, packet.local, now)
			} else {
				r.balancer.TrackSuccess(dnsID, packet.source, packet.local, now)
			}
		}
		return
	}
	r.balancer.TrackSuccess(dnsID, packet.source, packet.local, now)
	r.ping.notify(response.Type, true)
	if r.preprocess(response, now) {
		return
	}
	r.handlePacket(response, now)
}

// preprocess answers packets of unknown streams and consumes acknowledgements; true means the packet is handled.
func (r *tunnelRuntime) preprocess(packet wire.Packet, now time.Time) bool {
	stream := r.stream(packet.StreamID)
	if packet.StreamID != 0 && stream == nil {
		if !r.closedStreams.contains(packet.StreamID, now) {
			r.handleMissingStream(packet, now)
			return true
		}
		switch packet.Type {
		case wire.PacketStreamData, wire.PacketStreamResend:
			r.pushOrphan(wire.PacketStreamRST, packet.StreamID, 0)
		case wire.PacketStreamDataAck, wire.PacketStreamDataNack:
		default:
			if _, isAck := wire.AckedControl(packet.Type); isAck {
				break
			}
			if ackType, loaded := wire.ControlAck(packet.Type); loaded {
				r.pushOrphan(ackType, packet.StreamID, packet.SequenceNum)
			}
		}
		return true
	}
	if stream == nil {
		return false
	}
	if ackType, loaded := wire.ControlAck(packet.Type); loaded {
		stream.queue.PushTXPacket(wire.DefaultPriority(ackType), ackType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, compress.Off, 0, nil)
	}
	if _, isAck := wire.AckedControl(packet.Type); !isAck && packet.Type != wire.PacketStreamDataAck {
		return false
	}
	if packet.Type == wire.PacketStreamRSTAck {
		r.closedStreams.remember(packet.StreamID, "ACK acknowledged", now)
	}
	if !stream.arq.HandleAckPacket(packet.Type, packet.SequenceNum, packet.FragmentID, now) {
		return false
	}
	r.balancer.NoteStreamProgress(packet.StreamID)
	return true
}

func (r *tunnelRuntime) handleMissingStream(packet wire.Packet, now time.Time) {
	switch packet.Type {
	case wire.PacketPackedControlBlocks, wire.PacketPong, wire.PacketDNSQueryResponse,
		wire.PacketStreamDataAck, wire.PacketStreamDataNack:
		return
	case wire.PacketStreamRSTAck:
		r.closedStreams.remember(packet.StreamID, "ACK acknowledged", now)
		return
	case wire.PacketStreamRST:
		r.pushOrphan(wire.PacketStreamRSTAck, packet.StreamID, packet.SequenceNum)
		return
	}
	if _, isAck := wire.AckedControl(packet.Type); isAck {
		return
	}
	if ackType, loaded := wire.CloseStreamAck(packet.Type); loaded {
		r.pushOrphan(ackType, packet.StreamID, 0)
	} else {
		r.pushOrphan(wire.PacketStreamRST, packet.StreamID, 0)
	}
}

func (r *tunnelRuntime) pushOrphan(packetType uint8, streamID uint16, sequenceNum uint16) {
	if streamID == 0 {
		return
	}
	r.orphans.Push(wire.PriorityCritical, wire.Packet{Type: packetType, StreamID: streamID, SequenceNum: sequenceNum})
	r.signalDispatch()
}

// handlePacket is the reference handler table (client/handlers).
func (r *tunnelRuntime) handlePacket(packet wire.Packet, now time.Time) {
	switch packet.Type {
	case wire.PacketPackedControlBlocks:
		for block := range wire.PackedBlocks(packet.Payload) {
			inner := block.Packet(packet)
			if !r.preprocess(inner, now) {
				r.handlePacket(inner, now)
			}
		}
	case wire.PacketSessionBusy:
		r.client.RequestSessionRestart("session busy received")
	case wire.PacketErrorDrop:
		r.client.RequestSessionRestart("error drop received")
	case wire.PacketSOCKS5Connected:
		if stream := r.stream(packet.StreamID); stream != nil {
			stream.handleSOCKSConnected()
		}
	case wire.PacketSOCKS5SYNAck:
		if stream := r.stream(packet.StreamID); stream != nil {
			stream.arq.HandleAckPacket(packet.Type, packet.SequenceNum, packet.FragmentID, now)
		}
	case wire.PacketStreamData, wire.PacketStreamDataAck, wire.PacketStreamDataNack, wire.PacketStreamResend,
		wire.PacketStreamSYN, wire.PacketStreamSYNAck, wire.PacketStreamConnected, wire.PacketStreamConnectedAck,
		wire.PacketStreamConnectFail, wire.PacketStreamConnectFailAck, wire.PacketStreamCloseWrite, wire.PacketStreamCloseWriteAck,
		wire.PacketStreamCloseRead, wire.PacketStreamCloseReadAck, wire.PacketStreamRST, wire.PacketStreamRSTAck:
		if stream := r.stream(packet.StreamID); stream != nil {
			r.handleStreamPacket(stream, packet, now)
		}
	case wire.PacketMTUUpResponse, wire.PacketMTUDownResponse, wire.PacketPong,
		wire.PacketDNSQueryRequestAck, wire.PacketDNSQueryResponse:
	default:
		if _, isFailure := wire.SOCKSReply(packet.Type); isFailure {
			if stream := r.stream(packet.StreamID); stream != nil {
				stream.handleSOCKSFailure(packet.Type)
			}
			return
		}
		r.logger.Debug("unexpected packet type ", packet.Type, " for stream ", packet.StreamID)
	}
}

func (r *tunnelRuntime) handleStreamPacket(stream *clientStream, packet wire.Packet, now time.Time) {
	switch packet.Type {
	case wire.PacketStreamData, wire.PacketStreamResend:
		if stream.arq.IsClosed() || stream.isTerminal() {
			r.pushOrphan(wire.PacketStreamRST, packet.StreamID, 0)
			return
		}
		stream.arq.ReceiveData(packet.SequenceNum, packet.Payload, now)
	case wire.PacketStreamDataNack:
		if stream.arq.IsClosed() || stream.isTerminal() {
			return
		}
		if stream.arq.HandleDataNack(packet.SequenceNum, now) {
			r.balancer.NoteStreamProgress(packet.StreamID)
		}
	case wire.PacketStreamConnected:
		if stream.handleConnected() {
			r.balancer.NoteStreamProgress(packet.StreamID)
		}
	case wire.PacketStreamConnectFail:
		stream.handleConnectFail(now)
	case wire.PacketStreamCloseRead:
		stream.arq.MarkCloseReadReceived()
	case wire.PacketStreamCloseWrite:
		stream.arq.MarkCloseWriteReceived()
	case wire.PacketStreamRST:
		stream.arq.MarkRstReceived()
		stream.arq.Close("peer reset received", arq.CloseOptions{Force: true})
		stream.access.Lock()
		stream.markTerminalLocked(now)
		if stream.status != streamCancelled {
			stream.status = streamTimeWait
		}
		stream.access.Unlock()
	default:
		if stream.arq.HandleAckPacket(packet.Type, packet.SequenceNum, packet.FragmentID, now) {
			r.balancer.NoteStreamProgress(packet.StreamID)
		}
	}
}

func (s *clientStream) lateResultLocked() bool {
	return s.status == streamCancelled || !s.terminalSince.IsZero()
}

func (s *clientStream) handleConnected() bool {
	s.access.Lock()
	switch s.status {
	case streamActive, streamDraining, streamClosing, streamTimeWait, streamClosed:
		s.access.Unlock()
		return false
	}
	if s.lateResultLocked() {
		s.access.Unlock()
		s.arq.Close("late STREAM_CONNECTED result", arq.CloseOptions{SendRST: true})
		return false
	}
	s.status = streamActive
	s.access.Unlock()
	s.arq.SetIOReady(true)
	s.setResult(nil)
	return true
}

func (s *clientStream) handleConnectFail(now time.Time) {
	s.access.Lock()
	switch s.status {
	case streamDraining, streamClosing, streamTimeWait, streamClosed:
		s.access.Unlock()
		return
	}
	if s.lateResultLocked() {
		s.access.Unlock()
		s.arq.Close("late STREAM_CONNECT_FAIL result", arq.CloseOptions{SendRST: true})
		return
	}
	s.markTerminalLocked(now)
	s.status = streamTimeWait
	s.access.Unlock()
	s.setResult(errConnectFailed)
	s.arq.Close("STREAM connect failure received", arq.CloseOptions{Force: true})
}

func (s *clientStream) handleSOCKSConnected() {
	s.access.Lock()
	switch s.status {
	case streamActive, streamSOCKSFailed, streamDraining, streamClosing, streamTimeWait, streamClosed:
		s.access.Unlock()
		return
	case streamCancelled:
		s.access.Unlock()
		s.arq.Close("late SOCKS success after local cancellation", arq.CloseOptions{SendRST: true})
		return
	}
	if s.lateResultLocked() {
		s.access.Unlock()
		s.arq.Close("late SOCKS success result", arq.CloseOptions{SendRST: true})
		return
	}
	s.status = streamActive
	s.access.Unlock()
	s.setResult(nil)
	s.arq.SetIOReady(true)
}

func (s *clientStream) handleSOCKSFailure(packetType uint8) {
	s.access.Lock()
	switch s.status {
	case streamSOCKSFailed, streamDraining, streamClosing, streamTimeWait, streamClosed:
		s.access.Unlock()
		return
	case streamCancelled:
		s.access.Unlock()
		s.arq.Close("SOCKS failure received after local cancellation", arq.CloseOptions{SendRST: true})
		return
	}
	if s.lateResultLocked() {
		s.access.Unlock()
		s.arq.Close("late SOCKS failure result", arq.CloseOptions{SendRST: true})
		return
	}
	s.status = streamSOCKSFailed
	s.access.Unlock()
	s.setResult(socksError(packetType))
	s.arq.Close("SOCKS failure received", arq.CloseOptions{Force: true})
}

// closedStreams is the reference recently-closed set: late packets of streams that closed cleanly are answered without a reset.
type closedStreams struct {
	access  sync.Mutex
	expires map[uint16]time.Time
	order   []closedStream
}

type closedStream struct {
	id      uint16
	expires time.Time
}

func (c *closedStreams) remember(id uint16, reason string, now time.Time) {
	reason = strings.TrimSpace(reason)
	if id == 0 || reason == "" || reason != "close handshake completed" && reason != "client local disconnect completed" && !strings.HasSuffix(reason, "acknowledged") {
		return
	}
	expires := now.Add(terminalStreamRetention)
	c.access.Lock()
	defer c.access.Unlock()
	c.pruneLocked(now)
	if c.expires == nil {
		c.expires = make(map[uint16]time.Time)
	}
	c.expires[id] = expires
	c.order = append(c.order, closedStream{id: id, expires: expires})
	for len(c.expires) > maxClosedStreams {
		oldest := c.order[0]
		c.order = c.order[1:]
		if current, loaded := c.expires[oldest.id]; loaded && current.Equal(oldest.expires) {
			delete(c.expires, oldest.id)
		}
	}
}

func (c *closedStreams) contains(id uint16, now time.Time) bool {
	if id == 0 {
		return false
	}
	c.access.Lock()
	defer c.access.Unlock()
	c.pruneLocked(now)
	expires, loaded := c.expires[id]
	if !loaded {
		return false
	}
	if now.Before(expires) {
		return true
	}
	delete(c.expires, id)
	return false
}

func (c *closedStreams) prune(now time.Time) {
	c.access.Lock()
	defer c.access.Unlock()
	c.pruneLocked(now)
}

func (c *closedStreams) pruneLocked(now time.Time) {
	for len(c.order) > 0 {
		oldest := c.order[0]
		current, loaded := c.expires[oldest.id]
		if loaded && current.Equal(oldest.expires) {
			if now.Before(current) {
				break
			}
			delete(c.expires, oldest.id)
		}
		c.order = c.order[1:]
	}
	if len(c.order) > len(c.expires)*3/2+4 {
		order := make([]closedStream, 0, len(c.expires))
		for _, entry := range c.order {
			if current, loaded := c.expires[entry.id]; loaded && current.Equal(entry.expires) {
				order = append(order, entry)
			}
		}
		c.order = order
	}
	if len(c.order) == 0 {
		c.order = nil
	}
}

func (c *closedStreams) clear() {
	c.access.Lock()
	defer c.access.Unlock()
	clear(c.expires)
	c.order = nil
}
