package arq

import (
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/compress"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
)

const orphanSlot = -1

type DispatchStream struct {
	ID     uint16
	Queue  *TXQueue
	Stream *Stream
}

type Selection struct {
	stream      int
	id          int32
	streamID    uint16
	withOrphans bool
}

type Dispatch struct {
	Packet      wire.Packet
	Duplication int
	// Queue and Item are set for unpacked stream packets: the planner requeues STREAM_DATA and STREAM_RESEND there when no connection is available.
	Queue *TXQueue
	Item  *TXPacket
}

// Dispatcher is the round-robin selection of the reference asyncStreamDispatcher (client/dispatcher.go:22-391); it is not safe for concurrent use.
type Dispatcher struct {
	cursor int32
}

func NewDispatcher() *Dispatcher {
	return &Dispatcher{cursor: -1}
}

func slotID(streams []DispatchStream, index int) int32 {
	if index == len(streams) {
		return orphanSlot
	}
	return int32(streams[index].ID)
}

// Select picks the next stream (sorted by ID) or the orphan queue and advances the cursor; false means wait for work.
func (d *Dispatcher) Select(streams []DispatchStream, orphans *OrphanQueue) (Selection, bool) {
	withOrphans := orphans.Len() > 0
	count := len(streams)
	if withOrphans {
		count++
	}
	if count == 0 {
		return Selection{}, false
	}
	start := 0
	for index := range count {
		if slotID(streams, index) >= d.cursor {
			start = index
			break
		}
	}
	// stream survives a deferred PING peek: the reference then pops stream 0 even when the orphan slot wins.
	selection := Selection{stream: -1, id: -2, withOrphans: withOrphans}
	applied := false
	for offset := range count {
		index := (start + offset) % count
		id := slotID(streams, index)
		var packetType uint8
		if id == orphanSlot {
			packet, loaded := orphans.peek()
			if !loaded {
				continue
			}
			packetType = packet.Type
			selection.streamID = packet.StreamID
			selection.id = orphanSlot
		} else {
			queue := streams[index].Queue
			if queue == nil {
				continue
			}
			packet, loaded := queue.peek()
			if !loaded {
				continue
			}
			packetType = packet.Type
			selection.streamID = uint16(id)
			selection.id = id
			selection.stream = index
		}
		if !applied {
			d.cursor = id + 1
			applied = true
		}
		if id == 0 && packetType == wire.PacketPing && otherWork(streams, withOrphans, orphans) {
			continue
		}
		return selection, true
	}
	return Selection{}, false
}

func otherWork(streams []DispatchStream, withOrphans bool, orphans *OrphanQueue) bool {
	for _, stream := range streams {
		if stream.ID != 0 && stream.Queue != nil && stream.Queue.Len() > 0 {
			return true
		}
	}
	return withOrphans && orphans.Len() > 0
}

// Take dequeues the selection, packing control blocks across streams; false means select again at once.
func (d *Dispatcher) Take(selection Selection, streams []DispatchStream, orphans *OrphanQueue, maxPackedBlocks int, uploadCompression compress.Type, duplication int, setupDuplication int, now time.Time) (Dispatch, bool) {
	var selected *DispatchStream
	if selection.stream >= 0 {
		selected = &streams[selection.stream]
	}
	var item *TXPacket
	if selected != nil {
		packet, loaded := selected.Queue.pop()
		if !loaded {
			return Dispatch{}, false
		}
		noteDequeued(selected, packet, now)
		item = packet
		if (item.Type == wire.PacketStreamData || item.Type == wire.PacketStreamResend) &&
			(selected.Stream == nil || !selected.Stream.HasPendingSequence(item.SequenceNum)) {
			return Dispatch{}, false
		}
	} else {
		packet, loaded := orphans.pop()
		if !loaded {
			return Dispatch{}, false
		}
		item = &TXPacket{
			Type:           packet.Type,
			SequenceNum:    packet.SequenceNum,
			FragmentID:     packet.FragmentID,
			TotalFragments: packet.TotalFragments,
		}
	}
	maxBlocks := max(maxPackedBlocks, 1)
	var payload []byte
	blocks := 0
	if maxBlocks > 1 && wire.IsPackable(item.Type, len(item.Payload)) {
		payload = make([]byte, 0, maxBlocks*wire.PackedBlockSize)
		payload = wire.AppendPackedBlock(payload, wire.PackedBlock{
			Type:           item.Type,
			StreamID:       selection.streamID,
			SequenceNum:    item.SequenceNum,
			FragmentID:     item.FragmentID,
			TotalFragments: item.TotalFragments,
		})
		blocks = 1
		if selected != nil && selected.Queue.controlCount() > 0 {
			payload, blocks = packStream(payload, blocks, maxBlocks, selected, now)
		} else if selection.id == orphanSlot {
			payload, blocks = packOrphans(payload, blocks, maxBlocks, orphans)
		}
		count := len(streams)
		if selection.withOrphans {
			count++
		}
		for index := 0; index < count && blocks < maxBlocks; index++ {
			id := slotID(streams, index)
			if id == selection.id {
				continue
			}
			if id == orphanSlot {
				payload, blocks = packOrphans(payload, blocks, maxBlocks, orphans)
				continue
			}
			other := &streams[index]
			if other.Queue == nil || other.Queue.controlCount() <= 0 {
				continue
			}
			payload, blocks = packStream(payload, blocks, maxBlocks, other, now)
		}
	}
	if blocks > 1 {
		packetType := wire.PacketPackedControlBlocks
		return Dispatch{
			Packet: wire.Packet{
				Type:        packetType,
				Compression: uploadCompression,
				Payload:     payload,
			},
			Duplication: Duplication(packetType, duplication, setupDuplication),
		}, true
	}
	dispatch := Dispatch{
		Packet: wire.Packet{
			Type:           item.Type,
			StreamID:       selection.streamID,
			SequenceNum:    item.SequenceNum,
			FragmentID:     item.FragmentID,
			TotalFragments: item.TotalFragments,
			Compression:    item.Compression,
			Payload:        item.Payload,
		},
		Duplication: Duplication(item.Type, duplication, setupDuplication),
	}
	if selected != nil {
		dispatch.Queue = selected.Queue
		dispatch.Item = item
	}
	return dispatch, true
}

func noteDequeued(stream *DispatchStream, packet *TXPacket, now time.Time) {
	if stream.Stream != nil {
		stream.Stream.NoteTXPacketDequeued(packet.Type, packet.SequenceNum, packet.FragmentID, now)
	}
}

func packStream(payload []byte, blocks int, maxBlocks int, stream *DispatchStream, now time.Time) ([]byte, int) {
	for blocks < maxBlocks {
		packet, loaded := stream.Queue.popPackable()
		if !loaded {
			break
		}
		noteDequeued(stream, packet, now)
		payload = wire.AppendPackedBlock(payload, wire.PackedBlock{
			Type:           packet.Type,
			StreamID:       stream.ID,
			SequenceNum:    packet.SequenceNum,
			FragmentID:     packet.FragmentID,
			TotalFragments: packet.TotalFragments,
		})
		blocks++
	}
	return payload, blocks
}

func packOrphans(payload []byte, blocks int, maxBlocks int, orphans *OrphanQueue) ([]byte, int) {
	for blocks < maxBlocks {
		packet, loaded := orphans.popPackable()
		if !loaded {
			break
		}
		payload = wire.AppendPackedBlock(payload, wire.PackedBlock{
			Type:           packet.Type,
			StreamID:       packet.StreamID,
			SequenceNum:    packet.SequenceNum,
			FragmentID:     packet.FragmentID,
			TotalFragments: packet.TotalFragments,
		})
		blocks++
	}
	return payload, blocks
}

// Duplication is how many resolvers a packet of packetType fans out to (ref client/async_runtime.go:34-61).
func Duplication(packetType uint8, duplication int, setupDuplication int) int {
	count := max(duplication, 1)
	switch packetType {
	case wire.PacketStreamSYN, wire.PacketPackedControlBlocks, wire.PacketSOCKS5SYN,
		wire.PacketStreamCloseRead, wire.PacketStreamCloseWrite:
		count = max(count, setupDuplication)
	case wire.PacketPing:
		return min(count, 2)
	}
	return count
}
