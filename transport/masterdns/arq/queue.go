package arq

import (
	"container/list"
	"sync"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/compress"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
)

const (
	queueLevels       = wire.PriorityIdle + 1
	maxQueuedPingSize = 500
	packablePriority  = wire.PriorityHigh
)

// levelQueue is the reference mlq.MultiLevelQueue: FIFO per priority, lower first, unique keys.
type levelQueue[T any] struct {
	levels [queueLevels]list.List
	census map[uint64]levelEntry
}

type levelEntry struct {
	priority int
	element  *list.Element
}

type levelItem[T any] struct {
	key   uint64
	value T
}

func newLevelQueue[T any](initialCapacity int) levelQueue[T] {
	return levelQueue[T]{census: make(map[uint64]levelEntry, initialCapacity)}
}

func (q *levelQueue[T]) push(priority int, key uint64, value T) bool {
	if _, loaded := q.census[key]; loaded {
		return false
	}
	if priority < 0 || priority >= queueLevels {
		priority = wire.PriorityNormal
	}
	element := q.levels[priority].PushBack(levelItem[T]{key, value})
	q.census[key] = levelEntry{priority, element}
	return true
}

func (q *levelQueue[T]) peek() (T, bool) {
	for priority := range q.levels {
		if front := q.levels[priority].Front(); front != nil {
			return front.Value.(levelItem[T]).value, true
		}
	}
	var zero T
	return zero, false
}

func (q *levelQueue[T]) pop() (T, bool) {
	for priority := range q.levels {
		if front := q.levels[priority].Front(); front != nil {
			return q.removeElement(priority, front), true
		}
	}
	var zero T
	return zero, false
}

func (q *levelQueue[T]) popIf(maxPriority int, predicate func(T) bool) (T, bool) {
	for priority := 0; priority <= maxPriority && priority < queueLevels; priority++ {
		for element := q.levels[priority].Front(); element != nil; element = element.Next() {
			if predicate(element.Value.(levelItem[T]).value) {
				return q.removeElement(priority, element), true
			}
		}
	}
	var zero T
	return zero, false
}

func (q *levelQueue[T]) contains(key uint64) bool {
	_, loaded := q.census[key]
	return loaded
}

func (q *levelQueue[T]) remove(key uint64) (T, bool) {
	entry, loaded := q.census[key]
	if !loaded {
		var zero T
		return zero, false
	}
	return q.removeElement(entry.priority, entry.element), true
}

func (q *levelQueue[T]) removeElement(priority int, element *list.Element) T {
	item := q.levels[priority].Remove(element).(levelItem[T])
	delete(q.census, item.key)
	return item.value
}

func (q *levelQueue[T]) len() int {
	return len(q.census)
}

func (q *levelQueue[T]) clear() {
	for priority := range q.levels {
		q.levels[priority].Init()
	}
	clear(q.census)
}

type TXPacket struct {
	Type           uint8
	SequenceNum    uint16
	FragmentID     uint8
	TotalFragments uint8
	Compression    compress.Type
	Payload        []byte
	TTL            time.Duration
	counted        bool
}

// TXQueue is the per-stream send queue of the reference Stream_client (stream_client.go:186-334).
type TXQueue struct {
	access   sync.Mutex
	streamID uint16
	queue    levelQueue[*TXPacket]
	controls int
	wake     func()
}

func NewTXQueue(streamID uint16, initialCapacity int, wake func()) *TXQueue {
	return &TXQueue{
		streamID: streamID,
		queue:    newLevelQueue[*TXPacket](initialCapacity),
		wake:     wake,
	}
}

func (q *TXQueue) PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID, totalFragments uint8, compression compress.Type, ttl time.Duration, payload []byte) bool {
	dataKey := wire.IdentityKey(q.streamID, wire.PacketStreamData, sequenceNum, fragmentID)
	resendKey := wire.IdentityKey(q.streamID, wire.PacketStreamResend, sequenceNum, fragmentID)
	priority = wire.NormalizePriority(packetType, priority)
	q.access.Lock()
	switch packetType {
	case wire.PacketPing:
		if q.queue.len() > maxQueuedPingSize {
			q.access.Unlock()
			return false
		}
	case wire.PacketStreamData:
		if q.queue.contains(dataKey) || q.queue.contains(resendKey) {
			q.access.Unlock()
			return false
		}
	case wire.PacketStreamResend:
		if q.queue.contains(resendKey) {
			q.access.Unlock()
			return false
		}
	}
	packet := &TXPacket{
		Type:           packetType,
		SequenceNum:    sequenceNum,
		FragmentID:     fragmentID,
		TotalFragments: totalFragments,
		Compression:    compression,
		Payload:        payload,
		TTL:            ttl,
	}
	if !q.queue.push(priority, wire.IdentityKey(q.streamID, packetType, sequenceNum, fragmentID), packet) {
		q.access.Unlock()
		return false
	}
	if wire.IsPackable(packetType, len(payload)) {
		packet.counted = true
		q.controls++
	}
	if packetType == wire.PacketStreamResend {
		q.removeLocked(dataKey)
	}
	q.access.Unlock()
	if q.wake != nil {
		q.wake()
	}
	return true
}

func (q *TXQueue) RemoveQueuedData(sequenceNum uint16) bool {
	q.access.Lock()
	defer q.access.Unlock()
	removedData := q.removeLocked(wire.IdentityKey(q.streamID, wire.PacketStreamData, sequenceNum, 0))
	removedResend := q.removeLocked(wire.IdentityKey(q.streamID, wire.PacketStreamResend, sequenceNum, 0))
	return removedData || removedResend
}

func (q *TXQueue) RemoveQueuedDataNack(sequenceNum uint16) bool {
	q.access.Lock()
	defer q.access.Unlock()
	return q.removeLocked(wire.IdentityKey(q.streamID, wire.PacketStreamDataNack, sequenceNum, 0))
}

func (q *TXQueue) Len() int {
	q.access.Lock()
	defer q.access.Unlock()
	return q.queue.len()
}

func (q *TXQueue) Clear() {
	q.access.Lock()
	defer q.access.Unlock()
	q.queue.clear()
	q.controls = 0
}

func (q *TXQueue) removeLocked(key uint64) bool {
	packet, removed := q.queue.remove(key)
	if removed {
		q.uncount(packet)
	}
	return removed
}

func (q *TXQueue) uncount(packet *TXPacket) {
	if packet.counted {
		packet.counted = false
		q.controls--
	}
}

func (q *TXQueue) peek() (*TXPacket, bool) {
	q.access.Lock()
	defer q.access.Unlock()
	return q.queue.peek()
}

func (q *TXQueue) pop() (*TXPacket, bool) {
	q.access.Lock()
	defer q.access.Unlock()
	packet, loaded := q.queue.pop()
	if loaded {
		q.uncount(packet)
	}
	return packet, loaded
}

func (q *TXQueue) popPackable() (*TXPacket, bool) {
	q.access.Lock()
	defer q.access.Unlock()
	packet, loaded := q.queue.popIf(packablePriority, func(packet *TXPacket) bool {
		return wire.IsPackable(packet.Type, len(packet.Payload))
	})
	if loaded {
		q.uncount(packet)
	}
	return packet, loaded
}

func (q *TXQueue) controlCount() int {
	q.access.Lock()
	defer q.access.Unlock()
	return q.controls
}

// OrphanQueue holds the resets and acknowledgements the reference queues for streams it no longer tracks.
type OrphanQueue struct {
	access sync.Mutex
	queue  levelQueue[wire.Packet]
}

func NewOrphanQueue(initialCapacity int) *OrphanQueue {
	return &OrphanQueue{queue: newLevelQueue[wire.Packet](initialCapacity)}
}

func (q *OrphanQueue) Push(priority int, packet wire.Packet) bool {
	q.access.Lock()
	defer q.access.Unlock()
	return q.queue.push(priority, wire.StreamTypeKey(packet.StreamID, packet.Type), packet)
}

func (q *OrphanQueue) Len() int {
	if q == nil {
		return 0
	}
	q.access.Lock()
	defer q.access.Unlock()
	return q.queue.len()
}

func (q *OrphanQueue) Clear() {
	q.access.Lock()
	defer q.access.Unlock()
	q.queue.clear()
}

func (q *OrphanQueue) peek() (wire.Packet, bool) {
	q.access.Lock()
	defer q.access.Unlock()
	return q.queue.peek()
}

func (q *OrphanQueue) pop() (wire.Packet, bool) {
	q.access.Lock()
	defer q.access.Unlock()
	return q.queue.pop()
}

func (q *OrphanQueue) popPackable() (wire.Packet, bool) {
	q.access.Lock()
	defer q.access.Unlock()
	return q.queue.popIf(packablePriority, func(packet wire.Packet) bool {
		return wire.IsPackable(packet.Type, 0)
	})
}
