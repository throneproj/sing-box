package masterdns

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/arq"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	rxDropLogInterval        = 2 * time.Second
	cleanupInterval          = time.Second
	terminalStreamRetention  = 45 * time.Second
	cancelledSetupRetention  = 120 * time.Second
	minWriteDeadlineInterval = 250 * time.Millisecond
)

type inboundPacket struct {
	data   []byte
	source netip.AddrPort
	local  netip.AddrPort
}

type plannerTask struct {
	packet      wire.Packet
	duplication int
	queue       *arq.TXQueue
	item        *arq.TXPacket
}

type outboundFrame struct {
	resolver netip.AddrPort
	key      string
	query    []byte
}

type tunnelSocket struct {
	conn          net.PacketConn
	local         netip.AddrPort
	writeDeadline time.Time
}

type socketSet struct {
	ipv4    []*tunnelSocket
	ipv6    []*tunnelSocket
	closing atomic.Bool
}

func (s *socketSet) pick(index int, resolver netip.Addr) *tunnelSocket {
	sockets := s.ipv4
	if resolver.Unmap().Is6() {
		sockets = s.ipv6
	}
	if len(sockets) == 0 {
		return nil
	}
	return sockets[index%len(sockets)]
}

func (s *socketSet) close() {
	s.closing.Store(true)
	for _, socket := range s.ipv4 {
		socket.conn.Close()
	}
	for _, socket := range s.ipv6 {
		socket.conn.Close()
	}
}

// tunnelRuntime is the reference async runtime of one session: readers, processors, dispatcher, planners and writers.
type tunnelRuntime struct {
	ctx      context.Context
	cancel   context.CancelFunc
	logger   logger.ContextLogger
	client   *Client
	dialer   N.Dialer
	balancer *Balancer
	session  Session
	mode     Mode

	socketAccess  sync.Mutex
	sockets       atomic.Pointer[socketSet]
	socketsBroken atomic.Bool

	inbound        chan inboundPacket
	plannerQueue   chan plannerTask
	writerQueue    chan []outboundFrame
	dispatchSignal chan struct{}
	plannerSpace   chan struct{}
	writerSpace    chan struct{}

	streamAccess    sync.RWMutex
	streams         map[uint16]*clientStream
	streamVersion   atomic.Uint64
	lastStreamID    uint16
	streamQueueSize int
	closed          bool

	orphans       *arq.OrphanQueue
	closedStreams closedStreams
	dispatcher    *arq.Dispatcher
	clock         streamClock
	ping          pinger
	rxDropped     atomic.Uint64
	rxDropLogged  atomic.Int64
	workers       sync.WaitGroup
}

func newTunnelRuntime(ctx context.Context, logger logger.ContextLogger, client *Client, dialer N.Dialer, session Session) (*tunnelRuntime, error) {
	settings := session.Settings
	rxtxWorkers := max(settings.RXTXWorkers, 1)
	processWorkers := max(session.ProcessWorkers, 1)
	batch := max(settings.MaxPacketsPerBatch, 1)
	duplication := max(settings.PacketDuplication, settings.SetupPacketDuplication, 1)
	queueSize := max(24, rxtxWorkers*24)
	streamQueueSize := max(settings.ARQWindowSize/8, batch*8)
	if settings.PacketDuplication > 1 {
		streamQueueSize += settings.PacketDuplication * 4
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &tunnelRuntime{
		ctx:             ctx,
		cancel:          cancel,
		logger:          logger,
		client:          client,
		dialer:          dialer,
		balancer:        client.Balancer(),
		session:         session,
		mode:            client.config.Mode,
		inbound:         make(chan inboundPacket, max(4096, clamp(max(rxtxWorkers+processWorkers, 2)*batch*duplication*16, 1024, 32768))),
		plannerQueue:    make(chan plannerTask, queueSize),
		writerQueue:     make(chan []outboundFrame, queueSize),
		dispatchSignal:  make(chan struct{}, 1),
		plannerSpace:    make(chan struct{}, 1),
		writerSpace:     make(chan struct{}, 1),
		streams:         make(map[uint16]*clientStream),
		streamQueueSize: clamp(streamQueueSize, 32, 512),
		orphans:         arq.NewOrphanQueue(clamp(batch*4+rxtxWorkers*2+duplication*4, 16, 128)),
		dispatcher:      arq.NewDispatcher(),
		clock:           streamClock{wake: make(chan struct{}, 1)},
	}
	r.ping.reset(settings.PingAggressiveInterval)
	sockets, err := r.openSockets()
	if err != nil {
		cancel()
		return nil, err
	}
	r.sockets.Store(sockets)
	r.openVirtualStream()
	r.startReaders(sockets)
	for range processWorkers {
		r.workers.Go(r.processLoop)
	}
	for range rxtxWorkers {
		r.workers.Go(r.planLoop)
	}
	for index := range rxtxWorkers {
		r.workers.Go(func() {
			r.writeLoop(index)
		})
	}
	r.workers.Go(r.dispatchLoop)
	r.workers.Go(r.clockLoop)
	r.workers.Go(r.pingLoop)
	r.workers.Go(r.cleanupLoop)
	return r, nil
}

func clamp(value int, minValue int, maxValue int) int {
	return min(max(value, minValue), maxValue)
}

func wakeup(signal chan struct{}) {
	select {
	case signal <- struct{}{}:
	default:
	}
}

func (r *tunnelRuntime) signalDispatch() {
	wakeup(r.dispatchSignal)
}

// openSockets binds RX_TX_WORKERS sockets for each address family the resolvers use.
func (r *tunnelRuntime) openSockets() (*socketSet, error) {
	var ipv4, ipv6 M.Socksaddr
	for _, connection := range r.balancer.AllConnections() {
		resolver := M.SocksaddrFromNetIP(connection.Resolver).Unwrap()
		if resolver.IsIPv4() {
			if !ipv4.IsValid() {
				ipv4 = resolver
			}
		} else if !ipv6.IsValid() {
			ipv6 = resolver
		}
	}
	var (
		sockets socketSet
		err     error
	)
	if ipv4.IsValid() || !ipv6.IsValid() {
		sockets.ipv4, err = r.listen(ipv4)
		if err != nil {
			return nil, err
		}
	}
	if ipv6.IsValid() {
		sockets.ipv6, err = r.listen(ipv6)
		if err != nil {
			sockets.close()
			return nil, err
		}
	}
	return &sockets, nil
}

func (r *tunnelRuntime) listen(destination M.Socksaddr) ([]*tunnelSocket, error) {
	count := max(r.session.Settings.RXTXWorkers, 1)
	sockets := make([]*tunnelSocket, 0, count)
	for range count {
		conn, err := r.dialer.ListenPacket(r.ctx, destination)
		if err != nil {
			for _, socket := range sockets {
				socket.conn.Close()
			}
			return nil, E.Cause(err, "open tunnel socket")
		}
		sockets = append(sockets, &tunnelSocket{conn: conn, local: M.AddrPortFromNet(conn.LocalAddr())})
	}
	return sockets, nil
}

func (r *tunnelRuntime) startReaders(sockets *socketSet) {
	for _, socket := range sockets.ipv4 {
		r.workers.Go(func() {
			r.readLoop(sockets, socket)
		})
	}
	for _, socket := range sockets.ipv6 {
		r.workers.Go(func() {
			r.readLoop(sockets, socket)
		})
	}
}

// rebind replaces the tunnel sockets after an interface change or when the network manager closed them.
func (r *tunnelRuntime) rebind() {
	r.socketAccess.Lock()
	defer r.socketAccess.Unlock()
	if r.ctx.Err() != nil {
		return
	}
	r.socketsBroken.Store(false)
	sockets, err := r.openSockets()
	if err != nil {
		r.logger.Debug(E.Cause(err, "rebind tunnel sockets"))
		r.socketsBroken.Store(true)
		return
	}
	r.startReaders(sockets)
	if previous := r.sockets.Swap(sockets); previous != nil {
		previous.close()
	}
}

func (r *tunnelRuntime) close() {
	r.cancel()
	r.socketAccess.Lock()
	if sockets := r.sockets.Load(); sockets != nil {
		sockets.close()
	}
	r.socketAccess.Unlock()
	r.workers.Wait()
	for {
		select {
		case packet := <-r.inbound:
			buf.Put(packet.data)
			continue
		case <-r.plannerQueue:
			continue
		case <-r.writerQueue:
			continue
		default:
		}
		break
	}
	r.closeStreams()
	r.closedStreams.clear()
	r.orphans.Clear()
}

func (r *tunnelRuntime) readLoop(sockets *socketSet, socket *tunnelSocket) {
	buffer := buf.Get(maxResponseSize)
	defer buf.Put(buffer)
	for {
		n, addr, err := socket.conn.ReadFrom(buffer)
		if err != nil {
			if r.ctx.Err() != nil || sockets.closing.Load() {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				r.socketsBroken.Store(true)
				return
			}
			continue
		}
		if n < 12 || buffer[2]&0x80 == 0 {
			continue
		}
		data := buf.Get(n)
		copy(data, buffer[:n])
		source := M.AddrPortFromNet(addr)
		select {
		case r.inbound <- inboundPacket{data: data, source: source, local: socket.local}:
		default:
			buf.Put(data)
			r.dropInbound(source)
		}
	}
}

func (r *tunnelRuntime) dropInbound(source netip.AddrPort) {
	dropped := r.rxDropped.Add(1)
	now := time.Now().UnixNano()
	last := r.rxDropLogged.Load()
	if now-last < int64(rxDropLogInterval) || !r.rxDropLogged.CompareAndSwap(last, now) {
		return
	}
	r.logger.Warn("inbound queue overloaded: ", dropped, " packets dropped, last from ", source)
}

func (r *tunnelRuntime) processLoop() {
	for {
		select {
		case <-r.ctx.Done():
			return
		case packet := <-r.inbound:
			r.handleResponse(packet)
			buf.Put(packet.data)
		}
	}
}

// dispatchLoop is the reference asyncStreamDispatcher: one dispatcher per session feeding the planners.
func (r *tunnelRuntime) dispatchLoop() {
	idle := time.NewTimer(arq.DefaultDispatcherIdlePoll)
	defer idle.Stop()
	var (
		version uint64
		streams []arq.DispatchStream
	)
	for {
		if current := r.streamVersion.Load(); current != version || streams == nil {
			version = current
			streams = r.dispatchStreams()
		}
		selection, loaded := r.dispatcher.Select(streams, r.orphans)
		if !loaded {
			select {
			case <-r.ctx.Done():
				return
			case <-r.dispatchSignal:
			case <-r.plannerSpace:
			case <-idle.C:
			}
			idle.Reset(arq.DefaultDispatcherIdlePoll)
			continue
		}
		for len(r.plannerQueue) == cap(r.plannerQueue) {
			select {
			case <-r.ctx.Done():
				return
			case <-r.plannerSpace:
			case <-idle.C:
				idle.Reset(arq.DefaultDispatcherIdlePoll)
			}
		}
		settings := r.session.Settings
		dispatch, taken := r.dispatcher.Take(selection, streams, r.orphans, r.session.MaxPackedBlocks, r.session.UploadCompression,
			settings.PacketDuplication, settings.SetupPacketDuplication, time.Now())
		if !taken {
			continue
		}
		r.ping.notify(dispatch.Packet.Type, false)
		dispatch.Packet.SessionID = r.session.ID
		dispatch.Packet.SessionCookie = r.session.Cookie
		r.plannerQueue <- plannerTask{
			packet:      dispatch.Packet,
			duplication: dispatch.Duplication,
			queue:       dispatch.Queue,
			item:        dispatch.Item,
		}
	}
}

func (r *tunnelRuntime) dispatchStreams() []arq.DispatchStream {
	r.streamAccess.RLock()
	streams := make([]arq.DispatchStream, 0, len(r.streams))
	for id, stream := range r.streams {
		streams = append(streams, arq.DispatchStream{ID: id, Queue: stream.queue, Stream: stream.arq})
	}
	r.streamAccess.RUnlock()
	slices.SortFunc(streams, func(a, b arq.DispatchStream) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return streams
}

func (r *tunnelRuntime) planLoop() {
	for {
		select {
		case <-r.ctx.Done():
			return
		case task := <-r.plannerQueue:
			wakeup(r.plannerSpace)
			frames := r.plan(task)
			if len(frames) == 0 {
				continue
			}
			select {
			case r.writerQueue <- frames:
			case <-r.ctx.Done():
				return
			}
		}
	}
}

// plan picks the resolvers, encodes the packet once and builds one query per domain.
func (r *tunnelRuntime) plan(task plannerTask) []outboundFrame {
	targets, _ := r.balancer.SelectTargets(task.packet.Type, task.packet.StreamID, max(task.duplication, 1))
	if len(targets) == 0 {
		if item := task.item; item != nil && (item.Type == wire.PacketStreamData || item.Type == wire.PacketStreamResend) {
			task.queue.PushTXPacket(wire.DefaultPriority(item.Type), item.Type, item.SequenceNum, item.FragmentID, item.TotalFragments, item.Compression, item.TTL, item.Payload)
		}
		return nil
	}
	raw, err := wire.AppendCompressedPacket(nil, task.packet, r.session.Settings.CompressionMinSize)
	if err != nil {
		return nil
	}
	encoded, err := wire.EncodeFrame(nil, r.client.Codec(), raw)
	if err != nil {
		return nil
	}
	frames := make([]outboundFrame, 0, len(targets))
	queries := make(map[string][]byte, 1)
	for _, target := range targets {
		query, loaded := queries[target.Domain]
		if !loaded {
			query, err = wire.AppendQuery(nil, r.client.NextQueryID(), r.client.Domain(target.Domain), encoded)
			if err != nil {
				continue
			}
			queries[target.Domain] = query
		}
		frames = append(frames, outboundFrame{resolver: target.Resolver, key: target.Key, query: query})
	}
	return frames
}

func (r *tunnelRuntime) writeLoop(index int) {
	refreshWindow := max(PacketTimeout/2, minWriteDeadlineInterval)
	for {
		select {
		case <-r.ctx.Done():
			return
		case frames := <-r.writerQueue:
			wakeup(r.writerSpace)
			now := time.Now()
			sockets := r.sockets.Load()
			for _, frame := range frames {
				socket := sockets.pick(index, frame.resolver.Addr())
				if socket == nil {
					r.socketsBroken.Store(true)
					continue
				}
				if socket.writeDeadline.IsZero() || now.Add(refreshWindow).After(socket.writeDeadline) {
					socket.writeDeadline = now.Add(PacketTimeout)
					socket.conn.SetWriteDeadline(socket.writeDeadline)
				}
				_, err := socket.conn.WriteTo(frame.query, net.UDPAddrFromAddrPort(frame.resolver))
				if err != nil {
					if errors.Is(err, net.ErrClosed) && !sockets.closing.Load() {
						r.socketsBroken.Store(true)
					}
					continue
				}
				r.balancer.TrackSend(binary.BigEndian.Uint16(frame.query), frame.resolver, socket.local, frame.key, now, PacketTimeout)
			}
		}
	}
}

func (r *tunnelRuntime) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case now := <-ticker.C:
			if r.socketsBroken.Load() {
				r.rebind()
			}
			r.closedStreams.prune(now)
			r.cleanupStreams(now)
		}
	}
}
