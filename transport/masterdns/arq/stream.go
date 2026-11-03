package arq

import (
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/compress"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
)

const (
	maxReadBuffer       = 256 << 10
	dataRTOGrowth       = 1.35
	controlRTOGrowth    = 1.25
	setupRTOGrowth      = 1.15
	setupRTOCap         = 350 * time.Millisecond
	setupMaxRetries     = 120
	setupPacketTTLFloor = 300 * time.Second
	drainRTOCap         = 2 * time.Second
	closeGrace          = 2 * time.Second
	drainStallWindow    = 30 * time.Second
	drainStallAfter     = 20 * time.Second
)

type Enqueuer interface {
	PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID, totalFragments uint8, compression compress.Type, ttl time.Duration, payload []byte) bool
}

type QueuedDataRemover interface {
	RemoveQueuedData(sequenceNum uint16) bool
}

type QueuedDataNackRemover interface {
	RemoveQueuedDataNack(sequenceNum uint16) bool
}

type dataItem struct {
	data           []byte
	createdAt      time.Time
	lastSentAt     time.Time
	dispatched     bool
	lastNackSentAt time.Time
	retries        int
	currentRTO     time.Duration
	sampleEligible bool
	compression    compress.Type
	ttl            time.Duration
}

type controlItem struct {
	packetType     uint8
	sequenceNum    uint16
	fragmentID     uint8
	totalFragments uint8
	payload        []byte
	priority       int
	createdAt      time.Time
	lastSentAt     time.Time
	dispatched     bool
	retries        int
	currentRTO     time.Duration
	sampleEligible bool
	ttl            time.Duration
}

type rtoEstimator struct {
	srtt        time.Duration
	rttvar      time.Duration
	base        time.Duration
	initialized bool
}

func (e *rtoEstimator) update(sample time.Duration, minRTO time.Duration, maxRTO time.Duration) {
	sample = clampDuration(sample, minRTO, maxRTO)
	if !e.initialized {
		e.srtt = sample
		e.rttvar = sample / 2
		e.initialized = true
	} else {
		delta := e.srtt - sample
		if delta < 0 {
			delta = -delta
		}
		e.rttvar = (3*e.rttvar + delta) / 4
		e.srtt = (7*e.srtt + sample) / 8
	}
	e.base = clampDuration(e.srtt+4*e.rttvar, minRTO, maxRTO)
}

func clampDuration(value time.Duration, minValue time.Duration, maxValue time.Duration) time.Duration {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func controlKey(packetType uint8, sequenceNum uint16, fragmentID uint8) uint32 {
	return uint32(packetType)<<24 | uint32(sequenceNum)<<8 | uint32(fragmentID)
}

func isSetupPacket(packetType uint8) bool {
	return packetType == wire.PacketStreamSYN || packetType == wire.PacketSOCKS5SYN
}

// Stream is the reference ARQ (internal/arq/arq.go) without goroutines: the owner drives Tick, the local side is Write/Read.
type Stream struct {
	access      sync.Mutex
	writeAccess sync.Mutex

	streamID    uint16
	mtu         int
	compression compress.Type
	enqueuer    Enqueuer
	dataRemover QueuedDataRemover
	nackRemover QueuedDataNackRemover
	onClosed    func(reason string)
	clock       func() time.Time
	isClient    bool
	isVirtual   bool

	windowSize               int
	receiveWindowSize        int
	limit                    int
	rto                      time.Duration
	maxRTO                   time.Duration
	inactivityTimeout        time.Duration
	dataPacketTTL            time.Duration
	maxDataRetries           int
	terminalDrainTimeout     time.Duration
	terminalAckWait          time.Duration
	enableControlReliability bool
	controlRTO               time.Duration
	controlMaxRTO            time.Duration
	controlMaxRetries        int
	controlPacketTTL         time.Duration
	dataNackMaxGap           int
	dataNackInitialDelay     time.Duration
	dataNackRepeat           time.Duration
	dataRTO                  rtoEstimator
	controlRTOEstimator      rtoEstimator

	ioReady       bool
	sndNxt        uint16
	rcvNxt        uint16
	sndBuf        map[uint16]*dataItem
	rcvBuf        map[uint16][]byte
	controlSndBuf map[uint32]*controlItem

	firstDataNackSeen map[uint16]time.Time
	lastDataNackSent  map[uint16]time.Time

	state        State
	closed       bool
	closeReason  string
	lastActivity time.Time

	closeReadSent      bool
	closeReadReceived  bool
	closeReadAcked     bool
	closeWriteSent     bool
	closeWriteReceived bool
	closeWriteAcked    bool
	rstReceived        bool
	rstSent            bool
	rstAcked           bool

	localWriteClosed   bool
	localWriterBroken  bool
	localWritePending  bool
	stopLocalRead      bool
	deferredClose      bool
	deferredReason     string
	deferredDeadline   time.Time
	deferredPacket     uint8
	clientEOFAt        time.Time
	closeReadAckedAt   time.Time
	lastDuplicateAckAt time.Time
	waitingAck         bool
	waitingAckFor      uint8
	ackWaitDeadline    time.Time
	drainProgressAt    time.Time
	drainQueueFailAt   time.Time
	drainQueueFails    int

	writing         bool
	localEOF        bool
	localEOFHandled bool
	localReadClosed bool
	writerExited    bool
	flushPending    bool
	readChunks      [][]byte
	readBuffered    int

	notifyClosed bool
	waiters      int
	wake         chan struct{}
	done         chan struct{}
}

func New(streamID uint16, mtu int, config Config, enqueuer Enqueuer, onClosed func(reason string)) *Stream {
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	windowSize := max(config.WindowSize, minWindowSize)
	maxRTO := max(config.MaxRTO, minRTO)
	controlMaxRTO := max(config.ControlMaxRTO, minRTO)
	s := &Stream{
		streamID:                 streamID,
		mtu:                      max(mtu, 1),
		compression:              config.Compression,
		enqueuer:                 enqueuer,
		onClosed:                 onClosed,
		clock:                    clock,
		isClient:                 config.IsClient,
		isVirtual:                config.IsVirtual,
		windowSize:               windowSize,
		receiveWindowSize:        windowSize * 2,
		limit:                    max(int(float64(windowSize)*0.8), minSendLimit),
		rto:                      min(max(config.RTO, minRTO), maxRTO),
		maxRTO:                   maxRTO,
		inactivityTimeout:        max(config.InactivityTimeout, minInactivityTimeout),
		dataPacketTTL:            max(config.DataPacketTTL, minDataPacketTTL),
		maxDataRetries:           max(config.MaxDataRetries, minMaxDataRetries),
		terminalDrainTimeout:     max(config.TerminalDrainTimeout, minTerminalDrainTimeout),
		terminalAckWait:          max(config.TerminalAckWaitTimeout, minTerminalAckWait),
		enableControlReliability: config.EnableControlReliability,
		controlRTO:               min(max(config.ControlRTO, minRTO), controlMaxRTO),
		controlMaxRTO:            controlMaxRTO,
		controlMaxRetries:        max(config.ControlMaxRetries, minControlMaxRetries),
		controlPacketTTL:         max(config.ControlPacketTTL, minControlPacketTTL),
		dataNackMaxGap:           max(config.DataNackMaxGap, 0),
		dataNackInitialDelay:     max(config.DataNackInitialDelay, 0),
		dataNackRepeat:           max(config.DataNackRepeat, minDataNackRepeat),
		ioReady:                  !config.StartPaused,
		sndBuf:                   make(map[uint16]*dataItem),
		rcvBuf:                   make(map[uint16][]byte),
		controlSndBuf:            make(map[uint32]*controlItem),
		firstDataNackSeen:        make(map[uint16]time.Time),
		lastDataNackSent:         make(map[uint16]time.Time),
		state:                    StateOpen,
		lastActivity:             clock(),
		wake:                     make(chan struct{}),
		done:                     make(chan struct{}),
	}
	s.dataRTO.base = s.rto
	s.controlRTOEstimator.base = s.controlRTO
	s.dataRemover, _ = enqueuer.(QueuedDataRemover)
	s.nackRemover, _ = enqueuer.(QueuedDataNackRemover)
	return s
}

func (s *Stream) release(now time.Time) {
	for s.flushPending {
		s.flushPending = false
		s.flush(now)
	}
	if s.waiters > 0 {
		close(s.wake)
		s.wake = make(chan struct{})
	}
	notifyClosed := s.notifyClosed
	s.notifyClosed = false
	reason := s.closeReason
	s.access.Unlock()
	if notifyClosed && s.onClosed != nil {
		s.onClosed(reason)
	}
}

func (s *Stream) wait(cancel <-chan struct{}) bool {
	wake := s.wake
	s.waiters++
	s.access.Unlock()
	var canceled bool
	select {
	case <-wake:
	case <-cancel:
		canceled = true
	}
	s.access.Lock()
	s.waiters--
	return !canceled
}

func (s *Stream) State() State {
	s.access.Lock()
	defer s.access.Unlock()
	return s.state
}

func (s *Stream) IsClosed() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.closed
}

func (s *Stream) IsReset() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.isReset()
}

func (s *Stream) isReset() bool {
	return s.state == StateReset || s.rstReceived || s.rstSent
}

func (s *Stream) Done() <-chan struct{} {
	return s.done
}

func (s *Stream) HasPendingSequence(sequenceNum uint16) bool {
	s.access.Lock()
	defer s.access.Unlock()
	_, loaded := s.sndBuf[sequenceNum]
	return loaded
}

func (s *Stream) SetIOReady(ready bool) {
	s.access.Lock()
	now := s.clock()
	if s.ioReady != ready {
		s.ioReady = ready
		if ready {
			s.flushPending = true
			s.processLocalEOF(now)
		}
	}
	s.release(now)
}

// Write segments p at the MTU and blocks while the send window is full, like the reference ioLoop reading a local socket.
func (s *Stream) Write(p []byte, cancel <-chan struct{}) (int, error) {
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	s.access.Lock()
	s.writing = true
	var (
		written int
		err     error
	)
	for written < len(p) {
		err = s.waitWritable(cancel)
		if err != nil {
			break
		}
		end := min(written+s.mtu, len(p))
		s.sendData(slices.Clone(p[written:end]), s.clock())
		written = end
	}
	s.writing = false
	now := s.clock()
	s.processLocalEOF(now)
	s.release(now)
	return written, err
}

func (s *Stream) waitWritable(cancel <-chan struct{}) error {
	for {
		if s.closed || s.stopLocalRead || s.localEOF {
			if s.isReset() {
				return ErrReset
			}
			return io.ErrClosedPipe
		}
		if s.ioReady && len(s.sndBuf) < s.limit {
			return nil
		}
		if !s.wait(cancel) {
			return ErrCanceled
		}
	}
}

func (s *Stream) sendData(data []byte, now time.Time) {
	s.lastActivity = now
	sequenceNum := s.sndNxt
	s.sndNxt++
	item := &dataItem{
		data:           data,
		createdAt:      now,
		currentRTO:     s.currentDataBaseRTO(),
		sampleEligible: true,
		compression:    s.compression,
	}
	s.sndBuf[sequenceNum] = item
	if !s.enqueuer.PushTXPacket(wire.DefaultPriority(wire.PacketStreamData), wire.PacketStreamData, sequenceNum, 0, 0, s.compression, 0, data) {
		item.dispatched = true
		item.lastSentAt = now.Add(-item.currentRTO)
	}
}

// CloseWrite is the local EOF: CLOSE_READ once the send buffer drains.
func (s *Stream) CloseWrite() {
	s.access.Lock()
	now := s.clock()
	if !s.localEOF {
		s.localEOF = true
		s.processLocalEOF(now)
	}
	s.release(now)
}

// processLocalEOF runs where the reference ioLoop would read the EOF: after pending writes, with window room and IO ready.
func (s *Stream) processLocalEOF(now time.Time) {
	if !s.localEOF || s.localEOFHandled || s.writing {
		return
	}
	if s.closed || s.stopLocalRead {
		s.localEOFHandled = true
		return
	}
	if !s.ioReady || len(s.sndBuf) >= s.limit {
		return
	}
	s.localEOFHandled = true
	if s.isClient && s.clientEOFAt.IsZero() {
		s.clientEOFAt = now
	}
	s.close("Local App Closed Connection (EOF)", CloseOptions{SendCloseRead: true, AfterDrain: true}, now)
}

// CloseRead means the local side stopped reading: buffered data is dropped and the next delivery fails like a broken socket.
func (s *Stream) CloseRead() {
	s.access.Lock()
	now := s.clock()
	if !s.localReadClosed {
		s.localReadClosed = true
		s.readChunks = nil
		s.readBuffered = 0
		if s.localWritePending {
			s.flushPending = true
		}
	}
	s.release(now)
}

// Read returns in-order data; after the peer's close or a stream close it drains what was delivered, then io.EOF or ErrReset.
func (s *Stream) Read(p []byte, cancel <-chan struct{}) (int, error) {
	s.access.Lock()
	for {
		if s.localReadClosed {
			s.access.Unlock()
			return 0, net.ErrClosed
		}
		if len(p) == 0 {
			s.access.Unlock()
			return 0, nil
		}
		if s.readBuffered > 0 {
			n := s.readBuffer(p)
			now := s.clock()
			if s.localWritePending && s.readBuffered < maxReadBuffer {
				s.flushPending = true
			}
			s.release(now)
			return n, nil
		}
		if s.localWriteClosed {
			s.access.Unlock()
			return 0, io.EOF
		}
		if s.closed {
			err := io.EOF
			if s.state == StateReset {
				err = ErrReset
			}
			s.access.Unlock()
			return 0, err
		}
		if !s.wait(cancel) {
			s.access.Unlock()
			return 0, ErrCanceled
		}
	}
}

func (s *Stream) readBuffer(p []byte) int {
	var n int
	for n < len(p) && len(s.readChunks) > 0 {
		copied := copy(p[n:], s.readChunks[0])
		n += copied
		if copied == len(s.readChunks[0]) {
			s.readChunks[0] = nil
			s.readChunks = s.readChunks[1:]
		} else {
			s.readChunks[0] = s.readChunks[0][copied:]
		}
	}
	s.readBuffered -= n
	if len(s.readChunks) == 0 {
		s.readChunks = nil
	}
	return n
}

// flush is the reference writeLoop pass that a flush signal triggers.
func (s *Stream) flush(now time.Time) {
	for !s.writerExited {
		if s.closed {
			s.writerExited = true
			return
		}
		if !s.ioReady {
			return
		}
		if _, ready := s.rcvBuf[s.rcvNxt]; !ready {
			s.localWritePending = false
			if s.closeReadReceived {
				s.halfCloseLocalWriter()
			}
			if s.rstReceived && s.tryFinalizePeerResetDrain() {
				s.writerExited = true
				return
			}
			s.tryFinalizeRemoteEOF()
			return
		}
		if !s.isVirtual && !s.localReadClosed && s.readBuffered >= maxReadBuffer {
			s.localWritePending = true
			return
		}
		for {
			data, ready := s.rcvBuf[s.rcvNxt]
			if !ready {
				break
			}
			delete(s.rcvBuf, s.rcvNxt)
			s.rcvNxt++
			if !s.isVirtual && !s.localReadClosed {
				s.readChunks = append(s.readChunks, data)
				s.readBuffered += len(data)
			}
		}
		s.localWritePending = false
		if s.localReadClosed {
			s.markLocalWriterBroken()
			reason := "Local App Closed Connection (writer closed)"
			if s.isGracefulCloseInProgress() {
				reason = "Local App Closed Connection (writer closed during graceful close)"
			}
			s.close(reason, CloseOptions{SendCloseWrite: true}, now)
			s.writerExited = true
			return
		}
		if s.tryFinalizePeerResetDrain() {
			s.writerExited = true
			return
		}
		s.tryFinalizeRemoteEOF()
	}
}

func (s *Stream) halfCloseLocalWriter() {
	if s.localWriteClosed || s.closed {
		return
	}
	s.localWriteClosed = true
}

func (s *Stream) markLocalWriterBroken() {
	s.localWriterBroken = true
	s.localWritePending = false
	s.rcvBuf = make(map[uint16][]byte)
}

func (s *Stream) NoteTXPacketDequeued(packetType uint8, sequenceNum uint16, fragmentID uint8, now time.Time) {
	s.access.Lock()
	defer s.access.Unlock()
	switch packetType {
	case wire.PacketStreamData, wire.PacketStreamResend:
		if item, loaded := s.sndBuf[sequenceNum]; loaded {
			item.lastSentAt = now
			item.dispatched = true
		}
	default:
		if !s.enableControlReliability {
			return
		}
		if item, loaded := s.controlSndBuf[controlKey(packetType, sequenceNum, fragmentID)]; loaded {
			item.lastSentAt = now
			item.dispatched = true
		}
	}
}

func (s *Stream) currentDataBaseRTO() time.Duration {
	if s.dataRTO.base <= 0 {
		return s.rto
	}
	return clampDuration(s.dataRTO.base, s.rto, s.maxRTO)
}

func (s *Stream) currentControlBaseRTO() time.Duration {
	if s.controlRTOEstimator.base <= 0 {
		return s.controlRTO
	}
	return clampDuration(s.controlRTOEstimator.base, s.controlRTO, s.controlMaxRTO)
}

func (s *Stream) markCloseReadSent() {
	s.closeReadSent = true
	if s.closeReadReceived {
		s.state = StateClosing
	} else {
		s.state = StateHalfClosedLocal
	}
	s.tryFinalizeRemoteEOF()
}

func (s *Stream) MarkCloseReadReceived() {
	s.access.Lock()
	now := s.clock()
	if !s.isVirtual {
		s.closeReadReceived = true
		if s.closeReadSent {
			s.state = StateClosing
		} else {
			s.state = StateHalfClosedRemote
		}
		s.flushPending = true
		s.tryFinalizeRemoteEOF()
	}
	s.release(now)
}

func (s *Stream) markCloseReadAcked(now time.Time) {
	s.closeReadAcked = true
	s.closeReadAckedAt = now
	if s.closeReadReceived {
		s.state = StateClosing
	}
}

func (s *Stream) markCloseWriteSent() {
	s.closeWriteSent = true
	s.localWriterBroken = true
	s.localWriteClosed = true
	s.rcvBuf = make(map[uint16][]byte)
	if s.closeReadReceived {
		s.state = StateClosing
	}
}

func (s *Stream) MarkCloseWriteReceived() {
	s.access.Lock()
	now := s.clock()
	if !s.isVirtual {
		s.closeWriteReceived = true
		s.stopLocalRead = true
		if s.dataRemover != nil {
			for sequenceNum := range s.sndBuf {
				s.dataRemover.RemoveQueuedData(sequenceNum)
			}
		}
		s.sndBuf = make(map[uint16]*dataItem)
		s.settleTerminalDrain(now)
		s.tryFinalizeRemoteEOF()
	}
	s.release(now)
}

func (s *Stream) markCloseWriteAcked() {
	s.closeWriteAcked = true
	s.localWriterBroken = true
	s.localWriteClosed = true
}

func (s *Stream) markRstSent() {
	s.rstSent = true
	s.clearAllQueues(true)
	s.state = StateReset
}

func (s *Stream) MarkRstReceived() {
	s.access.Lock()
	now := s.clock()
	if !s.isVirtual {
		s.rstReceived = true
		s.stopLocalRead = true
		s.clearOutboundState(true)
		s.state = StateReset
		// The reference drains on its writer goroutine, which the client's immediate Close(Force) wins against; Tick drains otherwise.
	}
	s.release(now)
}

func (s *Stream) markRstAcked() {
	s.rstAcked = true
	s.clearAllQueues(true)
	s.state = StateReset
}

func (s *Stream) clearAllQueues(clearControl bool) {
	s.sndBuf = make(map[uint16]*dataItem)
	s.rcvBuf = make(map[uint16][]byte)
	if clearControl {
		s.controlSndBuf = make(map[uint32]*controlItem)
	}
	clear(s.firstDataNackSeen)
	clear(s.lastDataNackSent)
}

func (s *Stream) clearOutboundState(clearControl bool) {
	if s.dataRemover != nil {
		for sequenceNum := range s.sndBuf {
			s.dataRemover.RemoveQueuedData(sequenceNum)
		}
	}
	if s.nackRemover != nil {
		for sequenceNum := range s.lastDataNackSent {
			s.nackRemover.RemoveQueuedDataNack(sequenceNum)
		}
	}
	s.sndBuf = make(map[uint16]*dataItem)
	if clearControl {
		s.controlSndBuf = make(map[uint32]*controlItem)
	}
	clear(s.firstDataNackSeen)
	clear(s.lastDataNackSent)
}

func (s *Stream) contiguousReady() int {
	var ready int
	for sequenceNum := s.rcvNxt; ; sequenceNum++ {
		if _, loaded := s.rcvBuf[sequenceNum]; !loaded {
			return ready
		}
		ready++
	}
}

func (s *Stream) maybeInitiateClientCloseReadAfterWriterBreak(now time.Time) {
	if !s.isClient || !s.localWriterBroken || s.closed || s.rstSent || s.rstReceived || s.closeReadSent || s.closeReadReceived {
		return
	}
	s.close("Client local endpoint disconnected after write side closed", CloseOptions{
		SendCloseRead: true,
		AfterDrain:    len(s.sndBuf) > 0 || s.localWritePending,
	}, now)
}

func (s *Stream) tryFinalizeClientLocalDisconnect() {
	if s.isClient && !s.closed && s.localWriterBroken && s.closeWriteAcked && s.closeReadSent && s.closeReadAcked &&
		len(s.sndBuf) == 0 && len(s.rcvBuf) == 0 && !s.localWritePending && !s.waitingAck && !s.deferredClose {
		s.finalizeClose("client local disconnect completed")
	}
}

func (s *Stream) clearWaitingAck(packetType uint8) {
	if s.waitingAck && s.waitingAckFor == packetType {
		s.waitingAck = false
		s.waitingAckFor = 0
		s.ackWaitDeadline = time.Time{}
	}
}

func (s *Stream) resetDrainTracking(now time.Time) {
	s.drainProgressAt = now
	s.drainQueueFailAt = time.Time{}
	s.drainQueueFails = 0
}

func (s *Stream) noteDrainQueueFailure(now time.Time) {
	if s.deferredClose || s.state == StateDraining {
		s.drainQueueFailAt = now
		s.drainQueueFails++
	}
}

func (s *Stream) runFinalAckWatchdog(now time.Time) {
	if s.closed || s.rstSent || s.rstReceived || !s.isClient || !s.closeReadSent || !s.closeReadAcked || s.closeReadReceived ||
		s.closeWriteSent || s.closeWriteAcked || s.closeWriteReceived || s.localWriterBroken || len(s.rcvBuf) != 0 ||
		s.localWritePending || s.rcvNxt == 0 || now.Sub(s.lastActivity) < closeGrace ||
		!s.lastDuplicateAckAt.IsZero() && now.Sub(s.lastDuplicateAckAt) < closeGrace {
		return
	}
	s.lastDuplicateAckAt = now
	s.enqueuer.PushTXPacket(wire.DefaultPriority(wire.PacketStreamDataAck), wire.PacketStreamDataAck, s.rcvNxt-1, 0, 0, compress.Off, 0, nil)
}

func (s *Stream) tryFinalizeRemoteEOF() {
	waitingForCloseReadAck := s.waitingAck && s.waitingAckFor == wire.PacketStreamCloseRead
	receiveDrained := len(s.rcvBuf) == 0 || s.localWriterBroken
	writeSideSettled := !s.localWriterBroken && (!s.closeWriteSent || s.closeWriteAcked) ||
		s.localWriterBroken && (s.closeWriteAcked || s.closeWriteReceived)
	if !s.closed && s.closeReadReceived && receiveDrained && (!s.localWritePending || s.localWriterBroken) &&
		(s.closeReadAcked || s.closeReadSent && !waitingForCloseReadAck) && writeSideSettled {
		s.finalizeClose("close handshake completed")
		return
	}
	s.tryFinalizeClientLocalDisconnect()
}

func (s *Stream) tryFinalizePeerResetDrain() bool {
	if !s.rstReceived || s.closed {
		return false
	}
	if s.contiguousReady() > 0 {
		s.flushPending = true
		return false
	}
	if s.localWritePending {
		return false
	}
	if len(s.rcvBuf) > 0 {
		s.finalizeClose("peer reset received with non-contiguous buffered data")
	} else {
		s.finalizeClose("peer reset received")
	}
	return true
}

func (s *Stream) deferTerminalPacket(reason string, packetType uint8, now time.Time) {
	if s.closed || s.isVirtual {
		return
	}
	if s.state != StateReset && s.state != StateClosed {
		s.state = StateDraining
	}
	s.stopLocalRead = true
	s.deferredClose = true
	s.deferredReason = reason
	s.deferredPacket = packetType
	deadline := now.Add(s.terminalDrainTimeout)
	if s.deferredDeadline.IsZero() || deadline.After(s.deferredDeadline) {
		s.deferredDeadline = deadline
	}
	s.resetDrainTracking(now)
	if len(s.sndBuf) == 0 {
		s.settleTerminalDrain(now)
	}
}

func (s *Stream) clearDeferred() {
	s.deferredClose = false
	s.deferredReason = ""
	s.deferredDeadline = time.Time{}
	s.deferredPacket = 0
}

func (s *Stream) settleTerminalDrain(now time.Time) {
	if s.closed || !s.deferredClose {
		return
	}
	var (
		packetType uint8
		reason     string
	)
	switch {
	case len(s.sndBuf) == 0:
		packetType = s.deferredPacket
		reason = s.deferredReason
	case !s.deferredDeadline.IsZero() && now.After(s.deferredDeadline):
		packetType = wire.PacketStreamRST
		reason = s.deferredReason + " but drain timeout expired"
	default:
		return
	}
	s.clearDeferred()
	s.close(reason, CloseOptions{
		SendCloseRead:  packetType == wire.PacketStreamCloseRead,
		SendCloseWrite: packetType == wire.PacketStreamCloseWrite,
		SendRST:        packetType == wire.PacketStreamRST,
	}, now)
}

func (s *Stream) emitTerminalPacket(packetType uint8, reason string, ttl time.Duration, now time.Time) {
	if s.closed || s.isVirtual {
		return
	}
	s.closeReason = reason
	s.stopLocalRead = true
	s.clearDeferred()
	if s.waitingAck && s.waitingAckFor == packetType {
		return
	}
	var ackType uint8
	switch packetType {
	case wire.PacketStreamCloseRead:
		if s.rstSent || s.rstReceived || s.closeReadSent {
			return
		}
		s.startAckWait(packetType, now)
		s.markCloseReadSent()
		ackType = wire.PacketStreamCloseReadAck
	case wire.PacketStreamCloseWrite:
		if s.rstReceived || s.rstSent || s.closeWriteSent {
			return
		}
		s.startAckWait(packetType, now)
		s.markCloseWriteSent()
		ackType = wire.PacketStreamCloseWriteAck
	case wire.PacketStreamRST:
		if s.rstReceived || s.rstSent {
			return
		}
		s.clearAllQueues(true)
		s.startAckWait(packetType, now)
		s.markRstSent()
		ackType = wire.PacketStreamRSTAck
	default:
		return
	}
	s.sendControl(packetType, 0, 0, 0, nil, wire.DefaultPriority(packetType), s.enableControlReliability, ackType, ttl, now)
}

func (s *Stream) startAckWait(packetType uint8, now time.Time) {
	s.waitingAck = true
	s.waitingAckFor = packetType
	s.ackWaitDeadline = now.Add(s.terminalAckWait)
}

// ReceiveData handles STREAM_DATA and STREAM_RESEND, acknowledging every accepted sequence.
func (s *Stream) ReceiveData(sequenceNum uint16, data []byte, now time.Time) bool {
	s.access.Lock()
	defer s.release(now)
	if s.closed || s.rstReceived || s.rstSent {
		return false
	}
	if s.localWriterBroken {
		s.closeWriteAfterWriterBroken(now)
		return false
	}
	s.processReceivedData(sequenceNum, slices.Clone(data), now)
	return true
}

func (s *Stream) closeWriteAfterWriterBroken(now time.Time) {
	if s.localWriterBroken && !s.closeWriteSent && !(s.waitingAck && s.waitingAckFor == wire.PacketStreamCloseWrite) &&
		!s.closed && !s.rstReceived && !s.rstSent {
		s.close("Inbound data received after local writer closed", CloseOptions{SendCloseWrite: true}, now)
	}
}

func (s *Stream) processReceivedData(sequenceNum uint16, data []byte, now time.Time) {
	if s.localWriterBroken || s.closeWriteSent || s.closeWriteAcked {
		s.closeWriteAfterWriterBroken(now)
		return
	}
	s.lastActivity = now
	diff := sequenceNum - s.rcvNxt
	if diff >= 32768 {
		s.pushDataAck(sequenceNum)
		return
	}
	if int(diff) > s.receiveWindowSize {
		return
	}
	_, exists := s.rcvBuf[sequenceNum]
	if !exists && len(s.rcvBuf) >= s.receiveWindowSize && sequenceNum != s.rcvNxt {
		return
	}
	if !exists {
		s.rcvBuf[sequenceNum] = data
	}
	s.pushDataAck(sequenceNum)
	if !exists {
		s.clearSentDataNack(sequenceNum)
	}
	s.maybeSendDataNacks(sequenceNum, now)
	s.flushPending = true
}

func (s *Stream) pushDataAck(sequenceNum uint16) {
	s.enqueuer.PushTXPacket(wire.DefaultPriority(wire.PacketStreamDataAck), wire.PacketStreamDataAck, sequenceNum, 0, 0, compress.Off, 0, nil)
}

func (s *Stream) isGracefulCloseInProgress() bool {
	if s.closed {
		return true
	}
	if s.waitingAck && (s.waitingAckFor == wire.PacketStreamCloseRead || s.waitingAckFor == wire.PacketStreamCloseWrite) {
		return true
	}
	if s.deferredClose && (s.deferredPacket == wire.PacketStreamCloseRead || s.deferredPacket == wire.PacketStreamCloseWrite) {
		return true
	}
	switch s.state {
	case StateHalfClosedLocal, StateHalfClosedRemote, StateClosing, StateDraining, StateTimeWait:
		return true
	}
	return s.closeReadSent || s.closeReadReceived || s.closeWriteSent || s.closeWriteReceived
}

func (s *Stream) receiveAck(sequenceNum uint16, now time.Time) bool {
	s.lastActivity = now
	item, loaded := s.sndBuf[sequenceNum]
	if !loaded {
		return false
	}
	delete(s.sndBuf, sequenceNum)
	if s.deferredClose || s.state == StateDraining {
		s.resetDrainTracking(now)
	}
	if item.sampleEligible && item.dispatched && !item.lastSentAt.IsZero() {
		s.dataRTO.update(now.Sub(item.lastSentAt), s.rto, s.maxRTO)
	}
	if s.dataRemover != nil {
		s.dataRemover.RemoveQueuedData(sequenceNum)
	}
	if s.closeReadReceived {
		s.tryFinalizeRemoteEOF()
	}
	s.settleTerminalDrain(now)
	s.processLocalEOF(now)
	return true
}

func (s *Stream) HandleDataNack(sequenceNum uint16, now time.Time) bool {
	s.access.Lock()
	defer s.release(now)
	if s.closed || s.isReset() {
		return false
	}
	s.lastActivity = now
	item, loaded := s.sndBuf[sequenceNum]
	if !loaded {
		return false
	}
	previousNackSentAt := item.lastNackSentAt
	if !previousNackSentAt.IsZero() && now.Sub(previousNackSentAt) < s.dataNackRepeat {
		return false
	}
	item.lastNackSentAt = now
	if !s.enqueuer.PushTXPacket(wire.DefaultPriority(wire.PacketStreamResend), wire.PacketStreamResend, sequenceNum, 0, 0, item.compression, item.ttl, item.data) {
		item.lastNackSentAt = previousNackSentAt
		return false
	}
	item.sampleEligible = false
	return true
}

func (s *Stream) maybeSendDataNacks(sequenceNum uint16, now time.Time) {
	if s.dataNackMaxGap <= 0 || s.closed {
		return
	}
	rcvNxt := s.rcvNxt
	diff := sequenceNum - rcvNxt
	if diff == 0 || diff >= 32768 {
		return
	}
	s.pruneDataNackState(rcvNxt)
	windowSpan := uint16(s.dataNackMaxGap)
	missing := make([]uint16, 0, s.dataNackMaxGap)
	if diff <= windowSpan {
		for candidate := rcvNxt; candidate != sequenceNum; candidate++ {
			if _, buffered := s.rcvBuf[candidate]; !buffered {
				missing = append(missing, candidate)
			}
		}
	} else {
		sampleCount := max(1, (s.dataNackMaxGap+19)/20)
		seen := make(map[uint16]struct{}, sampleCount)
		for candidate := rcvNxt; candidate != sequenceNum && len(seen) < sampleCount; candidate++ {
			if _, buffered := s.rcvBuf[candidate]; buffered {
				continue
			}
			missing = append(missing, candidate)
			seen[candidate] = struct{}{}
		}
		for candidate := rcvNxt + windowSpan - 1; ; candidate-- {
			if _, buffered := s.rcvBuf[candidate]; !buffered {
				if _, sampled := seen[candidate]; !sampled {
					missing = append(missing, candidate)
				}
				break
			}
			if candidate == rcvNxt {
				break
			}
		}
	}
	for _, candidate := range missing {
		if !s.shouldSendDataNack(candidate, now) {
			continue
		}
		if !s.enqueuer.PushTXPacket(wire.DefaultPriority(wire.PacketStreamDataNack), wire.PacketStreamDataNack, candidate, 0, 0, compress.Off, 0, nil) {
			s.noteDrainQueueFailure(now)
			continue
		}
		s.lastDataNackSent[candidate] = now
	}
}

func (s *Stream) shouldSendDataNack(sequenceNum uint16, now time.Time) bool {
	firstSeenAt, loaded := s.firstDataNackSeen[sequenceNum]
	if !loaded {
		s.firstDataNackSeen[sequenceNum] = now
		return s.dataNackInitialDelay <= 0
	}
	if s.dataNackInitialDelay > 0 && now.Sub(firstSeenAt) < s.dataNackInitialDelay {
		return false
	}
	lastSentAt, loaded := s.lastDataNackSent[sequenceNum]
	return !loaded || now.Sub(lastSentAt) >= s.dataNackRepeat
}

func sequenceBehind(base uint16, candidate uint16) bool {
	return candidate != base && base-candidate < 32768
}

func (s *Stream) pruneDataNackState(rcvNxt uint16) {
	for sequenceNum := range s.firstDataNackSeen {
		if sequenceBehind(rcvNxt, sequenceNum) {
			delete(s.firstDataNackSeen, sequenceNum)
		}
	}
	for sequenceNum := range s.lastDataNackSent {
		if sequenceBehind(rcvNxt, sequenceNum) {
			delete(s.lastDataNackSent, sequenceNum)
		}
	}
}

func (s *Stream) clearSentDataNack(sequenceNum uint16) {
	delete(s.firstDataNackSeen, sequenceNum)
	delete(s.lastDataNackSent, sequenceNum)
	if s.nackRemover != nil {
		s.nackRemover.RemoveQueuedDataNack(sequenceNum)
	}
}

func (s *Stream) gapRecoveryCandidates() []uint16 {
	if s.dataNackMaxGap <= 0 || len(s.rcvBuf) == 0 {
		return nil
	}
	if _, ready := s.rcvBuf[s.rcvNxt]; ready {
		return nil
	}
	maxGap := uint16(s.dataNackMaxGap)
	missing := make([]uint16, 0, s.dataNackMaxGap)
	for candidate := s.rcvNxt; candidate-s.rcvNxt < maxGap; candidate++ {
		if _, buffered := s.rcvBuf[candidate]; !buffered {
			missing = append(missing, candidate)
		}
	}
	return missing
}

func (s *Stream) runGapRecoveryWatchdog(now time.Time) {
	if s.dataNackMaxGap <= 0 || s.closed {
		return
	}
	missing := s.gapRecoveryCandidates()
	if len(missing) == 0 || now.Sub(s.lastActivity) < s.dataNackRepeat {
		return
	}
	s.pruneDataNackState(s.rcvNxt)
	for _, candidate := range missing {
		if !s.shouldSendDataNack(candidate, now) {
			continue
		}
		if !s.enqueuer.PushTXPacket(wire.DefaultPriority(wire.PacketStreamDataNack), wire.PacketStreamDataNack, candidate, 0, 0, compress.Off, 0, nil) {
			continue
		}
		s.lastDataNackSent[candidate] = now
	}
}

// SendControl queues a control packet and, when tracked, retransmits it until ackType (0: the table acknowledgement) arrives.
func (s *Stream) SendControl(packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte,
	priority int, track bool, ackType uint8, ttl time.Duration, now time.Time,
) bool {
	s.access.Lock()
	defer s.release(now)
	return s.sendControl(packetType, sequenceNum, fragmentID, totalFragments, payload, priority, track, ackType, ttl, now)
}

func (s *Stream) sendControl(packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte,
	priority int, track bool, ackType uint8, ttl time.Duration, now time.Time,
) bool {
	payload = slices.Clone(payload)
	priority = wire.NormalizePriority(packetType, priority)
	if !s.enableControlReliability || !track {
		return s.enqueuer.PushTXPacket(priority, packetType, sequenceNum, fragmentID, totalFragments, compress.Off, ttl, payload)
	}
	if ackType == 0 {
		var loaded bool
		ackType, loaded = wire.ControlAck(packetType)
		if !loaded {
			return true
		}
	}
	key := controlKey(packetType, sequenceNum, fragmentID)
	if _, loaded := s.controlSndBuf[key]; loaded {
		return true
	}
	initialRTO := s.currentControlBaseRTO()
	if isSetupPacket(packetType) {
		initialRTO = min(initialRTO, setupRTOCap)
	}
	pushed := s.enqueuer.PushTXPacket(priority, packetType, sequenceNum, fragmentID, totalFragments, compress.Off, ttl, payload)
	item := &controlItem{
		packetType:     packetType,
		sequenceNum:    sequenceNum,
		fragmentID:     fragmentID,
		totalFragments: totalFragments,
		payload:        payload,
		priority:       priority,
		createdAt:      now,
		currentRTO:     initialRTO,
		sampleEligible: true,
		ttl:            ttl,
	}
	if !pushed {
		item.dispatched = true
		item.lastSentAt = now.Add(-initialRTO)
	}
	s.controlSndBuf[key] = item
	return pushed
}

func (s *Stream) handleTrackedPacketTTLExpiry(packetType uint8, reason string, now time.Time) {
	if _, closesStream := wire.CloseStreamAck(packetType); closesStream &&
		packetType != wire.PacketStreamCloseRead && packetType != wire.PacketStreamCloseWrite {
		s.finalizeClose(reason)
		return
	}
	s.close(reason, CloseOptions{SendRST: true}, now)
}

func (s *Stream) handleTrackedTerminalAck(originType uint8) bool {
	if _, closesStream := wire.CloseStreamAck(originType); closesStream && originType != wire.PacketStreamCloseRead &&
		originType != wire.PacketStreamCloseWrite && originType != wire.PacketStreamRST {
		s.finalizeClose(packetTypeName(originType) + " acknowledged")
		return true
	}
	return false
}

func (s *Stream) handleCloseReadAck(now time.Time) {
	s.markCloseReadAcked(now)
	s.clearWaitingAck(wire.PacketStreamCloseRead)
	s.tryFinalizeRemoteEOF()
}

func (s *Stream) handleCloseWriteAck(now time.Time) {
	s.markCloseWriteAcked()
	s.clearWaitingAck(wire.PacketStreamCloseWrite)
	s.maybeInitiateClientCloseReadAfterWriterBreak(now)
	s.tryFinalizeRemoteEOF()
}

func (s *Stream) handleRSTAck() {
	s.markRstAcked()
	s.finalizeClose("RST acknowledged")
}

func (s *Stream) handleWaitingTerminalAck(ackType uint8, waitingCloseRead bool, waitingCloseWrite bool, waitingRST bool, now time.Time) bool {
	switch {
	case ackType == wire.PacketStreamCloseReadAck && waitingCloseRead:
		s.handleCloseReadAck(now)
	case ackType == wire.PacketStreamCloseWriteAck && waitingCloseWrite:
		s.handleCloseWriteAck(now)
	case ackType == wire.PacketStreamRSTAck && waitingRST:
		s.handleRSTAck()
	default:
		return false
	}
	return true
}

func (s *Stream) handleTrackedCloseOrResetAck(originType uint8, now time.Time) bool {
	switch originType {
	case wire.PacketStreamCloseRead:
		s.handleCloseReadAck(now)
	case wire.PacketStreamCloseWrite:
		s.handleCloseWriteAck(now)
	case wire.PacketStreamRST:
		s.handleRSTAck()
	default:
		return false
	}
	return true
}

func (s *Stream) receiveControlAck(ackType uint8, sequenceNum uint16, fragmentID uint8, now time.Time) bool {
	s.lastActivity = now
	originType, loaded := wire.AckedControl(ackType)
	if !loaded {
		return false
	}
	item, tracked := s.controlSndBuf[controlKey(originType, sequenceNum, fragmentID)]
	_, closesStream := wire.CloseStreamAck(originType)
	if !tracked && closesStream {
		for _, other := range s.controlSndBuf {
			if other.packetType == originType {
				tracked = true
				break
			}
		}
	}
	waitingCloseRead := ackType == wire.PacketStreamCloseReadAck && s.waitingAckFor == wire.PacketStreamCloseRead
	waitingCloseWrite := ackType == wire.PacketStreamCloseWriteAck && s.waitingAckFor == wire.PacketStreamCloseWrite
	waitingRST := ackType == wire.PacketStreamRSTAck && s.waitingAckFor == wire.PacketStreamRST
	if !tracked && !waitingCloseRead && !waitingCloseWrite && !waitingRST {
		return false
	}
	if tracked {
		if item != nil && item.sampleEligible && item.dispatched && !item.lastSentAt.IsZero() {
			s.controlRTOEstimator.update(now.Sub(item.lastSentAt), s.controlRTO, s.controlMaxRTO)
		}
		if closesStream {
			for key, other := range s.controlSndBuf {
				if other.packetType == originType {
					delete(s.controlSndBuf, key)
				}
			}
		} else {
			delete(s.controlSndBuf, controlKey(originType, sequenceNum, fragmentID))
		}
		if s.handleTrackedCloseOrResetAck(originType, now) || s.handleTrackedTerminalAck(originType) {
			return true
		}
	}
	if s.handleWaitingTerminalAck(ackType, waitingCloseRead, waitingCloseWrite, waitingRST, now) {
		return true
	}
	return tracked
}

// HandleAckPacket handles STREAM_DATA_ACK and every control acknowledgement; true means the stream tracked it.
func (s *Stream) HandleAckPacket(packetType uint8, sequenceNum uint16, fragmentID uint8, now time.Time) bool {
	s.access.Lock()
	defer s.release(now)
	if packetType == wire.PacketStreamDataAck {
		return s.receiveAck(sequenceNum, now)
	}
	if _, loaded := wire.AckedControl(packetType); !loaded {
		return false
	}
	return s.receiveControlAck(packetType, sequenceNum, fragmentID, now)
}

// Tick is one pass of the reference retransmitLoop; schedule it again NextTick after it returns.
func (s *Stream) Tick(now time.Time) {
	s.access.Lock()
	s.checkRetransmits(now)
	s.release(now)
}

// NextTick is the reference retransmitLoop interval, computed after each pass.
func (s *Stream) NextTick() time.Duration {
	s.access.Lock()
	defer s.access.Unlock()
	rto := s.rto
	if s.enableControlReliability && s.controlRTO < rto {
		rto = s.controlRTO
	}
	interval := max(rto/3, 50*time.Millisecond)
	if len(s.sndBuf) > 0 || s.enableControlReliability && len(s.controlSndBuf) > 0 {
		return interval
	}
	return max(interval*4, 100*time.Millisecond)
}

type retransmitJob struct {
	sequenceNum uint16
	item        *dataItem
}

func (s *Stream) checkRetransmits(now time.Time) {
	if s.closed {
		return
	}
	s.runGapRecoveryWatchdog(now)
	s.runFinalAckWatchdog(now)
	if s.handleTerminalRetransmitState(now) {
		return
	}
	draining := s.deferredClose || s.state == StateDraining
	drainCap := clampDuration(drainRTOCap, s.rto, s.maxRTO)
	var jobs []retransmitJob
	for _, sequenceNum := range s.outstandingSequences() {
		item := s.sndBuf[sequenceNum]
		if item.ttl > 0 {
			if now.Sub(item.createdAt) >= item.ttl {
				s.handleTrackedPacketTTLExpiry(wire.PacketStreamData, "Packet TTL expired", now)
				return
			}
		} else if now.Sub(item.createdAt) >= s.dataPacketTTL && item.retries >= s.maxDataRetries {
			s.close("Max retransmissions exceeded", CloseOptions{SendRST: true}, now)
			return
		}
		effectiveRTO := item.currentRTO
		if draining && effectiveRTO > drainCap {
			effectiveRTO = drainCap
		}
		if !item.dispatched || now.Sub(item.lastSentAt) < effectiveRTO {
			continue
		}
		jobs = append(jobs, retransmitJob{sequenceNum, item})
	}
	frontBudget := 1
	if len(jobs) > 1 {
		frontBudget = min(max(s.windowSize/10, 1), 64)
	}
	for index, job := range jobs {
		packetType := wire.PacketStreamData
		if index < frontBudget {
			packetType = wire.PacketStreamResend
		}
		if !s.enqueuer.PushTXPacket(wire.DefaultPriority(packetType), packetType, job.sequenceNum, 0, 0, job.item.compression, 0, job.item.data) {
			s.noteDrainQueueFailure(now)
			continue
		}
		if s.sndBuf[job.sequenceNum] != job.item {
			continue
		}
		maxRTO := s.maxRTO
		if draining && maxRTO > drainCap {
			maxRTO = drainCap
		}
		job.item.lastSentAt = now
		job.item.dispatched = false
		job.item.retries++
		job.item.sampleEligible = false
		job.item.currentRTO = clampDuration(time.Duration(float64(job.item.currentRTO)*dataRTOGrowth), s.currentDataBaseRTO(), maxRTO)
	}
	if s.enableControlReliability {
		s.checkControlRetransmits(now)
	}
}

// outstandingSequences orders the send buffer oldest first; the reference walks it in map order.
func (s *Stream) outstandingSequences() []uint16 {
	sequences := make([]uint16, 0, len(s.sndBuf))
	for sequenceNum := range s.sndBuf {
		sequences = append(sequences, sequenceNum)
	}
	slices.SortFunc(sequences, func(a, b uint16) int {
		return int(s.sndNxt-b) - int(s.sndNxt-a)
	})
	return sequences
}

func (s *Stream) handleTerminalRetransmitState(now time.Time) bool {
	if s.deferredClose {
		pending := len(s.sndBuf)
		var stalledFor time.Duration
		if !s.drainProgressAt.IsZero() {
			stalledFor = now.Sub(s.drainProgressAt)
		}
		queueBlocked := s.drainQueueFails >= 3 && !s.drainQueueFailAt.IsZero() && now.Sub(s.drainQueueFailAt) <= drainStallWindow
		if pending == 0 || !s.deferredDeadline.IsZero() && now.After(s.deferredDeadline) {
			s.settleTerminalDrain(now)
		} else if queueBlocked && stalledFor >= drainStallAfter {
			s.close("Deferred drain stalled after resend queue pressure", CloseOptions{SendRST: true}, now)
		}
		return s.closed
	}
	if s.waitingAck && !s.ackWaitDeadline.IsZero() && now.After(s.ackWaitDeadline) {
		switch s.waitingAckFor {
		case wire.PacketStreamRST:
			s.finalizeClose("Terminal ACK wait timeout")
			return true
		case wire.PacketStreamCloseRead, wire.PacketStreamCloseWrite:
			s.close("Close handshake ACK wait timeout", CloseOptions{SendRST: true}, now)
		}
		return false
	}
	if s.rstReceived && !s.closed {
		return s.tryFinalizePeerResetDrain()
	}
	receiveDrained := len(s.rcvBuf) == 0 && !s.localWritePending
	peerFinishedSending := s.closeReadReceived || s.localWriterBroken
	graceElapsed := !s.clientEOFAt.IsZero() && now.Sub(s.clientEOFAt) >= closeGrace ||
		!s.closeReadAckedAt.IsZero() && now.Sub(s.closeReadAckedAt) >= closeGrace
	if s.isClient && graceElapsed && !s.closed && !s.rstSent && !s.rstReceived && s.closeReadSent && s.closeReadAcked &&
		!s.closeWriteSent && !s.closeWriteAcked && !s.closeWriteReceived &&
		!(s.waitingAck && s.waitingAckFor == wire.PacketStreamCloseWrite) && receiveDrained && peerFinishedSending {
		s.close("Client close-read grace elapsed", CloseOptions{SendCloseWrite: true}, now)
		return false
	}
	if now.Sub(s.lastActivity) > s.inactivityTimeout {
		if len(s.sndBuf) > 0 || s.enableControlReliability && len(s.controlSndBuf) > 0 {
			s.lastActivity = now
			return false
		}
		s.close("Stream Inactivity Timeout (Dead)", CloseOptions{SendRST: true}, now)
		return true
	}
	return false
}

func (s *Stream) checkControlRetransmits(now time.Time) {
	keys := make([]uint32, 0, len(s.controlSndBuf))
	for key := range s.controlSndBuf {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		item, loaded := s.controlSndBuf[key]
		if !loaded {
			continue
		}
		if item.ttl > 0 {
			if now.Sub(item.createdAt) >= item.ttl {
				delete(s.controlSndBuf, key)
				s.handleTrackedPacketTTLExpiry(item.packetType, "Packet TTL expired", now)
				return
			}
		} else {
			maxRetries := s.controlMaxRetries
			packetTTL := s.controlPacketTTL
			if isSetupPacket(item.packetType) {
				maxRetries = max(maxRetries, setupMaxRetries)
				packetTTL = max(packetTTL, setupPacketTTLFloor)
			}
			exceededRetries := item.retries >= maxRetries
			if now.Sub(item.createdAt) >= packetTTL || exceededRetries {
				delete(s.controlSndBuf, key)
				reason := "Control packet expired"
				if exceededRetries {
					reason = "Control packet max retransmissions exceeded"
				}
				s.handleTrackedPacketTTLExpiry(item.packetType, reason, now)
				return
			}
		}
		if !item.dispatched || now.Sub(item.lastSentAt) < item.currentRTO {
			continue
		}
		if !s.enqueuer.PushTXPacket(item.priority, item.packetType, item.sequenceNum, item.fragmentID, item.totalFragments, compress.Off, item.ttl, item.payload) {
			continue
		}
		item.lastSentAt = now
		item.dispatched = false
		item.retries++
		item.sampleEligible = false
		growth := controlRTOGrowth
		floor := s.currentControlBaseRTO()
		if isSetupPacket(item.packetType) {
			growth = setupRTOGrowth
			floor = min(floor, setupRTOCap)
		}
		item.currentRTO = clampDuration(time.Duration(float64(item.currentRTO)*growth), floor, s.controlMaxRTO)
	}
}

func (s *Stream) finalizeClose(reason string) {
	if s.closed || s.isVirtual {
		return
	}
	s.closeReason = reason
	s.closed = true
	s.clearDeferred()
	s.waitingAck = false
	s.waitingAckFor = 0
	s.ackWaitDeadline = time.Time{}
	switch {
	case s.state == StateReset || s.rstReceived || s.rstSent:
		s.state = StateReset
	case s.closeReadSent || s.closeReadReceived || s.closeWriteSent || s.closeWriteReceived:
		s.state = StateTimeWait
	default:
		s.state = StateClosing
	}
	close(s.done)
	s.clearAllQueues(true)
	s.notifyClosed = true
}

// Close is the single close entry point: Force finalizes, otherwise CLOSE_READ (optionally after drain), CLOSE_WRITE or RST.
func (s *Stream) Close(reason string, options CloseOptions) {
	s.access.Lock()
	now := s.clock()
	s.close(reason, options, now)
	s.release(now)
}

func (s *Stream) close(reason string, options CloseOptions, now time.Time) {
	if s.isVirtual && !options.Force {
		return
	}
	if options.Force || !options.SendRST && !options.SendCloseRead && !options.SendCloseWrite {
		s.isVirtual = false
		s.finalizeClose(reason)
		return
	}
	if options.SendCloseRead {
		if options.AfterDrain {
			s.deferTerminalPacket(reason, wire.PacketStreamCloseRead, now)
		} else {
			s.emitTerminalPacket(wire.PacketStreamCloseRead, reason, options.TTL, now)
		}
		return
	}
	if options.SendCloseWrite {
		s.emitTerminalPacket(wire.PacketStreamCloseWrite, reason, options.TTL, now)
		return
	}
	if s.closed || s.rstSent || s.rstReceived || s.waitingAck && s.waitingAckFor == wire.PacketStreamRST ||
		s.deferredClose && s.deferredPacket == wire.PacketStreamRST {
		return
	}
	hasPendingData := len(s.sndBuf) > 0
	s.closeReason = reason
	s.state = StateReset
	s.clearDeferred()
	if options.AfterDrain && hasPendingData {
		s.deferTerminalPacket(reason, wire.PacketStreamRST, now)
		return
	}
	s.emitTerminalPacket(wire.PacketStreamRST, reason, options.TTL, now)
}

var closeStreamNames = map[uint8]string{
	wire.PacketStreamConnectFail:            "PACKET_STREAM_CONNECT_FAIL",
	wire.PacketSOCKS5ConnectFail:            "PACKET_SOCKS5_CONNECT_FAIL",
	wire.PacketSOCKS5RulesetDenied:          "PACKET_SOCKS5_RULESET_DENIED",
	wire.PacketSOCKS5NetworkUnreachable:     "PACKET_SOCKS5_NETWORK_UNREACHABLE",
	wire.PacketSOCKS5HostUnreachable:        "PACKET_SOCKS5_HOST_UNREACHABLE",
	wire.PacketSOCKS5ConnectionRefused:      "PACKET_SOCKS5_CONNECTION_REFUSED",
	wire.PacketSOCKS5TTLExpired:             "PACKET_SOCKS5_TTL_EXPIRED",
	wire.PacketSOCKS5CommandUnsupported:     "PACKET_SOCKS5_COMMAND_UNSUPPORTED",
	wire.PacketSOCKS5AddressTypeUnsupported: "PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED",
	wire.PacketSOCKS5AuthFailed:             "PACKET_SOCKS5_AUTH_FAILED",
	wire.PacketSOCKS5UpstreamUnavailable:    "PACKET_SOCKS5_UPSTREAM_UNAVAILABLE",
}

func packetTypeName(packetType uint8) string {
	if name, loaded := closeStreamNames[packetType]; loaded {
		return name
	}
	return "PACKET_UNKNOWN"
}
