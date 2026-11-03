package masterdnstest

import (
	"cmp"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/arq"
	"github.com/sagernet/sing-box/transport/masterdns/cipher"
	"github.com/sagernet/sing-box/transport/masterdns/compress"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	ModeSOCKS5 = "socks5"
	ModeTCP    = "tcp"
)

const (
	maxQuerySize          = 65535
	downloadProbeMinSize  = 20
	maxPacketsPerBatch    = 10
	maxDequeueAttempts    = 64
	tickInterval          = 50 * time.Millisecond
	connectTimeout        = 10 * time.Second
	setupAckTTL           = 400 * time.Second
	resultPacketTTL       = 300 * time.Second
	failurePacketTTL      = 120 * time.Second
	recentlyClosedTTL     = 45 * time.Second
	copyBufferSize        = 32 * 1024
	closedSessionCapacity = 256
)

var downloadProbeReserve = max(wire.MaxHeaderSize-wire.HeaderSize(wire.PacketMTUDownResponse), 0)

// DefaultPolicy is the client policy a MasterDnsVPN server sends with its default configuration.
var DefaultPolicy = wire.SessionPolicy{
	MaxPacketDuplication:      5,
	MaxSetupDuplication:       6,
	MaxUploadMTU:              150,
	MaxDownloadMTU:            4096,
	MaxRXTXWorkers:            255,
	MinPingAggressiveInterval: 50 * time.Millisecond,
	MaxPacketsPerBatch:        20,
	MaxARQWindowSize:          8000,
	MaxARQDataNackMaxGap:      255,
	MinCompressionMinSize:     120,
	MinARQInitialRTO:          50 * time.Millisecond,
}

type Options struct {
	Domain           string
	EncryptionMethod string
	EncryptionKey    string
	// Mode is socks5 (the default) or tcp.
	Mode string
	// Forward is the target of every tcp mode stream.
	Forward M.Socksaddr
	Dialer  N.Dialer
	// Policy is sent in SESSION_ACCEPT; nil sends the 7-byte form of StormDNS and older servers.
	Policy         *wire.SessionPolicy
	MaxUploadMTU   int
	MaxDownloadMTU int
}

// Server is a MasterDnsVPN-compatible authoritative server for tests; it answers on any packet conn it serves.
type Server struct {
	ctx         context.Context
	cancel      context.CancelFunc
	domain      string
	codec       *cipher.Codec
	mode        string
	forward     M.Socksaddr
	dialer      N.Dialer
	policy      *wire.SessionPolicy
	maxUpload   int
	maxDownload int
	busy        atomic.Bool
	inits       atomic.Int32
	closes      atomic.Int32
	dropMode    atomic.Uint32
	access      sync.Mutex
	conns       map[net.PacketConn]struct{}
	sessions    map[uint8]*session
	signatures  map[[wire.SessionInitSize]byte]uint8
	dropped     map[uint8]bool
	lastID      uint8
	closed      bool
	wg          sync.WaitGroup
}

func NewServer(options Options) (*Server, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(options.Domain), "."))
	if domain == "" {
		return nil, E.New("missing domain")
	}
	method := cipher.MethodXOR
	if options.EncryptionMethod != "" {
		var err error
		method, err = cipher.ParseMethod(options.EncryptionMethod)
		if err != nil {
			return nil, err
		}
	}
	codec, err := cipher.New(method, options.EncryptionKey)
	if err != nil {
		return nil, err
	}
	switch options.Mode {
	case "", ModeSOCKS5, ModeTCP:
	default:
		return nil, E.New("unknown mode: ", options.Mode)
	}
	dialer := options.Dialer
	if dialer == nil {
		dialer = N.SystemDialer
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		ctx:         ctx,
		cancel:      cancel,
		domain:      domain,
		codec:       codec,
		mode:        options.Mode,
		forward:     options.Forward,
		dialer:      dialer,
		policy:      options.Policy,
		maxUpload:   options.MaxUploadMTU,
		maxDownload: options.MaxDownloadMTU,
		conns:       make(map[net.PacketConn]struct{}),
		sessions:    make(map[uint8]*session),
		signatures:  make(map[[wire.SessionInitSize]byte]uint8),
		dropped:     make(map[uint8]bool),
	}
	server.wg.Go(server.tickLoop)
	return server, nil
}

func (s *Server) ServePacket(conn net.PacketConn) {
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		conn.Close()
		return
	}
	s.conns[conn] = struct{}{}
	s.wg.Add(1)
	s.access.Unlock()
	defer s.wg.Done()
	buffer := make([]byte, maxQuerySize)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		if response := s.handle(buffer[:n]); response != nil {
			conn.WriteTo(response, addr)
		}
	}
}

func (s *Server) Close() error {
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return nil
	}
	s.closed = true
	sessions := s.takeSessionsLocked()
	conns := make([]net.PacketConn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.access.Unlock()
	s.cancel()
	for _, conn := range conns {
		conn.Close()
	}
	for _, session := range sessions {
		session.close()
	}
	s.wg.Wait()
	return nil
}

// SetBusy makes SESSION_INIT answer SESSION_BUSY, like a full session table.
func (s *Server) SetBusy(busy bool) {
	s.busy.Store(busy)
}

// DropSessions forgets every session, so their next queries get ERROR_DROP.
func (s *Server) DropSessions() {
	s.access.Lock()
	sessions := s.takeSessionsLocked()
	s.access.Unlock()
	for _, session := range sessions {
		session.close()
	}
}

func (s *Server) SessionInits() int {
	return int(s.inits.Load())
}

func (s *Server) SessionCloses() int {
	return int(s.closes.Load())
}

func (s *Server) Sessions() int {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.sessions)
}

func (s *Server) Streams() int {
	return len(s.streams())
}

func (s *Server) takeSessionsLocked() []*session {
	sessions := make([]*session, 0, len(s.sessions))
	for id, session := range s.sessions {
		sessions = append(sessions, session)
		s.rememberDroppedLocked(id, session.base64Response)
	}
	clear(s.sessions)
	clear(s.signatures)
	return sessions
}

func (s *Server) rememberDroppedLocked(id uint8, base64Response bool) {
	if len(s.dropped) >= closedSessionCapacity {
		clear(s.dropped)
	}
	s.dropped[id] = base64Response
}

func (s *Server) streams() []*stream {
	s.access.Lock()
	sessions := make([]*session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.access.Unlock()
	var streams []*stream
	for _, session := range sessions {
		session.access.Lock()
		for _, stream := range session.streams {
			streams = append(streams, stream)
		}
		session.access.Unlock()
	}
	return streams
}

func (s *Server) tickLoop() {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		for _, stream := range s.streams() {
			stream.arq.Tick(time.Now())
		}
	}
}

func (s *Server) handle(message []byte) []byte {
	query, err := wire.ParseQuery(message)
	if err != nil {
		return nil
	}
	labels, _, loaded := wire.SplitName(query.Name, []string{s.domain})
	if !loaded || labels == "" {
		return nil
	}
	raw, err := wire.DecodeFrame(nil, s.codec, []byte(labels))
	if err != nil {
		return nil
	}
	packet, err := wire.ParsePacket(raw)
	if err != nil || packet.Inflate() != nil {
		return nil
	}
	var (
		reply          wire.Packet
		base64Response bool
	)
	switch packet.Type {
	case wire.PacketMTUUpRequest:
		if s.maxUpload > 0 && len(packet.Payload) > s.maxUpload {
			return nil
		}
		payload, accepted := wire.UploadProbeReply(packet.Payload)
		if !accepted {
			return nil
		}
		base64Response = packet.Payload[0] == wire.ResponseModeBase64
		reply = wire.Packet{SessionID: packet.SessionID, Type: wire.PacketMTUUpResponse, Payload: payload}
	case wire.PacketMTUDownRequest:
		payload, accepted := wire.DownloadProbeReply(packet.Payload, downloadProbeMinSize)
		if !accepted || s.maxDownload > 0 && len(payload)-downloadProbeReserve > s.maxDownload {
			return nil
		}
		base64Response = packet.Payload[0] == wire.ResponseModeBase64
		reply = wire.Packet{
			SessionID:      packet.SessionID,
			Type:           wire.PacketMTUDownResponse,
			StreamID:       packet.StreamID,
			SequenceNum:    packet.SequenceNum,
			FragmentID:     packet.FragmentID,
			TotalFragments: packet.TotalFragments,
			Payload:        payload,
		}
	case wire.PacketSessionInit:
		var accepted bool
		reply, base64Response, accepted = s.handleSessionInit(packet)
		if !accepted {
			return nil
		}
	case wire.PacketSessionClose:
		s.handleSessionClose(packet)
		return nil
	default:
		session, response := s.validate(message, query.Name, packet)
		if session == nil {
			return response
		}
		if !session.handle(packet, time.Now()) {
			return nil
		}
		return session.response(message, query.Name, time.Now())
	}
	response, err := wire.AppendResponse(nil, message, query.Name, reply, base64Response)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) handleSessionInit(packet wire.Packet) (wire.Packet, bool, bool) {
	s.inits.Add(1)
	if packet.SessionID != 0 {
		return wire.Packet{}, false, false
	}
	init, err := wire.ParseSessionInit(packet.Payload)
	if err != nil {
		return wire.Packet{}, false, false
	}
	if s.busy.Load() {
		return wire.Packet{Type: wire.PacketSessionBusy, Payload: init.VerifyCode[:]}, init.Base64Response, true
	}
	session := s.openSession([wire.SessionInitSize]byte(packet.Payload), init)
	if session == nil {
		return wire.Packet{}, false, false
	}
	accept := wire.SessionAccept{
		SessionID:           session.id,
		SessionCookie:       session.cookie,
		UploadCompression:   init.UploadCompression,
		DownloadCompression: init.DownloadCompression,
		VerifyCode:          init.VerifyCode,
	}
	if s.policy != nil {
		accept.HasPolicy = true
		accept.Policy = *s.policy
	}
	return wire.Packet{Type: wire.PacketSessionAccept, Payload: wire.AppendSessionAccept(nil, accept)}, init.Base64Response, true
}

// openSession reuses the session of an identical SESSION_INIT, so the three racing copies a client sends share one session.
func (s *Server) openSession(signature [wire.SessionInitSize]byte, init wire.SessionInit) *session {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return nil
	}
	if id, loaded := s.signatures[signature]; loaded {
		if session := s.sessions[id]; session != nil {
			return session
		}
	}
	id := s.lastID
	for range 255 {
		id++
		if id == 0 {
			id = 1
		}
		if s.sessions[id] == nil {
			break
		}
	}
	if s.sessions[id] != nil {
		return nil
	}
	s.lastID = id
	downloadMTU := int(init.DownloadMTU)
	if s.maxDownload > 0 {
		downloadMTU = min(downloadMTU, s.maxDownload)
	}
	session := &session{
		server:              s,
		id:                  id,
		cookie:              uint8(rand.Uint32()),
		base64Response:      init.Base64Response,
		downloadCompression: init.DownloadCompression,
		downloadMTU:         downloadMTU,
		maxPackedBlocks:     wire.MaxPackedBlocks(downloadMTU, 80, maxPacketsPerBatch),
		streams:             make(map[uint16]*stream),
		fragments:           make(map[uint16]*synFragments),
		recentlyClosed:      make(map[uint16]closedStream),
		orphans:             arq.NewOrphanQueue(16),
		dispatcher:          arq.NewDispatcher(),
	}
	s.sessions[id] = session
	s.signatures[signature] = id
	delete(s.dropped, id)
	return session
}

func (s *Server) handleSessionClose(packet wire.Packet) {
	s.closes.Add(1)
	s.access.Lock()
	session := s.sessions[packet.SessionID]
	if session == nil || session.cookie != packet.SessionCookie {
		s.access.Unlock()
		return
	}
	delete(s.sessions, packet.SessionID)
	for signature, id := range s.signatures {
		if id == packet.SessionID {
			delete(s.signatures, signature)
		}
	}
	s.rememberDroppedLocked(packet.SessionID, session.base64Response)
	s.access.Unlock()
	session.close()
}

// validate answers ERROR_DROP for unknown sessions; an unknown session's response mode alternates like the reference.
func (s *Server) validate(message []byte, name string, packet wire.Packet) (*session, []byte) {
	s.access.Lock()
	session := s.sessions[packet.SessionID]
	base64Response, dropped := s.dropped[packet.SessionID]
	s.access.Unlock()
	if session != nil {
		if session.cookie != packet.SessionCookie {
			return nil, nil
		}
		return session, nil
	}
	if !dropped {
		base64Response = s.dropMode.Add(1)&1 == 1
	}
	response, err := wire.AppendResponse(nil, message, name, wire.Packet{
		SessionID: packet.SessionID,
		Type:      wire.PacketErrorDrop,
		Payload:   wire.AppendErrorDropPayload(nil, rand.Uint32()),
	}, base64Response)
	if err != nil {
		return nil, nil
	}
	return nil, response
}

func (s *Server) rejectSYN(packetType uint8) bool {
	if s.mode == ModeTCP {
		return packetType == wire.PacketSOCKS5SYN
	}
	return packetType == wire.PacketStreamSYN
}

type closedStream struct {
	at       time.Time
	suppress bool
}

type synFragments struct {
	sequenceNum uint16
	parts       [][]byte
	received    int
	completed   bool
}

type session struct {
	server              *Server
	id                  uint8
	cookie              uint8
	base64Response      bool
	downloadCompression compress.Type
	downloadMTU         int
	maxPackedBlocks     int
	access              sync.Mutex
	streams             map[uint16]*stream
	fragments           map[uint16]*synFragments
	recentlyClosed      map[uint16]closedStream
	closed              bool
	orphans             *arq.OrphanQueue
	dispatchAccess      sync.Mutex
	dispatcher          *arq.Dispatcher
}

type stream struct {
	session    *session
	id         uint16
	arq        *arq.Stream
	queue      *arq.TXQueue
	access     sync.Mutex
	connecting bool
	connected  bool
	target     M.Socksaddr
	upstream   net.Conn
	closed     bool
}

func (c *session) close() {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return
	}
	c.closed = true
	streams := make([]*stream, 0, len(c.streams))
	for _, stream := range c.streams {
		streams = append(streams, stream)
	}
	clear(c.streams)
	c.access.Unlock()
	for _, stream := range streams {
		stream.arq.Close("session closed", arq.CloseOptions{Force: true})
		stream.closeUpstream()
	}
	c.orphans.Clear()
}

func (c *session) stream(id uint16) *stream {
	c.access.Lock()
	defer c.access.Unlock()
	return c.streams[id]
}

func (c *session) openStream(id uint16) *stream {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return nil
	}
	if stream := c.streams[id]; stream != nil {
		return stream
	}
	delete(c.recentlyClosed, id)
	stream := &stream{session: c, id: id}
	stream.queue = arq.NewTXQueue(id, 64, nil)
	stream.arq = arq.New(id, c.downloadMTU, arq.Config{
		WindowSize:               arq.DefaultWindowSize,
		RTO:                      arq.DefaultRTO,
		MaxRTO:                   arq.DefaultMaxRTO,
		EnableControlReliability: true,
		ControlRTO:               arq.DefaultControlRTO,
		ControlMaxRTO:            arq.DefaultControlMaxRTO,
		ControlMaxRetries:        arq.DefaultControlMaxRetries,
		InactivityTimeout:        arq.DefaultInactivityTimeout,
		DataPacketTTL:            arq.DefaultDataPacketTTL,
		MaxDataRetries:           arq.DefaultMaxDataRetries,
		ControlPacketTTL:         arq.DefaultControlPacketTTL,
		DataNackMaxGap:           arq.DefaultDataNackMaxGap,
		DataNackInitialDelay:     arq.DefaultDataNackInitialDelay,
		DataNackRepeat:           arq.DefaultDataNackRepeat,
		TerminalDrainTimeout:     arq.DefaultTerminalDrainTimeout,
		TerminalAckWaitTimeout:   arq.DefaultTerminalAckWaitTimeout,
		Compression:              c.downloadCompression,
	}, stream.queue, stream.onClosed)
	c.streams[id] = stream
	return stream
}

func (c *session) isRecentlyClosed(id uint16, now time.Time) (closed bool, suppress bool) {
	c.access.Lock()
	defer c.access.Unlock()
	record, loaded := c.recentlyClosed[id]
	if !loaded || now.Sub(record.at) > recentlyClosedTTL {
		return false, false
	}
	return true, record.suppress
}

func (c *session) noteClosed(id uint16, now time.Time, suppress bool) {
	c.access.Lock()
	defer c.access.Unlock()
	for streamID, record := range c.recentlyClosed {
		if now.Sub(record.at) > recentlyClosedTTL {
			delete(c.recentlyClosed, streamID)
		}
	}
	c.recentlyClosed[id] = closedStream{at: now, suppress: suppress}
}

func (c *session) pushOrphan(packetType uint8, streamID uint16, sequenceNum uint16) {
	if streamID == 0 {
		return
	}
	c.orphans.Push(wire.PriorityCritical, wire.Packet{Type: packetType, StreamID: streamID, SequenceNum: sequenceNum})
}

// handle is the reference handlePostSessionPacket; false means the packet gets no answer.
func (c *session) handle(packet wire.Packet, now time.Time) bool {
	if c.server.rejectSYN(packet.Type) {
		return false
	}
	if c.preprocess(packet, now) {
		return true
	}
	if packet.Type == wire.PacketPackedControlBlocks {
		for block := range wire.PackedBlocks(packet.Payload) {
			inner := block.Packet(packet)
			if inner.Type == wire.PacketPackedControlBlocks || c.server.rejectSYN(inner.Type) {
				continue
			}
			if !c.preprocess(inner, now) {
				c.dispatch(inner, now)
			}
		}
		return true
	}
	c.dispatch(packet, now)
	return true
}

func (c *session) preprocess(packet wire.Packet, now time.Time) bool {
	stream := c.stream(packet.StreamID)
	if packet.StreamID != 0 && stream == nil {
		closed, suppress := c.isRecentlyClosed(packet.StreamID, now)
		if !closed {
			return c.handleMissingStream(packet)
		}
		switch packet.Type {
		case wire.PacketStreamSYN, wire.PacketSOCKS5SYN, wire.PacketStreamData, wire.PacketStreamResend:
			c.pushOrphan(wire.PacketStreamRST, packet.StreamID, 0)
			return true
		case wire.PacketStreamDataAck, wire.PacketStreamDataNack:
			return true
		}
		if _, isAck := wire.AckedControl(packet.Type); isAck {
			return true
		}
		if ackType, loaded := wire.ControlAck(packet.Type); loaded {
			c.pushOrphan(ackType, packet.StreamID, packet.SequenceNum)
			return true
		}
		if suppress {
			return true
		}
		return c.handleMissingStream(packet)
	}
	switch packet.Type {
	case wire.PacketStreamData, wire.PacketStreamResend, wire.PacketDNSQueryRequest, wire.PacketStreamSYN, wire.PacketSOCKS5SYN:
	default:
		c.queueControlAck(stream, packet, now)
	}
	if stream == nil {
		return false
	}
	return stream.arq.HandleAckPacket(packet.Type, packet.SequenceNum, packet.FragmentID, now)
}

func (c *session) handleMissingStream(packet wire.Packet) bool {
	switch packet.Type {
	case wire.PacketStreamSYN, wire.PacketSOCKS5SYN, wire.PacketPackedControlBlocks, wire.PacketPing, wire.PacketDNSQueryRequest:
		return false
	case wire.PacketStreamDataAck, wire.PacketStreamDataNack:
		return true
	case wire.PacketStreamRST:
		c.pushOrphan(wire.PacketStreamRSTAck, packet.StreamID, packet.SequenceNum)
		return true
	}
	if packet.StreamID == 0 {
		return false
	}
	if _, isAck := wire.AckedControl(packet.Type); isAck {
		return true
	}
	if ackType, loaded := wire.CloseStreamAck(packet.Type); loaded {
		c.pushOrphan(ackType, packet.StreamID, 0)
	} else {
		c.pushOrphan(wire.PacketStreamRST, packet.StreamID, 0)
	}
	return true
}

func (c *session) queueControlAck(stream *stream, packet wire.Packet, now time.Time) {
	ackType, loaded := wire.ControlAck(packet.Type)
	if !loaded || stream == nil {
		return
	}
	if packet.Type == wire.PacketStreamSYN || packet.Type == wire.PacketSOCKS5SYN {
		stream.arq.SendControl(ackType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, nil, wire.DefaultPriority(ackType), false, 0, setupAckTTL, now)
		return
	}
	stream.queue.PushTXPacket(wire.DefaultPriority(ackType), ackType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, compress.Off, 0, nil)
}

func (c *session) dispatch(packet wire.Packet, now time.Time) {
	switch packet.Type {
	case wire.PacketStreamSYN:
		c.handleStreamSYN(packet, now)
		return
	case wire.PacketSOCKS5SYN:
		c.handleSOCKSSYN(packet, now)
		return
	case wire.PacketStreamRST:
		c.handleRST(packet, now)
		return
	}
	stream := c.stream(packet.StreamID)
	if stream == nil {
		return
	}
	switch packet.Type {
	case wire.PacketStreamData, wire.PacketStreamResend:
		if stream.arq.IsClosed() || stream.arq.IsReset() {
			c.pushOrphan(wire.PacketStreamRST, packet.StreamID, 0)
			return
		}
		stream.arq.ReceiveData(packet.SequenceNum, packet.Payload, now)
	case wire.PacketStreamDataNack:
		stream.arq.HandleDataNack(packet.SequenceNum, now)
	case wire.PacketStreamCloseRead:
		stream.arq.MarkCloseReadReceived()
	case wire.PacketStreamCloseWrite:
		stream.arq.MarkCloseWriteReceived()
	}
}

func (c *session) handleRST(packet wire.Packet, now time.Time) {
	c.pushOrphan(wire.PacketStreamRSTAck, packet.StreamID, packet.SequenceNum)
	stream := c.stream(packet.StreamID)
	if stream == nil {
		c.noteClosed(packet.StreamID, now, false)
		return
	}
	stream.queue.Clear()
	stream.arq.MarkRstReceived()
	stream.arq.Close("peer reset before/while connect", arq.CloseOptions{Force: true})
}

func (c *session) handleStreamSYN(packet wire.Packet, now time.Time) {
	if packet.StreamID == 0 {
		return
	}
	stream := c.openStream(packet.StreamID)
	if stream == nil {
		c.pushOrphan(wire.PacketStreamRST, packet.StreamID, 0)
		return
	}
	c.queueControlAck(stream, packet, now)
	if !c.server.forward.IsValid() {
		stream.sendResult(wire.PacketStreamConnectFail, packet.SequenceNum, now)
		return
	}
	stream.connect(c.server.forward, packet.SequenceNum, wire.PacketStreamConnected, now)
}

func (c *session) handleSOCKSSYN(packet wire.Packet, now time.Time) {
	if packet.StreamID == 0 {
		return
	}
	stream := c.openStream(packet.StreamID)
	if stream == nil {
		c.pushOrphan(wire.PacketStreamRST, packet.StreamID, 0)
		return
	}
	c.queueControlAck(stream, packet, now)
	payload, ready := c.collectFragments(packet)
	if !ready {
		return
	}
	destination, err := wire.ParseSOCKSTarget(payload)
	if err != nil {
		stream.sendResult(wire.PacketSOCKS5AddressTypeUnsupported, packet.SequenceNum, now)
		return
	}
	// Loopback and private addresses stay reachable so tests can use local servers; localhost names are denied like the reference.
	if destination.IsFqdn() && (destination.Fqdn == "localhost" || strings.HasSuffix(destination.Fqdn, ".localhost")) {
		stream.sendResult(wire.PacketSOCKS5RulesetDenied, packet.SequenceNum, now)
		return
	}
	stream.connect(destination, packet.SequenceNum, wire.PacketSOCKS5Connected, now)
}

// collectFragments assembles a SOCKS5_SYN target; it is ready once, when the last fragment arrives.
func (c *session) collectFragments(packet wire.Packet) ([]byte, bool) {
	total := max(int(packet.TotalFragments), 1)
	if int(packet.FragmentID) >= total {
		return nil, false
	}
	c.access.Lock()
	defer c.access.Unlock()
	fragments := c.fragments[packet.StreamID]
	if fragments == nil || fragments.sequenceNum != packet.SequenceNum || len(fragments.parts) != total {
		fragments = &synFragments{sequenceNum: packet.SequenceNum, parts: make([][]byte, total)}
		c.fragments[packet.StreamID] = fragments
	}
	if fragments.completed || fragments.parts[packet.FragmentID] != nil {
		return nil, false
	}
	fragments.parts[packet.FragmentID] = append([]byte{}, packet.Payload...)
	fragments.received++
	if fragments.received < total {
		return nil, false
	}
	fragments.completed = true
	var payload []byte
	for _, part := range fragments.parts {
		payload = append(payload, part...)
	}
	return payload, true
}

func (c *session) response(message []byte, name string, now time.Time) []byte {
	packet, loaded := c.dequeue(now)
	if !loaded {
		var nonce [4]byte
		for index := range nonce {
			nonce[index] = byte(rand.Uint32())
		}
		packet = wire.Packet{Type: wire.PacketPong, Payload: wire.AppendPingPayload(nil, nonce)}
	}
	packet.SessionID = c.id
	packet.SessionCookie = c.cookie
	response, err := wire.AppendResponse(nil, message, name, packet, c.base64Response)
	if err != nil {
		return nil
	}
	return response
}

func (c *session) dequeue(now time.Time) (wire.Packet, bool) {
	c.access.Lock()
	streams := make([]arq.DispatchStream, 0, len(c.streams))
	for id, stream := range c.streams {
		streams = append(streams, arq.DispatchStream{ID: id, Queue: stream.queue, Stream: stream.arq})
	}
	c.access.Unlock()
	slices.SortFunc(streams, func(a, b arq.DispatchStream) int {
		return cmp.Compare(a.ID, b.ID)
	})
	c.dispatchAccess.Lock()
	defer c.dispatchAccess.Unlock()
	for range maxDequeueAttempts {
		selection, loaded := c.dispatcher.Select(streams, c.orphans)
		if !loaded {
			return wire.Packet{}, false
		}
		dispatch, taken := c.dispatcher.Take(selection, streams, c.orphans, c.maxPackedBlocks, c.downloadCompression, 1, 1, now)
		if taken {
			return dispatch.Packet, true
		}
	}
	return wire.Packet{}, false
}

func (s *stream) sendResult(packetType uint8, sequenceNum uint16, now time.Time) {
	ttl := failurePacketTTL
	if packetType == wire.PacketStreamConnected || packetType == wire.PacketSOCKS5Connected {
		ttl = resultPacketTTL
	}
	s.arq.SendControl(packetType, sequenceNum, 0, 0, nil, wire.DefaultPriority(packetType), true, 0, ttl, now)
}

// connect dials once per stream; a repeated SYN after the dial gets the result again, or CONNECT_FAIL for another target.
func (s *stream) connect(destination M.Socksaddr, sequenceNum uint16, connectedType uint8, now time.Time) {
	failureType := wire.PacketStreamConnectFail
	if connectedType == wire.PacketSOCKS5Connected {
		failureType = wire.PacketSOCKS5ConnectFail
	}
	s.access.Lock()
	switch {
	case s.connected:
		sameTarget := s.target == destination
		s.access.Unlock()
		if sameTarget {
			s.sendResult(connectedType, sequenceNum, now)
		} else {
			s.sendResult(failureType, sequenceNum, now)
		}
		return
	case s.connecting || s.closed:
		s.access.Unlock()
		return
	}
	s.connecting = true
	s.target = destination
	s.access.Unlock()
	server := s.session.server
	server.wg.Go(func() {
		ctx, cancel := context.WithTimeout(server.ctx, connectTimeout)
		conn, err := server.dialer.DialContext(ctx, N.NetworkTCP, destination)
		cancel()
		if err != nil {
			if server.ctx.Err() == nil {
				if connectedType == wire.PacketSOCKS5Connected {
					failureType = socksFailure(err)
				}
				s.sendResult(failureType, sequenceNum, time.Now())
			}
			return
		}
		if !s.attach(conn) {
			conn.Close()
			return
		}
		s.arq.SetIOReady(true)
		s.sendResult(connectedType, sequenceNum, time.Now())
		server.wg.Go(func() { s.copyFromUpstream(conn) })
		server.wg.Go(func() { s.copyToUpstream(conn) })
	})
}

func (s *stream) attach(conn net.Conn) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed || s.session.server.ctx.Err() != nil {
		return false
	}
	s.connected = true
	s.upstream = conn
	return true
}

func (s *stream) closeUpstream() {
	s.access.Lock()
	s.closed = true
	upstream := s.upstream
	s.access.Unlock()
	if upstream != nil {
		upstream.Close()
	}
}

func (s *stream) onClosed(reason string) {
	c := s.session
	c.access.Lock()
	if c.streams[s.id] == s {
		delete(c.streams, s.id)
		delete(c.fragments, s.id)
	}
	c.access.Unlock()
	c.noteClosed(s.id, time.Now(), strings.Contains(reason, "close handshake completed") || strings.HasSuffix(reason, "acknowledged"))
	s.queue.Clear()
	s.closeUpstream()
}

func (s *stream) copyFromUpstream(conn net.Conn) {
	buffer := make([]byte, copyBufferSize)
	done := s.session.server.ctx.Done()
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			_, writeErr := s.arq.Write(buffer[:n], done)
			if writeErr != nil {
				N.CloseRead(conn)
				return
			}
		}
		if err != nil {
			s.arq.CloseWrite()
			return
		}
	}
}

func (s *stream) copyToUpstream(conn net.Conn) {
	buffer := make([]byte, copyBufferSize)
	done := s.session.server.ctx.Done()
	for {
		n, err := s.arq.Read(buffer, done)
		if n > 0 {
			_, writeErr := conn.Write(buffer[:n])
			if writeErr != nil {
				s.arq.CloseRead()
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				N.CloseWrite(conn)
			} else {
				conn.Close()
			}
			return
		}
	}
}

// socksFailure is the reference mapSOCKSConnectError for a direct dial.
func socksFailure(err error) uint8 {
	var dnsErr *net.DNSError
	var netErr net.Error
	message := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return wire.PacketSOCKS5TTLExpired
	case errors.As(err, &dnsErr):
		return wire.PacketSOCKS5HostUnreachable
	case errors.As(err, &netErr) && netErr.Timeout():
		return wire.PacketSOCKS5TTLExpired
	case strings.Contains(message, "connection refused"), strings.Contains(message, "actively refused"):
		return wire.PacketSOCKS5ConnectionRefused
	case strings.Contains(message, "network is unreachable"):
		return wire.PacketSOCKS5NetworkUnreachable
	case strings.Contains(message, "no route to host"), strings.Contains(message, "host is unreachable"), strings.Contains(message, "no such host"):
		return wire.PacketSOCKS5HostUnreachable
	default:
		return wire.PacketSOCKS5UpstreamUnavailable
	}
}
