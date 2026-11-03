package dnstt

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	udpWorkers         = 100
	udpResponseTimeout = 500 * time.Millisecond
	udpInitBackoff     = 100 * time.Millisecond
	udpMaxBackoff      = 5 * time.Second
	tcpFallbackTimeout = 10 * time.Second
)

func udpDestination(server M.Socksaddr) net.Addr {
	if server.IsIP() {
		return server.UDPAddr()
	}
	return server
}

type udpTransport struct {
	ctx         context.Context
	cancel      context.CancelFunc
	config      transportConfig
	server      M.Socksaddr
	tcpFallback bool
	handler     resolverHandler
	queue       chan []byte
	wg          sync.WaitGroup
}

func newUDPTransport(config transportConfig, options ResolverOptions, handler resolverHandler) *udpTransport {
	ctx, cancel := context.WithCancel(config.ctx)
	t := &udpTransport{
		ctx:         ctx,
		cancel:      cancel,
		config:      config,
		server:      options.Server,
		tcpFallback: options.TCPFallback,
		handler:     handler,
		queue:       make(chan []byte, config.queueSize),
	}
	t.wg.Add(1)
	go t.loop()
	return t
}

func (t *udpTransport) writeMessage(message []byte) {
	select {
	case t.queue <- message:
	default:
	}
}

func (t *udpTransport) close() {
	t.cancel()
	t.wg.Wait()
}

func (t *udpTransport) fail(err error) {
	if t.ctx.Err() == nil {
		t.handler.handleError(err)
	}
}

func (t *udpTransport) loop() {
	defer t.wg.Done()
	conn, err := t.config.dialer.ListenPacket(t.ctx, t.server)
	if err != nil {
		t.fail(err)
		return
	}
	stopClose := context.AfterFunc(t.ctx, func() {
		conn.Close()
	})
	defer stopClose()
	defer conn.Close()
	t.wg.Add(1)
	go t.readLoop(conn)
	destination := udpDestination(t.server)
	for {
		select {
		case <-t.ctx.Done():
			return
		case message := <-t.queue:
			_, err = conn.WriteTo(message, destination)
			if err != nil {
				t.fail(err)
				return
			}
		}
	}
}

func (t *udpTransport) readLoop(conn net.PacketConn) {
	defer t.wg.Done()
	defer conn.Close()
	buffer := make([]byte, maxMessageSize)
	server := t.server.Unwrap()
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			t.fail(err)
			return
		}
		if M.SocksaddrFromNet(addr).Unwrap() != server {
			continue
		}
		message := buffer[:n]
		if t.tcpFallback && isTruncated(message) {
			query := queryFromTruncated(message)
			if query != nil {
				t.wg.Add(1)
				go t.exchangeTCP(query)
			}
			continue
		}
		t.handler.handleMessage(message)
	}
}

func (t *udpTransport) exchangeTCP(query []byte) {
	defer t.wg.Done()
	response, err := exchangeTCP(t.ctx, t.config, t.server, query)
	if err != nil {
		t.config.logger.Debug("resolver ", t.server, ": tcp fallback: ", err)
		return
	}
	t.handler.handleMessage(response)
}

type udpExchangeTransport struct {
	ctx         context.Context
	cancel      context.CancelFunc
	config      transportConfig
	server      M.Socksaddr
	tcpFallback bool
	handler     resolverHandler
	queue       chan []byte
	wg          sync.WaitGroup
}

func newUDPExchangeTransport(config transportConfig, options ResolverOptions, handler resolverHandler) *udpExchangeTransport {
	ctx, cancel := context.WithCancel(config.ctx)
	t := &udpExchangeTransport{
		ctx:         ctx,
		cancel:      cancel,
		config:      config,
		server:      options.Server,
		tcpFallback: options.TCPFallback,
		handler:     handler,
		queue:       make(chan []byte, config.queueSize),
	}
	t.wg.Add(udpWorkers)
	for range udpWorkers {
		go t.worker()
	}
	return t
}

func (t *udpExchangeTransport) writeMessage(message []byte) {
	select {
	case t.queue <- message:
	default:
	}
}

func (t *udpExchangeTransport) close() {
	t.cancel()
	t.wg.Wait()
}

func (t *udpExchangeTransport) worker() {
	defer t.wg.Done()
	buffer := make([]byte, maxMessageSize)
	backoff := udpInitBackoff
	for {
		var query []byte
		select {
		case <-t.ctx.Done():
			return
		case query = <-t.queue:
		}
		err := t.exchange(query, buffer)
		if err == nil {
			backoff = udpInitBackoff
			continue
		}
		timer := time.NewTimer(backoff)
		select {
		case <-t.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, udpMaxBackoff)
	}
}

func (t *udpExchangeTransport) exchange(query []byte, buffer []byte) error {
	conn, err := t.config.dialer.ListenPacket(t.ctx, t.server)
	if err != nil {
		return err
	}
	defer conn.Close()
	stopClose := context.AfterFunc(t.ctx, func() {
		conn.Close()
	})
	defer stopClose()
	_, err = conn.WriteTo(query, udpDestination(t.server))
	if err != nil {
		return err
	}
	err = conn.SetReadDeadline(time.Now().Add(udpResponseTimeout))
	if err != nil {
		return err
	}
	for {
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		message, err := parseMessage(buffer[:n])
		if err != nil || message.rcode() != rcodeNoError {
			continue
		}
		if t.tcpFallback && message.Flags&0x0200 != 0 {
			response, err := exchangeTCP(t.ctx, t.config, t.server, query)
			if err != nil {
				return err
			}
			t.handler.handleMessage(response)
			return nil
		}
		t.handler.handleMessage(buffer[:n])
		return nil
	}
}

func isTruncated(message []byte) bool {
	return len(message) >= 4 && message[2]&0x02 != 0
}

// Replies are not matched to queries, so the question alone rebuilds the query bytes.
func queryFromTruncated(message []byte) []byte {
	if len(message) < 12 || binary.BigEndian.Uint16(message[4:]) != 1 {
		return nil
	}
	reader := &messageReader{data: message, offset: 12}
	question, err := reader.readQuestion()
	if err != nil {
		return nil
	}
	return appendQuery(nil, binary.BigEndian.Uint16(message), question.Name, question.Type)
}
