package dnstt

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const streamDialTimeout = 30 * time.Second

func writeStreamMessage(writer io.Writer, message []byte) error {
	if len(message) > 0xffff {
		return E.New("message too long: ", len(message))
	}
	buffer := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(buffer, uint16(len(message)))
	copy(buffer[2:], message)
	_, err := writer.Write(buffer)
	return err
}

func readStreamMessage(reader io.Reader) ([]byte, error) {
	var length [2]byte
	_, err := io.ReadFull(reader, length[:])
	if err != nil {
		return nil, err
	}
	message := make([]byte, binary.BigEndian.Uint16(length[:]))
	_, err = io.ReadFull(reader, message)
	return message, err
}

func exchangeTCP(ctx context.Context, config transportConfig, server M.Socksaddr, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, tcpFallbackTimeout)
	defer cancel()
	conn, err := config.dialer.DialContext(ctx, N.NetworkTCP, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	defer stopClose()
	err = writeStreamMessage(conn, query)
	if err != nil {
		return nil, err
	}
	return readStreamMessage(conn)
}

// A dead connection is redialed, while a failed dial ends the transport as in dnstt-client/tls.go.
type streamTransport struct {
	ctx     context.Context
	cancel  context.CancelFunc
	config  transportConfig
	server  M.Socksaddr
	dial    func(ctx context.Context) (net.Conn, error)
	handler resolverHandler
	queue   chan []byte
	wg      sync.WaitGroup
}

func newStreamTransport(config transportConfig, options ResolverOptions, handler resolverHandler, dial func(ctx context.Context) (net.Conn, error)) *streamTransport {
	ctx, cancel := context.WithCancel(config.ctx)
	t := &streamTransport{
		ctx:     ctx,
		cancel:  cancel,
		config:  config,
		server:  options.Server,
		dial:    dial,
		handler: handler,
		queue:   make(chan []byte, config.queueSize),
	}
	t.wg.Add(1)
	go t.loop()
	return t
}

func (t *streamTransport) writeMessage(message []byte) {
	select {
	case t.queue <- message:
	default:
	}
}

func (t *streamTransport) close() {
	t.cancel()
	t.wg.Wait()
}

func (t *streamTransport) loop() {
	defer t.wg.Done()
	var pending []byte
	for {
		conn, err := t.dialConn()
		if err != nil {
			if t.ctx.Err() == nil {
				t.handler.handleError(err)
			}
			return
		}
		pending = t.serve(conn, pending)
		if t.ctx.Err() != nil {
			return
		}
		if pending == nil {
			select {
			case <-t.ctx.Done():
				return
			case pending = <-t.queue:
			}
		}
	}
}

func (t *streamTransport) dialConn() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(t.ctx, streamDialTimeout)
	defer cancel()
	return t.dial(ctx)
}

// serve returns the query that could not be written, to be sent first on the next connection.
func (t *streamTransport) serve(conn net.Conn, pending []byte) []byte {
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		t.readLoop(conn)
	}()
	defer func() {
		conn.Close()
		<-readDone
	}()
	if pending != nil {
		err := writeStreamMessage(conn, pending)
		if err != nil {
			return nil
		}
	}
	for {
		select {
		case <-t.ctx.Done():
			return nil
		case <-readDone:
			return nil
		case message := <-t.queue:
			err := writeStreamMessage(conn, message)
			if err != nil {
				return message
			}
		}
	}
}

func (t *streamTransport) readLoop(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		message, err := readStreamMessage(reader)
		if err != nil {
			if !E.IsClosedOrCanceled(err) && err != io.EOF {
				t.config.logger.Debug("resolver ", t.server, ": ", err)
			}
			conn.Close()
			return
		}
		t.handler.handleMessage(message)
	}
}
