package dnstt

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	dnsttHTTPSenders     = 32
	vaydnsHTTPSenders    = 8
	httpRequestTimeout   = time.Minute
	httpMaxResponseSize  = 64000
	httpDefaultRetryWait = 10 * time.Second
	dnsMessageMimeType   = "application/dns-message"
)

// A non-200 reply pauses every sender per Retry-After, as in dnstt-client/http.go.
type httpsTransport struct {
	ctx           context.Context
	cancel        context.CancelFunc
	config        transportConfig
	server        M.Socksaddr
	url           string
	client        *http.Client
	transport     *dnsTransport.HTTPSTransportWrapper
	handler       resolverHandler
	queue         chan []byte
	notBefore     time.Time
	notBeforeLock sync.RWMutex
	wg            sync.WaitGroup
}

func newHTTPSTransport(config transportConfig, options ResolverOptions, handler resolverHandler) *httpsTransport {
	ctx, cancel := context.WithCancel(config.ctx)
	transport := dnsTransport.NewHTTPSTransportWrapper(tls.NewDialer(config.dialer, options.TLSConfig), options.Server, new(atomic.Bool))
	t := &httpsTransport{
		ctx:       ctx,
		cancel:    cancel,
		config:    config,
		server:    options.Server,
		url:       options.URL,
		client:    &http.Client{Transport: transport},
		transport: transport,
		handler:   handler,
		queue:     make(chan []byte, config.queueSize),
	}
	t.wg.Add(config.httpSenders)
	for range config.httpSenders {
		go t.sendLoop()
	}
	return t
}

func (t *httpsTransport) writeMessage(message []byte) {
	select {
	case t.queue <- message:
	default:
	}
}

func (t *httpsTransport) close() {
	t.cancel()
	t.wg.Wait()
	t.transport.Close()
}

func (t *httpsTransport) sendLoop() {
	defer t.wg.Done()
	for {
		var message []byte
		select {
		case <-t.ctx.Done():
			return
		case message = <-t.queue:
		}
		t.notBeforeLock.RLock()
		notBefore := t.notBefore
		t.notBeforeLock.RUnlock()
		if time.Until(notBefore) > 0 {
			continue
		}
		err := t.send(message)
		if err != nil && t.ctx.Err() == nil {
			t.config.logger.Debug("resolver ", t.server, ": ", err)
		}
	}
}

func (t *httpsTransport) send(message []byte) error {
	ctx, cancel := context.WithTimeout(t.ctx, httpRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(message))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", dnsMessageMimeType)
	request.Header.Set("Content-Type", dnsMessageMimeType)
	request.Header.Set("User-Agent", "")
	response, err := t.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		contentType := response.Header.Get("Content-Type")
		if contentType != dnsMessageMimeType {
			return E.New("unknown HTTP response Content-Type ", strconv.Quote(contentType))
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, httpMaxResponseSize))
		if err == nil {
			t.handler.handleMessage(body)
		}
		return nil
	}
	now := time.Now()
	var retryAfter time.Time
	if value := response.Header.Get("Retry-After"); value != "" {
		retryAfter, err = parseRetryAfter(value, now)
		if err != nil {
			t.config.logger.Debug("resolver ", t.server, ": cannot parse Retry-After value ", strconv.Quote(value))
		}
	}
	if retryAfter.IsZero() {
		retryAfter = now.Add(httpDefaultRetryWait)
	}
	if retryAfter.Before(now) {
		return nil
	}
	t.notBeforeLock.Lock()
	if !retryAfter.Before(t.notBefore) {
		t.config.logger.Warn("resolver ", t.server, ": got ", response.Status, ", ceasing sending for ", retryAfter.Sub(now))
		t.notBefore = retryAfter
	}
	t.notBeforeLock.Unlock()
	return nil
}

func parseRetryAfter(value string, now time.Time) (time.Time, error) {
	if retryAt, err := http.ParseTime(value); err == nil {
		return retryAt, nil
	}
	seconds, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return time.Time{}, err
	}
	return now.Add(time.Duration(seconds) * time.Second), nil
}
