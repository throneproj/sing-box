package masterdns

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/compress"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	ErrSessionInitFailed = E.New("session init failed")
	ErrSessionInitBusy   = E.New("session init busy: server is at capacity or rejected the request")
)

const (
	sessionInitRacers           = 3
	sessionInitStagger          = 100 * time.Millisecond
	sessionInitSafetyTimeout    = 30 * time.Second
	sessionInitRetryBase        = time.Second
	sessionInitRetryStep        = time.Second
	sessionInitRetryLinearAfter = 5
	sessionInitRetryMax         = 60 * time.Second
	sessionCloseBurstTargets    = 10
	sessionCloseBurstRounds     = 3
	sessionCloseBurstTimeout    = time.Second
	defaultProcessWorkers       = 6
)

type Session struct {
	ID                  uint8
	Cookie              uint8
	Base64Response      bool
	UploadCompression   compress.Type
	DownloadCompression compress.Type
	UploadMTU           int
	UploadMTUChars      int
	SafeUploadMTU       int
	DownloadMTU         int
	MaxPackedBlocks     int
	Settings            wire.ClientSettings
	ProcessWorkers      int
}

func defaultClientSettings(config Config) wire.ClientSettings {
	return wire.ClientSettings{
		PacketDuplication:      config.PacketDuplication,
		SetupPacketDuplication: config.SetupPacketDuplication,
		MaxUploadMTU:           config.MTU.MaxUpload,
		MaxDownloadMTU:         config.MTU.MaxDownload,
		RXTXWorkers:            4,
		PingAggressiveInterval: 100 * time.Millisecond,
		MaxPacketsPerBatch:     8,
		ARQWindowSize:          1000,
		ARQDataNackMaxGap:      32,
		CompressionMinSize:     120,
		ARQInitialRTO:          500 * time.Millisecond,
		ARQControlInitialRTO:   500 * time.Millisecond,
		ARQMaxRTO:              3 * time.Second,
		ARQControlMaxRTO:       2 * time.Second,
	}
}

func sessionInitRetryDelay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	delay := sessionInitRetryBase
	if failures > sessionInitRetryLinearAfter {
		delay += time.Duration(failures-sessionInitRetryLinearAfter) * sessionInitRetryStep
	}
	return min(delay, sessionInitRetryMax)
}

func deriveProcessWorkers(current int, rxtxWorkers int) int {
	rxtxWorkers = max(rxtxWorkers, 1)
	current = max(current, min(max(4, rxtxWorkers+1), 256))
	if current < rxtxWorkers {
		return rxtxWorkers
	}
	return min(current, 256)
}

func (c *Client) initializeSession(ctx context.Context, maxAttempts int) error {
	upload, download := c.syncedMTU()
	if upload <= 0 || download <= 0 {
		return ErrSessionInitFailed
	}
	for range max(maxAttempts, 1) {
		err := c.initializeSessionRequest(ctx)
		if err == nil || errors.Is(err, ErrNoValidConnections) || errors.Is(err, ErrSessionInitBusy) || ctx.Err() != nil {
			return err
		}
	}
	return ErrSessionInitFailed
}

type sessionInitResult struct {
	packet wire.Packet
	err    error
}

// initializeSessionRequest races one SESSION_INIT query three times on one resolver, 100 ms apart, and takes the first usable answer.
func (c *Client) initializeSessionRequest(ctx context.Context) error {
	conn, payload, verifyCode, err := c.nextSessionInitAttempt()
	if err != nil {
		return err
	}
	c.logger.Debug("session init attempt with ", conn.Domain, " via ", conn.Resolver)
	query, err := c.buildQuery(c.domains[conn.Domain], wire.Packet{
		Type:    wire.PacketSessionInit,
		Payload: payload,
	})
	if err != nil {
		return ErrSessionInitFailed
	}
	base64Response := payload[0] == wire.ResponseModeBase64
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan sessionInitResult, sessionInitRacers)
	launched := 0
launch:
	for range sessionInitRacers {
		if launched > 0 {
			timer := time.NewTimer(sessionInitStagger)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				break launch
			}
		}
		launched++
		c.workers.Go(func() {
			packet, err := c.exchangeResolver(ctx, conn.Resolver, query, base64Response, c.config.MTU.TestTimeout*3)
			select {
			case results <- sessionInitResult{packet: packet, err: err}:
			case <-requestCtx.Done():
			}
		})
	}
	var lastErr error
	safety := time.NewTimer(sessionInitSafetyTimeout)
	defer safety.Stop()
	for received := 0; received < launched; {
		select {
		case result := <-results:
			received++
			if result.err == nil {
				err = c.applySessionInitPacket(result.packet, payload, verifyCode)
				if err == nil || errors.Is(err, ErrSessionInitBusy) {
					return err
				}
			}
			lastErr = result.err
			safety.Reset(sessionInitSafetyTimeout)
		case <-safety.C:
			return ErrSessionInitFailed
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if lastErr == nil {
		return ErrSessionInitFailed
	}
	return lastErr
}

func (c *Client) nextSessionInitAttempt() (Connection, []byte, [wire.VerifyCodeSize]byte, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.initReady {
		var verifyCode [wire.VerifyCodeSize]byte
		rand.Read(verifyCode[:])
		c.initPayload = wire.AppendSessionInit(nil, wire.SessionInit{
			Base64Response:      c.config.Base64Response,
			UploadCompression:   c.uploadCompression,
			DownloadCompression: c.downloadCompression,
			UploadMTU:           uint16(c.uploadMTU),
			DownloadMTU:         uint16(c.downloadMTU),
			VerifyCode:          verifyCode,
		})
		c.initVerify = verifyCode
		c.initReady = true
		c.initCursor = 0
	}
	active := c.balancer.ActiveConnections()
	for checked := range len(active) {
		index := (c.initCursor + checked) % len(active)
		if !active[index].Valid || active[index].Key == "" {
			continue
		}
		c.initCursor = (index + 1) % len(active)
		return active[index], c.initPayload, c.initVerify, nil
	}
	return Connection{}, nil, [wire.VerifyCodeSize]byte{}, ErrNoValidConnections
}

func (c *Client) applySessionInitPacket(packet wire.Packet, payload []byte, verifyCode [wire.VerifyCodeSize]byte) error {
	c.access.Lock()
	ready := c.ready
	c.access.Unlock()
	if ready {
		return nil
	}
	switch packet.Type {
	case wire.PacketSessionBusy:
		if !wire.SessionBusyMatches(packet.Payload, verifyCode) {
			return ErrSessionInitFailed
		}
		return ErrSessionInitBusy
	case wire.PacketSessionAccept:
		accept, err := wire.ParseSessionAccept(packet.Payload)
		if err != nil || accept.VerifyCode != verifyCode {
			return ErrSessionInitFailed
		}
		c.access.Lock()
		defer c.access.Unlock()
		if c.ready {
			return nil
		}
		c.sessionID = accept.SessionID
		c.sessionCookie = accept.SessionCookie
		c.base64Response = payload[0] == wire.ResponseModeBase64
		c.uploadCompression = accept.UploadCompression
		c.downloadCompression = accept.DownloadCompression
		if accept.HasPolicy {
			c.applyPolicyLocked(accept.Policy)
		}
		c.ready = true
		c.applyCompressionPolicyLocked()
		c.resetInitStateLocked()
		c.sessionResetPending.Store(false)
		return nil
	default:
		return ErrSessionInitFailed
	}
}

// applyPolicyLocked caps the client settings to the server policy for this and every later session, lowering the synced MTUs with them.
func (c *Client) applyPolicyLocked(policy wire.SessionPolicy) {
	before := c.settings
	c.settings = c.settings.Apply(policy)
	c.processWorkers = deriveProcessWorkers(c.processWorkers, c.settings.RXTXWorkers)
	if c.uploadMTU > 0 {
		c.uploadMTU = min(c.uploadMTU, c.settings.MaxUploadMTU)
		c.uploadMTUChars = wire.EncodedChars(c.uploadMTU, c.config.EncryptionMethod)
		c.safeUploadMTU = wire.SafeUploadMTU(c.uploadMTU, c.config.EncryptionMethod)
		c.maxPackedBlocks = wire.MaxPackedBlocks(c.uploadMTU, 80, c.settings.MaxPacketsPerBatch)
	} else {
		c.uploadMTUChars = 0
		c.safeUploadMTU = 0
		c.maxPackedBlocks = 1
	}
	if c.downloadMTU > 0 {
		c.downloadMTU = min(c.downloadMTU, c.settings.MaxDownloadMTU)
	}
	c.closeResolverPools()
	after := c.settings
	logChange := func(name string, requested any, effective any) {
		if requested != effective {
			c.logger.Warn("server policy adjusted ", name, ": requested ", requested, ", effective ", effective)
		}
	}
	logChange("packet_duplication", before.PacketDuplication, after.PacketDuplication)
	logChange("setup_packet_duplication", before.SetupPacketDuplication, after.SetupPacketDuplication)
	logChange("max_upload_mtu", before.MaxUploadMTU, after.MaxUploadMTU)
	logChange("max_download_mtu", before.MaxDownloadMTU, after.MaxDownloadMTU)
	logChange("rx_tx_workers", before.RXTXWorkers, after.RXTXWorkers)
	logChange("ping_aggressive_interval", before.PingAggressiveInterval, after.PingAggressiveInterval)
	logChange("max_packets_per_batch", before.MaxPacketsPerBatch, after.MaxPacketsPerBatch)
	logChange("arq_window_size", before.ARQWindowSize, after.ARQWindowSize)
	logChange("arq_data_nack_max_gap", before.ARQDataNackMaxGap, after.ARQDataNackMaxGap)
	logChange("compression_min_size", before.CompressionMinSize, after.CompressionMinSize)
	logChange("arq_initial_rto", before.ARQInitialRTO, after.ARQInitialRTO)
	logChange("arq_control_initial_rto", before.ARQControlInitialRTO, after.ARQControlInitialRTO)
}

// applyCompressionPolicyLocked turns compression off for a direction whose MTU is too small; the choice carries into later sessions.
func (c *Client) applyCompressionPolicyLocked() {
	upload := compress.ForMTU(c.uploadCompression, c.uploadMTU, c.settings.CompressionMinSize)
	download := compress.ForMTU(c.downloadCompression, c.downloadMTU, c.settings.CompressionMinSize)
	if upload != compress.Normalize(uint8(c.uploadCompression)) {
		c.logger.Info("upload compression ", c.uploadCompression, " disabled for upload MTU ", c.uploadMTU)
	}
	if download != compress.Normalize(uint8(c.downloadCompression)) {
		c.logger.Info("download compression ", c.downloadCompression, " disabled for download MTU ", c.downloadMTU)
	}
	c.uploadCompression = upload
	c.downloadCompression = download
}

func (c *Client) resetInitStateLocked() {
	c.initPayload = nil
	c.initVerify = [wire.VerifyCodeSize]byte{}
	c.initReady = false
	c.initCursor = 0
}

func (c *Client) resetSession() {
	c.access.Lock()
	c.ready = false
	c.sessionID = 0
	c.sessionCookie = 0
	c.base64Response = false
	c.resetInitStateLocked()
	c.access.Unlock()
}

func (c *Client) sessionLocked() Session {
	return Session{
		ID:                  c.sessionID,
		Cookie:              c.sessionCookie,
		Base64Response:      c.base64Response,
		UploadCompression:   c.uploadCompression,
		DownloadCompression: c.downloadCompression,
		UploadMTU:           c.uploadMTU,
		UploadMTUChars:      c.uploadMTUChars,
		SafeUploadMTU:       c.safeUploadMTU,
		DownloadMTU:         c.downloadMTU,
		MaxPackedBlocks:     c.maxPackedBlocks,
		Settings:            c.settings,
		ProcessWorkers:      c.processWorkers,
	}
}

// closeSessionBurst tells the server the session is gone with three one-way SESSION_CLOSE rounds within a second.
func (c *Client) closeSessionBurst(ctx context.Context) {
	c.access.Lock()
	ready, sessionID, sessionCookie := c.ready, c.sessionID, c.sessionCookie
	c.access.Unlock()
	if !ready || sessionID == 0 || !c.sessionResetPending.CompareAndSwap(false, true) {
		return
	}
	targets := c.balancer.UniqueConnections(sessionCloseBurstTargets)
	if len(targets) == 0 {
		if best, loaded := c.balancer.BestConnection(); loaded {
			targets = []Connection{best}
		}
	}
	if len(targets) == 0 {
		c.sessionResetPending.Store(false)
		return
	}
	deadline := time.Now().Add(sessionCloseBurstTimeout)
	burstCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()
	for round := range sessionCloseBurstRounds {
		var group sync.WaitGroup
		for _, target := range targets {
			group.Go(func() {
				query, err := c.buildQuery(c.domains[target.Domain], wire.Packet{
					SessionID:     sessionID,
					Type:          wire.PacketSessionClose,
					SessionCookie: sessionCookie,
				})
				if err == nil {
					c.sendOneWay(burstCtx, target.Resolver, query, deadline)
				}
			})
		}
		group.Wait()
		if round == sessionCloseBurstRounds-1 {
			break
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		time.Sleep(min(sessionCloseBurstTimeout/sessionCloseBurstRounds, remaining))
	}
	c.logger.Debug("sent session close burst for session ", sessionID, " to ", len(targets), " resolvers")
}
