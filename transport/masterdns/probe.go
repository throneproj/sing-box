package masterdns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

const (
	ProbeStageUpload   = "upload"
	ProbeStageDownload = "download"
)

const (
	ProbeReasonTimeout = "timeout"
	ProbeReasonRcode   = "rcode"
	ProbeReasonAnswer  = "answer"
)

const (
	probeExchangeTimeout = 3 * time.Second
	probeBurstSize       = 8
	probeBurstInterval   = 20 * time.Millisecond
)

type ProbeResult struct {
	Passed        bool
	FailedStage   string
	Reason        string
	FirstReply    time.Duration
	BurstSent     int
	BurstAnswered int
}

// ProbeResolver checks the minimum upload and download sizes on each domain until one passes, then sends a burst of
// minimum uploads on it; only option errors are returned.
func ProbeResolver(ctx context.Context, dialer N.Dialer, options option.MasterDNSOutboundOptions, resolver netip.AddrPort) (ProbeResult, error) {
	if !resolver.IsValid() {
		return ProbeResult{}, E.New("invalid resolver: ", resolver)
	}
	resolver = netip.AddrPortFrom(resolver.Addr().Unmap(), resolver.Port())
	options.Resolvers = []string{resolver.String()}
	config, err := NewConfig(options)
	if err != nil {
		return ProbeResult{}, err
	}
	client, err := newClient(logger.NOP(), config, dialer)
	if err != nil {
		return ProbeResult{}, err
	}
	// The startup MTU test rejects these sizes on every resolver, so the probe must not pass them.
	uploadSize := max(config.MTU.MinUpload, minUploadMTUFloor)
	uploadLimit := min(config.MTU.MaxUpload, defaultUploadMaxCap)
	domains := common.Filter(config.Domains, func(it string) bool {
		return min(wire.MaxUploadPayload(it, config.EncryptionMethod), uploadLimit) >= uploadSize
	})
	if len(domains) == 0 {
		return ProbeResult{}, E.New("no domain carries the minimum upload size ", uploadSize)
	}
	downloadSize := max(config.MTU.MinDownload, minDownloadMTUFloor)
	if downloadSize > config.MTU.MaxDownload {
		return ProbeResult{}, E.New("maximum download MTU ", config.MTU.MaxDownload, " is below the minimum size ", downloadSize)
	}
	var (
		result     ProbeResult
		failedRank = -1
	)
	for _, name := range domains {
		domain := client.domains[name]
		stage := ProbeStageUpload
		query, check, err := client.uploadProbeQuery(domain, uploadSize)
		if err != nil {
			return ProbeResult{}, err
		}
		reply := client.probeExchange(ctx, resolver, query, check)
		if result.FirstReply == 0 {
			result.FirstReply = reply.rtt
		}
		if reply.reason == "" {
			stage = ProbeStageDownload
			query, check, err = client.downloadProbeQuery(domain, uploadSize, downloadSize)
			if err != nil {
				return ProbeResult{}, err
			}
			reply = client.probeExchange(ctx, resolver, query, check)
		}
		if reply.reason == "" {
			result.Passed = true
			result.FailedStage, result.Reason = "", ""
			result.BurstSent, result.BurstAnswered, err = client.probeBurst(ctx, resolver, domain, uploadSize)
			if err != nil {
				return ProbeResult{}, err
			}
			return result, nil
		}
		// A failed download outranks a failed upload, and any reply outranks silence.
		rank := 0
		if stage == ProbeStageDownload {
			rank = 2
		}
		if reply.reason != ProbeReasonTimeout {
			rank++
		}
		if rank > failedRank {
			failedRank = rank
			result.FailedStage, result.Reason = stage, reply.reason
		}
		if ctx.Err() != nil {
			break
		}
	}
	return result, nil
}

// probeReply has a zero rtt when nothing came back and an empty reason when the answer passed the check.
type probeReply struct {
	rtt    time.Duration
	reason string
}

func (c *Client) uploadProbeQuery(domain wire.Domain, size int) ([]byte, func(wire.Packet) bool, error) {
	code := c.probeCode.Add(1)
	query, err := c.buildQuery(domain, wire.ProbePacket(wire.PacketMTUUpRequest, wire.NewUploadProbe(size, c.config.Base64Response, code)))
	return query, func(packet wire.Packet) bool {
		return wire.CheckUploadProbe(packet, code, size)
	}, err
}

func (c *Client) downloadProbeQuery(domain wire.Domain, uploadSize int, size int) ([]byte, func(wire.Packet) bool, error) {
	size += downloadProbeReserve
	code := c.probeCode.Add(1)
	query, err := c.buildQuery(domain, wire.ProbePacket(wire.PacketMTUDownRequest, wire.NewDownloadProbe(uploadSize, size, c.config.Base64Response, code)))
	return query, func(packet wire.Packet) bool {
		return wire.CheckDownloadProbe(packet, code, size)
	}, err
}

// probeBurst sends uploads probeBurstInterval apart and counts the passed ones.
func (c *Client) probeBurst(ctx context.Context, resolver netip.AddrPort, domain wire.Domain, size int) (int, int, error) {
	var (
		group    sync.WaitGroup
		answered atomic.Int32
		sent     int
	)
	for i := range probeBurstSize {
		if i > 0 && !sleepContext(ctx, probeBurstInterval) {
			break
		}
		query, check, err := c.uploadProbeQuery(domain, size)
		if err != nil {
			group.Wait()
			return 0, 0, err
		}
		group.Go(func() {
			if c.probeExchange(ctx, resolver, query, check).reason == "" {
				answered.Add(1)
			}
		})
		sent++
	}
	group.Wait()
	return sent, int(answered.Load()), nil
}

// probeExchange sends one probe from a fresh socket, so a late reply to another probe cannot be taken for its own.
func (c *Client) probeExchange(ctx context.Context, resolver netip.AddrPort, query []byte, check func(wire.Packet) bool) probeReply {
	conn, err := c.dialResolver(ctx, resolver)
	if err != nil {
		return probeReply{reason: ProbeReasonTimeout}
	}
	defer conn.Close()
	startedAt := time.Now()
	response, err := exchange(ctx, conn, query, probeExchangeTimeout)
	if err != nil {
		return probeReply{reason: ProbeReasonTimeout}
	}
	// A reply faster than the clock resolution must not read as none.
	reply := probeReply{rtt: max(time.Since(startedAt), time.Nanosecond), reason: ProbeReasonAnswer}
	if rcode, loaded := wire.ResponseRCode(response); loaded && rcode != 0 {
		reply.reason = ProbeReasonRcode
	} else if packet, err := wire.ParseResponse(response, c.config.Base64Response); err == nil && check(packet) {
		reply.reason = ""
	}
	return reply
}
