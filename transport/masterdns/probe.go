package masterdns

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type ProbeMode uint8

const (
	ProbeModeFull ProbeMode = iota
	ProbeModeQuick
)

const (
	ProbeStageUpload   = "upload"
	ProbeStageDownload = "download"
	ProbeStageTimeout  = "timeout"
	ProbeStageDecode   = "decode"
)

type ProbeResult struct {
	Resolver       netip.AddrPort
	Passed         bool
	FailedStage    string
	UploadMTU      int
	UploadMTUChars int
	DownloadMTU    int
	Latency        time.Duration
}

// ProbeResolver runs the startup MTU test against one resolver; the first domain that passes wins and only option errors are returned.
func ProbeResolver(ctx context.Context, dialer N.Dialer, options option.MasterDNSOutboundOptions, resolver netip.AddrPort, mode ProbeMode) (ProbeResult, error) {
	client, err := newProbeClient(dialer, options, resolver)
	if err != nil {
		return ProbeResult{Resolver: resolver}, err
	}
	return client.probeResolver(ctx, resolver, mode), nil
}

// ProbeResolvers reports every finished probe to onResult one at a time; probes cut short by ctx are not reported.
func ProbeResolvers(ctx context.Context, dialer N.Dialer, options option.MasterDNSOutboundOptions, resolvers []netip.AddrPort, mode ProbeMode, parallelism int, onResult func(ProbeResult)) error {
	if len(resolvers) == 0 {
		return nil
	}
	for _, resolver := range resolvers {
		if !resolver.IsValid() || resolver.Port() == 0 {
			return E.New("invalid resolver: ", resolver)
		}
	}
	client, err := newProbeClient(dialer, options, resolvers[0])
	if err != nil {
		return err
	}
	if parallelism <= 0 {
		parallelism = mtuTestParallelism(client.config.MTU.TestParallelism, len(resolvers), client.settings.RXTXWorkers)
	}
	parallelism = min(parallelism, len(resolvers))
	var (
		group        sync.WaitGroup
		resultAccess sync.Mutex
	)
	jobs := make(chan netip.AddrPort)
	for range parallelism {
		group.Go(func() {
			for resolver := range jobs {
				result := client.probeResolver(ctx, resolver, mode)
				if ctx.Err() != nil || onResult == nil {
					continue
				}
				resultAccess.Lock()
				onResult(result)
				resultAccess.Unlock()
			}
		})
	}
	defer group.Wait()
	defer close(jobs)
	for _, resolver := range resolvers {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case jobs <- resolver:
		}
	}
	return nil
}

func newProbeClient(dialer N.Dialer, options option.MasterDNSOutboundOptions, resolver netip.AddrPort) (*Client, error) {
	if !resolver.IsValid() {
		return nil, E.New("invalid resolver: ", resolver)
	}
	options.Resolvers = []string{netip.AddrPortFrom(resolver.Addr().Unmap(), resolver.Port()).String()}
	config, err := NewConfig(options)
	if err != nil {
		return nil, err
	}
	return newClient(logger.NOP(), config, dialer)
}

func (c *Client) probeResolver(ctx context.Context, resolver netip.AddrPort, mode ProbeMode) ProbeResult {
	failed := ProbeResult{Resolver: resolver, FailedStage: ProbeStageTimeout}
	failedRank := probeStageRank(MTURejectTimeout)
	conn := Connection{Resolver: netip.AddrPortFrom(resolver.Addr().Unmap(), resolver.Port())}
	for _, domain := range c.config.Domains {
		conn.Domain = domain
		result, reason := c.probeConnection(ctx, conn, wire.MaxUploadPayload(domain, c.config.EncryptionMethod), mode == ProbeModeQuick)
		if reason == MTURejectNone {
			return ProbeResult{
				Resolver:       resolver,
				Passed:         true,
				UploadMTU:      result.UploadMTU,
				UploadMTUChars: result.UploadMTUChars,
				DownloadMTU:    result.DownloadMTU,
				Latency:        result.ResolveTime,
			}
		}
		if rank := probeStageRank(reason); rank > failedRank {
			failedRank = rank
			failed = ProbeResult{
				Resolver:       resolver,
				FailedStage:    probeStage(reason),
				UploadMTU:      result.UploadMTU,
				UploadMTUChars: result.UploadMTUChars,
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return failed
}

func probeStage(reason MTURejectReason) string {
	switch reason {
	case MTURejectDownload:
		return ProbeStageDownload
	case MTURejectUpload:
		return ProbeStageUpload
	case MTURejectDecode:
		return ProbeStageDecode
	default:
		return ProbeStageTimeout
	}
}

func probeStageRank(reason MTURejectReason) int {
	switch reason {
	case MTURejectDownload:
		return 3
	case MTURejectUpload:
		return 2
	case MTURejectDecode:
		return 1
	default:
		return 0
	}
}
