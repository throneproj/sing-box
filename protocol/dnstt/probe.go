package dnstt

import (
	"context"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type ProbeResult = dnstt.ProbeResult

const (
	ProbeStagePoll  = dnstt.ProbeStagePoll
	ProbeStageQName = dnstt.ProbeStageQName

	ProbeReasonTimeout = dnstt.ProbeReasonTimeout
	ProbeReasonRcode   = dnstt.ProbeReasonRcode
	ProbeReasonAnswer  = dnstt.ProbeReasonAnswer
	ProbeReasonQName   = dnstt.ProbeReasonQName
)

func Probe(ctx context.Context, dialer N.Dialer, options option.DNSTTOutboundOptions, resolver option.DNSTTResolverOptions) (ProbeResult, error) {
	options.Resolvers = []option.DNSTTResolverOptions{resolver}
	clientOptions, system, err := newClientOptions(ctx, logger.NOP(), dialer, options)
	if err != nil {
		return ProbeResult{Rcode: -1}, err
	}
	if system != nil {
		defer system.Close()
	}
	return dnstt.Probe(ctx, clientOptions)
}
