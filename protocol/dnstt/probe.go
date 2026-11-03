package dnstt

import (
	"context"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type (
	ProbeLevel  = dnstt.ProbeLevel
	ProbeResult = dnstt.ProbeResult
)

const (
	ProbeLevelPoll      = dnstt.ProbeLevelPoll
	ProbeLevelQName     = dnstt.ProbeLevelQName
	ProbeLevelHandshake = dnstt.ProbeLevelHandshake

	ProbeStagePoll      = dnstt.ProbeStagePoll
	ProbeStageQName     = dnstt.ProbeStageQName
	ProbeStageHandshake = dnstt.ProbeStageHandshake
)

func Probe(ctx context.Context, dialer N.Dialer, options option.DNSTTOutboundOptions, resolver option.DNSTTResolverOptions, level ProbeLevel) (ProbeResult, error) {
	options.Resolvers = []option.DNSTTResolverOptions{resolver}
	clientOptions, system, err := newClientOptions(ctx, logger.NOP(), dialer, options)
	if err != nil {
		return ProbeResult{Rcode: -1}, err
	}
	if system != nil {
		defer system.Close()
	}
	return dnstt.Probe(ctx, clientOptions, level)
}
