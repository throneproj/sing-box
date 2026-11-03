package masterdns

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masterdns"
	N "github.com/sagernet/sing/common/network"
)

type (
	ProbeMode   = masterdns.ProbeMode
	ProbeResult = masterdns.ProbeResult
)

const (
	ProbeModeFull  = masterdns.ProbeModeFull
	ProbeModeQuick = masterdns.ProbeModeQuick

	ProbeStageUpload   = masterdns.ProbeStageUpload
	ProbeStageDownload = masterdns.ProbeStageDownload
	ProbeStageTimeout  = masterdns.ProbeStageTimeout
	ProbeStageDecode   = masterdns.ProbeStageDecode
)

func ProbeResolver(ctx context.Context, dialer N.Dialer, options option.MasterDNSOutboundOptions, resolver netip.AddrPort, mode ProbeMode) (ProbeResult, error) {
	return masterdns.ProbeResolver(ctx, dialer, options, resolver, mode)
}

func ProbeResolvers(ctx context.Context, dialer N.Dialer, options option.MasterDNSOutboundOptions, resolvers []netip.AddrPort, mode ProbeMode, parallelism int, onResult func(ProbeResult)) error {
	return masterdns.ProbeResolvers(ctx, dialer, options, resolvers, mode, parallelism, onResult)
}
