package masterdns

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masterdns"
	N "github.com/sagernet/sing/common/network"
)

type ProbeResult = masterdns.ProbeResult

const (
	ProbeStageUpload   = masterdns.ProbeStageUpload
	ProbeStageDownload = masterdns.ProbeStageDownload

	ProbeReasonTimeout = masterdns.ProbeReasonTimeout
	ProbeReasonRcode   = masterdns.ProbeReasonRcode
	ProbeReasonAnswer  = masterdns.ProbeReasonAnswer
)

func ProbeResolver(ctx context.Context, dialer N.Dialer, options option.MasterDNSOutboundOptions, resolver netip.AddrPort) (ProbeResult, error) {
	return masterdns.ProbeResolver(ctx, dialer, options, resolver)
}
