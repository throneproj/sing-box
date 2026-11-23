//go:build with_psiphon && PSIPHON_DISABLE_QUIC

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/psiphon"
)

func registerPsiphonOutbound(registry *outbound.Registry) {
	psiphon.RegisterOutbound(registry)
}

func PsiphonAvailableEgressRegions() []string {
	return psiphon.AvailableEgressRegions()
}
