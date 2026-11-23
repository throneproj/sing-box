//go:build with_psiphon && !PSIPHON_DISABLE_QUIC

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
)

// Psiphon's QUIC stack does not build against the qpack version selected here.
func registerPsiphonOutbound(registry *outbound.Registry) {
	"with_psiphon requires the PSIPHON_DISABLE_QUIC build tag"
}

func PsiphonAvailableEgressRegions() []string {
	return nil
}
