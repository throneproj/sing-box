//go:build with_quic

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/warpmasque"
)

func registerWARPMASQUEEndpoint(registry *endpoint.Registry) {
	warpmasque.RegisterEndpoint(registry)
}
