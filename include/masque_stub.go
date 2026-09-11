//go:build !with_quic

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func registerMASQUEEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.MASQUEEndpointOptions](registry, C.TypeMASQUE, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEEndpointOptions) (adapter.Endpoint, error) {
		return nil, C.ErrQUICNotIncluded
	})
}
