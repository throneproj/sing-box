//go:build !with_tor_transports

package tor

import (
	"context"

	"github.com/sagernet/sing-box/common/proxybridge"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

var errTransportsNotIncluded = E.New(`pluggable transports are not included in this build, rebuild with -tags with_tor_transports`)

type transportListener struct{}

func validateTransport(bridge *bridge) error {
	return errTransportsNotIncluded
}

func newTransportListener(ctx context.Context, logger logger.ContextLogger, dialer N.Dialer, proxy *proxybridge.Bridge, bridges []*bridge) (*transportListener, error) {
	return nil, errTransportsNotIncluded
}

func (l *transportListener) Port() uint16 {
	return 0
}

func (l *transportListener) Secret() string {
	return ""
}
