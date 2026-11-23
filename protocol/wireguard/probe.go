package wireguard

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
)

// ProbeHandshake measures one handshake of the endpoint with target, from a socket bound through listenerControl.
func ProbeHandshake(ctx context.Context, options option.WireGuardEndpointOptions, target netip.AddrPort, listenerControl control.Func) (time.Duration, error) {
	// The endpoint's own dialer lets these sockets fragment unless udp_fragment is off.
	if options.UDPFragment == nil || *options.UDPFragment {
		listenerControl = control.Append(listenerControl, control.EnableUDPFragment())
	} else {
		listenerControl = control.Append(listenerControl, control.DisableUDPFragment())
	}
	var newOpener func() []byte
	if options.QUICOpener {
		newOpener = dialer.NewQUICOpener
	}
	return wireguard.ProbeHandshake(ctx, wireguard.EndpointOptions{
		MTU:        options.MTU,
		PrivateKey: options.PrivateKey,
		Peers:      common.Map(options.Peers, mapPeerOptions),
		AmneziaWG:  mapAmneziaWGOptions(options.AmneziaWG),
	}, target, listenerControl, newOpener)
}
