// hiddify: TCP dialer with optional anti-DPI features (TCP Fast Open or TLS
// fragmentation). Replaces the bare tfo.Dialer so the egress can fragment the
// TLS ClientHello when `tls_fragment` is enabled on the outbound dialer.
package dialer

import (
	"context"
	"net"

	"github.com/database64128/tfo-go/v2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ExtendedTCPDialer is a TCP dialer with extra features such as "TCP Fast Open"
// or "TLS Fragmentation".
type ExtendedTCPDialer struct {
	net.Dialer
	DisableTFO  bool
	TLSFragment *TLSFragment
}

// tcpDialer is the concrete TCP dialer stored on DefaultDialer.
type tcpDialer = ExtendedTCPDialer

func newTCPDialer(dialer net.Dialer, tfoEnabled bool, tlsFragment *TLSFragment) (tcpDialer, error) {
	return tcpDialer{Dialer: dialer, DisableTFO: !tfoEnabled, TLSFragment: tlsFragment}, nil
}

func (d *ExtendedTCPDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if (d.DisableTFO && !(d.TLSFragment != nil && d.TLSFragment.Enabled)) || N.NetworkName(network) != N.NetworkTCP {
		switch N.NetworkName(network) {
		case N.NetworkTCP, N.NetworkUDP:
			return d.Dialer.DialContext(ctx, network, destination.String())
		default:
			return d.Dialer.DialContext(ctx, network, destination.AddrString())
		}
	}
	// Create a TLS-Fragmented dialer
	if d.TLSFragment != nil && d.TLSFragment.Enabled {
		fragmentConn := &fragmentConn{
			dialer:      d.Dialer,
			fragment:    *d.TLSFragment,
			network:     network,
			destination: destination,
		}
		conn, err := d.Dialer.DialContext(ctx, network, destination.String())
		if err != nil {
			fragmentConn.err = err
			return nil, err
		}
		fragmentConn.conn = conn
		return fragmentConn, nil
	}
	// Create a TFO dialer
	return &slowOpenConn{
		dialer:      &tfo.Dialer{Dialer: d.Dialer, DisableTFO: d.DisableTFO},
		ctx:         ctx,
		network:     network,
		destination: destination,
		create:      make(chan struct{}),
		done:        make(chan struct{}),
	}, nil
}
