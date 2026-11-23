package wireguard

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

// ProbeHandshake sends one handshake initiation to target from a fresh socket, with what Start sends before and with
// it, and returns the time until the session is established; ctx bounds the wait.
func ProbeHandshake(ctx context.Context, options EndpointOptions, target netip.AddrPort, listenerControl control.Func, newOpener func() []byte) (time.Duration, error) {
	if len(options.Peers) != 1 {
		return 0, E.New("probe requires exactly one peer")
	}
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	peerOptions := options.Peers[0]
	peerOptions.Endpoint = M.SocksaddrFromNetIP(target)
	// A persistent keepalive would send the initiation from Up, before the clock starts.
	peerOptions.PersistentKeepaliveInterval = ""
	options.Peers = []PeerOptions{peerOptions}
	options.ListenPort = 0
	endpoint, err := NewEndpoint(options)
	if err != nil {
		return 0, err
	}
	peer := endpoint.peers[0]
	bind := conn.NewStdNetBind(listenerControl).(*conn.StdNetBind)
	bind.SetSinglePeerMode()
	if newOpener != nil {
		bind.SetFlowOpener(newOpener)
	}
	if peer.reserved != [3]uint8{} {
		bind.SetReservedForEndpoint(target, peer.reserved)
	}
	tunDevice := &probeDevice{
		mtu:    endpoint.options.MTU,
		events: make(chan wgTun.Event),
		closed: make(chan struct{}),
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	wgDevice := device.NewDevice(ctx, tunDevice, bind, logger, 1)
	defer wgDevice.Close()
	established := make(chan struct{}, 1)
	wgDevice.SetSessionStateFunc(func(_ device.NoisePublicKey, state device.PeerSessionState) {
		if state != device.PeerSessionEstablished {
			return
		}
		select {
		case established <- struct{}{}:
		default:
		}
	})
	err = wgDevice.IpcSet(endpoint.ipcConf + peer.GenerateIpcLines())
	if err != nil {
		return 0, E.Cause(err, "setup wireguard")
	}
	err = wgDevice.Up()
	if err != nil {
		return 0, err
	}
	wgPeer, loaded := wgDevice.LookupActivePeer(peer.publicKey)
	if !loaded {
		return 0, E.New("missing peer")
	}
	start := time.Now()
	err = wgPeer.SendHandshakeInitiation(false)
	if err != nil {
		return 0, err
	}
	select {
	case <-established:
		return time.Since(start), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// probeDevice is a TUN that never carries a packet: the probe only handshakes.
type probeDevice struct {
	mtu       uint32
	events    chan wgTun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

func (d *probeDevice) File() *os.File {
	return nil
}

func (d *probeDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-d.closed
	return 0, os.ErrClosed
}

func (d *probeDevice) Write(bufs [][]byte, offset int) (int, error) {
	return len(bufs), nil
}

func (d *probeDevice) MTU() (int, error) {
	return int(d.mtu), nil
}

func (d *probeDevice) Name() (string, error) {
	return "sing-box", nil
}

func (d *probeDevice) Events() <-chan wgTun.Event {
	return d.events
}

func (d *probeDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.events)
		close(d.closed)
	})
	return nil
}

func (d *probeDevice) BatchSize() int {
	return 1
}
