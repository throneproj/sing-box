package warpmasque

import (
	"context"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	masquetransport "github.com/sagernet/sing-box/transport/warpmasque"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// ProbeHandshake times one handshake with target from sockets bound through listenerControl, on the carrier the
// endpoint dials; when HTTP/3 may fall back to HTTP/2, both race and the first to complete counts. No tunnel opens.
func ProbeHandshake(ctx context.Context, options option.WARPMASQUEEndpointOptions, target netip.AddrPort, listenerControl control.Func) (time.Duration, error) {
	tlsOptions, err := newTLSOptions(options)
	if err != nil {
		return 0, err
	}
	privateKey, privateKeyPEM, err := loadPrivateKey(options.PrivateKey)
	if err != nil {
		return 0, err
	}
	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}
	tlsOptions, err = clientTLSOptions(tlsOptions, privateKey, privateKeyPEM, timeFunc())
	if err != nil {
		return 0, err
	}
	destination := M.SocksaddrFromNetIP(target).Unwrap()
	useHTTP3 := options.HTTPVersion != 2
	useHTTP2 := options.HTTPVersion == 2 || !options.DisableVersionFallback
	if useHTTP3 && useHTTP2 {
		return probeEitherCarrier(ctx, options, tlsOptions, destination, listenerControl)
	}
	return probeCarrier(ctx, options, tlsOptions, destination, listenerControl, useHTTP2)
}

// probeEitherCarrier races the carriers, as a sequential fallback would not fit the attempt's time bound, and returns
// only after the losing leg has released its sockets.
func probeEitherCarrier(ctx context.Context, options option.WARPMASQUEEndpointOptions, tlsOptions option.OutboundTLSOptions, destination M.Socksaddr, listenerControl control.Func) (time.Duration, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type carrierResult struct {
		useHTTP2 bool
		duration time.Duration
		err      error
	}
	results := make(chan carrierResult, 2)
	for _, useHTTP2 := range []bool{false, true} {
		go func() {
			duration, err := probeCarrier(ctx, options, tlsOptions, destination, listenerControl, useHTTP2)
			results <- carrierResult{useHTTP2, duration, err}
		}()
	}
	var (
		passed   bool
		duration time.Duration
		http3Err error
		http2Err error
	)
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			if !passed {
				passed = true
				duration = result.duration
				cancel()
			}
		case result.useHTTP2:
			http2Err = E.Cause(result.err, carrierName(true))
		default:
			http3Err = E.Cause(result.err, carrierName(false))
		}
	}
	if passed {
		return duration, nil
	}
	return 0, E.Errors(http3Err, http2Err)
}

func probeCarrier(ctx context.Context, options option.WARPMASQUEEndpointOptions, tlsOptions option.OutboundTLSOptions, destination M.Socksaddr, listenerControl control.Func, useHTTP2 bool) (time.Duration, error) {
	if useHTTP2 {
		tlsFragment, err := dialer.NewTLSFragment(options.DialerOptions)
		if err != nil {
			return 0, err
		}
		tlsConfig, err := tls.NewClient(ctx, logger.NOP(), options.Server, tlsOptions)
		if err != nil {
			return 0, err
		}
		tcpDialer := &dialer.ExtendedTCPDialer{
			Dialer:      net.Dialer{Control: listenerControl},
			DisableTFO:  !options.TCPFastOpen,
			TLSFragment: tlsFragment,
		}
		if options.TCPMultiPath {
			tcpDialer.SetMultipathTCP(true)
		}
		start := time.Now()
		err = masquetransport.HandshakeHTTP2(ctx, &probeTCPDialer{tcpDialer}, destination, tlsConfig)
		if err != nil {
			return 0, err
		}
		return time.Since(start), nil
	}
	tlsConfig, err := tls.NewSTDClient(ctx, logger.NOP(), options.Server, tlsOptions)
	if err != nil {
		return 0, err
	}
	stdConfig, err := tlsConfig.STDConfig()
	if err != nil {
		return 0, err
	}
	network := N.NetworkUDP
	if destination.IsIPv4() {
		network += "4"
	}
	listenConfig := net.ListenConfig{Control: listenerControl}
	packetConn, err := listenConfig.ListenPacket(ctx, network, "")
	if err != nil {
		return 0, err
	}
	// The endpoint's dialer sends the opener when it creates the socket.
	if options.QUICOpener {
		_, err = packetConn.WriteTo(dialer.NewQUICOpener(), destination.UDPAddr())
		if err != nil {
			packetConn.Close()
			return 0, err
		}
	}
	start := time.Now()
	err = masquetransport.HandshakeHTTP3(ctx, packetConn, destination, stdConfig, newQUICConfig(options, tlsConfig.HandshakeTimeout()))
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// probeTCPDialer turns the TCP half of the endpoint's dialer into an N.Dialer; HandshakeHTTP2 never listens.
type probeTCPDialer struct {
	*dialer.ExtendedTCPDialer
}

func (d *probeTCPDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
