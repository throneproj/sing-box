package trusttunnel

import (
	"net/http"
	"net/netip"
	"runtime"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	udpAuthority         = "_udp2"
	icmpAuthority        = "_icmp"
	healthCheckAuthority = "_check"
)

const (
	connectionTimeout  = 30 * time.Second
	healthCheckTimeout = 7 * time.Second
	idleTimeout        = 2 * (connectionTimeout + healthCheckTimeout)
)

const (
	paddedAddressLength      = 16
	serverPacketHeaderLength = 4 + 2*(paddedAddressLength+2)
	clientPacketHeaderLength = serverPacketHeaderLength + 1
	maxUDPPayloadLength      = 65535 - 20 - 8
)

var (
	userAgent    = platformName() + " unknown"
	udpUserAgent = platformName() + " " + udpAuthority
)

func platformName() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "darwin":
		return "Mac"
	case "ios":
		return "iOS"
	case "android":
		return "Android"
	default:
		return "Linux"
	}
}

func putPaddedAddress(buffer []byte, address netip.Addr) {
	if address.Is4() {
		clear(buffer[:12])
		ipv4 := address.As4()
		copy(buffer[12:16], ipv4[:])
	} else {
		ipv6 := address.As16()
		copy(buffer[:16], ipv6[:])
	}
}

func readPaddedAddress(buffer []byte) netip.Addr {
	address := netip.AddrFrom16([16]byte(buffer[:16]))
	if [12]byte(buffer[:12]) == [12]byte{} && address != netip.IPv6Loopback() {
		return netip.AddrFrom4([4]byte(buffer[12:16]))
	}
	return address
}

func statusError(response *http.Response) error {
	if response.StatusCode == http.StatusProxyAuthRequired {
		return E.New("authentication failed")
	}
	if warning := response.Header.Get("X-Warning"); warning != "" {
		return E.New("unexpected status: ", response.Status, " (", warning, ")")
	}
	return E.New("unexpected status: ", response.Status)
}
