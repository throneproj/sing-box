package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type MASQUEEndpointOptions struct {
	System                 bool                             `json:"system,omitempty"`
	Name                   string                           `json:"name,omitempty"`
	MTU                    uint32                           `json:"mtu,omitempty"`
	Address                badoption.Listable[netip.Prefix] `json:"address"`
	PrivateKey             string                           `json:"private_key"`
	PeerPublicKey          string                           `json:"peer_public_key,omitempty"`
	HTTPVersion            int                              `json:"http_version,omitempty" enum:"2,3"`
	DisableVersionFallback bool                             `json:"disable_version_fallback,omitempty"`
	UDPTimeout             badoption.Duration               `json:"udp_timeout,omitempty"`
	UDPMapping             UDPNATBehavior                   `json:"udp_mapping,omitempty"`
	UDPFiltering           UDPNATBehavior                   `json:"udp_filtering,omitempty"`
	UDPNATMax              uint32                           `json:"udp_nat_max,omitempty"`
	ServerOptions
	OutboundTLSOptionsContainer
	QUICOptions
	DialerOptions
}
