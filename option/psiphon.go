package option

import "github.com/sagernet/sing/common/json/badoption"

type PsiphonOutboundOptions struct {
	DialerOptions
	DataDirectory                      string                     `json:"data_directory,omitempty"`
	EgressRegion                       string                     `json:"egress_region,omitempty"`
	PropagationChannelID               string                     `json:"propagation_channel_id,omitempty"`
	SponsorID                          string                     `json:"sponsor_id,omitempty"`
	RemoteServerListURLs               badoption.Listable[string] `json:"remote_server_list_urls,omitempty"`
	RemoteServerListSignaturePublicKey string                     `json:"remote_server_list_signature_public_key,omitempty"`
}
