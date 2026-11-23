package option

import "github.com/sagernet/sing/common/json/badoption"

type TorOutboundOptions struct {
	DialerOptions
	ExecutablePath string                     `json:"executable_path,omitempty"`
	ExtraArgs      []string                   `json:"extra_args,omitempty"`
	DataDirectory  string                     `json:"data_directory,omitempty"`
	GeoIPFile      string                     `json:"geoip_file,omitempty"`
	GeoIP6File     string                     `json:"geoip6_file,omitempty"`
	Bridges        badoption.Listable[string] `json:"bridges,omitempty"`
	ExitCountries  badoption.Listable[string] `json:"exit_countries,omitempty"`
	Options        map[string]string          `json:"torrc,omitempty"`
}
