package option

import "github.com/sagernet/sing/common/json/badoption"

type DNSTTOutboundOptions struct {
	DialerOptions
	Mode              string                   `json:"mode,omitempty" enum:"dnstt,vaydns"`
	DNSTTCompat       bool                     `json:"dnstt_compat,omitempty"`
	Domain            string                   `json:"domain,omitempty"`
	PublicKey         string                   `json:"public_key,omitempty"`
	RecordType        string                   `json:"record_type,omitempty" enum:"txt,null,cname,a,aaaa,mx,ns,srv,caa"`
	ClientIDSize      int                      `json:"client_id_size,omitempty"`
	MaxQNameLen       int                      `json:"max_qname_len,omitempty"`
	RPS               float64                  `json:"rps,omitempty"`
	IdleTimeout       badoption.Duration       `json:"idle_timeout,omitempty"`
	KeepAliveInterval badoption.Duration       `json:"keepalive_interval,omitempty"`
	HandshakeTimeout  badoption.Duration       `json:"handshake_timeout,omitempty"`
	Resolvers         []DNSTTResolverOptions   `json:"resolvers,omitempty"`
	ResolverStrategy  string                   `json:"resolver_strategy,omitempty" enum:"round_robin,failover,fanout"`
	SOCKS             *DNSTTSOCKSOptions       `json:"socks,omitempty"`
	Shadowsocks       *DNSTTShadowsocksOptions `json:"shadowsocks,omitempty"`
	SSH               *DNSTTSSHOptions         `json:"ssh,omitempty"`
}

type DNSTTResolverOptions struct {
	Type string `json:"type,omitempty" enum:"udp,tcp,tls,https,system"`
	ServerOptions
	Path string `json:"path,omitempty"`
	OutboundTLSOptionsContainer
	TCPFallback bool `json:"tcp_fallback,omitempty"`
}

type DNSTTSOCKSOptions struct {
	Username   string             `json:"username,omitempty"`
	Password   string             `json:"password,omitempty"`
	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
}

type DNSTTShadowsocksOptions struct {
	Method     string             `json:"method"`
	Password   string             `json:"password"`
	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
}

type DNSTTSSHOptions struct {
	User                 string                     `json:"user,omitempty"`
	Password             string                     `json:"password,omitempty"`
	PrivateKey           badoption.Listable[string] `json:"private_key,omitempty"`
	PrivateKeyPath       string                     `json:"private_key_path,omitempty"`
	PrivateKeyPassphrase string                     `json:"private_key_passphrase,omitempty"`
	HostKey              badoption.Listable[string] `json:"host_key,omitempty"`
	HostKeyAlgorithms    badoption.Listable[string] `json:"host_key_algorithms,omitempty"`
	ClientVersion        string                     `json:"client_version,omitempty"`
}
