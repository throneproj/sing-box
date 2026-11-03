package option

import "github.com/sagernet/sing/common/json/badoption"

type MasterDNSOutboundOptions struct {
	DialerOptions
	Domain                 badoption.Listable[string] `json:"domain,omitempty"`
	Resolvers              badoption.Listable[string] `json:"resolvers,omitempty"`
	Mode                   string                     `json:"mode,omitempty" enum:"socks5,tcp"`
	EncryptionMethod       string                     `json:"encryption_method,omitempty" enum:"none,xor,chacha20,aes-128-gcm,aes-192-gcm,aes-256-gcm"`
	EncryptionKey          string                     `json:"encryption_key,omitempty"`
	Base64Response         bool                       `json:"base64_response,omitempty"`
	UploadCompression      string                     `json:"upload_compression,omitempty" enum:"off,zstd,lz4,zlib"`
	DownloadCompression    string                     `json:"download_compression,omitempty" enum:"off,zstd,lz4,zlib"`
	BalancingStrategy      string                     `json:"balancing_strategy,omitempty" enum:"round_robin,random,least_loss,lowest_latency,hybrid,loss_then_latency,least_loss_top_random,least_loss_top_round_robin"`
	PacketDuplication      int                        `json:"packet_duplication,omitempty"`
	SetupPacketDuplication int                        `json:"setup_packet_duplication,omitempty"`
	MTU                    *MasterDNSMTUOptions       `json:"mtu,omitempty"`
}

type MasterDNSMTUOptions struct {
	MinUpload       int                `json:"min_upload,omitempty"`
	MaxUpload       int                `json:"max_upload,omitempty"`
	MinDownload     int                `json:"min_download,omitempty"`
	MaxDownload     int                `json:"max_download,omitempty"`
	TestRetries     int                `json:"test_retries,omitempty"`
	TestTimeout     badoption.Duration `json:"test_timeout,omitempty"`
	TestParallelism int                `json:"test_parallelism,omitempty"`
	AutoRemoveLow   *bool              `json:"auto_remove_low,omitempty"`
}
