package masterdns

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masterdns/cipher"
	"github.com/sagernet/sing-box/transport/masterdns/compress"
	"github.com/sagernet/sing-box/transport/masterdns/wire"
	E "github.com/sagernet/sing/common/exceptions"
)

type Mode uint8

const (
	ModeSOCKS5 Mode = iota
	ModeTCP
)

// BalancingStrategy values are the reference RESOLVER_BALANCING_STRATEGY codes.
type BalancingStrategy uint8

const (
	BalancingRoundRobinDefault BalancingStrategy = iota
	BalancingRandom
	BalancingRoundRobin
	BalancingLeastLoss
	BalancingLowestLatency
	BalancingHybrid
	BalancingLossThenLatency
	BalancingLeastLossTopRandom
	BalancingLeastLossTopRoundRobin
)

const (
	DefaultPacketDuplication      = 3
	DefaultSetupPacketDuplication = 4
	DefaultMinUploadMTU           = 38
	DefaultMaxUploadMTU           = 150
	DefaultMinDownloadMTU         = 200
	DefaultMaxDownloadMTU         = 4000
	DefaultMTUTestRetries         = 2
	DefaultMTUTestTimeout         = 2 * time.Second
	DefaultMTUTestParallelism     = 32
)

type Config struct {
	// Domains are lower-case without the trailing dot, longest first.
	Domains []string
	// Resolvers are sorted by address string; SystemResolver asks for the system DNS servers to be added at start.
	Resolvers              []netip.AddrPort
	SystemResolver         bool
	Mode                   Mode
	EncryptionMethod       cipher.Method
	EncryptionKey          string
	Base64Response         bool
	UploadCompression      compress.Type
	DownloadCompression    compress.Type
	BalancingStrategy      BalancingStrategy
	PacketDuplication      int
	SetupPacketDuplication int
	MTU                    MTUConfig
}

type MTUConfig struct {
	MinUpload       int
	MaxUpload       int
	MinDownload     int
	MaxDownload     int
	TestRetries     int
	TestTimeout     time.Duration
	TestParallelism int
	AutoRemoveLow   bool
}

func NewConfig(options option.MasterDNSOutboundOptions) (Config, error) {
	var (
		config Config
		err    error
	)
	config.Domains, err = normalizeDomains(options.Domain)
	if err != nil {
		return Config{}, err
	}
	config.Resolvers, config.SystemResolver, err = ParseResolvers(options.Resolvers)
	if err != nil {
		return Config{}, err
	}
	if len(config.Resolvers) == 0 && !config.SystemResolver {
		return Config{}, E.New("missing resolvers")
	}
	switch options.Mode {
	case "", "socks5":
		config.Mode = ModeSOCKS5
	case "tcp":
		config.Mode = ModeTCP
	default:
		return Config{}, E.New("unknown mode: ", options.Mode)
	}
	config.EncryptionMethod = cipher.MethodXOR
	if options.EncryptionMethod != "" {
		config.EncryptionMethod, err = cipher.ParseMethod(options.EncryptionMethod)
		if err != nil {
			return Config{}, err
		}
	}
	config.EncryptionKey = strings.TrimSpace(options.EncryptionKey)
	if config.EncryptionMethod != cipher.MethodNone && config.EncryptionKey == "" {
		return Config{}, E.New("missing encryption key")
	}
	config.Base64Response = options.Base64Response
	config.UploadCompression, err = compress.ParseType(options.UploadCompression)
	if err != nil {
		return Config{}, err
	}
	config.DownloadCompression, err = compress.ParseType(options.DownloadCompression)
	if err != nil {
		return Config{}, err
	}
	config.BalancingStrategy, err = parseBalancingStrategy(options.BalancingStrategy)
	if err != nil {
		return Config{}, err
	}
	config.PacketDuplication = min(defaultBelowOne(options.PacketDuplication, DefaultPacketDuplication), 10)
	config.SetupPacketDuplication = min(max(defaultBelowOne(options.SetupPacketDuplication, DefaultSetupPacketDuplication), config.PacketDuplication), 12)
	config.MTU, err = newMTUConfig(options.MTU)
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

func newMTUConfig(options *option.MasterDNSMTUOptions) (MTUConfig, error) {
	if options == nil {
		options = &option.MasterDNSMTUOptions{}
	}
	if options.MinUpload < 0 || options.MaxUpload < 0 || options.MinDownload < 0 || options.MaxDownload < 0 {
		return MTUConfig{}, E.New("mtu values cannot be negative")
	}
	config := MTUConfig{
		MinUpload:       defaultBelowOne(options.MinUpload, DefaultMinUploadMTU),
		MaxUpload:       defaultBelowOne(options.MaxUpload, DefaultMaxUploadMTU),
		MinDownload:     defaultBelowOne(options.MinDownload, DefaultMinDownloadMTU),
		MaxDownload:     defaultBelowOne(options.MaxDownload, DefaultMaxDownloadMTU),
		TestRetries:     defaultBelowOne(options.TestRetries, DefaultMTUTestRetries),
		TestTimeout:     time.Duration(options.TestTimeout),
		TestParallelism: defaultBelowOne(options.TestParallelism, DefaultMTUTestParallelism),
		AutoRemoveLow:   options.AutoRemoveLow == nil || *options.AutoRemoveLow,
	}
	if config.TestTimeout <= 0 {
		config.TestTimeout = DefaultMTUTestTimeout
	}
	if config.MinUpload > config.MaxUpload {
		return MTUConfig{}, E.New("minimum upload MTU ", config.MinUpload, " is above the maximum ", config.MaxUpload)
	}
	if config.MinDownload > config.MaxDownload {
		return MTUConfig{}, E.New("minimum download MTU ", config.MinDownload, " is above the maximum ", config.MaxDownload)
	}
	return config, nil
}

// normalizeDomains lower-cases, de-duplicates and orders domains longest first like the reference client.
func normalizeDomains(domains []string) ([]string, error) {
	var normalized []string
	for _, domain := range domains {
		name := strings.TrimSuffix(strings.TrimSpace(domain), ".")
		if name == "" || name == "." {
			continue
		}
		parsed, err := wire.NewDomain(name)
		if err != nil {
			return nil, E.Cause(err, "invalid domain: ", domain)
		}
		if !slices.Contains(normalized, parsed.String()) {
			normalized = append(normalized, parsed.String())
		}
	}
	if len(normalized) == 0 {
		return nil, E.New("missing domain")
	}
	slices.SortFunc(normalized, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	return normalized, nil
}

func parseBalancingStrategy(name string) (BalancingStrategy, error) {
	switch name {
	case "", "least_loss":
		return BalancingLeastLoss, nil
	case "round_robin":
		return BalancingRoundRobin, nil
	case "random":
		return BalancingRandom, nil
	case "lowest_latency":
		return BalancingLowestLatency, nil
	case "hybrid":
		return BalancingHybrid, nil
	case "loss_then_latency":
		return BalancingLossThenLatency, nil
	case "least_loss_top_random":
		return BalancingLeastLossTopRandom, nil
	case "least_loss_top_round_robin":
		return BalancingLeastLossTopRoundRobin, nil
	default:
		return 0, E.New("unknown balancing strategy: ", name)
	}
}

func defaultBelowOne(value int, fallback int) int {
	if value < 1 {
		return fallback
	}
	return value
}
