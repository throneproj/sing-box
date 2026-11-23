package tor

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

// tor refuses Socks5Proxy next to an external plugin, so with the listener vanilla bridges reach it under this name
const vanillaTransport = "vanilla"

type bridge struct {
	transport   string
	address     netip.AddrPort
	fingerprint string
	arguments   map[string][]string
}

func parseBridges(lines []string) ([]*bridge, error) {
	var bridges []*bridge
	for index, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parsed, err := parseBridge(line)
		if err != nil {
			return nil, E.Cause(err, "bridges[", index, "]")
		}
		bridges = append(bridges, parsed)
	}
	return common.UniqBy(bridges, (*bridge).line), nil
}

func parseBridge(line string) (*bridge, error) {
	fields := strings.Fields(line)
	if len(fields) > 0 && strings.EqualFold(fields[0], "Bridge") {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return nil, E.New("missing bridge address")
	}
	var parsed bridge
	if isTransportName(fields[0]) {
		switch fields[0] {
		case "obfs4", "webtunnel", "meek_lite", "snowflake":
			parsed.transport = fields[0]
		case "meek":
			parsed.transport = "meek_lite"
		case "obfs2", "obfs3", "scramblesuit":
			return nil, E.New("obsolete transport is not supported: ", fields[0])
		case "conjure":
			return nil, E.New("unsupported transport: ", fields[0])
		default:
			return nil, E.New("unknown transport: ", fields[0])
		}
		fields = fields[1:]
		if len(fields) == 0 {
			return nil, E.New("missing bridge address")
		}
	}
	address, err := netip.ParseAddrPort(fields[0])
	if err != nil || address.Addr().Zone() != "" || address.Port() == 0 {
		return nil, E.New("invalid bridge address: ", fields[0])
	}
	parsed.address = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	fields = fields[1:]
	if parsed.transport == "" {
		if common.Any(fields, func(it string) bool {
			return strings.Contains(it, "=")
		}) {
			return nil, E.New("bridge arguments require a transport")
		}
		// like tor, everything after the address of a vanilla bridge is its fingerprint
		if len(fields) > 0 {
			parsed.fingerprint = strings.Join(fields, "")
			if !isFingerprint(parsed.fingerprint) {
				return nil, E.New("invalid bridge fingerprint: ", parsed.fingerprint)
			}
			parsed.fingerprint = strings.ToUpper(parsed.fingerprint)
		}
		return &parsed, nil
	}
	if len(fields) > 0 && !strings.Contains(fields[0], "=") {
		if !isFingerprint(fields[0]) {
			return nil, E.New("invalid bridge fingerprint: ", fields[0])
		}
		parsed.fingerprint = strings.ToUpper(fields[0])
		fields = fields[1:]
	}
	parsed.arguments = make(map[string][]string)
	for _, field := range fields {
		key, value, found := strings.Cut(field, "=")
		if !found || key == "" {
			return nil, E.New("invalid bridge argument: ", field)
		}
		parsed.arguments[key] = append(parsed.arguments[key], value)
	}
	err = validateTransport(&parsed)
	if err != nil {
		return nil, E.Cause(err, parsed.transport)
	}
	return &parsed, nil
}

func isTransportName(value string) bool {
	for index, char := range value {
		if char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || index > 0 && char >= '0' && char <= '9' {
			continue
		}
		return false
	}
	return value != ""
}

func isFingerprint(value string) bool {
	_, err := hex.DecodeString(value)
	return len(value) == 40 && err == nil
}

func (b *bridge) pluginTransport() string {
	if b.transport == "" {
		return vanillaTransport
	}
	return b.transport
}

func (b *bridge) prefix(transport string) string {
	prefix := b.address.String()
	if transport != "" {
		prefix = transport + " " + prefix
	}
	if b.fingerprint != "" {
		prefix += " " + b.fingerprint
	}
	return prefix
}

func (b *bridge) line() string {
	var builder strings.Builder
	builder.WriteString(b.prefix(b.transport))
	for _, key := range slices.Sorted(maps.Keys(b.arguments)) {
		for _, value := range b.arguments[key] {
			builder.WriteString(" " + key + "=" + value)
		}
	}
	return builder.String()
}

// with the listener, tor gets the secret and bridge index as arguments while the real ones stay in-process
func (b *bridge) torLine(secret string, index int) string {
	if secret == "" {
		return b.prefix(b.transport)
	}
	return b.prefix(b.pluginTransport()) + " t=" + secret + " i=" + F.ToString(index)
}

func parseExitCountries(countries []string) ([]string, error) {
	parsed := make([]string, 0, len(countries))
	for _, country := range countries {
		code := strings.ToLower(country)
		if len(code) != 2 || code[0] < 'a' || code[0] > 'z' || code[1] < 'a' || code[1] > 'z' {
			return nil, E.New("invalid exit country: ", country)
		}
		parsed = append(parsed, code)
	}
	slices.Sort(parsed)
	return slices.Compact(parsed), nil
}

func dataDirectoryKey(bridges []*bridge, exitCountries []string) string {
	lines := common.Map(bridges, (*bridge).line)
	slices.Sort(lines)
	digest := sha256.Sum256([]byte(strings.Join(append(lines, strings.Join(exitCountries, ",")), "\n")))
	return hex.EncodeToString(digest[:8])
}
