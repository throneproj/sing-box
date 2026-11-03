package masterdns

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	defaultResolverPort = 53
	maxResolverHosts    = 65536
)

// ParseResolvers expands resolver entries: "system", an IP, IP:port, [IPv6]:port, a CIDR or CIDR:port.
// Addresses are de-duplicated by IP with the first port winning and sorted by their string form, like the reference resolver file.
func ParseResolvers(entries []string) (resolvers []netip.AddrPort, system bool, err error) {
	seen := make(map[netip.Addr]bool)
	add := func(addr netip.Addr, port uint16) {
		if !seen[addr] {
			seen[addr] = true
			resolvers = append(resolvers, netip.AddrPortFrom(addr, port))
		}
	}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if strings.EqualFold(entry, "system") {
			system = true
			continue
		}
		target, port, err := parseResolverEntry(entry)
		if err != nil {
			return nil, false, E.Cause(err, "invalid resolver: ", entry)
		}
		if !target.isPrefix {
			add(target.addr, port)
			continue
		}
		first, last, err := prefixHostRange(target.prefix)
		if err != nil {
			return nil, false, E.Cause(err, "invalid resolver: ", entry)
		}
		for addr := first; ; addr = addr.Next() {
			add(addr, port)
			if addr == last {
				break
			}
		}
	}
	keys := make(map[netip.Addr]string, len(resolvers))
	for _, resolver := range resolvers {
		keys[resolver.Addr()] = resolver.Addr().String()
	}
	slices.SortFunc(resolvers, func(a, b netip.AddrPort) int {
		return strings.Compare(keys[a.Addr()], keys[b.Addr()])
	})
	return resolvers, system, nil
}

type resolverTarget struct {
	addr     netip.Addr
	prefix   netip.Prefix
	isPrefix bool
}

func parseResolverEntry(entry string) (resolverTarget, uint16, error) {
	target, err := parseResolverTarget(entry)
	if err == nil {
		return target, defaultResolverPort, nil
	}
	host, portText, err := splitResolverHostPort(entry)
	if err != nil {
		return resolverTarget{}, 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return resolverTarget{}, 0, E.New("invalid port: ", portText)
	}
	target, err = parseResolverTarget(host)
	if err != nil {
		return resolverTarget{}, 0, err
	}
	return target, uint16(port), nil
}

func parseResolverTarget(text string) (resolverTarget, error) {
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return resolverTarget{}, err
		}
		// The reference walks IPv4-mapped prefixes as IPv6 and resolves only their first address.
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		return resolverTarget{prefix: prefix.Masked(), isPrefix: true}, nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return resolverTarget{}, err
	}
	return resolverTarget{addr: addr.Unmap()}, nil
}

func splitResolverHostPort(text string) (string, string, error) {
	if strings.HasPrefix(text, "[") {
		end := strings.IndexByte(text, ']')
		if end == -1 {
			return "", "", E.New("missing ]")
		}
		host := strings.TrimSpace(text[1:end])
		remainder := strings.TrimSpace(text[end+1:])
		if !strings.HasPrefix(remainder, ":") {
			return "", "", E.New("missing port")
		}
		port := strings.TrimSpace(remainder[1:])
		if host == "" || port == "" {
			return "", "", E.New("missing host or port")
		}
		return host, port, nil
	}
	colon := strings.LastIndexByte(text, ':')
	if colon <= 0 || colon == len(text)-1 {
		return "", "", E.New("missing port")
	}
	host := strings.TrimSpace(text[:colon])
	port := strings.TrimSpace(text[colon+1:])
	if host == "" || port == "" {
		return "", "", E.New("missing host or port")
	}
	return host, port, nil
}

// prefixHostRange returns the usable hosts of a prefix: IPv4 skips the network and broadcast addresses below /31, IPv6 skips the network address below /127.
func prefixHostRange(prefix netip.Prefix) (first netip.Addr, last netip.Addr, err error) {
	network := prefix.Addr()
	hostBits := network.BitLen() - prefix.Bits()
	// The reference counts an IPv4 /1 as two hosts and then walks two billion addresses.
	if network.Is4() && (hostBits >= 31 || 1<<hostBits-2 > maxResolverHosts) || network.Is6() && hostBits > 16 {
		return netip.Addr{}, netip.Addr{}, E.New("subnet larger than ", maxResolverHosts, " hosts")
	}
	broadcast := network.AsSlice()
	for index, remaining := len(broadcast)-1, hostBits; remaining > 0; index, remaining = index-1, remaining-8 {
		broadcast[index] |= byte(1<<min(remaining, 8) - 1)
	}
	first = network
	last, _ = netip.AddrFromSlice(broadcast)
	if hostBits > 1 {
		first = network.Next()
		if network.Is4() {
			last = last.Prev()
		}
	}
	return first, last, nil
}
