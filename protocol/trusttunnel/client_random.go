package trusttunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"sync/atomic"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const clientRandomLength = 32

// clientRandomConfig makes every new TLS or QUIC connection send a ClientHello
// random matching the client_random prefix and mask required by the server.
//
// crypto/tls takes the ClientHello random from Config.Rand, so the prefix is
// applied by cloning the TLS config per connection and replacing its entropy
// source. Bits outside the mask, and every later read, stay untouched.
type clientRandomConfig struct {
	tls.Config
	prefix []byte
	mask   []byte
}

func newClientRandomConfig(config tls.Config, options option.TrustTunnelOutboundOptions) (tls.Config, error) {
	if options.TLS.ECH != nil && options.TLS.ECH.Enabled {
		// The random of the inner ClientHello is not the one sent on the wire.
		return nil, E.New("client_random is not compatible with ECH")
	}
	prefix, mask, err := parseClientRandom(options.ClientRandom)
	if err != nil {
		return nil, err
	}
	// uTLS and REALITY build their own ClientHello and reject STDConfig, fail
	// here instead of on the first connection.
	_, err = config.STDConfig()
	if err != nil {
		return nil, E.Cause(err, "client_random")
	}
	return &clientRandomConfig{config, prefix, mask}, nil
}

func (c *clientRandomConfig) Client(conn net.Conn) (tls.Conn, error) {
	config, _, err := c.cloneWithRandom()
	if err != nil {
		return nil, err
	}
	return config.Client(conn)
}

// STDConfig returns a fresh standard config for every caller. sing-quic calls
// this method once per dial, so each QUIC connection gets its own reader and
// applies the prefix independently.
func (c *clientRandomConfig) STDConfig() (*tls.STDConfig, error) {
	_, stdConfig, err := c.cloneWithRandom()
	return stdConfig, err
}

func (c *clientRandomConfig) Clone() tls.Config {
	return &clientRandomConfig{c.Config.Clone(), c.prefix, c.mask}
}

func (c *clientRandomConfig) cloneWithRandom() (tls.Config, *tls.STDConfig, error) {
	config := c.Config.Clone()
	stdConfig, err := config.STDConfig()
	if err != nil {
		return nil, nil, err
	}
	stdConfig.Rand = &clientRandomReader{prefix: c.prefix, mask: c.mask}
	return config, stdConfig, nil
}

// parseClientRandom parses the TrustTunnel `prefix[/mask]` syntax. Both parts
// are hex encoded, the mask defaults to all bits set and covers the leading
// bytes of the prefix only.
func parseClientRandom(clientRandom string) (prefix []byte, mask []byte, err error) {
	prefixString, maskString, hasMask := strings.Cut(clientRandom, "/")
	prefix, err = hex.DecodeString(prefixString)
	if err != nil {
		return nil, nil, E.Cause(err, "decode client_random prefix")
	}
	if len(prefix) == 0 {
		return nil, nil, E.New("empty client_random prefix")
	}
	if len(prefix) > clientRandomLength {
		return nil, nil, E.New("client_random prefix too long: ", len(prefix), " bytes")
	}
	mask = bytes.Repeat([]byte{0xFF}, len(prefix))
	if hasMask {
		var maskBytes []byte
		maskBytes, err = hex.DecodeString(maskString)
		if err != nil {
			return nil, nil, E.Cause(err, "decode client_random mask")
		}
		if len(maskBytes) == 0 {
			return nil, nil, E.New("empty client_random mask")
		}
		copy(mask, maskBytes)
	}
	return prefix, mask, nil
}

// clientRandomReader is the entropy source of a single TLS connection. The
// ClientHello random is the first 32 byte read of a client handshake, so the
// prefix is applied there and nowhere else.
type clientRandomReader struct {
	prefix  []byte
	mask    []byte
	applied atomic.Bool
}

func (r *clientRandomReader) Read(p []byte) (int, error) {
	n, err := rand.Read(p)
	if err != nil || n != clientRandomLength {
		return n, err
	}
	if r.applied.CompareAndSwap(false, true) {
		for i, prefixByte := range r.prefix {
			p[i] = p[i]&^r.mask[i] | prefixByte&r.mask[i]
		}
	}
	return n, nil
}
