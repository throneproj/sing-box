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
// crypto/tls and uTLS take the ClientHello random from the config's entropy
// source, so every connection gets its own clientRandomReader.
type clientRandomConfig struct {
	tls.Config
	prefix []byte
	mask   []byte
}

func newClientRandomConfig(config tls.Config, clientRandom string, tlsOptions option.OutboundTLSOptions) (tls.Config, error) {
	if tlsOptions.ECH != nil && tlsOptions.ECH.Enabled {
		// The random of the inner ClientHello is not the one sent on the wire.
		return nil, E.New("client_random is not compatible with ECH")
	}
	if tlsOptions.UTLS != nil && tlsOptions.UTLS.Enabled && tlsOptions.UTLS.Fingerprint == "custom" {
		// The padded ClientHello is rebuilt with a fresh random during the handshake.
		return nil, E.New("client_random is not compatible with the custom uTLS fingerprint")
	}
	if _, isRandCapable := config.(tls.RandCapableConfig); !isRandCapable {
		return nil, E.New("client_random is not compatible with REALITY or the system TLS engines")
	}
	prefix, mask, err := parseClientRandom(clientRandom)
	if err != nil {
		return nil, err
	}
	return &clientRandomConfig{
		Config: config,
		prefix: prefix,
		mask:   mask,
	}, nil
}

func (c *clientRandomConfig) Client(conn net.Conn) (tls.Conn, error) {
	return c.Config.(tls.RandCapableConfig).ClientWithRand(conn, c.newReader())
}

// STDConfig returns a fresh standard config for every caller. sing-quic calls
// this method once per dial, so each QUIC connection gets its own reader.
func (c *clientRandomConfig) STDConfig() (*tls.STDConfig, error) {
	stdConfig, err := c.Config.STDConfig()
	if err != nil {
		return nil, err
	}
	stdConfig = stdConfig.Clone()
	stdConfig.Rand = c.newReader()
	return stdConfig, nil
}

func (c *clientRandomConfig) Clone() tls.Config {
	return &clientRandomConfig{
		Config: c.Config.Clone(),
		prefix: c.prefix,
		mask:   c.mask,
	}
}

func (c *clientRandomConfig) newReader() *clientRandomReader {
	return &clientRandomReader{prefix: c.prefix, mask: c.mask}
}

// parseClientRandom parses the TrustTunnel prefix[/mask] hex syntax, an omitted
// mask sets every bit of the prefix.
func parseClientRandom(clientRandom string) (prefix []byte, mask []byte, err error) {
	prefixString, maskString, hasMask := strings.Cut(clientRandom, "/")
	prefix, err = hex.DecodeString(prefixString)
	if err != nil {
		return nil, nil, E.Cause(err, "decode client_random prefix")
	}
	if len(prefix) == 0 || len(prefix) > clientRandomLength {
		return nil, nil, E.New("client_random prefix must be 1 to ", clientRandomLength, " bytes")
	}
	if !hasMask {
		return prefix, bytes.Repeat([]byte{0xFF}, len(prefix)), nil
	}
	mask, err = hex.DecodeString(maskString)
	if err != nil {
		return nil, nil, E.Cause(err, "decode client_random mask")
	}
	if len(mask) != len(prefix) {
		return nil, nil, E.New("client_random mask must be as long as the prefix")
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
