package trusttunnel

import (
	"crypto/aes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"sync/atomic"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const clientRandomAuthKeyInfo = "tls13 encryption context"

// newClientRandomAuthKeyConfig derives the ClientHello random from
// client_random_auth_key and the SNI sent on the wire, like the official
// client does for the endpoint's client_random_auth_key rule.
func newClientRandomAuthKeyConfig(config tls.Config, authKey string, serverName string, tlsOptions option.OutboundTLSOptions) (tls.Config, error) {
	err := checkClientRandomConfig(config, tlsOptions, "client_random_auth_key")
	if err != nil {
		return nil, err
	}
	if tlsOptions.DisableSNI {
		return nil, E.New("client_random_auth_key is not compatible with disable_sni")
	}
	if tlsOptions.TLSTricks != nil && tlsOptions.TLSTricks.MixedCaseSNI {
		// The random has to match the server name the endpoint receives byte for byte.
		return nil, E.New("client_random_auth_key is not compatible with mixedcase_sni")
	}
	serverName = strings.TrimRight(serverName, ".")
	if serverName == "" || M.ParseAddr(serverName).IsValid() {
		// crypto/tls and uTLS send no SNI for an empty or IP server name.
		return nil, E.New("client_random_auth_key requires a domain server name")
	}
	key, err := hex.DecodeString(authKey)
	if err != nil {
		return nil, E.Cause(err, "decode client_random_auth_key")
	}
	serverNameHash := sha256.Sum256([]byte(serverName))
	return &clientRandomConfig{
		Config: config,
		newReader: func() io.Reader {
			return &clientRandomAuthKeyReader{authKey: key, serverNameHash: serverNameHash[:aes.BlockSize]}
		},
	}, nil
}

// clientRandomAuthKeyReader is the entropy source of a single TLS connection.
// Its first 32 byte read becomes salt || AES-128(HKDF-SHA256(key, salt), SHA256(SNI)[:16]).
type clientRandomAuthKeyReader struct {
	authKey        []byte
	serverNameHash []byte
	applied        atomic.Bool
}

func (r *clientRandomAuthKeyReader) Read(p []byte) (int, error) {
	n, err := rand.Read(p)
	if err != nil || n != clientRandomLength || !r.applied.CompareAndSwap(false, true) {
		return n, err
	}
	err = deriveClientRandom(p, r.authKey, r.serverNameHash)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func deriveClientRandom(random []byte, authKey []byte, serverNameHash []byte) error {
	key, err := hkdf.Key(sha256.New, authKey, random[:clientRandomLength/2], clientRandomAuthKeyInfo, aes.BlockSize)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	block.Encrypt(random[clientRandomLength/2:], serverNameHash)
	return nil
}
