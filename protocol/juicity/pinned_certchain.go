package juicity

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"net"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type pinnedCertChainConfig struct {
	tls.Config
	pinnedHash []byte
}

func newPinnedCertChainConfig(config tls.Config, pinnedCertChain string, tlsOptions option.OutboundTLSOptions) (tls.Config, error) {
	if len(tlsOptions.CertificateSHA256) > 0 || len(tlsOptions.CertificatePublicKeySHA256) > 0 {
		return nil, E.New("pinned_certchain_sha256 is conflict with certificate_sha256 or certificate_public_key_sha256")
	}
	if len(tlsOptions.Certificate) > 0 || tlsOptions.CertificatePath != "" {
		return nil, E.New("pinned_certchain_sha256 is conflict with certificate or certificate_path")
	}
	if _, err := config.STDConfig(); err != nil {
		return nil, E.New("pinned_certchain_sha256 is not compatible with REALITY, uTLS or the system TLS engines")
	}
	pinnedHash, err := base64.URLEncoding.DecodeString(pinnedCertChain)
	if err != nil {
		pinnedHash, err = base64.StdEncoding.DecodeString(pinnedCertChain)
		if err != nil {
			pinnedHash, err = hex.DecodeString(pinnedCertChain)
			if err != nil {
				return nil, E.New("decode pinned_certchain_sha256: not base64 or hex")
			}
		}
	}
	if len(pinnedHash) != sha256.Size {
		return nil, E.New("invalid pinned_certchain_sha256: decoded to ", len(pinnedHash), " bytes instead of ", sha256.Size, " (a hex pin is read as base64, use the base64 form)")
	}
	return &pinnedCertChainConfig{
		Config:     config,
		pinnedHash: pinnedHash,
	}, nil
}

func (c *pinnedCertChainConfig) STDConfig() (*tls.STDConfig, error) {
	stdConfig, err := c.Config.STDConfig()
	if err != nil {
		return nil, err
	}
	stdConfig = stdConfig.Clone()
	stdConfig.InsecureSkipVerify = true
	// disable_sni moves the CA verification into VerifyConnection.
	stdConfig.VerifyConnection = nil
	stdConfig.VerifyPeerCertificate = c.verifyPeerCertificate
	return stdConfig, nil
}

func (c *pinnedCertChainConfig) Client(conn net.Conn) (tls.Conn, error) {
	return nil, E.New("pinned_certchain_sha256 is only supported over QUIC")
}

func (c *pinnedCertChainConfig) Clone() tls.Config {
	return &pinnedCertChainConfig{
		Config:     c.Config.Clone(),
		pinnedHash: c.pinnedHash,
	}
}

func (c *pinnedCertChainConfig) verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	var chainHash []byte
	for _, rawCert := range rawCerts {
		certHash := sha256.Sum256(rawCert)
		if chainHash == nil {
			chainHash = certHash[:]
		} else {
			nextHash := sha256.Sum256(append(chainHash, certHash[:]...))
			chainHash = nextHash[:]
		}
	}
	if !bytes.Equal(chainHash, c.pinnedHash) {
		return E.New("unrecognized peer certificate chain: sha256 ", base64.URLEncoding.EncodeToString(chainHash))
	}
	return nil
}
