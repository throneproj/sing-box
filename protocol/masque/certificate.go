package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

func parsePrivateKey(content string) (*ecdsa.PrivateKey, error) {
	keyDER, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return nil, E.Cause(err, "decode private_key")
	}
	privateKey, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		parsedKey, pkcs8Err := x509.ParsePKCS8PrivateKey(keyDER)
		if pkcs8Err != nil {
			return nil, E.Cause(err, "parse private_key")
		}
		var isECDSA bool
		privateKey, isECDSA = parsedKey.(*ecdsa.PrivateKey)
		if !isECDSA {
			return nil, E.New("private_key is not an ECDSA key")
		}
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, E.New("private_key is not a P-256 key")
	}
	return privateKey, nil
}

func encodePrivateKey(privateKey *ecdsa.PrivateKey) (string, error) {
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), nil
}

func peerPublicKeySHA256(content string) ([]byte, error) {
	publicKeyDER, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return nil, E.Cause(err, "decode peer_public_key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return nil, E.Cause(err, "parse peer_public_key")
	}
	// Re-marshal so the hash matches what the TLS pin computes from the server certificate.
	publicKeyDER, err = x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, E.Cause(err, "marshal peer_public_key")
	}
	publicKeyHash := sha256.Sum256(publicKeyDER)
	return publicKeyHash[:], nil
}

func newClientCertificate(privateKey *ecdsa.PrivateKey, now time.Time) (string, error) {
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		NotBefore:          now.Add(-time.Minute),
		NotAfter:           now.Add(24 * time.Hour),
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})), nil
}
