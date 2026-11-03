package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/crypto/chacha20"
)

type Method uint8

const (
	MethodNone Method = iota
	MethodXOR
	MethodChaCha20
	MethodAES128GCM
	MethodAES192GCM
	MethodAES256GCM
)

const (
	chachaNonceSize = 16
	chachaBlockSize = 64
	aesNonceSize    = 12
	aesTagSize      = 16
)

var ErrInvalidCiphertext = E.New("invalid ciphertext")

func ParseMethod(name string) (Method, error) {
	switch name {
	case "none":
		return MethodNone, nil
	case "xor":
		return MethodXOR, nil
	case "chacha20":
		return MethodChaCha20, nil
	case "aes-128-gcm":
		return MethodAES128GCM, nil
	case "aes-192-gcm":
		return MethodAES192GCM, nil
	case "aes-256-gcm":
		return MethodAES256GCM, nil
	default:
		return MethodNone, E.New("unknown encryption method: ", name)
	}
}

func (m Method) String() string {
	switch m {
	case MethodNone:
		return "none"
	case MethodXOR:
		return "xor"
	case MethodChaCha20:
		return "chacha20"
	case MethodAES128GCM:
		return "aes-128-gcm"
	case MethodAES192GCM:
		return "aes-192-gcm"
	case MethodAES256GCM:
		return "aes-256-gcm"
	default:
		return "unknown"
	}
}

// Overhead is the ciphertext expansion of one non-empty message.
func (m Method) Overhead() int {
	switch m {
	case MethodChaCha20:
		return chachaNonceSize
	case MethodAES128GCM, MethodAES192GCM, MethodAES256GCM:
		return aesNonceSize + aesTagSize
	default:
		return 0
	}
}

type Codec struct {
	method Method
	key    []byte
	aead   cipher.AEAD
	random io.Reader
}

func New(method Method, key string) (*Codec, error) {
	codec := &Codec{
		method: method,
		key:    deriveKey(method, key),
		random: rand.Reader,
	}
	switch method {
	case MethodNone, MethodXOR, MethodChaCha20:
	case MethodAES128GCM, MethodAES192GCM, MethodAES256GCM:
		block, err := aes.NewCipher(codec.key)
		if err != nil {
			return nil, err
		}
		codec.aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	default:
		return nil, E.New("unknown encryption method: ", uint8(method))
	}
	return codec, nil
}

func (c *Codec) Method() Method {
	return c.method
}

// Encrypt appends the encryption of plaintext to dst; empty input stays empty, as in the reference.
func (c *Codec) Encrypt(dst []byte, plaintext []byte) ([]byte, error) {
	switch c.method {
	case MethodNone:
		return append(dst, plaintext...), nil
	case MethodXOR:
		return c.xor(dst, plaintext), nil
	}
	if len(plaintext) == 0 {
		return dst, nil
	}
	start := len(dst)
	if c.method == MethodChaCha20 {
		dst = slices.Grow(dst, chachaNonceSize+len(plaintext))[:start+chachaNonceSize+len(plaintext)]
		nonce := dst[start : start+chachaNonceSize]
		for {
			_, err := io.ReadFull(c.random, nonce)
			if err != nil {
				return nil, E.Cause(err, "generate chacha20 nonce")
			}
			if chachaCounterFits(nonce, len(plaintext)) {
				break
			}
		}
		stream, err := chacha20.NewUnauthenticatedCipher(c.key, nonce[4:])
		if err != nil {
			return nil, err
		}
		stream.SetCounter(binary.LittleEndian.Uint32(nonce))
		stream.XORKeyStream(dst[start+chachaNonceSize:], plaintext)
		return dst, nil
	}
	dst = slices.Grow(dst, aesNonceSize+len(plaintext)+aesTagSize)[:start+aesNonceSize]
	nonce := dst[start:]
	_, err := io.ReadFull(c.random, nonce)
	if err != nil {
		return nil, E.Cause(err, "generate aes-gcm nonce")
	}
	return c.aead.Seal(dst, nonce, plaintext, nil), nil
}

// Decrypt appends the decryption of ciphertext to dst.
func (c *Codec) Decrypt(dst []byte, ciphertext []byte) ([]byte, error) {
	switch c.method {
	case MethodNone:
		return append(dst, ciphertext...), nil
	case MethodXOR:
		return c.xor(dst, ciphertext), nil
	}
	if len(ciphertext) == 0 {
		return dst, nil
	}
	if c.method == MethodChaCha20 {
		if len(ciphertext) <= chachaNonceSize {
			return nil, ErrInvalidCiphertext
		}
		nonce, data := ciphertext[:chachaNonceSize], ciphertext[chachaNonceSize:]
		// The reference panics here instead.
		if !chachaCounterFits(nonce, len(data)) {
			return nil, ErrInvalidCiphertext
		}
		stream, err := chacha20.NewUnauthenticatedCipher(c.key, nonce[4:])
		if err != nil {
			return nil, err
		}
		stream.SetCounter(binary.LittleEndian.Uint32(nonce))
		start := len(dst)
		dst = slices.Grow(dst, len(data))[:start+len(data)]
		stream.XORKeyStream(dst[start:], data)
		return dst, nil
	}
	if len(ciphertext) <= aesNonceSize {
		return nil, ErrInvalidCiphertext
	}
	plaintext, err := c.aead.Open(dst, ciphertext[:aesNonceSize], ciphertext[aesNonceSize:], nil)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}

func (c *Codec) xor(dst []byte, data []byte) []byte {
	start := len(dst)
	dst = slices.Grow(dst, len(data))[:start+len(data)]
	for i, value := range data {
		dst[start+i] = value ^ c.key[i%len(c.key)]
	}
	return dst
}

// chachaCounterFits reports whether the 32-bit block counter in the nonce prefix covers the message without wrapping.
func chachaCounterFits(nonce []byte, length int) bool {
	blocks := (uint64(length) + chachaBlockSize - 1) / chachaBlockSize
	return uint64(binary.LittleEndian.Uint32(nonce))+blocks <= 1<<32
}

func deriveKey(method Method, key string) []byte {
	switch method {
	case MethodChaCha20, MethodAES256GCM:
		sum := sha256.Sum256([]byte(key))
		return sum[:]
	case MethodAES128GCM:
		sum := md5.Sum([]byte(key))
		return sum[:]
	case MethodAES192GCM:
		derived := make([]byte, 24)
		copy(derived, key)
		return derived
	default:
		derived := make([]byte, 32)
		copy(derived, key)
		return derived
	}
}
