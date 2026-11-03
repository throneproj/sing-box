package dnstt

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/flynn/noise"
)

const (
	noiseKeyLength      = 32
	noiseMaxPayloadSize = 4096
	noisePrologue       = "dnstt 2020-04-13"
)

var noiseCipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

func readNoiseMessage(reader io.Reader) ([]byte, error) {
	var length [2]byte
	_, err := io.ReadFull(reader, length[:])
	if err != nil {
		return nil, err
	}
	message := make([]byte, binary.BigEndian.Uint16(length[:]))
	_, err = io.ReadFull(reader, message)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return message, err
}

// Length and message are separate writes, so over KCP they leave as separate segments as in the reference.
func writeNoiseMessage(writer io.Writer, message []byte) error {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(message)))
	_, err := writer.Write(length[:])
	if err != nil {
		return err
	}
	_, err = writer.Write(message)
	return err
}

func noiseClientHandshake(conn io.ReadWriter, serverPublicKey []byte) (sendCipher *noise.CipherState, receiveCipher *noise.CipherState, err error) {
	handshakeState, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noiseCipherSuite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		Prologue:    []byte(noisePrologue),
		PeerStatic:  serverPublicKey,
	})
	if err != nil {
		return nil, nil, err
	}
	message, _, _, err := handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	err = writeNoiseMessage(conn, message)
	if err != nil {
		return nil, nil, err
	}
	message, err = readNoiseMessage(conn)
	if err != nil {
		return nil, nil, err
	}
	payload, sendCipher, receiveCipher, err := handshakeState.ReadMessage(nil, message)
	if err != nil {
		return nil, nil, err
	}
	if len(payload) != 0 {
		return nil, nil, E.New("unexpected server payload")
	}
	return sendCipher, receiveCipher, nil
}

type noiseConn struct {
	net.Conn
	sendCipher    *noise.CipherState
	receiveCipher *noise.CipherState
	readBuffer    []byte
}

func newNoiseConn(conn net.Conn, sendCipher *noise.CipherState, receiveCipher *noise.CipherState) *noiseConn {
	return &noiseConn{
		Conn:          conn,
		sendCipher:    sendCipher,
		receiveCipher: receiveCipher,
	}
}

func (c *noiseConn) Read(p []byte) (n int, err error) {
	for len(c.readBuffer) == 0 {
		var message []byte
		message, err = readNoiseMessage(c.Conn)
		if err != nil {
			return
		}
		c.readBuffer, err = c.receiveCipher.Decrypt(message[:0], nil, message)
		if err != nil {
			return
		}
	}
	n = copy(p, c.readBuffer)
	c.readBuffer = c.readBuffer[n:]
	return
}

func (c *noiseConn) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		chunk := p[:min(len(p), noiseMaxPayloadSize)]
		var message []byte
		message, err = c.sendCipher.Encrypt(nil, nil, chunk)
		if err != nil {
			return
		}
		err = writeNoiseMessage(c.Conn, message)
		if err != nil {
			return
		}
		n += len(chunk)
		p = p[len(chunk):]
	}
	return
}
