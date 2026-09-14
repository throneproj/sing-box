package tls

import (
	"io"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
)

// RandCapableConfig is implemented by client configs that can run a connection's
// handshake on a caller-provided entropy source, the ClientHello random included.
type RandCapableConfig interface {
	ClientWithRand(conn net.Conn, randReader io.Reader) (Conn, error)
}

// ClientWithRand copies the config instead of calling Clone, which would pick a
// new mixed-case SNI for every connection.
func (c *STDClientConfig) ClientWithRand(conn net.Conn, randReader io.Reader) (Conn, error) {
	clientConfig := *c
	clientConfig.config = c.config.Clone()
	clientConfig.config.Rand = randReader
	return clientConfig.Client(conn)
}

func (w *KTLSClientConfig) ClientWithRand(conn net.Conn, randReader io.Reader) (Conn, error) {
	randCapable, isRandCapable := w.Config.(RandCapableConfig)
	if !isRandCapable {
		return nil, E.New("custom entropy is not supported by the wrapped TLS config")
	}
	return randCapable.ClientWithRand(conn, randReader)
}
