//go:build with_utls

package tls

import (
	"io"
	"net"
)

func (c *UTLSClientConfig) ClientWithRand(conn net.Conn, randReader io.Reader) (Conn, error) {
	clientConfig := *c
	clientConfig.config = c.config.Clone()
	clientConfig.config.Rand = randReader
	return clientConfig.Client(conn)
}
