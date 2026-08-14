//go:build with_utls

package tls

import (
	E "github.com/sagernet/sing/common/exceptions"
)

func (c *UTLSClientConfig) SetCustomSNI(serverName string) error {
	if c.disableSNI {
		return E.New("custom SNI conflicts with disable_sni")
	}
	c.customSNI = serverName
	c.verifyServerName = !c.config.InsecureSkipVerify
	c.SetServerName(c.serverName)
	return nil
}
