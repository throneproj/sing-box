package tls

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// CustomSNIConfig is implemented by client configs that can send one server
// name on the wire while verifying the certificate against another.
type CustomSNIConfig interface {
	SetCustomSNI(serverName string) error
}

func (c *STDClientConfig) SetCustomSNI(serverName string) error {
	if c.disableSNI {
		return E.New("custom SNI conflicts with disable_sni")
	}
	c.customSNI = serverName
	if !c.config.InsecureSkipVerify {
		c.config.InsecureSkipVerify = true
		c.verifyServerName = true
	}
	c.SetServerName(c.serverName)
	return nil
}

func (w *KTLSClientConfig) SetCustomSNI(serverName string) error {
	customSNIConfig, isCustomSNIConfig := w.Config.(CustomSNIConfig)
	if !isCustomSNIConfig {
		return E.New("custom SNI is not supported by the wrapped TLS config")
	}
	return customSNIConfig.SetCustomSNI(serverName)
}
