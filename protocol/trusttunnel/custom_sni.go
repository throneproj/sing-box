package trusttunnel

import (
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// setCustomSNI sends custom_sni in the ClientHello while the certificate is
// still verified against the TLS server_name, like the official client does
// with custom_sni and hostname.
func setCustomSNI(config tls.Config, customSNI string, tlsOptions option.OutboundTLSOptions) error {
	if tlsOptions.ECH != nil && tlsOptions.ECH.Enabled {
		// ECH already carries its own outer and inner server names.
		return E.New("custom_sni is not compatible with ECH")
	}
	customSNIConfig, isCustomSNIConfig := config.(tls.CustomSNIConfig)
	if !isCustomSNIConfig {
		return E.New("custom_sni is not compatible with REALITY or the system TLS engines")
	}
	return customSNIConfig.SetCustomSNI(customSNI)
}
