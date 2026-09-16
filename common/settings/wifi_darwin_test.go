//go:build darwin && !ios

package settings

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestParseDarwinWIFIInterface(t *testing.T) {
	ports := "\nHardware Port: Ethernet Adapter (en3)\nDevice: en3\nEthernet Address: 00:00:5e:00:53:01\n\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: 00:00:5e:00:53:02\n\nHardware Port: Thunderbolt Bridge\nDevice: bridge0\nEthernet Address: 00:00:5e:00:53:03\n"
	if got := parseDarwinWIFIInterface(ports); got != "en0" {
		t.Fatalf("interface = %q, want en0", got)
	}
	if got := parseDarwinWIFIInterface("\nHardware Port: Ethernet\nDevice: en5\n"); got != "" {
		t.Fatalf("interface = %q, want none without a Wi-Fi port", got)
	}
}

func TestParseDarwinWIFIState(t *testing.T) {
	summary := "<dictionary> {\n  BSSID : 0:0:5e:0:53:ab\n  ConnectionID : 12\n  IPv4 : <array> {\n    0 : <dictionary> {\n      SSID : nested-should-not-match\n    }\n  }\n  InterfaceType : WiFi\n  SSID : Home Café 5G\n  Security : WPA2 Personal\n}\n"
	want := adapter.WIFIState{SSID: "Home Café 5G", BSSID: "0:0:5e:0:53:ab"}
	if got := parseDarwinWIFIState(summary); got != want {
		t.Fatalf("state = %+v, want %+v", got, want)
	}
	ethernet := "<dictionary> {\n  ConnectionID : 3\n  InterfaceType : Ethernet\n}\n"
	if got := parseDarwinWIFIState(ethernet); got != (adapter.WIFIState{}) {
		t.Fatalf("state = %+v, want empty without SSID", got)
	}
	if got := parseDarwinWIFIState(""); got != (adapter.WIFIState{}) {
		t.Fatalf("state = %+v, want empty for empty output", got)
	}
}
