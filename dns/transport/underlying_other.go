//go:build !darwin

package transport

import (
	"os/exec"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func detectUnderlyingServer(interfaceName string) (M.Socksaddr, error) {
	output, err := exec.Command("resolvectl", "-i", interfaceName, "dns").Output()
	if err != nil {
		return M.Socksaddr{}, E.Cause(err, "execute resolvectl")
	}
	// Link 2 (eth0): 192.168.1.1
	fields := strings.Fields(string(output))
	if len(fields) < 4 {
		return M.Socksaddr{}, E.New("unexpected resolvectl output: ", string(output))
	}
	server := M.ParseSocksaddrHostPortStr(fields[3], "53")
	if !server.IsValid() {
		return M.Socksaddr{}, E.New("unexpected resolvectl output: ", string(output))
	}
	return server, nil
}
