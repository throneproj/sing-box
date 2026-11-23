//go:build with_psiphon && windows

package psiphon

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SO_PROTOCOL_INFOW from winsock2.h, not defined by x/sys/windows.
const soProtocolInfoW = 0x2005

func socketNetwork(fd int) (string, error) {
	var info windows.WSAProtocolInfo
	size := int32(unsafe.Sizeof(info))
	err := windows.Getsockopt(windows.Handle(fd), windows.SOL_SOCKET, soProtocolInfoW, (*byte)(unsafe.Pointer(&info)), &size)
	if err != nil {
		return "", os.NewSyscallError("getsockopt", err)
	}
	return networkName(info.SocketType == windows.SOCK_DGRAM, info.AddressFamily == windows.AF_INET6), nil
}
