//go:build with_psiphon && unix

package psiphon

import (
	"os"

	"golang.org/x/sys/unix"
)

func socketNetwork(fd int) (string, error) {
	socketType, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return "", os.NewSyscallError("getsockopt", err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return "", os.NewSyscallError("getsockname", err)
	}
	_, isIPv6 := address.(*unix.SockaddrInet6)
	return networkName(socketType == unix.SOCK_DGRAM, isIPv6), nil
}
