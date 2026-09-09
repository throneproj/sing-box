package process

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

// nsi.dll holds the per-connection query that iphlpapi's GetExtendedTcpTable is built
// on top of, so a keyed read replaces a snapshot of the whole machine TCP table. It is
// undocumented, but the layout below is unchanged from Windows 7 to Windows 11 and is
// checked against our own socket at startup; findPid falls back to the table scan.
const (
	nsiActive        = 1
	nsiTCPEstabTable = 4 // connections only, both address families; 3 is all, 5 is listeners
	nsiParamStatic   = 2
	nsiTCPKeySize    = 56 // SOCKADDR_INET local + SOCKADDR_INET remote
	nsiSockaddrSize  = 28
	// Offset of pid in { UINT unk[3]; UINT pid; ULONGLONG create_time; ULONGLONG mod_info }.
	nsiPIDOffset = 12
)

// NPI_MODULEID { USHORT Length; NPI_MODULEID_TYPE Type; GUID Guid; }
type npiModuleID struct {
	Length uint16
	_      uint16
	Type   uint32
	Guid   windows.GUID
}

var nsiTCPModuleID = npiModuleID{
	Length: 24,
	Type:   1, // MIT_GUID
	Guid: windows.GUID{
		Data1: 0xeb004a03, Data2: 0x9b1a, Data3: 0x11d4,
		Data4: [8]byte{0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc},
	},
}

var (
	modnsi              = windows.NewLazySystemDLL("nsi.dll")
	procNsiGetParameter = modnsi.NewProc("NsiGetParameter")
)

var (
	nsiOnce      sync.Once
	nsiAvailable bool
	nsiInitError error
)

// nsiStatus reports whether keyed lookups are usable, and why not when they are not.
func nsiStatus() (bool, error) {
	nsiOnce.Do(nsiInit)
	return nsiAvailable, nsiInitError
}

func nsiInit() {
	defer func() {
		// Undocumented API: a layout change must degrade to the table scan, not crash.
		if cause := recover(); cause != nil {
			nsiAvailable = false
			nsiInitError = E.New("panic during probe: ", cause)
		}
	}()
	if err := procNsiGetParameter.Find(); err != nil {
		nsiInitError = err
		return
	}
	if err := nsiVerify(); err != nil {
		nsiInitError = err
		return
	}
	nsiAvailable = true
}

// nsiVerify confirms a keyed read resolves this process's own connection, and that a
// key with no row is reported as a miss instead of as some other process. A field that
// moved would return a create timestamp or a counter, which will not be our own pid.
func nsiVerify() error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		<-done
	}()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		return err
	}
	defer conn.Close()

	local, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return err
	}
	remote, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}
	pid, err := nsiGetPID(local, remote)
	if err != nil {
		return E.Cause(err, "keyed lookup of own connection")
	}
	if pid != windows.GetCurrentProcessId() {
		return E.New("keyed lookup returned pid ", pid, ", expected ", windows.GetCurrentProcessId())
	}
	if _, err = nsiGetPID(netip.AddrPortFrom(local.Addr(), 1), netip.AddrPortFrom(remote.Addr(), 2)); err == nil {
		return E.New("keyed lookup of an absent connection succeeded")
	}
	return nil
}

func nsiGetPID(source, destination netip.AddrPort) (uint32, error) {
	key, ok := nsiTCPKey(source, destination)
	if !ok {
		return 0, E.New("unsupported address")
	}
	var pid uint32
	r, _, _ := syscall.SyscallN(procNsiGetParameter.Addr(),
		nsiActive,
		uintptr(unsafe.Pointer(&nsiTCPModuleID)),
		nsiTCPEstabTable,
		uintptr(unsafe.Pointer(&key[0])), nsiTCPKeySize,
		nsiParamStatic,
		uintptr(unsafe.Pointer(&pid)), 4, nsiPIDOffset,
	)
	if r != 0 {
		return 0, windows.Errno(r)
	}
	return pid, nil
}

// nsiFindPidTCP resolves the owner of one TCP connection without reading the table.
func nsiFindPidTCP(source, destination netip.AddrPort) (uint32, error) {
	available, err := nsiStatus()
	if !available {
		return 0, err
	}
	return nsiGetPID(source, destination)
}

func nsiTCPKey(source, destination netip.AddrPort) ([nsiTCPKeySize]byte, bool) {
	var key [nsiTCPKeySize]byte
	if !nsiWriteSockaddr(key[:nsiSockaddrSize], source) {
		return key, false
	}
	if !nsiWriteSockaddr(key[nsiSockaddrSize:], destination) {
		return key, false
	}
	// A mixed-family key matches nothing; both halves belong to one socket anyway.
	if key[0] != key[nsiSockaddrSize] {
		return key, false
	}
	return key, true
}

func nsiWriteSockaddr(b []byte, ap netip.AddrPort) bool {
	addr := ap.Addr().Unmap()
	if !addr.IsValid() || ap.Port() == 0 {
		return false
	}
	binary.BigEndian.PutUint16(b[2:4], ap.Port())
	if addr.Is4() {
		binary.LittleEndian.PutUint16(b[0:2], windows.AF_INET)
		v4 := addr.As4()
		copy(b[4:8], v4[:])
		return true
	}
	binary.LittleEndian.PutUint16(b[0:2], windows.AF_INET6)
	v6 := addr.As16()
	copy(b[8:24], v6[:])
	if zone := addr.Zone(); zone != "" {
		scope, err := strconv.ParseUint(zone, 10, 32)
		if err != nil {
			return false
		}
		binary.LittleEndian.PutUint32(b[24:28], uint32(scope))
	}
	return true
}
