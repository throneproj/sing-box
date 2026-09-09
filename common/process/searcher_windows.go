package process

import (
	"context"
	"net/netip"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/winiphlpapi"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"golang.org/x/sys/windows"
)

var _ Searcher = (*windowsSearcher)(nil)

type windowsSearcher struct {
	processPath *freelru.Cache[uint32, string]
}

// A path is fixed for the lifetime of a PID, so the only staleness is PID reuse; a
// few seconds keeps a burst of connections from one process down to a single lookup
// while staying far inside the window Windows takes to recycle a PID.
const processPathLifetime = 4 * time.Second

func NewSearcher(config Config) (Searcher, error) {
	err := initWin32API()
	if err != nil {
		return nil, E.Cause(err, "init win32 api")
	}
	processPath, err := freelru.New[uint32, string](512, maphash.NewHasher[uint32]().Hash32, true)
	if err != nil {
		return nil, err
	}
	processPath.SetLifetime(processPathLifetime)
	if config.Logger != nil {
		if available, nsiErr := nsiStatus(); available {
			config.Logger.Debug("using NSI keyed process lookup")
		} else {
			// Correct but far slower, and it means an assumption about an undocumented
			// interface broke: say so loudly enough to reach a bug report.
			config.Logger.Warn(E.Cause(nsiErr, "NSI keyed process lookup unavailable, falling back to full TCP table scans per connection (high CPU with many connections)"))
		}
	}
	return &windowsSearcher{processPath: processPath}, nil
}

func initWin32API() error {
	return winiphlpapi.LoadExtendedTable()
}

func (s *windowsSearcher) ResetCache() {
	s.processPath.Purge()
}

func (s *windowsSearcher) Close() error {
	return nil
}

func (s *windowsSearcher) FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	pid, err := findPid(network, source, destination)
	if err != nil {
		return nil, err
	}
	path, err := s.processPathOf(pid)
	if err != nil {
		return &adapter.ConnectionOwner{ProcessID: pid, UserId: -1}, err
	}
	return &adapter.ConnectionOwner{ProcessID: pid, ProcessPath: path, UserId: -1}, nil
}

// findPid prefers the keyed NSI read, which needs the peer to form its key, and falls
// back to the table scan whenever that is unavailable or the row is not found.
func findPid(network string, source netip.AddrPort, destination netip.AddrPort) (uint32, error) {
	if N.NetworkName(network) == N.NetworkTCP && destination.IsValid() {
		pid, err := nsiFindPidTCP(source, destination)
		if err == nil {
			return pid, nil
		}
	}
	return winiphlpapi.FindPid(network, source)
}

func (s *windowsSearcher) processPathOf(pid uint32) (string, error) {
	if path, loaded := s.processPath.Get(pid); loaded {
		return path, nil
	}
	path, err := getProcessPath(pid)
	if err != nil {
		return "", err
	}
	s.processPath.Add(pid, path)
	return path, nil
}

func getProcessPath(pid uint32) (string, error) {
	switch pid {
	case 0:
		return ":System Idle Process", nil
	case 4:
		return ":System", nil
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	size := uint32(syscall.MAX_LONG_PATH)
	buf := make([]uint16, syscall.MAX_LONG_PATH)
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}
