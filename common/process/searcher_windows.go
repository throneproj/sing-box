package process

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/winiphlpapi"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var _ Searcher = (*windowsSearcher)(nil)

// A cached path goes stale only when its PID is reused or its service is reconfigured; the lifetime bounds both.
const pathCacheLifetime = 4 * time.Second

type windowsSearcher struct {
	processPathCache *freelru.Cache[uint32, string]
	servicePathCache *freelru.Cache[string, string]
}

func NewSearcher(_ Config) (Searcher, error) {
	err := initWin32API()
	if err != nil {
		return nil, E.Cause(err, "init win32 api")
	}
	processPathCache := common.Must1(freelru.New[uint32, string](512, maphash.NewHasher[uint32]().Hash32, true))
	processPathCache.SetLifetime(pathCacheLifetime)
	servicePathCache := common.Must1(freelru.New[string, string](64, maphash.NewHasher[string]().Hash32, true))
	servicePathCache.SetLifetime(pathCacheLifetime)
	return &windowsSearcher{
		processPathCache: processPathCache,
		servicePathCache: servicePathCache,
	}, nil
}

func initWin32API() error {
	return winiphlpapi.LoadExtendedTable()
}

func (s *windowsSearcher) ResetCache() {
	s.processPathCache.Purge()
	s.servicePathCache.Purge()
}

func (s *windowsSearcher) Close() error {
	return nil
}

func (s *windowsSearcher) FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	owner, err := winiphlpapi.FindSocketOwner(network, source, destination)
	if err != nil {
		return nil, err
	}
	path, err := s.findProcessPath(owner.Pid)
	if err != nil {
		return &adapter.ConnectionOwner{ProcessID: owner.Pid, UserId: -1}, err
	}
	processPaths := []string{path}
	if owner.ServiceName != "" {
		servicePath := s.findServiceDLLPath(owner.ServiceName)
		if servicePath != "" {
			processPaths = []string{servicePath, path}
		}
	}
	return &adapter.ConnectionOwner{ProcessID: owner.Pid, ProcessPaths: processPaths, UserId: -1}, nil
}

func (s *windowsSearcher) findProcessPath(pid uint32) (string, error) {
	path, loaded := s.processPathCache.Get(pid)
	if loaded {
		return path, nil
	}
	path, err := getProcessPath(pid)
	if err != nil {
		return "", err
	}
	s.processPathCache.Add(pid, path)
	return path, nil
}

func (s *windowsSearcher) findServiceDLLPath(serviceName string) string {
	servicePath, loaded := s.servicePathCache.Get(serviceName)
	if loaded {
		return servicePath
	}
	// A service running in its own process has no ServiceDll, so the miss is cached too.
	servicePath, err := getServiceDLLPath(serviceName)
	if err != nil {
		servicePath = ""
	}
	s.servicePathCache.Add(serviceName, servicePath)
	return servicePath
}

func getServiceDLLPath(serviceName string) (string, error) {
	serviceKeyPath := `SYSTEM\CurrentControlSet\Services\` + serviceName
	var lastErr error
	for _, keyPath := range []string{serviceKeyPath + `\Parameters`, serviceKeyPath} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
		if err != nil {
			lastErr = err
			continue
		}
		value, valueType, err := key.GetStringValue("ServiceDll")
		key.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if valueType == registry.EXPAND_SZ {
			return registry.ExpandString(value)
		}
		return value, nil
	}
	return "", lastErr
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
	// Grow only on demand: a constant-length MAX_LONG_PATH buffer is 64 KiB on the caller's goroutine stack.
	bufferLength := uint32(syscall.MAX_PATH)
	for {
		buf := make([]uint16, bufferLength)
		size := bufferLength
		err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
		if err == nil {
			return windows.UTF16ToString(buf[:size]), nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || bufferLength == syscall.MAX_LONG_PATH {
			return "", err
		}
		bufferLength = syscall.MAX_LONG_PATH
	}
}
