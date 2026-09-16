//go:build darwin && !ios

package settings

import (
	"context"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/shell"
)

// darwinWIFIMonitor reads the Wi-Fi state from `ipconfig getsummary`, which
// reports SSID and BSSID without the location permission that CoreWLAN and
// `networksetup -getairportnetwork` need on recent macOS. The router refreshes
// the state on interface changes; the poll only catches a roaming SSID change
// on the same interface.
type darwinWIFIMonitor struct {
	interfaceName string
	callback      func(adapter.WIFIState)
	access        sync.Mutex
	cancel        context.CancelFunc
	done          chan struct{}
}

const darwinWIFIPollInterval = 15 * time.Second

var (
	darwinHardwarePortRegexp = regexp.MustCompile(`(?m)^Hardware Port: Wi-Fi\nDevice: (\S+)$`)
	darwinSSIDRegexp         = regexp.MustCompile(`(?m)^  SSID : (.*)$`)
	darwinBSSIDRegexp        = regexp.MustCompile(`(?m)^  BSSID : (\S+)$`)
)

func NewWIFIMonitor(callback func(adapter.WIFIState)) (WIFIMonitor, error) {
	output, err := shell.Exec("/usr/sbin/networksetup", "-listallhardwareports").ReadOutput()
	if err != nil {
		return nil, err
	}
	interfaceName := parseDarwinWIFIInterface(output)
	if interfaceName == "" {
		return nil, os.ErrInvalid
	}
	return &darwinWIFIMonitor{
		interfaceName: interfaceName,
		callback:      callback,
	}, nil
}

func parseDarwinWIFIInterface(hardwarePorts string) string {
	match := darwinHardwarePortRegexp.FindStringSubmatch(strings.ReplaceAll(hardwarePorts, "\r\n", "\n"))
	if match == nil {
		return ""
	}
	return match[1]
}

func parseDarwinWIFIState(summary string) adapter.WIFIState {
	summary = strings.ReplaceAll(summary, "\r\n", "\n")
	var state adapter.WIFIState
	if match := darwinSSIDRegexp.FindStringSubmatch(summary); match != nil {
		state.SSID = strings.TrimSpace(match[1])
	}
	if state.SSID == "" {
		return adapter.WIFIState{}
	}
	if match := darwinBSSIDRegexp.FindStringSubmatch(summary); match != nil {
		state.BSSID = match[1]
	}
	return state
}

func (m *darwinWIFIMonitor) ReadWIFIState(ctx context.Context) adapter.WIFIState {
	output, err := shell.Exec("/usr/sbin/ipconfig", "getsummary", m.interfaceName).ReadOutput()
	if err != nil {
		return adapter.WIFIState{}
	}
	return parseDarwinWIFIState(output)
}

func (m *darwinWIFIMonitor) Start() error {
	if m.callback == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.access.Lock()
	m.cancel = cancel
	m.done = make(chan struct{})
	m.access.Unlock()
	go m.poll(ctx, m.ReadWIFIState(ctx))
	return nil
}

func (m *darwinWIFIMonitor) poll(ctx context.Context, lastState adapter.WIFIState) {
	defer close(m.done)
	ticker := time.NewTicker(darwinWIFIPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		state := m.ReadWIFIState(ctx)
		if state != lastState {
			lastState = state
			m.callback(state)
		}
	}
}

func (m *darwinWIFIMonitor) Close() error {
	m.access.Lock()
	cancel, done := m.cancel, m.done
	m.access.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	return nil
}
