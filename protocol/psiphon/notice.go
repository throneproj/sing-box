//go:build with_psiphon

package psiphon

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

var hub = &noticeHub{tunnels: make(chan struct{})}

// Psiphon notices are process-wide, so a single writer serves every outbound.
var installNoticeWriter = sync.OnceValue(func() error {
	return psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(hub.handle))
})

type noticeHub struct {
	access    sync.Mutex
	outbounds []*Outbound
	tunnels   chan struct{}
	regions   []string
}

type notice struct {
	NoticeType string          `json:"noticeType"`
	Data       json.RawMessage `json:"data"`
}

type noticeData struct {
	Count        int      `json:"count"`
	Regions      []string `json:"regions"`
	Region       string   `json:"region"`
	ServerRegion string   `json:"serverRegion"`
	Message      string   `json:"message"`
}

// AvailableEgressRegions returns the last non-empty egress region list Psiphon reported in this process.
func AvailableEgressRegions() []string {
	hub.access.Lock()
	defer hub.access.Unlock()
	return slices.Clone(hub.regions)
}

func (h *noticeHub) register(outbound *Outbound) error {
	err := installNoticeWriter()
	if err != nil {
		return E.Cause(err, "set notice writer")
	}
	h.access.Lock()
	h.outbounds = append(h.outbounds, outbound)
	h.access.Unlock()
	return nil
}

func (h *noticeHub) unregister(outbound *Outbound) {
	h.access.Lock()
	h.outbounds = common.Filter(h.outbounds, func(it *Outbound) bool {
		return it != outbound
	})
	h.access.Unlock()
}

func (h *noticeHub) tunnelsChanged() <-chan struct{} {
	h.access.Lock()
	defer h.access.Unlock()
	return h.tunnels
}

// Called under Psiphon's notice lock: it must not emit notices itself.
func (h *noticeHub) handle(content []byte) {
	var message notice
	err := json.Unmarshal(content, &message)
	if err != nil {
		return
	}
	var data noticeData
	_ = json.Unmarshal(message.Data, &data)
	h.access.Lock()
	switch message.NoticeType {
	case "Tunnels":
		close(h.tunnels)
		h.tunnels = make(chan struct{})
	case "AvailableEgressRegions":
		// Reported empty on a first start, before any server list is imported.
		if len(data.Regions) > 0 {
			h.regions = data.Regions
		}
	}
	var noticeLogger logger.ContextLogger
	if len(h.outbounds) > 0 {
		noticeLogger = h.outbounds[0].logger
	}
	h.access.Unlock()
	if noticeLogger == nil {
		return
	}
	switch message.NoticeType {
	case "Tunnels":
		noticeLogger.Debug("active tunnels: ", data.Count)
	case "ConnectedServerRegion":
		noticeLogger.Info("connected to server in ", data.ServerRegion)
	case "ClientRegion":
		noticeLogger.Debug("client region: ", data.Region)
	case "AvailableEgressRegions":
		noticeLogger.Debug("available egress regions: ", strings.Join(data.Regions, ", "))
	case "Info":
		noticeLogger.Debug(data.Message)
	case "Warning", "UpstreamProxyError":
		noticeLogger.Warn(data.Message)
	case "Error", "InternalError":
		noticeLogger.Error(data.Message)
	case "Homepage", "ClientUpgradeAvailable", "TrafficRateLimits":
	case "ClientAddress":
		// carries the public client address unredacted
	default:
		noticeLogger.Debug(message.NoticeType, ": ", string(message.Data))
	}
}
