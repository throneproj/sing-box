package daemon

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/log"
)

const defaultAttachedLogMaxLines = 3000

var _ log.LeveledPlatformWriter = (*StartedService)(nil)

// StartOrReloadService and CloseService must not be called on an attached service.
func NewAttachedService(ctx context.Context) *StartedService {
	instance := attachInstance(ctx)
	s := NewStartedService(ServiceOptions{
		Context:     ctx,
		LogMaxLines: defaultAttachedLogMaxLines,
	})
	s.instance = instance
	s.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
	s.startedAt = time.Now()
	instance.urlTestHistoryStorage.AddUpdateHook(s.urlTestSubscriber)
	if instance.clashMode != nil {
		instance.clashMode.AddUpdateHook(s.clashModeSubscriber)
	}
	s.attachedLogFactory = instance.logFactory
	instance.logFactory.AttachPlatformWriter(s)
	return s
}

// LogLevel keeps an attached service's history at the configured level while no log stream is connected, so the box
// does not format every line just for it. A daemon's service and a connected stream take every level.
func (s *StartedService) LogLevel() log.Level {
	if s.attachedLogFactory == nil || s.logStreams.Load() > 0 {
		return log.LevelTrace
	}
	return s.attachedLogFactory.Level()
}
