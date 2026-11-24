package group

import (
	"sync/atomic"
	"time"
)

// While the screen is off nobody is looking at the selection, so the periodic probes only have to keep it from going
// stale. Urgent rounds are never held back.
const (
	sleepWatchInterval    = 2 * time.Minute
	sleepRoundStretch     = 3
	sleepRecoveryInterval = 30 * time.Second
)

var screenOff atomic.Bool

// SetScreenOff tells every auto-selector in the process whether the device screen is off.
func SetScreenOff(off bool) {
	screenOff.Store(off)
}

func isScreenOff() bool {
	return screenOff.Load()
}

// sleepDue reports whether a loop ticking every tick may act now: always while the screen is on, and at most once per
// period while it is off. Half a tick of slack keeps timer jitter from costing a whole extra tick.
func sleepDue(last time.Time, now time.Time, tick time.Duration, period time.Duration) bool {
	return !isScreenOff() || last.IsZero() || now.Sub(last) >= period-tick/2
}
