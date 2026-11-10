package option

import "github.com/sagernet/sing/common/json/badoption"

type SelectorOutboundOptions struct {
	Outbounds                 []string `json:"outbounds" reference:"outbound"`
	Default                   string   `json:"default,omitempty" reference:"outbound"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`
}

type URLTestOutboundOptions struct {
	Outbounds                 []string           `json:"outbounds" reference:"outbound"`
	URL                       string             `json:"url,omitempty"`
	Interval                  badoption.Duration `json:"interval,omitempty"`
	Tolerance                 uint16             `json:"tolerance,omitempty"`
	IdleTimeout               badoption.Duration `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
}

// AutoSelectorOutboundOptions configures the auto selector: a urltest group
// built for large member sets (hundreds), with sampled health tracking, inline
// dial failover and local-outage immunity.
//
// The order of Outbounds is meaningful: it is taken as the initial ranking
// prior, so a caller that already ranked its servers gets a good pick from the
// very first probe instead of waiting for a full sweep.
type AutoSelectorOutboundOptions struct {
	Outbounds []string `json:"outbounds"`

	URL string `json:"url,omitempty"`
	// ConnectivityURL is fetched *without* the proxy to tell a dead local
	// network apart from dead servers. Optional: when empty the selector falls
	// back to error classification plus the round-quorum heuristic, which is
	// what censored networks need since any fixed endpoint may be blocked.
	ConnectivityURL string `json:"connectivity_url,omitempty"`
	// Upstream is the outbound every member dials through when the group sits
	// behind a fixed hop in a chain. It is checked before a correlated failure is
	// blamed on the members: if it is down, the members were never reached.
	Upstream string `json:"upstream,omitempty"`

	// Interval is the probe period of the active tier (the top-ranked members
	// that could actually be selected next). BenchInterval is the much slower
	// period over which every remaining member is rotated through. This split
	// is what keeps a 300-member group cheap.
	Interval      badoption.Duration `json:"interval,omitempty"`
	BenchInterval badoption.Duration `json:"bench_interval,omitempty"`
	ActiveSize    int                `json:"active_size,omitempty"`
	Sampling      int                `json:"sampling,omitempty"`
	Timeout       badoption.Duration `json:"timeout,omitempty"`
	Concurrency   int                `json:"concurrency,omitempty"`

	// WatchInterval is how often the *selected* member alone is re-probed,
	// independent of Interval. It exists because an exit can break without ever
	// producing a dial error — it still accepts TCP, it just carries nothing —
	// and waiting out a tier interval to notice is far too slow when Interval is
	// minutes. A failure here pulls the next full round forward immediately.
	WatchInterval badoption.Duration `json:"watch_interval,omitempty"`

	// Warm restores the health the caller recorded the last time this selector
	// ran. Without it a restart is a cold start: every member reads as untested,
	// the first pick is only as good as the ordering prior, and the whole pool
	// has to be re-measured before the ranking means anything.
	Warm []AutoSelectorWarmEntry `json:"warm,omitempty"`

	// Pinned restores a member the user chose by hand (see SelectOutbound). It
	// is a standing preference rather than run-scoped state, so it survives a
	// restart the same way any other setting does.
	Pinned string `json:"pinned,omitempty"`

	// Tolerance is the stickiness margin in milliseconds: a challenger must beat
	// the incumbent by this much before the selection moves.
	Tolerance     uint16               `json:"tolerance,omitempty"`
	MaxRTT        badoption.Duration   `json:"max_rtt,omitempty"`
	FailTolerance float64              `json:"fail_tolerance,omitempty"`
	Baselines     []badoption.Duration `json:"baselines,omitempty"`
	Expected      int                  `json:"expected,omitempty"`

	// Strategy "priority" uses the highest-priority healthy member instead of the
	// best measured one, and moves back up to a recovered member only after it has
	// passed FailbackChecks checks in a row and FailbackDelay since its last failure.
	// Moving back up leaves live connections alone unless FailbackInterrupt is set.
	Strategy string `json:"strategy,omitempty"`
	// Tiers orders members for the priority strategy, most preferred first: a
	// member's priority is the first tier listing it, members in no tier share one
	// more tier after the last, and within a tier the health ranking applies.
	// Without tiers, the order of Outbounds is the priority order.
	Tiers             [][]string         `json:"tiers,omitempty"`
	FailbackChecks    int                `json:"failback_checks,omitempty"`
	FailbackDelay     badoption.Duration `json:"failback_delay,omitempty"`
	FailbackInterrupt bool               `json:"failback_interrupt,omitempty"`

	// Balance spreads traffic over the qualified set instead of pinning the
	// single best member. Disabled by default.
	//
	// BalanceMode "rotate" (default) moves the whole selection every
	// BalanceInterval, which keeps session affinity intact and keeps per-member
	// traffic accounting exact. "connection" picks per dial: a wider spread, at
	// the cost of a changing egress IP mid-session and approximate accounting.
	Balance         bool               `json:"balance,omitempty"`
	BalanceMode     string             `json:"balance_mode,omitempty"`
	BalanceInterval badoption.Duration `json:"balance_interval,omitempty"`

	// DialRetries bounds how many further members one dial may try after the
	// selected one fails, before the error is handed back to the client.
	DialRetries               int  `json:"dial_retries,omitempty"`
	InterruptExistConnections bool `json:"interrupt_exist_connections,omitempty"`

	Passive *AutoSelectorPassiveOptions `json:"passive,omitempty"`
}

// AutoSelectorPassiveOptions scores members on the connections they carry, not
// only on probes. A connection is answered at its first byte back, or failed: a
// TCP connection that sent and closed with nothing back, a UDP flow left
// unanswered, a failed dial. A member whose recent outcomes are mostly failures
// is held out of the selection, for longer each time it repeats, and a site that
// failed on a member goes to the one that last answered it instead.
type AutoSelectorPassiveOptions struct {
	Enabled bool `json:"enabled,omitempty"`
	// SiteMemory is how long a site keeps the member that last answered it, and
	// avoids one that failed it. Zero means one hour.
	SiteMemory badoption.Duration `json:"site_memory,omitempty"`
}

// AutoSelectorWarmEntry is one member's health carried over from a previous run.
// Age is what makes it safe to trust: the entry is replayed as a sample taken
// that many seconds ago, so it expires out of the sampling window on exactly the
// same schedule a live measurement would, and a long-stopped selector starts
// cold again on its own.
type AutoSelectorWarmEntry struct {
	Tag string `json:"tag"`
	// RTT in milliseconds; 0 means the member was known to be failing.
	RTT uint16 `json:"rtt"`
	// Seconds since the measurement was taken.
	Age uint32 `json:"age,omitempty"`
}
