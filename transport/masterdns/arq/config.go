package arq

import (
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/compress"
	E "github.com/sagernet/sing/common/exceptions"
)

// Client defaults of the reference client_config.toml.simple.
const (
	DefaultWindowSize             = 1000
	DefaultRTO                    = 500 * time.Millisecond
	DefaultMaxRTO                 = 3 * time.Second
	DefaultControlRTO             = 500 * time.Millisecond
	DefaultControlMaxRTO          = 2 * time.Second
	DefaultControlMaxRetries      = 126
	DefaultInactivityTimeout      = 1800 * time.Second
	DefaultDataPacketTTL          = 2400 * time.Second
	DefaultControlPacketTTL       = 1200 * time.Second
	DefaultMaxDataRetries         = 126
	DefaultDataNackMaxGap         = 32
	DefaultDataNackInitialDelay   = 100 * time.Millisecond
	DefaultDataNackRepeat         = 800 * time.Millisecond
	DefaultTerminalDrainTimeout   = 120 * time.Second
	DefaultTerminalAckWaitTimeout = 90 * time.Second
	DefaultMaxPacketsPerBatch     = 8
	DefaultDispatcherIdlePoll     = 20 * time.Millisecond
	// SetupPacketTTL is the TTL the reference client gives STREAM_SYN and SOCKS5_SYN.
	SetupPacketTTL = 120 * time.Second
)

const (
	minWindowSize           = 300
	minSendLimit            = 50
	minRTO                  = 50 * time.Millisecond
	minInactivityTimeout    = 120 * time.Second
	minDataPacketTTL        = 120 * time.Second
	minMaxDataRetries       = 60
	minTerminalDrainTimeout = 60 * time.Second
	minTerminalAckWait      = 30 * time.Second
	minControlMaxRetries    = 5
	minControlPacketTTL     = 120 * time.Second
	minDataNackRepeat       = 100 * time.Millisecond
)

var (
	ErrCanceled = E.New("canceled")
	ErrReset    = E.New("stream reset")
)

type State uint8

const (
	StateOpen State = iota
	StateHalfClosedLocal
	StateHalfClosedRemote
	StateClosing
	StateReset
	StateClosed
	StateDraining
	StateTimeWait
)

type Config struct {
	WindowSize               int
	RTO                      time.Duration
	MaxRTO                   time.Duration
	IsVirtual                bool
	StartPaused              bool
	EnableControlReliability bool
	ControlRTO               time.Duration
	ControlMaxRTO            time.Duration
	ControlMaxRetries        int
	InactivityTimeout        time.Duration
	DataPacketTTL            time.Duration
	MaxDataRetries           int
	ControlPacketTTL         time.Duration
	DataNackMaxGap           int
	DataNackInitialDelay     time.Duration
	DataNackRepeat           time.Duration
	TerminalDrainTimeout     time.Duration
	TerminalAckWaitTimeout   time.Duration
	Compression              compress.Type
	IsClient                 bool
	// Clock defaults to time.Now; it must agree with the times passed to the methods that take one.
	Clock func() time.Time
}

type CloseOptions struct {
	Force          bool
	SendRST        bool
	SendCloseWrite bool
	SendCloseRead  bool
	AfterDrain     bool
	TTL            time.Duration
}
