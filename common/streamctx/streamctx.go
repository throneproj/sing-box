package streamctx

import "context"

// New builds the lifetime context of a stream dialed under dial.
//
// A stream over a multiplexed transport is the connection itself, so it must outlive the
// context that dialed it: callers such as the DNS transports cancel their dial context as
// soon as the query completes. The returned context is therefore bound to base (the
// transport) and to cancel; dial's cancellation is forwarded only until stop is called,
// which the dialer does once the stream is established or failed. Values still resolve
// through dial so per-connection metadata reaches the underlying dialer.
func New(base, dial context.Context) (ctx context.Context, cancel context.CancelCauseFunc, stop func()) {
	streamCtx, cancel := context.WithCancelCause(base)
	stopForward := context.AfterFunc(dial, func() {
		cancel(context.Cause(dial))
	})
	return &valueContext{Context: streamCtx, dial: dial}, cancel, func() { stopForward() }
}

type valueContext struct {
	context.Context
	dial context.Context
}

// The stream chain is consulted first so cancel-cause lookups land on the stream's own cancelCtx.
func (c *valueContext) Value(key any) any {
	if value := c.Context.Value(key); value != nil {
		return value
	}
	return c.dial.Value(key)
}
