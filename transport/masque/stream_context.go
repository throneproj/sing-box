package masque

import "context"

// The stream outlives its dial: dial cancels it only until stop is called, but its values stay visible.
func newStreamContext(lifetime context.Context, dial context.Context) (ctx context.Context, cancel context.CancelCauseFunc, stop func()) {
	streamCtx, cancel := context.WithCancelCause(lifetime)
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
