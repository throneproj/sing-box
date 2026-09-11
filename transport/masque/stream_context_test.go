package masque

import (
	"context"
	"errors"
	"testing"
	"time"
)

func waitDone(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("context not cancelled")
	}
}

func TestStreamContextDialCancelForwardedWhileDialing(t *testing.T) {
	dial, cancelDial := context.WithCancelCause(context.Background())
	ctx, _, stop := newStreamContext(context.Background(), dial)
	defer stop()
	cause := errors.New("dial aborted")
	cancelDial(cause)
	waitDone(t, ctx)
	if !errors.Is(context.Cause(ctx), cause) {
		t.Fatalf("cause = %v, want %v", context.Cause(ctx), cause)
	}
}

func TestStreamContextDialCancelIgnoredAfterStop(t *testing.T) {
	dial, cancelDial := context.WithCancel(context.Background())
	ctx, cancel, stop := newStreamContext(context.Background(), dial)
	stop()
	cancelDial()
	if ctx.Err() != nil {
		t.Fatalf("stream cancelled by dial context after stop: %v", ctx.Err())
	}
	cause := errors.New("closed")
	cancel(cause)
	waitDone(t, ctx)
	if !errors.Is(context.Cause(ctx), cause) {
		t.Fatalf("cause = %v, want %v", context.Cause(ctx), cause)
	}
}

func TestStreamContextLifetimeCancelPropagates(t *testing.T) {
	lifetime, cancelLifetime := context.WithCancelCause(context.Background())
	ctx, _, stop := newStreamContext(lifetime, context.Background())
	defer stop()
	cause := errors.New("endpoint closed")
	cancelLifetime(cause)
	waitDone(t, ctx)
	if !errors.Is(context.Cause(ctx), cause) {
		t.Fatalf("cause = %v, want %v", context.Cause(ctx), cause)
	}
}

func TestStreamContextValuesAndDeadline(t *testing.T) {
	type dialKey struct{}
	type lifetimeKey struct{}
	lifetime := context.WithValue(context.Background(), lifetimeKey{}, "lifetime")
	dial, cancelDial := context.WithTimeout(context.WithValue(context.Background(), dialKey{}, "dial"), time.Hour)
	defer cancelDial()
	ctx, _, stop := newStreamContext(lifetime, dial)
	defer stop()
	if ctx.Value(dialKey{}) != "dial" {
		t.Fatalf("dial value = %v", ctx.Value(dialKey{}))
	}
	if ctx.Value(lifetimeKey{}) != "lifetime" {
		t.Fatalf("lifetime value = %v", ctx.Value(lifetimeKey{}))
	}
	if ctx.Value("missing") != nil {
		t.Fatal("unexpected value for missing key")
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		t.Fatal("dial deadline must not become the stream deadline")
	}
}

func TestStreamContextChildFollowsStream(t *testing.T) {
	dial, cancelDial := context.WithCancel(context.Background())
	ctx, cancel, stop := newStreamContext(context.Background(), dial)
	stop()
	child, cancelChild := context.WithCancel(ctx)
	defer cancelChild()
	cancelDial()
	if child.Err() != nil {
		t.Fatalf("child cancelled by dial context: %v", child.Err())
	}
	cancel(errors.New("closed"))
	waitDone(t, child)
}
