package tor

import (
	"context"

	"github.com/cretz/bine/process"
)

// ProcessCreator, when registered in the context, starts the tor executable instead of a plain exec.
type ProcessCreator interface {
	NewProcess(ctx context.Context, executablePath string, args ...string) (process.Process, error)
}

type processCreatorFunc func(ctx context.Context, args ...string) (process.Process, error)

func (f processCreatorFunc) New(ctx context.Context, args ...string) (process.Process, error) {
	return f(ctx, args...)
}
