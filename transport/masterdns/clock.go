package masterdns

import (
	"container/heap"
	"sync"
	"time"

	"github.com/sagernet/sing-box/transport/masterdns/arq"
)

// streamClock drives every ARQ stream of a session from one goroutine, each at its own NextTick.
type streamClock struct {
	access  sync.Mutex
	entries clockEntries
	wake    chan struct{}
}

type clockEntry struct {
	at     time.Time
	stream *arq.Stream
}

type clockEntries []clockEntry

func (e clockEntries) Len() int           { return len(e) }
func (e clockEntries) Less(i, j int) bool { return e[i].at.Before(e[j].at) }
func (e clockEntries) Swap(i, j int)      { e[i], e[j] = e[j], e[i] }
func (e *clockEntries) Push(x any)        { *e = append(*e, x.(clockEntry)) }

func (e *clockEntries) Pop() any {
	old := *e
	entry := old[len(old)-1]
	old[len(old)-1] = clockEntry{}
	*e = old[:len(old)-1]
	return entry
}

func (c *streamClock) schedule(stream *arq.Stream, at time.Time) {
	c.access.Lock()
	heap.Push(&c.entries, clockEntry{at: at, stream: stream})
	earliest := c.entries[0].stream == stream
	c.access.Unlock()
	if earliest {
		wakeup(c.wake)
	}
}

func (c *streamClock) popDue(now time.Time, due []*arq.Stream) []*arq.Stream {
	c.access.Lock()
	defer c.access.Unlock()
	for len(c.entries) > 0 && !c.entries[0].at.After(now) {
		due = append(due, heap.Pop(&c.entries).(clockEntry).stream)
	}
	return due
}

func (c *streamClock) reschedule(streams []*arq.Stream, now time.Time) time.Time {
	c.access.Lock()
	defer c.access.Unlock()
	for _, stream := range streams {
		select {
		case <-stream.Done():
		default:
			heap.Push(&c.entries, clockEntry{at: now.Add(stream.NextTick()), stream: stream})
		}
	}
	if len(c.entries) == 0 {
		return time.Time{}
	}
	return c.entries[0].at
}

func (r *tunnelRuntime) clockLoop() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var due []*arq.Stream
	for {
		now := time.Now()
		due = r.clock.popDue(now, due[:0])
		for _, stream := range due {
			stream.Tick(now)
		}
		next := r.clock.reschedule(due, now)
		clear(due)
		wait := time.Hour
		if !next.IsZero() {
			wait = max(time.Until(next), 0)
		}
		timer.Reset(wait)
		select {
		case <-r.ctx.Done():
			return
		case <-r.clock.wake:
		case <-timer.C:
		}
	}
}
