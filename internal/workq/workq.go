// Package workq is the queue of digests waiting to be catalogued. It lives in the matcher's
// memory on purpose: the queue is derived state, rebuilt at the start of every run from the
// inventory minus what the cache already holds, so there is nothing worth persisting. A work
// item that survived a restart would be stale — the pod may be gone and the digest no longer
// running — and cataloguing it would produce an SBOM the next prune deletes (ADR 0009).
//
// Nothing here knows about HTTP. The queue hands out items and takes results; internal/dispatch
// is what puts a network between the two.
package workq

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/obayer/kiebitzr/internal/metrics"
)

// Item is one digest to catalogue, with the reference it can be pulled by.
type Item struct {
	Digest string
	Ref    string
}

// Failure is a digest that will not get an SBOM this run, with the stage it failed at and
// whatever the worker had to say about it. The message is not a label — it goes to the log,
// where the registry's own words belong.
type Failure struct {
	Digest  string
	Reason  string
	Message string
}

// Outcome is what became of the work a run filled in.
type Outcome struct {
	// Done is how many digests gained an SBOM.
	Done int
	// Failed are the digests a worker reported on, or that used up their attempts.
	Failed []Failure
	// Pending are the digests still outstanding when waiting stopped.
	Pending []string
}

// Options configure one queue.
type Options struct {
	// Deadline is how long a handed-out item may stay out before it is offered again. It has
	// to exceed the time cataloguing one image takes, or healthy work is handed out twice.
	Deadline time.Duration
	// MaxAttempts bounds how often an item is handed out when no result comes back at all.
	// It does not bound reported failures: a worker that answers has answered.
	MaxAttempts int
	// SweepInterval is how often expired items are looked for while waiting.
	SweepInterval time.Duration
	// Now is the clock, injectable so the deadline arithmetic is testable without sleeping.
	Now func() time.Time
}

// Default timings, used for whatever Options leaves at zero.
const (
	defaultDeadline      = 10 * time.Minute
	defaultMaxAttempts   = 3
	defaultSweepInterval = 5 * time.Second
)

// Queue is the work of one run. It is safe for concurrent use: one filler and any number of
// workers taking and reporting.
type Queue struct {
	opts Options

	mu sync.Mutex
	// changed is closed and replaced on every state change, which is how waiting takers and
	// the waiting run are woken without polling.
	changed  chan struct{}
	pending  []Item
	inflight map[string]lease
	attempts map[string]int
	done     int
	failures []Failure
}

// lease is a handed-out item and the moment it stops counting as handed out.
type lease struct {
	item     Item
	deadline time.Time
}

// New returns an empty queue. Fill gives it work.
func New(opts Options) *Queue {
	if opts.Deadline <= 0 {
		opts.Deadline = defaultDeadline
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaultMaxAttempts
	}
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = defaultSweepInterval
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Queue{
		opts:     opts,
		changed:  make(chan struct{}),
		inflight: make(map[string]lease),
		attempts: make(map[string]int),
	}
}

// Fill replaces the queue's contents with the work of a new run and forgets the previous one.
// Everything a run needs to know about the last one is already in its Outcome.
func (q *Queue) Fill(items []Item) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.pending = make([]Item, len(items))
	copy(q.pending, items)
	q.inflight = make(map[string]lease, len(items))
	q.attempts = make(map[string]int, len(items))
	q.done = 0
	q.failures = nil
	q.wake()
}

// Take hands out the next item, blocking until there is one or ctx ends. The second return
// value is false only when ctx ended, which is what a long-poll turns into "nothing for you
// right now".
func (q *Queue) Take(ctx context.Context) (Item, bool) {
	for {
		q.mu.Lock()
		if len(q.pending) > 0 {
			item := q.pending[0]
			q.pending = q.pending[1:]
			q.attempts[item.Digest]++
			q.inflight[item.Digest] = lease{
				item:     item,
				deadline: q.opts.Now().Add(q.opts.Deadline),
			}
			q.wake()
			q.mu.Unlock()
			return item, true
		}
		changed := q.changed
		q.mu.Unlock()

		select {
		case <-ctx.Done():
			return Item{}, false
		case <-changed:
		}
	}
}

// Done records that a digest's SBOM arrived. It is idempotent: a result that crosses a requeue
// is counted once, because the SBOM it refers to is in the cache either way.
func (q *Queue) Done(digest string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.settle(digest) {
		return
	}
	q.done++
	q.wake()
}

// Failed records that a worker could not catalogue a digest. A reported failure is final: the
// worker reached a conclusion, and handing the same image out again would reach it twice.
// MaxAttempts governs only the case where no answer comes back at all.
func (q *Queue) Failed(digest, reason, message string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.settle(digest) {
		return
	}
	q.failures = append(q.failures, Failure{Digest: digest, Reason: reason, Message: message})
	q.wake()
}

// Sweep offers expired items again and gives up on the ones that have used up their attempts.
// It returns how many it put back.
//
// An item expires when the worker holding it never answered — it died, was evicted, or lost
// the network. Retrying that is right. Retrying it forever is not: an image that reliably kills
// whatever catalogues it would otherwise circulate for the whole run, which is why attempts are
// bounded and the giving-up is recorded rather than silent.
func (q *Queue) Sweep() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := q.opts.Now()
	requeued := 0
	for digest, l := range q.inflight {
		if now.Before(l.deadline) {
			continue
		}
		delete(q.inflight, digest)
		if q.attempts[digest] >= q.opts.MaxAttempts {
			q.failures = append(q.failures, Failure{
				Digest: digest,
				Reason: metrics.ReasonCatalogue,
				Message: fmt.Sprintf("no result after %d attempts of %s each",
					q.attempts[digest], q.opts.Deadline),
			})
			continue
		}
		q.pending = append(q.pending, l.item)
		requeued++
	}
	if requeued > 0 {
		q.wake()
	}
	return requeued
}

// Wait blocks until every filled item has been accounted for, or until ctx ends — which is how
// the cataloguing budget of a run expires. Whatever is still outstanding then is pending.
func (q *Queue) Wait(ctx context.Context) Outcome {
	ticker := time.NewTicker(q.opts.SweepInterval)
	defer ticker.Stop()

	for {
		q.mu.Lock()
		outstanding := len(q.pending) + len(q.inflight)
		changed := q.changed
		q.mu.Unlock()

		if outstanding == 0 {
			return q.Outcome()
		}

		select {
		case <-ctx.Done():
			return q.Outcome()
		case <-ticker.C:
			q.Sweep()
		case <-changed:
		}
	}
}

// Outcome is the state of the work as it stands. Called by Wait when it returns, and usable on
// its own for a run that wants to look without waiting.
func (q *Queue) Outcome() Outcome {
	q.mu.Lock()
	defer q.mu.Unlock()

	out := Outcome{Done: q.done}
	out.Failed = append(out.Failed, q.failures...)
	for _, item := range q.pending {
		out.Pending = append(out.Pending, item.Digest)
	}
	for digest := range q.inflight {
		out.Pending = append(out.Pending, digest)
	}
	return out
}

// Depth is how much work is not yet accounted for, handed out or not. This is the signal to
// scale a worker pool on: a worker is network-bound on the registry pull, so its own CPU says
// nothing about whether more of them would help.
func (q *Queue) Depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending) + len(q.inflight)
}

// settle removes a digest from wherever it is waiting and reports whether it was anywhere at
// all. A digest that is nowhere has already been settled, and must not be counted twice.
func (q *Queue) settle(digest string) bool {
	if _, ok := q.inflight[digest]; ok {
		delete(q.inflight, digest)
		return true
	}
	for i, item := range q.pending {
		if item.Digest == digest {
			q.pending = append(q.pending[:i], q.pending[i+1:]...)
			return true
		}
	}
	return false
}

// wake releases everyone waiting on a state change. The caller holds the lock.
func (q *Queue) wake() {
	close(q.changed)
	q.changed = make(chan struct{})
}
