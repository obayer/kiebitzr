package workq

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/obayer/kiebitzr/internal/metrics"
)

const (
	digestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// clock is a hand-wound clock, so deadline arithmetic is tested without sleeping.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func items(digests ...string) []Item {
	out := make([]Item, 0, len(digests))
	for _, digest := range digests {
		out = append(out, Item{Digest: digest, Ref: "registry.example/app@" + digest})
	}
	return out
}

func newQueue(t *testing.T, clk *clock, opts Options) *Queue {
	t.Helper()
	opts.Now = clk.Now
	return New(opts)
}

func TestTakeHandsOutEveryItemOnce(t *testing.T) {
	q := newQueue(t, newClock(), Options{Deadline: time.Minute})
	q.Fill(items(digestA, digestB))

	var got []string
	for range 2 {
		item, ok := q.Take(context.Background())
		if !ok {
			t.Fatal("Take() = not ok, want an item")
		}
		got = append(got, item.Digest)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{digestA, digestB}) {
		t.Fatalf("Take() handed out %v, want both digests", got)
	}

	// Nothing is left, so a taker blocks until its context ends — which is what a long-poll
	// returns 204 for.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, ok := q.Take(ctx); ok {
		t.Fatal("Take() handed out an item from an empty queue")
	}
}

func TestTakeBlocksUntilWorkArrives(t *testing.T) {
	q := newQueue(t, newClock(), Options{Deadline: time.Minute})

	taken := make(chan Item, 1)
	go func() {
		item, ok := q.Take(context.Background())
		if ok {
			taken <- item
		}
	}()

	// The taker is waiting on an empty queue; filling it has to wake them.
	q.Fill(items(digestA))
	select {
	case item := <-taken:
		if item.Digest != digestA {
			t.Fatalf("Take() = %s, want %s", item.Digest, digestA)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Take() did not wake when the queue was filled")
	}
}

func TestDoneAccountsForTheDigest(t *testing.T) {
	q := newQueue(t, newClock(), Options{Deadline: time.Minute})
	q.Fill(items(digestA))

	item, _ := q.Take(context.Background())
	q.Done(item.Digest)

	out := q.Outcome()
	if out.Done != 1 || len(out.Pending) != 0 || len(out.Failed) != 0 {
		t.Fatalf("Outcome() = %+v, want one done and nothing outstanding", out)
	}
	if q.Depth() != 0 {
		t.Fatalf("Depth() = %d, want 0", q.Depth())
	}
}

// A result that crosses a requeue must not be counted twice: two workers can legitimately hold
// the same digest after an expiry, and both may answer.
func TestDoneIsIdempotent(t *testing.T) {
	q := newQueue(t, newClock(), Options{Deadline: time.Minute})
	q.Fill(items(digestA))

	item, _ := q.Take(context.Background())
	q.Done(item.Digest)
	q.Done(item.Digest)

	if out := q.Outcome(); out.Done != 1 {
		t.Fatalf("Done = %d after two reports of the same digest, want 1", out.Done)
	}
}

// A reported failure is final. The worker reached a conclusion about that image, and handing it
// out again would only reach the same conclusion a second time.
func TestFailedIsNotRetried(t *testing.T) {
	q := newQueue(t, newClock(), Options{Deadline: time.Minute, MaxAttempts: 3})
	q.Fill(items(digestA))

	item, _ := q.Take(context.Background())
	q.Failed(item.Digest, metrics.ReasonUnreachable, "UNAUTHORIZED: authentication required")

	out := q.Outcome()
	if len(out.Failed) != 1 {
		t.Fatalf("Failed = %+v, want one entry", out.Failed)
	}
	if out.Failed[0].Reason != metrics.ReasonUnreachable {
		t.Fatalf("reason = %q, want %q", out.Failed[0].Reason, metrics.ReasonUnreachable)
	}
	// The registry's own words have to survive, because the metric cannot tell the three
	// causes of an unreachable image apart and the log line is what does.
	if out.Failed[0].Message == "" {
		t.Fatal("the message the worker reported was dropped")
	}
	if len(out.Pending) != 0 {
		t.Fatalf("Pending = %v, want nothing: a reported failure is settled", out.Pending)
	}
}

// A worker that takes an item and never answers must not take the digest with it.
func TestSweepOffersAnExpiredItemAgain(t *testing.T) {
	clk := newClock()
	q := newQueue(t, clk, Options{Deadline: time.Minute, MaxAttempts: 3})
	q.Fill(items(digestA))

	if _, ok := q.Take(context.Background()); !ok {
		t.Fatal("Take() = not ok")
	}
	// Still within the deadline: nothing to do.
	clk.advance(59 * time.Second)
	if requeued := q.Sweep(); requeued != 0 {
		t.Fatalf("Sweep() = %d before the deadline, want 0", requeued)
	}

	clk.advance(2 * time.Second)
	if requeued := q.Sweep(); requeued != 1 {
		t.Fatalf("Sweep() = %d after the deadline, want 1", requeued)
	}
	item, ok := q.Take(context.Background())
	if !ok || item.Digest != digestA {
		t.Fatalf("Take() = %+v, %v, want the requeued digest", item, ok)
	}
}

// An image that reliably kills whatever catalogues it would otherwise circulate for the whole
// run. Attempts are bounded, and giving up is recorded rather than silent.
func TestSweepGivesUpAfterTheAttemptLimit(t *testing.T) {
	clk := newClock()
	q := newQueue(t, clk, Options{Deadline: time.Minute, MaxAttempts: 2})
	q.Fill(items(digestA))

	for attempt := range 2 {
		if _, ok := q.Take(context.Background()); !ok {
			t.Fatalf("Take() = not ok on attempt %d", attempt+1)
		}
		clk.advance(2 * time.Minute)
		q.Sweep()
	}

	out := q.Outcome()
	if len(out.Failed) != 1 || out.Failed[0].Digest != digestA {
		t.Fatalf("Failed = %+v, want %s given up on", out.Failed, digestA)
	}
	if out.Failed[0].Reason != metrics.ReasonCatalogue {
		t.Fatalf("reason = %q, want %q", out.Failed[0].Reason, metrics.ReasonCatalogue)
	}
	if len(out.Pending) != 0 {
		t.Fatalf("Pending = %v, want nothing left circulating", out.Pending)
	}
	if q.Depth() != 0 {
		t.Fatalf("Depth() = %d, want 0", q.Depth())
	}
}

func TestWaitReturnsWhenEverythingIsAccountedFor(t *testing.T) {
	q := newQueue(t, newClock(), Options{Deadline: time.Minute, SweepInterval: time.Millisecond})
	q.Fill(items(digestA, digestB))

	go func() {
		for range 2 {
			item, ok := q.Take(context.Background())
			if !ok {
				return
			}
			q.Done(item.Digest)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := q.Wait(ctx)

	if out.Done != 2 {
		t.Fatalf("Done = %d, want 2", out.Done)
	}
	if len(out.Pending) != 0 {
		t.Fatalf("Pending = %v, want none", out.Pending)
	}
	if ctx.Err() != nil {
		t.Fatal("Wait() ran until the context expired instead of returning when drained")
	}
}

// This is the cold start: the budget runs out with work still outstanding, and what is left has
// to come back as pending rather than as a failure or as silence.
func TestWaitReportsOutstandingWorkAsPendingWhenTheBudgetEnds(t *testing.T) {
	q := newQueue(t, newClock(), Options{Deadline: time.Hour, SweepInterval: time.Hour})
	q.Fill(items(digestA, digestB))

	// One digest is taken and answered; the other is never picked up at all.
	item, _ := q.Take(context.Background())
	q.Done(item.Digest)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	out := q.Wait(ctx)

	if out.Done != 1 {
		t.Fatalf("Done = %d, want the one that finished", out.Done)
	}
	if len(out.Pending) != 1 {
		t.Fatalf("Pending = %v, want the one that did not", out.Pending)
	}
	if len(out.Failed) != 0 {
		t.Fatalf("Failed = %+v, want none: running out of budget is not a failure", out.Failed)
	}
}

// A new run starts from the inventory, not from what the last one left behind.
func TestFillForgetsThePreviousRun(t *testing.T) {
	q := newQueue(t, newClock(), Options{Deadline: time.Minute})
	q.Fill(items(digestA))
	item, _ := q.Take(context.Background())
	q.Failed(item.Digest, metrics.ReasonCatalogue, "malformed package database")

	q.Fill(items(digestB))

	out := q.Outcome()
	if len(out.Failed) != 0 || out.Done != 0 {
		t.Fatalf("Outcome() = %+v after Fill, want a clean slate", out)
	}
	if got := q.Depth(); got != 1 {
		t.Fatalf("Depth() = %d after Fill, want 1", got)
	}
}

// Many workers against one queue is the normal case, and no digest may be handed to two of them
// at once.
func TestConcurrentTakersEachGetTheirOwnItem(t *testing.T) {
	const count = 50
	digests := make([]string, 0, count)
	for i := range count {
		digests = append(digests, digestOf(i))
	}
	q := newQueue(t, newClock(), Options{Deadline: time.Minute})
	q.Fill(items(digests...))

	var (
		mu    sync.Mutex
		taken []string
		wg    sync.WaitGroup
	)
	for range 8 {
		wg.Go(func() {
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				item, ok := q.Take(ctx)
				cancel()
				if !ok {
					return
				}
				mu.Lock()
				taken = append(taken, item.Digest)
				mu.Unlock()
				q.Done(item.Digest)
			}
		})
	}
	wg.Wait()

	slices.Sort(taken)
	if len(slices.Compact(slices.Clone(taken))) != count {
		t.Fatalf("handed out %d items, %d of them distinct, want %d distinct",
			len(taken), len(slices.Compact(slices.Clone(taken))), count)
	}
}

// digestOf builds a distinct, well-formed digest for index i.
func digestOf(i int) string {
	hex := []byte("0000000000000000000000000000000000000000000000000000000000000000")
	for pos := len(hex) - 1; pos >= 0 && i > 0; pos-- {
		hex[pos] = "0123456789abcdef"[i%16]
		i /= 16
	}
	return "sha256:" + string(hex)
}
