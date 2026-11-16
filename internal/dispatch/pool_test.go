package dispatch

import (
	"context"
	"testing"
	"time"

	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/runner"
	"github.com/obayer/kiebitzr/internal/workq"
)

const digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

func TestPoolReportsWhatTheWorkersDid(t *testing.T) {
	queue := workq.New(workq.Options{Deadline: time.Minute, SweepInterval: time.Millisecond})
	pool := NewPool(queue)

	// One worker that catalogues the first digest and gives up on the second.
	go func() {
		for range 2 {
			item, ok := queue.Take(context.Background())
			if !ok {
				return
			}
			if item.Digest == digestA {
				queue.Done(item.Digest)
				continue
			}
			queue.Failed(item.Digest, metrics.ReasonUnreachable, "UNAUTHORIZED")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report := pool.Catalogue(ctx, []runner.Work{
		{Digest: digestA, Ref: refA},
		{Digest: digestB, Ref: "registry.example/api@" + digestB},
	})

	if report.Scanned != 1 {
		t.Fatalf("Scanned = %d, want 1", report.Scanned)
	}
	if len(report.Failures) != 1 || report.Failures[0].Digest != digestB {
		t.Fatalf("Failures = %+v, want one for %s", report.Failures, digestB)
	}
	if report.Failures[0].Reason != metrics.ReasonUnreachable {
		t.Fatalf("reason = %q, want %q", report.Failures[0].Reason, metrics.ReasonUnreachable)
	}
	if len(report.Pending) != 0 {
		t.Fatalf("Pending = %v, want none", report.Pending)
	}
}

// The cold start: nobody picks the work up before the budget ends, and what is left has to come
// back as pending so the run still publishes.
func TestPoolReportsUnworkedDigestsAsPending(t *testing.T) {
	queue := workq.New(workq.Options{Deadline: time.Hour, SweepInterval: time.Hour})
	pool := NewPool(queue)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	report := pool.Catalogue(ctx, []runner.Work{{Digest: digestA, Ref: refA}})

	if report.Scanned != 0 || len(report.Failures) != 0 {
		t.Fatalf("report = %+v, want nothing scanned and no failures", report)
	}
	if len(report.Pending) != 1 || report.Pending[0] != digestA {
		t.Fatalf("Pending = %v, want %s", report.Pending, digestA)
	}
}

// Depth is what a worker pool is scaled on, so it has to count the handed-out work too — a
// queue whose items are all in flight is not idle.
func TestPoolDepthCountsOutstandingWork(t *testing.T) {
	queue := workq.New(workq.Options{Deadline: time.Minute})
	pool := NewPool(queue)
	queue.Fill([]workq.Item{{Digest: digestA, Ref: refA}, {Digest: digestB, Ref: refA}})

	if got := pool.Depth(); got != 2 {
		t.Fatalf("Depth() = %d, want 2", got)
	}
	item, _ := queue.Take(context.Background())
	if got := pool.Depth(); got != 2 {
		t.Fatalf("Depth() = %d after one was handed out, want it still counted", got)
	}
	queue.Done(item.Digest)
	if got := pool.Depth(); got != 1 {
		t.Fatalf("Depth() = %d after one finished, want 1", got)
	}
}

// Pool is the cataloguing stage of a run, so it has to satisfy the interface the runner drives.
var _ runner.Cataloguing = (*Pool)(nil)
