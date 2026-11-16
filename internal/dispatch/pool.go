package dispatch

import (
	"context"

	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/runner"
	"github.com/obayer/kiebitzr/internal/workq"
)

// Pool is the cataloguing stage of a run when the work goes to workers. It fills the queue and
// waits for it to drain; the workers themselves it never knows about, because they come to it.
type Pool struct {
	queue *workq.Queue
}

// NewPool returns the cataloguing stage over one queue.
func NewPool(queue *workq.Queue) *Pool {
	return &Pool{queue: queue}
}

// Catalogue hands the work list to the queue and waits for the pool to work through it, until
// ctx ends — which is the cataloguing budget of the run. What is still outstanding then comes
// back as pending, so the run publishes what it has.
func (p *Pool) Catalogue(ctx context.Context, work []runner.Work) runner.Report {
	items := make([]workq.Item, 0, len(work))
	for _, item := range work {
		items = append(items, workq.Item{Digest: item.Digest, Ref: item.Ref})
	}
	p.queue.Fill(items)

	outcome := p.queue.Wait(ctx)
	report := runner.Report{Scanned: outcome.Done, Pending: outcome.Pending}
	for _, failure := range outcome.Failed {
		// The message is deliberately dropped here: it was logged where it arrived, and a
		// message is not a label (ADR 0008).
		report.Failures = append(report.Failures,
			metrics.Failure{Digest: failure.Digest, Reason: failure.Reason})
	}
	return report
}

// Depth is how much work is outstanding, for kiebitzr_catalogue_queue_depth.
func (p *Pool) Depth() int { return p.queue.Depth() }
