package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/runner"
	"github.com/obayer/kiebitzr/internal/workq"
)

// retryDelay is how long a worker waits before trying the matcher again after a failed
// request. A worker that cannot reach the matcher must not spin.
const retryDelay = 5 * time.Second

// Client is a worker's side of the work API.
type Client struct {
	base string
	http *http.Client
}

// NewClient returns a client for the matcher at base, for example
// http://kiebitzr-matcher:8081. The timeout has to exceed the server's poll window, or every
// request for work would be cut off before it could answer.
func NewClient(base string, timeout time.Duration) (*Client, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("matcher url %q: %w", base, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("matcher url %q: want an http or https url", base)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("matcher url %q: no host", base)
	}
	return &Client{
		base: parsed.String(),
		http: &http.Client{Timeout: timeout},
	}, nil
}

// Next asks for one item. The second return value is false when the matcher had nothing, which
// is the normal answer for most of the day.
func (c *Client) Next(ctx context.Context) (workq.Item, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/work", nil)
	if err != nil {
		return workq.Item{}, false, fmt.Errorf("build work request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return workq.Item{}, false, fmt.Errorf("ask for work: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return workq.Item{}, false, nil
	case http.StatusOK:
	default:
		return workq.Item{}, false, fmt.Errorf("ask for work: %s", resp.Status)
	}

	var item workItem
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return workq.Item{}, false, fmt.Errorf("decode work item: %w", err)
	}
	if item.Digest == "" || item.Ref == "" {
		return workq.Item{}, false, errors.New("work item without a digest or reference")
	}
	return workq.Item{Digest: item.Digest, Ref: item.Ref}, true, nil
}

// Submit hands the SBOM of a digest back. The body is streamed, so an SBOM never has to be
// held in memory twice.
func (c *Client) Submit(ctx context.Context, digest string, body io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/sbom/"+digest, body)
	if err != nil {
		return fmt.Errorf("build sbom request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.send(req, "submit sbom")
}

// Fail reports that an image could not be catalogued, with the stage and the underlying
// message. Both travel, because the error type does not survive the trip and the metric alone
// cannot tell the causes of an unreachable image apart.
func (c *Client) Fail(ctx context.Context, digest, reason, message string) error {
	payload, err := json.Marshal(failureReport{Reason: reason, Message: message})
	if err != nil {
		return fmt.Errorf("encode failure report: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/failure/"+digest, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build failure request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.send(req, "report failure")
}

func (c *Client) send(req *http.Request, what string) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// The body is drained so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: %s", what, resp.Status)
	}
	return nil
}

// Worker is one cataloguing process: it asks the matcher for an image, produces its SBOM and
// hands it back. It holds no cache, no vulnerability database and no Kubernetes credential —
// the registry credentials are all it needs, which is the separation ADR 0009 is after.
type Worker struct {
	client   *Client
	producer runner.Producer
	exporter *metrics.WorkerExporter
	log      *slog.Logger
	// tempDir is where an SBOM is buffered before it is posted; empty uses the operating
	// system's temporary directory, which is where image layers are unpacked anyway.
	tempDir string
	// retry is how long to wait after a failed request to the matcher.
	retry time.Duration
}

// NewWorker returns a worker that polls one matcher.
func NewWorker(
	client *Client, producer runner.Producer, exporter *metrics.WorkerExporter, log *slog.Logger,
) *Worker {
	return &Worker{client: client, producer: producer, exporter: exporter, log: log, retry: retryDelay}
}

// Run polls for work until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	w.log.Info("worker started")
	for ctx.Err() == nil {
		item, ok, err := w.client.Next(ctx)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			w.log.Warn("asking the matcher for work failed", "err", err, "retry_in", w.retry)
			w.sleep(ctx)
			continue
		case !ok:
			// Nothing to do; the matcher held the request open, so this is not a busy loop.
			continue
		}
		w.handle(ctx, item)
	}
}

// handle catalogues one image and reports the result, whichever it is. It never returns an
// error: a worker that cannot do one image carries on with the next, and the matcher is told
// so the digest is not left outstanding for nothing.
func (w *Worker) handle(ctx context.Context, item workq.Item) {
	started := time.Now()

	sbom, err := w.produce(ctx, item)
	if err != nil {
		if ctx.Err() != nil {
			// Shutting down is not a verdict on the image. Saying nothing leaves the item to
			// its lease, and another worker picks it up.
			return
		}
		reason := runner.CatalogueReason(err)
		w.exporter.Image(metrics.OutcomeFailed)
		w.log.Warn("cataloguing failed", "digest", item.Digest, "reason", reason, "err", err)
		if reportErr := w.client.Fail(ctx, item.Digest, reason, err.Error()); reportErr != nil {
			w.log.Warn("reporting a failure failed", "digest", item.Digest, "err", reportErr)
		}
		return
	}
	defer func() {
		_ = sbom.Close()
		_ = os.Remove(sbom.Name())
	}()

	if err := w.client.Submit(ctx, item.Digest, sbom); err != nil {
		// The SBOM is lost, but the work is not: the item's lease expires and it is offered
		// again. Counted as failed because this worker did not deliver.
		w.exporter.Image(metrics.OutcomeFailed)
		w.log.Warn("handing back an sbom failed", "digest", item.Digest, "err", err)
		return
	}

	w.exporter.Image(metrics.OutcomeCatalogued)
	w.log.Info("catalogued", "digest", item.Digest,
		"duration_seconds", time.Since(started).Seconds())
}

// produce catalogues the image into a temporary file and returns it, rewound.
//
// A file rather than a pipe into the request body: an SBOM is a couple of megabytes, the
// temporary directory already has to exist for unpacking image layers, and a failure halfway
// through encoding then cannot leave a half-posted request behind.
func (w *Worker) produce(ctx context.Context, item workq.Item) (*os.File, error) {
	file, err := os.CreateTemp(w.tempDir, "kiebitzr-sbom-*.json")
	if err != nil {
		return nil, fmt.Errorf("create a temporary file for the sbom: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}
	}()

	if err := w.producer.CatalogueTo(ctx, item.Ref, file); err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind the sbom of %s: %w", item.Digest, err)
	}
	keep = true
	return file, nil
}

// sleep waits for the retry delay, or returns early when the context ends.
func (w *Worker) sleep(ctx context.Context) {
	timer := time.NewTimer(w.retry)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
