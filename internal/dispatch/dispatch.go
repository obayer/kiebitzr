// Package dispatch puts a network between the work queue and the processes that do the work.
// The matcher serves the queue; workers poll it, catalogue one image and hand the SBOM back
// (ADR 0009).
//
// Workers pull, and nothing pushes to them. That is what keeps `list` on pods the only
// Kubernetes permission this service needs: a push model would have to discover worker pods,
// which costs either more rights or a message bus. Pulling costs a long-poll.
package dispatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/workq"
)

// maxSBOMBytes bounds the SBOM a worker may post. A measured SBOM is about 2 MB, and the
// largest images produce several times that, so the limit is generous — it exists to stop a
// worker filling the cache volume with one request, not to police image sizes.
const maxSBOMBytes = 256 << 20

// DefaultPollTimeout is how long a GET /work is held open before it answers "nothing".
// Long enough that an idle pool costs almost no requests, short enough that a worker notices
// a shutdown promptly.
const DefaultPollTimeout = 30 * time.Second

// SBOMWriter commits an SBOM under its digest, atomically. internal/cache implements it.
type SBOMWriter interface {
	Write(digest string, fn func(io.Writer) error) error
}

// Server is the matcher's side: it hands out work and takes results.
type Server struct {
	queue *workq.Queue
	store SBOMWriter
	log   *slog.Logger
	poll  time.Duration
	// maxSBOM is the body limit, a field rather than the constant so a test can reach the
	// rejection without producing a quarter of a gigabyte.
	maxSBOM int64
}

// NewServer returns the work API over one queue and one store. poll is how long a request for
// work waits before answering that there is none; zero uses DefaultPollTimeout.
func NewServer(queue *workq.Queue, store SBOMWriter, log *slog.Logger, poll time.Duration) *Server {
	if poll <= 0 {
		poll = DefaultPollTimeout
	}
	return &Server{queue: queue, store: store, log: log, poll: poll, maxSBOM: maxSBOMBytes}
}

// workItem is the wire form of a work item.
type workItem struct {
	Digest string `json:"digest"`
	Ref    string `json:"ref"`
}

// failureReport is the wire form of a worker's verdict on an image it could not catalogue.
// The message carries the registry's own words, which the metric cannot: an unreachable image
// has three causes that only the underlying error tells apart, and the log line is where the
// metrics runbook says to look for them.
type failureReport struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// Handler is the work API. It is deliberately not mounted next to /metrics: a POST surface
// does not belong on the endpoint Prometheus scrapes, and the two have to be separable by
// network policy.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /work", s.handleWork)
	mux.HandleFunc("POST /sbom/{digest}", s.handleSBOM)
	mux.HandleFunc("POST /failure/{digest}", s.handleFailure)
	return mux
}

// handleWork hands out one item, or answers that there is nothing to do. The wait is bounded
// by the poll timeout and by the request's own context, so a shutdown ends it too.
func (s *Server) handleWork(w http.ResponseWriter, r *http.Request) {
	// Bounded by the request's own context as well, so a client that goes away and a shutdown
	// both end the wait.
	ctx, cancel := context.WithTimeout(r.Context(), s.poll)
	defer cancel()

	item, ok := s.queue.Take(ctx)
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(workItem{Digest: item.Digest, Ref: item.Ref}); err != nil {
		// The item is already handed out, so it is not lost: its lease expires and it is
		// offered again. Nothing to do here but say so.
		s.log.Warn("handing out work failed", "digest", item.Digest, "err", err)
	}
}

// handleSBOM takes the SBOM a worker produced and commits it under its digest.
//
// The digest comes from the request path, and cache.Store.Write validates it before anything
// is written. That check used to guard against a digest a kubelet reported; here it is what
// stops a worker writing outside the cache directory, so an invalid one is a bad request and
// never reaches the filesystem.
func (s *Server) handleSBOM(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	body := http.MaxBytesReader(w, r.Body, s.maxSBOM)

	err := s.store.Write(digest, func(dst io.Writer) error {
		if _, copyErr := io.Copy(dst, body); copyErr != nil {
			return fmt.Errorf("read sbom of %s: %w", digest, copyErr)
		}
		return nil
	})
	if err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			http.Error(w, "sbom too large", http.StatusRequestEntityTooLarge)
			return
		}
		// A write that failed leaves no entry, so the item stays outstanding and is offered
		// again when its lease expires. The worker is told, so it can count the attempt.
		s.log.Warn("storing a worker's sbom failed", "digest", digest, "err", err)
		http.Error(w, "sbom rejected", http.StatusBadRequest)
		return
	}

	s.queue.Done(digest)
	w.WriteHeader(http.StatusNoContent)
}

// handleFailure records a worker's verdict on an image it could not catalogue.
func (s *Server) handleFailure(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")

	var report failureReport
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReportBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		http.Error(w, "malformed failure report", http.StatusBadRequest)
		return
	}
	// A reason becomes a label value, so an unknown one is refused rather than published:
	// otherwise a worker could invent series (ADR 0001's cardinality rule, from outside).
	if !metrics.IsReason(report.Reason) {
		http.Error(w, "unknown reason", http.StatusBadRequest)
		return
	}

	// The shape of this line is load-bearing: the metrics runbook points at `image failed`
	// with its digest and reason, and says the registry's own message is what tells the causes
	// of an unreachable image apart.
	s.log.Warn("image failed", "digest", digest, "reason", report.Reason, "err", report.Message)
	s.queue.Failed(digest, report.Reason, report.Message)
	w.WriteHeader(http.StatusNoContent)
}

// maxReportBytes bounds a failure report. It carries a reason and one error message.
const maxReportBytes = 64 << 10
