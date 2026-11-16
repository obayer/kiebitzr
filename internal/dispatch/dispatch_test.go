package dispatch

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/workq"
)

const (
	digestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	refA    = "registry.example/app@" + digestA
)

// handlerTransport dispatches a request straight into the handler, with no socket in between.
// The round trip is still a real one — client, encoding, status codes, handler — but it binds
// no port, so the test does not depend on being allowed to listen and cannot collide with
// anything else on the machine.
type handlerTransport struct{ handler http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// memStore is an in-memory stand-in for cache.Store, including its digest validation: that
// check is what stops a worker writing outside the cache directory, so the fake has to have it
// or the test would prove nothing.
type memStore struct {
	mu     sync.Mutex
	sboms  map[string]string
	failOn map[string]error
}

func newStore() *memStore {
	return &memStore{sboms: map[string]string{}, failOn: map[string]error{}}
}

func (s *memStore) Write(digest string, fn func(io.Writer) error) error {
	if !validDigest(digest) {
		return storeError("not a usable digest")
	}
	s.mu.Lock()
	err := s.failOn[digest]
	s.mu.Unlock()
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		return err
	}
	s.mu.Lock()
	s.sboms[digest] = buf.String()
	s.mu.Unlock()
	return nil
}

func (s *memStore) get(digest string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	content, ok := s.sboms[digest]
	return content, ok
}

func (s *memStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sboms)
}

type storeError string

func (e storeError) Error() string { return string(e) }

func validDigest(digest string) bool {
	alg, hex, found := strings.Cut(digest, ":")
	if !found || alg != "sha256" || len(hex) != 64 {
		return false
	}
	return !strings.ContainsFunc(hex, func(r rune) bool {
		return ('0' > r || r > '9') && ('a' > r || r > 'f')
	})
}

// harness is the work API with a client wired straight into it.
type harness struct {
	server  *Server
	handler http.Handler
	queue   *workq.Queue
	store   *memStore
	client  *Client
}

func newHarness(t *testing.T, poll time.Duration) *harness {
	t.Helper()
	queue := workq.New(workq.Options{Deadline: time.Minute, MaxAttempts: 3})
	store := newStore()
	server := NewServer(queue, store, slog.New(slog.DiscardHandler), poll)
	handler := server.Handler()
	return &harness{
		server:  server,
		handler: handler,
		queue:   queue,
		store:   store,
		client: &Client{
			base: "http://matcher.invalid",
			http: &http.Client{Transport: handlerTransport{handler}},
		},
	}
}

// fill gives the queue one item and hands it out, as a worker would.
func (h *harness) take(t *testing.T) workq.Item {
	t.Helper()
	h.queue.Fill([]workq.Item{{Digest: digestA, Ref: refA}})
	item, ok, err := h.client.Next(context.Background())
	if err != nil || !ok {
		t.Fatalf("Next() = %+v, %v, %v, want an item", item, ok, err)
	}
	return item
}

// The whole loop: ask for work, hand the SBOM back, see it committed and the item accounted
// for.
func TestWorkAndSubmitRoundTrip(t *testing.T) {
	h := newHarness(t, time.Second)
	item := h.take(t)

	if item.Digest != digestA || item.Ref != refA {
		t.Fatalf("Next() = %+v, want %s with its reference", item, digestA)
	}
	if err := h.client.Submit(context.Background(), item.Digest,
		strings.NewReader(`{"artifacts":[]}`)); err != nil {
		t.Fatalf("Submit() = %v, want no error", err)
	}

	if content, ok := h.store.get(digestA); !ok || content != `{"artifacts":[]}` {
		t.Fatalf("the store holds %q, %v, want the posted sbom", content, ok)
	}
	if out := h.queue.Outcome(); out.Done != 1 || len(out.Pending) != 0 {
		t.Fatalf("Outcome() = %+v, want the digest done", out)
	}
}

// An empty queue answers "nothing", and it does so by holding the request rather than by
// refusing it — which is what keeps an idle pool from polling in a loop.
func TestWorkAnswersNothingWhenTheQueueIsEmpty(t *testing.T) {
	h := newHarness(t, 20*time.Millisecond)

	started := time.Now()
	_, ok, err := h.client.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() = %v, want no error", err)
	}
	if ok {
		t.Fatal("Next() returned an item from an empty queue")
	}
	if time.Since(started) < 20*time.Millisecond {
		t.Fatal("the request was not held open for the poll window")
	}
}

// A digest that is not one must never reach the filesystem. Before a worker existed this
// guarded against an imageID a kubelet reported; now it is a network boundary.
func TestSubmitRejectsADigestThatIsNotOne(t *testing.T) {
	h := newHarness(t, time.Second)

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
		"/sbom/"+"not-a-digest", strings.NewReader("{}")))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /sbom with an invalid digest = %d, want 400", rec.Code)
	}
	if h.store.count() != 0 {
		t.Fatal("an invalid digest reached the store")
	}
}

func TestSubmitRejectsAnOversizedBody(t *testing.T) {
	h := newHarness(t, time.Second)
	h.server.maxSBOM = 16
	h.queue.Fill([]workq.Item{{Digest: digestA, Ref: refA}})

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
		"/sbom/"+digestA, strings.NewReader(strings.Repeat("x", 64))))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST /sbom over the limit = %d, want 413", rec.Code)
	}
	if h.store.count() != 0 {
		t.Fatal("an oversized body was committed")
	}
}

// A worker's verdict travels as a reason plus the underlying message, because the error type
// does not survive the trip and the metric alone cannot tell the causes apart.
func TestFailureCarriesTheReasonAndTheMessage(t *testing.T) {
	h := newHarness(t, time.Second)
	item := h.take(t)

	if err := h.client.Fail(context.Background(), item.Digest,
		metrics.ReasonUnreachable, "UNAUTHORIZED: authentication required"); err != nil {
		t.Fatalf("Fail() = %v, want no error", err)
	}

	out := h.queue.Outcome()
	if len(out.Failed) != 1 {
		t.Fatalf("Outcome() = %+v, want one failure", out)
	}
	if out.Failed[0].Reason != metrics.ReasonUnreachable {
		t.Fatalf("reason = %q, want %q", out.Failed[0].Reason, metrics.ReasonUnreachable)
	}
	if !strings.Contains(out.Failed[0].Message, "UNAUTHORIZED") {
		t.Fatalf("message = %q, want the registry's own words", out.Failed[0].Message)
	}
}

// A reason becomes a label value, so an invented one is refused rather than published.
func TestFailureRejectsAnUnknownReason(t *testing.T) {
	h := newHarness(t, time.Second)
	h.queue.Fill([]workq.Item{{Digest: digestA, Ref: refA}})

	for _, body := range []string{
		`{"reason":"made_up","message":"x"}`,
		`{"reason":"","message":"x"}`,
		`{"reason":"catalogue","extra":"unexpected field"}`,
		`not json`,
	} {
		t.Run(body, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
				"/failure/"+digestA, strings.NewReader(body)))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST /failure %s = %d, want 400", body, rec.Code)
			}
		})
	}
	if out := h.queue.Outcome(); len(out.Failed) != 0 {
		t.Fatalf("Outcome() = %+v, want every report refused", out)
	}
}

// A store that cannot be written leaves the item outstanding, so its lease expires and it is
// offered again — rather than being counted as done against an SBOM that is not there.
func TestSubmitThatCannotBeStoredLeavesTheItemOutstanding(t *testing.T) {
	h := newHarness(t, time.Second)
	h.store.failOn[digestA] = storeError("no space left on device")
	item := h.take(t)

	if err := h.client.Submit(context.Background(), item.Digest, strings.NewReader("{}")); err == nil {
		t.Fatal("Submit() = no error, want the rejection reported to the worker")
	}

	out := h.queue.Outcome()
	if out.Done != 0 {
		t.Fatalf("Done = %d, want 0: nothing was stored", out.Done)
	}
	if len(out.Pending) != 1 {
		t.Fatalf("Pending = %v, want the digest still outstanding", out.Pending)
	}
}

func TestNewClientRejectsAnUnusableURL(t *testing.T) {
	for _, base := range []string{"", "kiebitzr:8081", "ftp://kiebitzr:8081", "http://"} {
		t.Run(base, func(t *testing.T) {
			if _, err := NewClient(base, time.Second); err == nil {
				t.Fatalf("NewClient(%q) = no error, want one", base)
			}
		})
	}
}

func TestNewClientAcceptsAUsableURL(t *testing.T) {
	client, err := NewClient("http://kiebitzr-matcher:8081", time.Second)
	if err != nil {
		t.Fatalf("NewClient() = %v, want no error", err)
	}
	if client.http.Timeout != time.Second {
		t.Fatalf("timeout = %s, want 1s", client.http.Timeout)
	}
}
