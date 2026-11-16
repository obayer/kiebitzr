package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/obayer/kiebitzr/internal/buildaccess"
	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/vulndb"
)

const (
	digestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeLister answers every list with the same pods, or with err.
type fakeLister struct {
	mu     sync.Mutex
	pods   []corev1.Pod
	err    error
	calls  int
	notify chan int
}

func (l *fakeLister) List(_ context.Context, _ metav1.ListOptions) (*corev1.PodList, error) {
	l.mu.Lock()
	l.calls++
	calls := l.calls
	l.mu.Unlock()

	if l.notify != nil {
		l.notify <- calls
	}
	if l.err != nil {
		return nil, l.err
	}
	return &corev1.PodList{Items: l.pods}, nil
}

func (l *fakeLister) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// fakeProducer stands in for internal/catalog: it writes an SBOM for a reference, or fails.
// Errors are keyed by digest, which it takes from the reference the way a real pull does.
type fakeProducer struct {
	errs   map[string]error
	called []string
	delay  time.Duration
}

func (p *fakeProducer) CatalogueTo(_ context.Context, ref string, w io.Writer) error {
	_, digest, _ := strings.Cut(ref, "@")
	p.called = append(p.called, digest)
	time.Sleep(p.delay)
	if err := p.errs[digest]; err != nil {
		return err
	}
	_, err := io.WriteString(w, `{"artifacts":[]}`)
	return err
}

// fakeStore is an in-memory SBOM cache.
type fakeStore struct {
	sboms    map[string]string
	openErrs map[string]error
	writeErr error
	pruned   []map[string]struct{}
	pruneErr error
}

func (s *fakeStore) Has(digest string) bool {
	_, ok := s.sboms[digest]
	return ok
}

func (s *fakeStore) Open(digest string) (io.ReadSeekCloser, error) {
	if err := s.openErrs[digest]; err != nil {
		return nil, err
	}
	content, ok := s.sboms[digest]
	if !ok {
		return nil, errors.New("not cached")
	}
	return nopSeekCloser{bytes.NewReader([]byte(content))}, nil
}

// Write mirrors cache.Store.Write: the entry appears only when the function succeeded, so a
// failed catalogue leaves the digest uncached and Has keeps reporting false.
func (s *fakeStore) Write(digest string, fn func(io.Writer) error) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		return err
	}
	s.sboms[digest] = buf.String()
	return nil
}

func (s *fakeStore) Prune(keep map[string]struct{}) (int, error) {
	s.pruned = append(s.pruned, keep)
	return 0, s.pruneErr
}

type nopSeekCloser struct{ *bytes.Reader }

func (nopSeekCloser) Close() error { return nil }

// fakeSession returns prepared findings per digest, and what the policy would have removed
// from them.
type fakeSession struct {
	findings   map[string][]metrics.Vulnerability
	suppressed map[string][]metrics.Suppressed
	errs       map[string]error
	built      time.Time
	closed     bool
}

func (s *fakeSession) Match(_ context.Context, digest string, sbom io.ReadSeeker) (vulndb.MatchResult, error) {
	if _, err := io.ReadAll(sbom); err != nil {
		return vulndb.MatchResult{}, err
	}
	if err := s.errs[digest]; err != nil {
		return vulndb.MatchResult{}, err
	}
	return vulndb.MatchResult{Findings: s.findings[digest], Suppressed: s.suppressed[digest]}, nil
}

func (s *fakeSession) Built() (time.Time, bool) { return s.built, !s.built.IsZero() }

func (s *fakeSession) Close() error {
	s.closed = true
	return nil
}

// fakeOpener hands out one session, or fails.
type fakeOpener struct {
	session *fakeSession
	err     error
	opens   int
}

func (o *fakeOpener) Open(_ context.Context) (vulndb.Session, error) {
	o.opens++
	if o.err != nil {
		return nil, o.err
	}
	return o.session, nil
}

func runningPod(name, image, imageID string) corev1.Pod {
	return corev1.Pod{
		Namespace: "prod", Name: name,
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:    "app",
				Image:   image,
				ImageID: imageID,
			}},
		},
	}
}

func vuln(digest, cve string) metrics.Vulnerability {
	return metrics.Vulnerability{
		Digest:        digest,
		CVE:           cve,
		Severity:      "High",
		Package:       "openssl",
		SourcePackage: "openssl",
		PackageType:   "apk",
		Installed:     "3.0.11-r0",
		Location:      "/lib/apk/db/installed",
		FixedIn:       "3.0.12-r0",
		FixState:      "fixed",
	}
}

// harness is a runner with every collaborator faked. Cataloguing goes through the real Serial
// stage over a fake producer, so the tests exercise the path a single-pod installation uses.
type harness struct {
	lister   *fakeLister
	store    *fakeStore
	producer *fakeProducer
	opener   *fakeOpener
	session  *fakeSession
	exporter *metrics.Exporter
	runner   *Runner
}

func newHarness(t *testing.T, pods ...corev1.Pod) *harness {
	t.Helper()

	session := &fakeSession{
		findings:   map[string][]metrics.Vulnerability{},
		suppressed: map[string][]metrics.Suppressed{},
		errs:       map[string]error{},
		built:      time.Unix(1762200000, 0),
	}
	log := slog.New(slog.DiscardHandler)
	h := &harness{
		lister:   &fakeLister{pods: pods},
		store:    &fakeStore{sboms: map[string]string{}, openErrs: map[string]error{}},
		producer: &fakeProducer{errs: map[string]error{}},
		opener:   &fakeOpener{session: session},
		session:  session,
		exporter: metrics.New(),
	}
	h.runner = New(h.lister, h.store, NewSerial(h.producer, h.store, log),
		h.opener, h.exporter, log, Options{
			Interval:         time.Minute,
			Timeout:          time.Minute,
			CatalogueTimeout: 45 * time.Second,
		})
	return h
}

func (h *harness) scrape(t *testing.T) string {
	t.Helper()
	return scrape(t, h.exporter)
}

// scrape is what a Prometheus server would see.
func scrape(t *testing.T, exporter *metrics.Exporter) string {
	t.Helper()
	rec := httptest.NewRecorder()
	exporter.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

func mustContain(t *testing.T, body string, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if !strings.Contains(body, line) {
			t.Fatalf("scrape does not contain %q:\n%s", line, body)
		}
	}
}

func TestRunPublishesImagesAndFindings(t *testing.T) {
	h := newHarness(t,
		runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA),
		runningPod("api-0", "registry.example/api:2.0.0", "registry.example/api@"+digestB),
	)
	// digestA has no SBOM yet and is catalogued by this run; digestB already has one.
	h.store.sboms[digestB] = `{"artifacts":[]}`
	h.session.findings[digestA] = []metrics.Vulnerability{vuln(digestA, "CVE-2024-0001")}

	h.runner.Run(context.Background())

	body := h.scrape(t)
	mustContain(t, body,
		`kiebitzr_image_info{build_access="unknown",container="app",image="registry.example/app:1.4.0",image_digest="`+digestA+
			`",namespace="prod",owner_kind="Pod",owner_name="web-0"} 1`,
		`kiebitzr_vulnerability{cve="CVE-2024-0001",fix_state="fixed",fixed_in="3.0.12-r0",image_digest="`+digestA+
			`",installed="3.0.11-r0",known_exploited="false",location="/lib/apk/db/installed",package="openssl",package_type="apk",severity="High",source_package="openssl"} 1`,
		`kiebitzr_images{state="scanned"} 1`,
		`kiebitzr_images{state="cached"} 1`,
		`kiebitzr_images{state="failed"} 0`,
		`kiebitzr_images{state="pending"} 0`,
		`kiebitzr_db_built_timestamp_seconds 1.7622e+09`,
	)
	if strings.Contains(body, "kiebitzr_last_success_timestamp_seconds 0\n") {
		t.Fatalf("last success is still zero after a successful run:\n%s", body)
	}
	if !h.session.closed {
		t.Fatal("the vulnerability database was not closed after the run")
	}
}

// The classification has to reach the series an operator queries, and it is applied per
// reference: one digest reached under two names keeps one answer per name, each correct for
// what it describes. A query that wants one answer per digest aggregates.
func TestRunClassifiesImagesByBuildAccess(t *testing.T) {
	h := newHarness(t,
		runningPod("web-0", "registry.example/org/platform/app:1.4.0",
			"registry.example/org/platform/app@"+digestA),
		runningPod("mirror-0", "registry.example/org/mirror/app:1.4.0",
			"registry.example/org/mirror/app@"+digestA),
		runningPod("api-0", "ghcr.io/someone/tool:2.0.0", "ghcr.io/someone/tool@"+digestB),
	)
	h.store.sboms[digestA] = `{"artifacts":[]}`
	h.store.sboms[digestB] = `{"artifacts":[]}`
	h.runner.opts.BuildAccess = buildAccessRules(t, `
build-access:
  - repository: registry.example/org/platform/*
    access: own
  - repository: registry.example/org/mirror/*
    access: none
`)

	h.runner.Run(context.Background())

	body := h.scrape(t)
	mustContain(t, body,
		`kiebitzr_image_info{build_access="own",container="app",image="registry.example/org/platform/app:1.4.0",`,
		`kiebitzr_image_info{build_access="none",container="app",image="registry.example/org/mirror/app:1.4.0",`,
		// Nothing classified it, which is a work item and not a verdict.
		`kiebitzr_image_info{build_access="unknown",container="app",image="ghcr.io/someone/tool:2.0.0",`,
	)
}

// An installation that declares nothing gets "unknown" everywhere, not "none": nobody has
// looked, and that is a different statement from "there is nobody to ask".
func TestRunWithoutBuildAccessRulesPublishesUnknown(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0",
		"registry.example/app@"+digestA))
	h.store.sboms[digestA] = `{"artifacts":[]}`

	h.runner.Run(context.Background())

	mustContain(t, h.scrape(t), `kiebitzr_image_info{build_access="unknown",`)
}

func buildAccessRules(t *testing.T, content string) *buildaccess.Rules {
	t.Helper()
	path := filepath.Join(t.TempDir(), "build-access.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimPrefix(content, "\n")), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v, want no error", err)
	}
	rules, err := buildaccess.Load(path)
	if err != nil {
		t.Fatalf("buildaccess.Load() = %v, want no error", err)
	}
	return rules
}

// What the filters removed belongs in the published result for the same reason the findings
// do: it is produced once per run, and a configuration that hides a lot has to be readable as
// a number rather than as a quiet screen.
func TestRunPublishesWhatTheFiltersRemoved(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0",
		"registry.example/app@"+digestA))
	h.store.sboms[digestA] = `{"artifacts":[]}`
	h.session.findings[digestA] = []metrics.Vulnerability{vuln(digestA, "CVE-2024-0001")}
	h.session.suppressed[digestA] = []metrics.Suppressed{
		{Digest: digestA, Reason: metrics.SuppressedMinSeverity, Count: 112},
	}

	h.runner.Run(context.Background())

	mustContain(t, h.scrape(t),
		`kiebitzr_vulnerability_suppressed{image_digest="`+digestA+`",reason="min_severity"} 112`)
}

// Without a database a published result would claim that nothing is vulnerable, so the run
// has to fail and leave the previous result in place.
func TestRunWithoutADatabaseKeepsThePreviousResult(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA))
	h.store.sboms[digestA] = "{}"
	h.session.findings[digestA] = []metrics.Vulnerability{vuln(digestA, "CVE-2024-0001")}
	h.runner.Run(context.Background())
	before := successLine(h.scrape(t))

	h.opener.err = errors.New("database too old")
	h.runner.Run(context.Background())

	body := h.scrape(t)
	mustContain(t, body,
		`kiebitzr_scan_errors_total{reason="database"} 1`,
		`kiebitzr_vulnerability{cve="CVE-2024-0001",`,
	)
	if got := successLine(body); got != before {
		t.Fatalf("last success = %q, want it unchanged at %q", got, before)
	}
}

func TestRunWithoutAnInventoryFails(t *testing.T) {
	h := newHarness(t)
	h.lister.err = errors.New("pods is forbidden")

	h.runner.Run(context.Background())

	mustContain(t, h.scrape(t), `kiebitzr_scan_errors_total{reason="list_pods"} 1`)
	if h.opener.opens != 0 {
		t.Fatal("the database was opened although the inventory had failed")
	}
}

// One unreachable image must not cost the findings of every other image.
func TestRunContinuesAfterAFailedImage(t *testing.T) {
	h := newHarness(t,
		runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA),
		runningPod("api-0", "registry.example/api:2.0.0", "registry.example/api@"+digestB),
	)
	h.producer.errs[digestA] = errors.New("unauthorized")
	h.store.sboms[digestB] = "{}"
	h.session.findings[digestB] = []metrics.Vulnerability{vuln(digestB, "CVE-2024-0002")}

	h.runner.Run(context.Background())

	body := h.scrape(t)
	mustContain(t, body,
		`kiebitzr_scan_errors_total{reason="catalogue"} 1`,
		`kiebitzr_images{state="failed"} 1`,
		`kiebitzr_images{state="cached"} 1`,
		`kiebitzr_vulnerability{cve="CVE-2024-0002",`,
	)
	// The run as a whole succeeded, so its freshness timestamp moves.
	if successLine(body) == "kiebitzr_last_success_timestamp_seconds 0" {
		t.Fatalf("a run with one failed image must still count as a run:\n%s", body)
	}
	// Both digests still appear as running images; only the findings are missing.
	mustContain(t, body, `image_digest="`+digestA+`"`)
}

// unreachableImageError stands for what internal/catalog returns when the image cannot be reached
// for the configured platform. The run loop recognises it by its method, not by its type.
type unreachableImageError struct{}

func (unreachableImageError) Error() string       { return "no matching manifest for linux/arm64" }
func (unreachableImageError) ResolveFailed() bool { return true }

// A wrong platform, a missing credential or an image that was never pushed is a different
// problem from an image whose contents break the cataloguer, and the metrics have to say so.
func TestRunSeparatesUnreachableImagesFromFailedCataloguing(t *testing.T) {
	h := newHarness(t,
		runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA),
		runningPod("api-0", "registry.example/api:2.0.0", "registry.example/api@"+digestB),
	)
	h.producer.errs[digestA] = fmt.Errorf("catalogue: %w", unreachableImageError{})
	h.producer.errs[digestB] = errors.New("malformed package database")

	h.runner.Run(context.Background())

	mustContain(t, h.scrape(t),
		`kiebitzr_scan_errors_total{reason="unreachable_image"} 1`,
		`kiebitzr_scan_errors_total{reason="catalogue"} 1`,
		`kiebitzr_images{state="failed"} 2`,
		// The counter says how many failed at each stage; these say which digest did, which
		// is the question an operator actually has in front of a cluster.
		`kiebitzr_image_failed{image_digest="`+digestA+`",reason="unreachable_image"} 1`,
		`kiebitzr_image_failed{image_digest="`+digestB+`",reason="catalogue"} 1`,
	)
}

func TestRunCountsAFailedMatch(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA))
	h.store.sboms[digestA] = "{}"
	h.session.errs[digestA] = errors.New("sbom is not readable")

	h.runner.Run(context.Background())

	mustContain(t, h.scrape(t),
		`kiebitzr_scan_errors_total{reason="match"} 1`,
		`kiebitzr_images{state="failed"} 1`,
	)
}

func TestRunCountsAnUnreadableCacheEntry(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA))
	// The entry exists, so the digest is never handed to cataloguing — and then cannot be read.
	h.store.sboms[digestA] = "{}"
	h.store.openErrs[digestA] = errors.New("permission denied")

	h.runner.Run(context.Background())

	mustContain(t, h.scrape(t),
		`kiebitzr_scan_errors_total{reason="catalogue"} 1`,
		`kiebitzr_images{state="failed"} 1`,
	)
}

func TestRunCountsUnresolvedImageIDs(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0", ""))

	h.runner.Run(context.Background())

	mustContain(t, h.scrape(t), `kiebitzr_scan_errors_total{reason="unresolved_image_id"} 1`)
}

func TestRunPrunesTheCacheToTheRunningDigests(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA))
	h.store.sboms[digestA] = "{}"

	h.runner.Run(context.Background())

	if len(h.store.pruned) != 1 {
		t.Fatalf("Prune called %d times, want once", len(h.store.pruned))
	}
	if got := slices.Sorted(maps.Keys(h.store.pruned[0])); !slices.Equal(got, []string{digestA}) {
		t.Fatalf("Prune kept %v, want only the running digest", got)
	}
}

func TestRunReportsAFailedPruneWithoutFailingTheRun(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA))
	h.store.sboms[digestA] = "{}"
	h.store.pruneErr = errors.New("read-only file system")

	h.runner.Run(context.Background())

	body := h.scrape(t)
	mustContain(t, body, `kiebitzr_scan_errors_total{reason="cache_write"} 1`)
	if successLine(body) == "kiebitzr_last_success_timestamp_seconds 0" {
		t.Fatalf("a failed prune must not fail the run:\n%s", body)
	}
}

// A run has to be allowed to outlive its interval. The first run of a cold cache catalogues
// every image in the cluster, and tying the bound to the interval would mean such an
// installation never finishes a catalogue.
func TestRunIsBoundedByTheTimeoutNotTheInterval(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA))
	h.runner.opts.Interval = time.Millisecond
	h.runner.opts.Timeout = time.Minute
	h.producer.delay = 20 * time.Millisecond // far longer than the interval
	h.session.findings[digestA] = []metrics.Vulnerability{vuln(digestA, "CVE-2024-0001")}

	h.runner.Run(context.Background())

	body := h.scrape(t)
	mustContain(t, body, `kiebitzr_vulnerability{cve="CVE-2024-0001",`)
	if successLine(body) == "kiebitzr_last_success_timestamp_seconds 0" {
		t.Fatalf("a run longer than the interval was not allowed to finish:\n%s", body)
	}
}

// A digest that already has an SBOM is never catalogued again. That is what makes a
// steady-state run a diff rather than a rescan, and with a worker pool it is also what keeps
// the work list short.
func TestRunNeverCataloguesACachedDigest(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA))
	h.store.sboms[digestA] = "{}"

	h.runner.Run(context.Background())

	if len(h.producer.called) != 0 {
		t.Fatalf("cataloguing was asked for %v, want nothing for a cached digest", h.producer.called)
	}
	mustContain(t, h.scrape(t),
		`kiebitzr_images{state="cached"} 1`,
		`kiebitzr_images{state="scanned"} 0`,
	)
}

// stubCataloguing returns a fixed report without doing anything, so a run can be exercised
// against outcomes the serial stage would need real timing to produce.
type stubCataloguing struct{ report Report }

func (s stubCataloguing) Catalogue(context.Context, []Work) Report { return s.report }

// Cataloguing that runs out of its budget must not cost the whole run. This is the cold-start
// case: the digests that were catalogued are published with their findings, and the ones that
// were not are named as pending rather than appearing clean.
func TestRunPublishesWithPendingDigests(t *testing.T) {
	h := newHarness(t,
		runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA),
		runningPod("api-0", "registry.example/api:2.0.0", "registry.example/api@"+digestB),
	)
	// digestA was catalogued before the budget ran out; digestB never got looked at.
	h.store.sboms[digestA] = "{}"
	h.session.findings[digestA] = []metrics.Vulnerability{vuln(digestA, "CVE-2024-0001")}
	h.runner.catalogue = stubCataloguing{report: Report{Pending: []string{digestB}}}

	h.runner.Run(context.Background())

	body := h.scrape(t)
	mustContain(t, body,
		`kiebitzr_image_pending{image_digest="`+digestB+`"} 1`,
		`kiebitzr_images{state="pending"} 1`,
		`kiebitzr_images{state="failed"} 0`,
		// The work that was done is published, not withheld.
		`kiebitzr_vulnerability{cve="CVE-2024-0001",`,
	)
	// A pending digest is not a failure: nothing is known to be wrong with that image.
	mustContain(t, body, `kiebitzr_scan_errors_total{reason="catalogue"} 0`)
	if successLine(body) == "kiebitzr_last_success_timestamp_seconds 0" {
		t.Fatalf("a run with pending digests must still count as a run:\n%s", body)
	}
	// Both digests are still reported as running; only digestB has no findings yet.
	mustContain(t, body, `image_digest="`+digestB+`"`)
}

// A cancelled run must not publish its partial result as if it were complete.
func TestRunDoesNotPublishACancelledRun(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0", "registry.example/app@"+digestA))
	h.store.sboms[digestA] = "{}"
	h.session.findings[digestA] = []metrics.Vulnerability{vuln(digestA, "CVE-2024-0001")}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.runner.Run(ctx)

	body := h.scrape(t)
	if strings.Contains(body, "kiebitzr_vulnerability{") {
		t.Fatalf("a cancelled run published findings:\n%s", body)
	}
	mustContain(t, body, "kiebitzr_last_success_timestamp_seconds 0")
}

func TestLoopRunsImmediatelyAndStopsOnCancel(t *testing.T) {
	h := newHarness(t)
	h.lister.notify = make(chan int, 4)
	h.runner.opts.Interval = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.runner.Loop(ctx)
		close(done)
	}()

	// The first run must not wait for the first tick.
	select {
	case <-h.lister.notify:
	case <-time.After(5 * time.Second):
		t.Fatal("Loop did not run before the first tick")
	}
	// Drain, so the loop is never blocked on the notify channel while we wait for it to stop.
	go func() {
		for range h.lister.notify {
		}
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Loop did not return after the context was cancelled")
	}
	if h.lister.callCount() == 0 {
		t.Fatal("Loop never listed pods")
	}
}

// successLine returns the kiebitzr_last_success_timestamp_seconds sample of a scrape.
func successLine(body string) string {
	for line := range strings.Lines(body) {
		if strings.HasPrefix(line, "kiebitzr_last_success_timestamp_seconds ") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
