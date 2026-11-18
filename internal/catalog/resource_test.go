//go:build integration

package catalog

// The resource harness: what a run costs in memory and time, measured per phase against real
// images, at a resolution the cluster cannot reach.
//
// Why it exists. The sizing figures in ADR 0001 and `running-kiebitzr.md` come from one pilot
// observation, and reading the exporter's own `go_*` series back out of Prometheus cannot
// confirm them: the peak lasts one to two scrapes at a 60-second interval, so what comes back
// is a lower bound on a spike whose real height nobody has seen. Sampling inside the process
// closes exactly that gap, and nothing else here is new — the phases below are the ones the
// run loop already performs, in the order it performs them.
//
// What it deliberately does not do. It takes no profile and attributes nothing to a function.
// That is the next step and only worth taking if the numbers here point somewhere; a harness
// that answers "how much" is cheap, one that answers "where" needs pprof and a decision about
// shipping it.

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	runtimemetrics "runtime/metrics"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/obayer/kiebitzr/internal/cache"
	"github.com/obayer/kiebitzr/internal/vulndb"
)

// profileEnv gates the harness. Both tests below are in the `integration` build and would
// otherwise run as part of `test:integration`, where they do not belong: they catalogue
// several images instead of one and take tens of minutes. `mise run measure` sets it.
const profileEnv = "KIEBITZR_PROFILE"

// sampleInterval is how often the Go runtime's own accounting is read while a phase runs.
// 50 ms against a peak that lasts seconds leaves no room for the sampling error that makes
// the Prometheus figures a lower bound, and the read itself costs five counters.
const sampleInterval = 50 * time.Millisecond

// defaultProfileImages span the range that matters for memory, in both size and ecosystem: a
// single static binary, a distribution base with a binary on top, and a large interpreted
// image whose packages come from three managers at once. Roughly 27, 45 and 559 MiB of
// layers, which is the spread the scaling question needs — whether the peak follows what
// there is to catalogue, or sits at a fixed cost.
//
// All are on `ghcr.io`, and that is a constraint rather than a preference: the agent sandbox
// allowlists that registry and the host it serves blobs from, so a subject on `gcr.io`,
// `quay.io` or Docker Hub fails to resolve before it is ever catalogued. Docker Hub would be
// the wrong default anyway — its unauthenticated pull limit is what TODO T16 and T17 are
// about, and a harness that trips it measures the rate limiter. Measuring elsewhere means
// extending `allow_domain` in the sandbox profile.
//
// This is not the cluster's inventory on purpose: the harness has to be repeatable by
// somebody who has no cluster. Override it with KIEBITZR_PROFILE_IMAGES, comma-separated,
// to measure what you actually run; the last entry is what the parallelism sweep uses.
var defaultProfileImages = []string{
	"ghcr.io/anchore/syft:v1.56.0",
	"ghcr.io/aquasecurity/trivy:0.58.0",
	"ghcr.io/home-assistant/home-assistant:2025.1.0",
}

// catalogueParallelism is the sweep of the knob in catalog.go. One is what ships; the comment
// on the constant claims that raising it multiplies peak memory, and this is what checks it.
var catalogueParallelism = []int{1, 2, 4}

// TestResourceUseOfTheRunPhases measures each phase of a cold run against every subject image:
// reaching the registry, cataloguing with Syft, and matching the SBOM against the real
// vulnerability database. It downloads that database once, like a first run in a cluster does.
func TestResourceUseOfTheRunPhases(t *testing.T) {
	requireProfiling(t)

	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatalf("cache.New() = %v, want no error", err)
	}
	cataloguer, err := New(platformOrDefault())
	if err != nil {
		t.Fatalf("New() = %v, want no error", err)
	}
	database, err := vulndb.New(vulndb.Config{Dir: store.DatabaseDir()}, "resource-harness")
	if err != nil {
		t.Fatalf("vulndb.New() = %v, want no error", err)
	}

	rows := &table{}

	// Opening the database is a phase of its own: Grype downloads and opens hundreds of
	// megabytes here, and whether that stays in the heap or in the page cache is half the
	// question about how much memory the container needs.
	var session vulndb.Session
	cost, err := measure(func() error {
		var openErr error
		session, openErr = database.Open(context.Background())
		return openErr
	})
	if err != nil {
		t.Fatalf("Open() = %v, want no error (is grype.anchore.io reachable?)", err)
	}
	defer func() { _ = session.Close() }()
	rows.add("(database)", "open", cost, "")

	if built, ok := session.Built(); ok {
		t.Logf("vulnerability database built %s", built.Format(time.RFC3339))
	}

	for _, image := range profileImages() {
		// One subject per subtest, because a subject that cannot be reached must not take
		// the other measurements down with it: resolving is fatal, and a registry this
		// machine has no route to is the likeliest thing to go wrong here.
		t.Run(image, func(t *testing.T) {
			measureOneImage(t, rows, store, cataloguer, session, image)
		})
	}

	t.Log("\n" + rows.String())
}

// measureOneImage takes the three per-image phases of a cold run: reaching the registry,
// cataloguing, and matching the result against the open database.
func measureOneImage(
	t *testing.T, rows *table, store *cache.Store,
	cataloguer *Cataloguer, session vulndb.Session, image string,
) {
	t.Helper()

	var digest, ref string
	cost, err := measure(func() error {
		digest, ref = resolve(t, image)
		return nil
	})
	if err != nil {
		t.Fatalf("resolve(%s) = %v, want no error", image, err)
	}
	rows.add(image, "resolve", cost, "")

	cost, err = measure(func() error {
		return store.Write(digest, func(w io.Writer) error {
			return cataloguer.CatalogueTo(context.Background(), ref, w)
		})
	})
	if err != nil {
		t.Fatalf("CatalogueTo(%s) = %v, want no error", ref, err)
	}
	rows.add(image, "catalogue", cost, "sbom "+mib(sbomBytes(t, store, digest)))

	var findings int
	cost, err = measure(func() error {
		sbom, openErr := store.Open(digest)
		if openErr != nil {
			return openErr
		}
		defer func() { _ = sbom.Close() }()

		result, matchErr := session.Match(context.Background(), digest, sbom)
		findings = len(result.Findings)
		return matchErr
	})
	if err != nil {
		t.Fatalf("Match(%s) = %v, want no error", digest, err)
	}
	rows.add(image, "match", cost, fmt.Sprintf("%d findings", findings))
}

// TestPeakMemoryAgainstCatalogueParallelism catalogues one image repeatedly with Syft's
// parallelism raised, and reports what that does to the peak. It answers the open question of
// ADR 0001 that the `parallelism = 1` constant rests on — whether parallel cataloguing really
// multiplies peak memory, and if so by how much.
//
// The subject is the largest of the default images, because a knob that costs nothing on a
// small image says nothing about the case the constant was chosen for.
func TestPeakMemoryAgainstCatalogueParallelism(t *testing.T) {
	requireProfiling(t)

	images := profileImages()
	image := images[len(images)-1]

	cataloguer, err := New(platformOrDefault())
	if err != nil {
		t.Fatalf("New() = %v, want no error", err)
	}
	digest, ref := resolve(t, image)

	rows := &table{}
	for _, parallelism := range catalogueParallelism {
		// A fresh store per round, so no round can take the previous round's SBOM from the
		// cache instead of cataloguing.
		store, storeErr := cache.New(t.TempDir())
		if storeErr != nil {
			t.Fatalf("cache.New() = %v, want no error", storeErr)
		}

		cost, measureErr := measure(func() error {
			return store.Write(digest, func(w io.Writer) error {
				return cataloguer.catalogueTo(context.Background(), ref, w, parallelism)
			})
		})
		if measureErr != nil {
			t.Errorf("catalogueTo(%s, parallelism=%d) = %v, want no error", ref, parallelism, measureErr)
			continue
		}
		rows.add(image, fmt.Sprintf("parallelism %d", parallelism), cost, "")
	}

	t.Log("\n" + rows.String())
}

// requireProfiling skips unless the harness was asked for, and says how to ask.
func requireProfiling(t *testing.T) {
	t.Helper()
	if os.Getenv(profileEnv) == "" {
		t.Skipf("set %s=1, or run `mise run measure`, to take the resource measurements", profileEnv)
	}
}

// profileImages is the subject list, overridable for an installation's own images.
func profileImages() []string {
	if list := os.Getenv("KIEBITZR_PROFILE_IMAGES"); list != "" {
		var images []string
		for image := range strings.SplitSeq(list, ",") {
			if image = strings.TrimSpace(image); image != "" {
				images = append(images, image)
			}
		}
		if len(images) > 0 {
			return images
		}
	}
	return defaultProfileImages
}

// cost is what one phase took.
type cost struct {
	elapsed time.Duration
	// peakLive is the high-water mark of reachable heap objects during the phase — the
	// figure ADR 0001 calls the live heap.
	peakLive uint64
	// peakMapped is the high-water mark of memory the runtime holds from the operating
	// system and has not released: the arena, and what a container limit has to cover.
	peakMapped uint64
	// allocated is everything the phase allocated, collected or not. It is the allocation
	// pressure behind the peak, and the number an optimisation would move.
	allocated uint64
	gcCycles  uint64
	// maxRSS is the process high-water mark after the phase. It only ever rises, so it says
	// which phase raised it rather than what this phase alone used.
	maxRSS  uint64
	samples int
}

// measure runs fn while sampling the Go runtime's own accounting, and reports what it cost.
//
// The heap is settled first: without that, memory the previous phase allocated and the
// collector has not yet returned counts against this one, which is how a cheap phase inherits
// an expensive one's peak.
func measure(fn func() error) (cost, error) {
	settle()

	type peak struct {
		live, mapped uint64
		samples      int
	}
	var (
		stop   = make(chan struct{})
		peaked = make(chan peak, 1)
	)
	go func() {
		var p peak
		ticker := time.NewTicker(sampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				peaked <- p
				return
			case <-ticker.C:
				state := readRuntime()
				p.samples++
				p.live = max(p.live, state.live)
				p.mapped = max(p.mapped, state.mapped)
			}
		}
	}()

	before := readRuntime()
	started := time.Now()
	err := fn()
	elapsed := time.Since(started)
	close(stop)
	p := <-peaked
	after := readRuntime()

	return cost{
		elapsed: elapsed,
		// A phase shorter than the tick can escape every sample, so the state on either
		// side of it counts too: a peak below what was measurably there is not a peak.
		peakLive:   max(p.live, before.live, after.live),
		peakMapped: max(p.mapped, before.mapped, after.mapped),
		allocated:  after.allocs - before.allocs,
		gcCycles:   after.cycles - before.cycles,
		maxRSS:     maxRSS(),
		samples:    p.samples,
	}, err
}

// settle collects twice and hands what it can back to the operating system, so each phase
// starts from a comparable baseline. Twice, because the first cycle can leave objects that
// only became unreachable during it.
func settle() {
	runtime.GC()
	runtime.GC()
	debug.FreeOSMemory()
}

// runtimeState is one reading of the runtime's memory accounting.
type runtimeState struct {
	live, mapped, allocs, cycles uint64
}

// readRuntime takes one reading. The sample slice is built per call rather than shared: the
// sampling goroutine and the phase itself both read, and runtimemetrics.Read writes into the
// slice it is given.
func readRuntime() runtimeState {
	samples := []runtimemetrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/gc/heap/allocs:bytes"},
		{Name: "/gc/cycles/total:gc-cycles"},
	}
	runtimemetrics.Read(samples)
	return runtimeState{
		live: samples[0].Value.Uint64(),
		// Total minus released is what is actually backed by memory. Total alone counts
		// address space the runtime has already given back, which no limit has to cover.
		mapped: samples[1].Value.Uint64() - samples[2].Value.Uint64(),
		allocs: samples[3].Value.Uint64(),
		cycles: samples[4].Value.Uint64(),
	}
}

// maxRSS is the process' resident high-water mark, as the kernel accounts it. It is the one
// figure here that includes what is not heap — the mapped vulnerability database, the
// runtime's own structures — and therefore the closest of these to what a container limit
// is measured against.
func maxRSS() uint64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	rss := uint64(usage.Maxrss)
	if runtime.GOOS != "darwin" {
		// Darwin reports bytes, Linux and the BSDs kilobytes.
		rss *= 1024
	}
	return rss
}

// sbomBytes is the size of the stored SBOM, which is the cheapest proxy for how much there
// was to catalogue — the question is whether the peak follows it.
func sbomBytes(t *testing.T, store *cache.Store, digest string) uint64 {
	t.Helper()
	sbom, err := store.Open(digest)
	if err != nil {
		t.Fatalf("Open(%s) = %v, want no error", digest, err)
	}
	defer func() { _ = sbom.Close() }()

	size, err := sbom.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatalf("Seek(%s) = %v, want no error", digest, err)
	}
	return uint64(size)
}

// table collects the measurements so the whole run prints as one block rather than
// interleaved with Syft's logging.
type table struct {
	rows []string
}

func (t *table) add(subject, phase string, c cost, note string) {
	if len(t.rows) == 0 {
		t.rows = append(t.rows,
			fmt.Sprintf("%-44s %-14s %9s %9s %9s %9s %9s %5s  %s",
				"SUBJECT", "PHASE", "TIME", "LIVE", "MAPPED", "ALLOC", "MAXRSS", "GC", "NOTE"))
	}
	t.rows = append(t.rows,
		fmt.Sprintf("%-44s %-14s %9s %9s %9s %9s %9s %5d  %s",
			truncate(subject, 44), phase, c.elapsed.Round(time.Millisecond),
			mib(c.peakLive), mib(c.peakMapped), mib(c.allocated), mib(c.maxRSS),
			c.gcCycles, note))
}

func (t *table) String() string { return strings.Join(t.rows, "\n") }

func mib(bytes uint64) string {
	return fmt.Sprintf("%.1fMiB", float64(bytes)/(1<<20))
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-1] + "…"
}
