//go:build integration

package runner

import (
	"context"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	corev1 "k8s.io/api/core/v1"

	"github.com/obayer/kiebitzr/internal/cache"
	"github.com/obayer/kiebitzr/internal/catalog"
	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/vulndb"
)

// defaultImage is a small, public, multi-arch image standing in for what a cluster runs.
// Override it with KIEBITZR_TEST_IMAGE.
const defaultImage = "ghcr.io/anchore/syft:v1.56.0"

// TestRunAgainstARealImage is the whole pipeline with nothing faked but the cluster: a real
// registry, Syft, the real vulnerability database and Grype. It needs network access to the
// registry and to the database host, and it downloads the database, so it is behind the
// `integration` build tag.
//
// It is also where the resource questions of ADR 0001 get their answer: the log line at the
// end reports how long a cold run of one image takes.
//
// The default subject is a Go image, which exercises the *invariants* of `source_package` and
// `location` but not their interesting case: with no distribution packages, every package is
// its own source and there is one location. A distribution-based image with a binary in it
// shows both, and is worth running by hand when either label is touched:
//
//	KIEBITZR_TEST_IMAGE=ghcr.io/aquasecurity/trivy:0.58.0 mise run test:integration
//
// Measured that way on 2026-11-13: 83 of 326 findings named another source package —
// `libcrypto3` from openssl, `libcurl` from curl — and the locations were the apk database and
// the one Go binary.
func TestRunAgainstARealImage(t *testing.T) {
	image := os.Getenv("KIEBITZR_TEST_IMAGE")
	if image == "" {
		image = defaultImage
	}
	platform := os.Getenv("KIEBITZR_TEST_PLATFORM")
	if platform == "" {
		platform = "linux/arm64"
	}
	digest, repository := resolveImage(t, image)

	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatalf("cache.New() = %v, want no error", err)
	}
	cataloguer, err := catalog.New(platform)
	if err != nil {
		t.Fatalf("catalog.New() = %v, want no error", err)
	}
	database, err := vulndb.New(vulndb.Config{Dir: store.DatabaseDir()}, "integration-test")
	if err != nil {
		t.Fatalf("vulndb.New() = %v, want no error", err)
	}

	exporter := metrics.New(0)
	lister := &fakeLister{pods: []corev1.Pod{runningPod("web-0", image, repository+"@"+digest)}}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// The rule is written from the resolved repository and matched against the reference the
	// pod asked for, which is how the normalisation earns its place: those two are the same
	// image under different spellings whenever the subject is given in short form.
	r := New(lister, store, NewSerial(cataloguer, store, log), database, exporter, log, Options{
		Interval:         20 * time.Minute,
		Timeout:          20 * time.Minute,
		CatalogueTimeout: 15 * time.Minute,
		BuildAccess: buildAccessRules(t, "build-access:\n  - repository: "+repository+
			"\n    access: own\n"),
	})

	started := time.Now()
	r.Run(context.Background())
	t.Logf("cold run of one image took %s", time.Since(started).Round(time.Millisecond))

	body := scrape(t, exporter)
	if !strings.Contains(body, `kiebitzr_images{state="scanned"} 1`) {
		t.Fatalf("the image was not catalogued:\n%s", body)
	}
	if !strings.Contains(body, `image_digest="`+digest+`"`) {
		t.Fatalf("the running image is missing from the result:\n%s", body)
	}
	if strings.Contains(body, "kiebitzr_last_success_timestamp_seconds 0\n") {
		t.Fatalf("the run did not succeed:\n%s", body)
	}
	if strings.Contains(body, "kiebitzr_db_built_timestamp_seconds 0\n") {
		t.Fatalf("the database build time is unknown:\n%s", body)
	}

	// Declared configuration, so the assertion is on the declaration reaching the series — and
	// on the reference being normalised the same way the rule was.
	if !strings.Contains(body, `build_access="own"`) {
		t.Fatalf("the image was not classified as own:\n%s", body)
	}

	// Findings are not asserted by count: a well-maintained image may legitimately have none.
	// What must hold is that every series carries the labels of ADR 0001.
	findings := regexp.MustCompile(`kiebitzr_vulnerability\{[^}]*\}`).FindAllString(body, -1)
	t.Logf("%d findings for %s", len(findings), image)
	for _, series := range findings {
		for _, label := range []string{
			"cve=", "severity=", "package=", "source_package=", "package_type=", "installed=",
			"location=", "fix_state=", "image_digest=",
		} {
			if !strings.Contains(series, label) {
				t.Fatalf("finding %s is missing the label %s", series, label)
			}
		}
	}
	assertSourcePackagesAndLocations(t, findings)

	// The second run must take everything from the cache.
	r.Run(context.Background())
	if body := scrape(t, exporter); !strings.Contains(body, `kiebitzr_images{state="cached"} 1`) {
		t.Fatalf("the second run did not use the cache:\n%s", body)
	}

	assertAnIgnoreRuleIsCounted(t, store, cataloguer, lister, findings, log)
}

// assertSourcePackagesAndLocations checks the two labels that cannot be verified with
// synthetic matches: both are derived from real package metadata, and both have a fallback
// whose whole purpose is that the label is never empty-but-meaningful.
func assertSourcePackagesAndLocations(t *testing.T, findings []string) {
	t.Helper()
	sourcePackage := regexp.MustCompile(`source_package="([^"]*)"`)
	pkg := regexp.MustCompile(`\bpackage="([^"]*)"`)
	location := regexp.MustCompile(`location="([^"]*)"`)

	differ := map[string]string{}
	locations := map[string]struct{}{}
	for _, series := range findings {
		source := submatch(t, sourcePackage, series)
		if source == "" {
			t.Fatalf("finding %s has an empty source_package; a package that is its own source "+
				"carries its own name", series)
		}
		if binary := submatch(t, pkg, series); source != binary {
			differ[binary] = source
		}

		path := submatch(t, location, series)
		switch {
		case path == "":
			t.Fatalf("finding %s has an empty location; a package without a recorded path is "+
				"`unknown`", series)
		case path == "unknown" || strings.HasPrefix(path, "/"):
			locations[path] = struct{}{}
		default:
			t.Fatalf("finding %s has the location %q, want an absolute path or `unknown`",
				series, path)
		}
	}

	// Logged rather than asserted: both of these are properties of the subject image. A
	// Go-only image legitimately has no binary package that differs from its source, and one
	// with a single binary legitimately has one location. Logged all the same, because this is
	// the only place the two labels are seen on real package metadata rather than on
	// hand-written matches — and what they look like there is the thing worth recording.
	t.Logf("%d of %d findings name a source package other than the installed one",
		countDiffering(differ, findings), len(findings))
	for _, binary := range firstSorted(differ, 5) {
		t.Logf("  %s is built from %s", binary, differ[binary])
	}
	t.Logf("%d distinct locations", len(locations))
	for _, path := range firstSorted(locations, 5) {
		t.Logf("  %s", path)
	}
}

// countDiffering is how many findings, not how many packages, name another source package.
func countDiffering(differ map[string]string, findings []string) int {
	pkg := regexp.MustCompile(`\bpackage="([^"]*)"`)
	var n int
	for _, series := range findings {
		if _, ok := differ[pkg.FindStringSubmatch(series)[1]]; ok {
			n++
		}
	}
	return n
}

// firstSorted is up to n keys of a map in a stable order, so a log line does not reorder
// itself between runs.
func firstSorted[V any](m map[string]V, n int) []string {
	keys := slices.Sorted(maps.Keys(m))
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

// assertAnIgnoreRuleIsCounted is the end-to-end proof for the suppression metric. The unit
// tests hand the policy a list of ignored matches; only Grype itself can say that its own
// ignored matches arrive here, and that is the half an operator's trust rests on — an ignore
// rule that is too broad has to show up as a number rather than as silence.
//
// It reuses the SBOM and the database the run above already fetched, so it costs a re-match
// and no network.
func assertAnIgnoreRuleIsCounted(
	t *testing.T, store *cache.Store, cataloguer *catalog.Cataloguer,
	lister *fakeLister, findings []string, log *slog.Logger,
) {
	t.Helper()
	if len(findings) == 0 {
		// Logged and not skipped: everything above this point did run and did assert, and a
		// test that reports itself as skipped would hide that.
		t.Log("the subject image has no findings, so there is nothing an ignore rule could remove")
		return
	}
	cve := submatch(t, regexp.MustCompile(`cve="([^"]*)"`), findings[0])

	path := filepath.Join(t.TempDir(), "ignore.yaml")
	rule := "ignore:\n  - vulnerability: " + cve + "\n    reason: integration test\n"
	if err := os.WriteFile(path, []byte(rule), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v, want no error", err)
	}
	filtered, err := vulndb.New(vulndb.Config{
		Dir:        store.DatabaseDir(),
		IgnoreFile: path,
	}, "integration-test")
	if err != nil {
		t.Fatalf("vulndb.New() = %v, want no error", err)
	}

	exporter := metrics.New(0)
	New(lister, store, NewSerial(cataloguer, store, log), filtered, exporter, log, Options{
		Interval: 20 * time.Minute, Timeout: 20 * time.Minute, CatalogueTimeout: 15 * time.Minute,
	}).Run(context.Background())

	body := scrape(t, exporter)
	if strings.Contains(body, `cve="`+cve+`"`) {
		t.Fatalf("%s survived an ignore rule naming it:\n%s", cve, body)
	}
	suppressed := regexp.MustCompile(`kiebitzr_vulnerability_suppressed\{[^}]*reason="ignore_rule"[^}]*\} (\d+)`)
	match := suppressed.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("an ignore rule removed %s and nothing counted it:\n%s", cve, body)
	}
	t.Logf("the ignore rule for %s suppressed %s findings", cve, match[1])
}

func submatch(t *testing.T, re *regexp.Regexp, series string) string {
	t.Helper()
	match := re.FindStringSubmatch(series)
	if match == nil {
		t.Fatalf("%s does not match %s", series, re)
	}
	return match[1]
}

// resolveImage asks the registry for the digest of a reference, which is what the kubelet
// reports for a running container.
func resolveImage(t *testing.T, image string) (digest, repository string) {
	t.Helper()
	parsed, err := name.ParseReference(image)
	if err != nil {
		t.Fatalf("ParseReference(%q) = %v, want no error", image, err)
	}
	desc, err := remote.Head(parsed, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		t.Fatalf("Head(%q) = %v, want no error (is the registry reachable?)", image, err)
	}
	return desc.Digest.String(), parsed.Context().Name()
}
