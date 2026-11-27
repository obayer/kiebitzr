package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// scrape is what a Prometheus server would see.
func scrape(t *testing.T, e *Exporter) string {
	t.Helper()
	rec := httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

func imageInfo() ImageInfo {
	return ImageInfo{
		Digest:    digest,
		Image:     "registry.example/app:1.4.0",
		Namespace: "prod",
		OwnerKind: "Deployment",
		OwnerName: "web",
		Container: "app",
	}
}

func finding(cve string) Vulnerability {
	return Vulnerability{
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

// Before the first run the endpoint must already answer, and it must say that nothing has
// succeeded yet rather than stay silent.
func TestFreshExporterReportsNoSuccess(t *testing.T) {
	e := New(0)

	want := `
# HELP kiebitzr_images Number of image digests the last run catalogued, took from the cache, failed on or did not reach.
# TYPE kiebitzr_images gauge
kiebitzr_images{state="cached"} 0
kiebitzr_images{state="failed"} 0
kiebitzr_images{state="pending"} 0
kiebitzr_images{state="scanned"} 0
# HELP kiebitzr_last_success_timestamp_seconds Unix time of the last run that completed without a fatal error.
# TYPE kiebitzr_last_success_timestamp_seconds gauge
kiebitzr_last_success_timestamp_seconds 0
`
	if err := testutil.GatherAndCompare(e.registry, strings.NewReader(want),
		"kiebitzr_images", "kiebitzr_last_success_timestamp_seconds"); err != nil {
		t.Fatal(err)
	}
	if got := testutil.CollectAndCount(e.registry, "kiebitzr_vulnerability"); got != 0 {
		t.Fatalf("kiebitzr_vulnerability series = %d, want 0", got)
	}
	if got := testutil.ToFloat64(e.errors.WithLabelValues(ReasonCatalogue)); got != 0 {
		t.Fatalf("scan_errors_total{reason=catalogue} = %v, want the series to exist at 0", got)
	}
}

// Both exporters say which binary is answering, from the first scrape and without anyone
// wiring it up. Without this, "no series for a metric" means an older build and a cluster with
// nothing to report at the same time — the ambiguity that cost a whole diagnosis once.
func TestBuildInfoIsAlwaysServed(t *testing.T) {
	const header = "# HELP kiebitzr_build_info Always 1, labelled with the version and commit" +
		" of the running binary, and with the maximum vulnerability database age its Grype" +
		" accepts (none for a worker).\n# TYPE kiebitzr_build_info gauge\n"

	// The link-time defaults for version and commit, because a test binary carries no -ldflags.
	tests := map[string]struct {
		registry *prometheus.Registry
		want     string
	}{
		"matcher": {
			New(120 * time.Hour).registry,
			`kiebitzr_build_info{commit="unknown",grype_db_max_age="120h0m0s",version="dev"} 1`,
		},
		// A worker holds no database at all, and `none` says so. An empty value could not be
		// told from a build that does not have the label, and "0s" would read as a limit that
		// refuses everything.
		"worker": {
			NewWorker().registry,
			`kiebitzr_build_info{commit="unknown",grype_db_max_age="none",version="dev"} 1`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := testutil.GatherAndCompare(tt.registry,
				strings.NewReader(header+tt.want+"\n"), "kiebitzr_build_info"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPublish(t *testing.T) {
	e := New(0)
	e.Publish(Result{
		Images:          []ImageInfo{imageInfo()},
		Vulnerabilities: []Vulnerability{finding("CVE-2024-0001")},
		Counts:          Counts{Scanned: 1, Cached: 2, Failed: 3},
	})

	want := `
# HELP kiebitzr_image_info One for every container running an image digest, carrying where it runs.
# TYPE kiebitzr_image_info gauge
kiebitzr_image_info{build_access="unknown",container="app",image="registry.example/app:1.4.0",image_digest="` + digest + `",namespace="prod",owner_kind="Deployment",owner_name="web"} 1
# HELP kiebitzr_images Number of image digests the last run catalogued, took from the cache, failed on or did not reach.
# TYPE kiebitzr_images gauge
kiebitzr_images{state="cached"} 2
kiebitzr_images{state="failed"} 3
kiebitzr_images{state="pending"} 0
kiebitzr_images{state="scanned"} 1
# HELP kiebitzr_vulnerability One for every known vulnerability found in a running image digest.
# TYPE kiebitzr_vulnerability gauge
kiebitzr_vulnerability{cve="CVE-2024-0001",fix_state="fixed",fixed_in="3.0.12-r0",image_digest="` + digest + `",installed="3.0.11-r0",known_exploited="false",location="/lib/apk/db/installed",package="openssl",package_type="apk",severity="High",source_package="openssl"} 1
`
	if err := testutil.GatherAndCompare(e.registry, strings.NewReader(want),
		"kiebitzr_image_info", "kiebitzr_images", "kiebitzr_vulnerability"); err != nil {
		t.Fatal(err)
	}
}

// A finding that is gone must vanish with the swap, and nothing may survive from the run
// before it.
func TestPublishReplacesTheWholeResult(t *testing.T) {
	e := New(0)
	e.Publish(Result{Vulnerabilities: []Vulnerability{finding("CVE-2024-0001"), finding("CVE-2024-0002")}})
	e.Publish(Result{Vulnerabilities: []Vulnerability{finding("CVE-2024-0002")}})

	if got := testutil.CollectAndCount(e.registry, "kiebitzr_vulnerability"); got != 1 {
		t.Fatalf("kiebitzr_vulnerability series = %d, want only the one still published", got)
	}
	want := `
# HELP kiebitzr_vulnerability One for every known vulnerability found in a running image digest.
# TYPE kiebitzr_vulnerability gauge
kiebitzr_vulnerability{cve="CVE-2024-0002",fix_state="fixed",fixed_in="3.0.12-r0",image_digest="` + digest + `",installed="3.0.11-r0",known_exploited="false",location="/lib/apk/db/installed",package="openssl",package_type="apk",severity="High",source_package="openssl"} 1
`
	if err := testutil.GatherAndCompare(e.registry, strings.NewReader(want), "kiebitzr_vulnerability"); err != nil {
		t.Fatal(err)
	}
}

// Two equal label sets would make every scrape fail as a duplicate series, so Publish has to
// collapse them whatever the caller hands over.
func TestPublishCollapsesEqualLabelSets(t *testing.T) {
	e := New(0)
	e.Publish(Result{
		Images:          []ImageInfo{imageInfo(), imageInfo()},
		Vulnerabilities: []Vulnerability{finding("CVE-2024-0001"), finding("CVE-2024-0001")},
	})

	if _, err := e.registry.Gather(); err != nil {
		t.Fatalf("Gather() = %v, want no duplicate series", err)
	}
	for _, name := range []string{"kiebitzr_image_info", "kiebitzr_vulnerability"} {
		if got := testutil.CollectAndCount(e.registry, name); got != 1 {
			t.Fatalf("%s series = %d, want 1", name, got)
		}
	}
}

func TestRunSucceeded(t *testing.T) {
	e := New(0)
	finished := time.Unix(1762300000, 0)
	e.RunSucceeded(finished, 90*time.Second)

	if got, want := testutil.ToFloat64(e.lastSuccess), float64(finished.Unix()); got != want {
		t.Fatalf("last_success = %v, want %v", got, want)
	}
	if got := testutil.ToFloat64(e.runDuration); got != 90 {
		t.Fatalf("run_duration_seconds = %v, want 90", got)
	}
}

// The contract of ADR 0001: a failed run keeps serving the previous result and leaves the
// freshness timestamp alone, so the gap itself becomes the signal.
func TestRunFailedKeepsPreviousResult(t *testing.T) {
	e := New(0)
	e.Publish(Result{Vulnerabilities: []Vulnerability{finding("CVE-2024-0001")}})
	e.RunSucceeded(time.Unix(1762300000, 0), time.Minute)

	e.RunFailed(ReasonListPods)

	if got := testutil.ToFloat64(e.errors.WithLabelValues(ReasonListPods)); got != 1 {
		t.Fatalf("scan_errors_total{reason=list_pods} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(e.lastSuccess); got != 1762300000 {
		t.Fatalf("last_success = %v, want it untouched by the failed run", got)
	}
	if got := testutil.CollectAndCount(e.registry, "kiebitzr_vulnerability"); got != 1 {
		t.Fatalf("kiebitzr_vulnerability series = %d, want the previous result to survive", got)
	}
}

func TestErrorsBy(t *testing.T) {
	e := New(0)
	e.ErrorsBy(ReasonImageID, 3)
	e.ErrorsBy(ReasonImageID, 0)

	if got := testutil.ToFloat64(e.errors.WithLabelValues(ReasonImageID)); got != 3 {
		t.Fatalf("scan_errors_total{reason=unresolved_image_id} = %v, want 3", got)
	}
}

func TestDatabaseBuilt(t *testing.T) {
	e := New(0)
	built := time.Unix(1762200000, 0)
	e.DatabaseBuilt(built)

	if got, want := testutil.ToFloat64(e.dbBuilt), float64(built.Unix()); got != want {
		t.Fatalf("db_built_timestamp_seconds = %v, want %v", got, want)
	}
}

func TestHandlerServesTheOwnRegistryOnly(t *testing.T) {
	e := New(0)
	e.Publish(Result{Images: []ImageInfo{imageInfo()}})

	rec := httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"kiebitzr_image_info", "kiebitzr_images", "go_goroutines"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body does not mention %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "promhttp_metric_handler") {
		t.Fatalf("body contains default-registry metrics:\n%s", body)
	}
}

// The risk score is a value, not a label, and it is reported per digest as the highest of
// that digest's findings — triage starts at the worst one.
func TestPublishReportsTheHighestRiskPerDigest(t *testing.T) {
	e := New(0)
	low, high := finding("CVE-2024-0001"), finding("CVE-2024-0002")
	low.Risk = 12.5
	high.Risk = 73.25
	high.KnownExploited = true
	e.Publish(Result{Vulnerabilities: []Vulnerability{low, high}})

	want := `
# HELP kiebitzr_image_risk_score Highest risk score among the findings of an image digest, 0 to 100, as Grype computes it.
# TYPE kiebitzr_image_risk_score gauge
kiebitzr_image_risk_score{image_digest="` + digest + `"} 73.25
`
	if err := testutil.GatherAndCompare(e.registry, strings.NewReader(want),
		"kiebitzr_image_risk_score"); err != nil {
		t.Fatal(err)
	}
	if got := testutil.CollectAndCount(e.registry, "kiebitzr_vulnerability"); got != 2 {
		t.Fatalf("kiebitzr_vulnerability series = %d, want 2", got)
	}
}

// Exploitation in the wild is a label, because "critical and exploited" is the set that gets
// patched tonight and it has to be selectable.
func TestKnownExploitedIsALabel(t *testing.T) {
	e := New(0)
	exploited := finding("CVE-2024-0003")
	exploited.KnownExploited = true
	e.Publish(Result{Vulnerabilities: []Vulnerability{exploited}})

	if !strings.Contains(scrape(t, e), `known_exploited="true"`) {
		t.Fatalf("scrape does not carry known_exploited=true:\n%s", scrape(t, e))
	}
}

// The package type is what separates a finding a newer image of the same lineage can carry a
// fix for from one compiled into a binary, which moves only when its publisher rebuilds. Both
// report fix_state="fixed", which is why that label cannot answer "can I patch this at all"
// and this one has to exist.
func TestPackageTypeSeparatesDistroFromCompiledFindings(t *testing.T) {
	e := New(0)
	distro, compiled := finding("CVE-2024-0004"), finding("CVE-2024-0005")
	compiled.Package, compiled.PackageType = "stdlib", "go-module"
	e.Publish(Result{Vulnerabilities: []Vulnerability{distro, compiled}})

	body := scrape(t, e)
	for _, want := range []string{`package_type="apk"`, `package_type="go-module"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("scrape does not carry %s:\n%s", want, body)
		}
	}
	if got := testutil.CollectAndCount(e.registry, "kiebitzr_vulnerability"); got != 2 {
		t.Fatalf("kiebitzr_vulnerability series = %d, want 2", got)
	}
}

// The type belongs to the identity of a series, so two findings differing only in it stay
// two. This guards the deduplication key: vulnerabilityLabels clears the risk score and
// nothing else, and clearing the type there would silently merge the two buckets above.
func TestPublishKeepsFindingsThatDifferOnlyInPackageType(t *testing.T) {
	e := New(0)
	first, second := finding("CVE-2024-0001"), finding("CVE-2024-0001")
	second.PackageType = "go-module"
	e.Publish(Result{Vulnerabilities: []Vulnerability{first, second}})

	if got := testutil.CollectAndCount(e.registry, "kiebitzr_vulnerability"); got != 2 {
		t.Fatalf("kiebitzr_vulnerability series = %d, want 2", got)
	}
}

// Two findings whose labels are equal but whose risk differs must collapse to one series.
// Deduplication keys on the label set alone for exactly this reason: a duplicate label set
// makes the whole scrape fail, and the risk score is not part of the identity of a series.
func TestPublishCollapsesEqualLabelSetsWithDifferentRisk(t *testing.T) {
	e := New(0)
	first, second := finding("CVE-2024-0001"), finding("CVE-2024-0001")
	first.Risk = 10
	second.Risk = 90
	e.Publish(Result{Vulnerabilities: []Vulnerability{first, second}})

	if got := testutil.CollectAndCount(e.registry, "kiebitzr_vulnerability"); got != 1 {
		t.Fatalf("kiebitzr_vulnerability series = %d, want 1", got)
	}
	// The first wins, as everywhere else in the deduplication.
	want := "kiebitzr_image_risk_score{image_digest=\"" + digest + "\"} 10"
	if !strings.Contains(scrape(t, e), want) {
		t.Fatalf("scrape does not contain %q:\n%s", want, scrape(t, e))
	}
}

// A failed digest is reported with the stage it failed at, beside the count.
// The consequence of the location label, stated as a test because it is the one that costs
// something: two binaries in one image built with the same toolchain used to collapse into one
// series, and are now one each. That split is the answer the label exists to give — which
// binary carries the finding — and the cardinality it buys it with.
func TestPublishKeepsFindingsThatDifferOnlyInLocation(t *testing.T) {
	first := finding("CVE-2024-0001")
	first.Package, first.SourcePackage, first.PackageType = "stdlib", "stdlib", "go-module"
	first.Installed, first.Location = "go1.24.6", "/usr/local/bin/gosu"
	second := first
	second.Location = "/usr/local/bin/tini"

	e := New(0)
	e.Publish(Result{Vulnerabilities: []Vulnerability{first, second}})

	if _, err := e.registry.Gather(); err != nil {
		t.Fatalf("Gather() = %v, want no duplicate series", err)
	}
	if got := testutil.CollectAndCount(e.registry, "kiebitzr_vulnerability"); got != 2 {
		t.Fatalf("kiebitzr_vulnerability series = %d, want one per binary carrying the finding", got)
	}
}

// The filters are the one place this service produces silence deliberately, so what they
// removed has to be a number. Without it an ignore rule matching half the cluster reads
// exactly like a cluster with nothing to report (kbz:req:00001).
func TestPublishReportsWhatTheFiltersRemoved(t *testing.T) {
	e := New(0)
	e.Publish(Result{
		Vulnerabilities: []Vulnerability{finding("CVE-2024-0001")},
		Suppressions: []Suppressed{
			{Digest: digest, Reason: SuppressedIgnoreRule, Count: 7},
			{Digest: digest, Reason: SuppressedMinSeverity, Count: 112},
		},
	})

	want := `
# HELP kiebitzr_vulnerability_suppressed How many findings of an image digest a configured filter removed in the last run, by filter.
# TYPE kiebitzr_vulnerability_suppressed gauge
kiebitzr_vulnerability_suppressed{image_digest="` + digest + `",reason="ignore_rule"} 7
kiebitzr_vulnerability_suppressed{image_digest="` + digest + `",reason="min_severity"} 112
`
	if err := testutil.GatherAndCompare(e.registry, strings.NewReader(want),
		"kiebitzr_vulnerability_suppressed"); err != nil {
		t.Fatal(err)
	}
}

// No filter configured, or nothing removed: no series at all. A zero per digest and filter
// would be three series per image bought for an answer nobody asked for, and the configuration
// itself is in the start-up log.
func TestPublishWithoutSuppressionsServesNoSeries(t *testing.T) {
	e := New(0)
	e.Publish(Result{Vulnerabilities: []Vulnerability{finding("CVE-2024-0001")}})

	if got := scrape(t, e); strings.Contains(got, "kiebitzr_vulnerability_suppressed") {
		t.Fatal("scrape carries kiebitzr_vulnerability_suppressed, want no series where nothing was suppressed")
	}
}

// Two tallies for one digest and filter would be a duplicate series and fail the scrape, so
// the count must not be part of the deduplication key.
func TestPublishCollapsesEqualSuppressionLabelSets(t *testing.T) {
	e := New(0)
	e.Publish(Result{Suppressions: []Suppressed{
		{Digest: digest, Reason: SuppressedOnlyFixed, Count: 3},
		{Digest: digest, Reason: SuppressedOnlyFixed, Count: 9},
	}})

	if got := testutil.CollectAndCount(snapshotCollector{e}, "kiebitzr_vulnerability_suppressed"); got != 1 {
		t.Fatalf("kiebitzr_vulnerability_suppressed series = %d, want 1", got)
	}
	want := `
# HELP kiebitzr_vulnerability_suppressed How many findings of an image digest a configured filter removed in the last run, by filter.
# TYPE kiebitzr_vulnerability_suppressed gauge
kiebitzr_vulnerability_suppressed{image_digest="` + digest + `",reason="only_fixed"} 3
`
	if err := testutil.GatherAndCompare(e.registry, strings.NewReader(want),
		"kiebitzr_vulnerability_suppressed"); err != nil {
		t.Fatal(err)
	}
}

func TestPublishReportsFailuresPerDigest(t *testing.T) {
	e := New(0)
	e.Publish(Result{
		Failures: []Failure{{Digest: digest, Reason: ReasonUnreachable}},
		Counts:   Counts{Failed: 1},
	})

	want := `
# HELP kiebitzr_image_failed One for every image digest the last run could not analyse, carrying the stage it failed at.
# TYPE kiebitzr_image_failed gauge
kiebitzr_image_failed{image_digest="` + digest + `",reason="unreachable_image"} 1
`
	if err := testutil.GatherAndCompare(e.registry, strings.NewReader(want),
		"kiebitzr_image_failed"); err != nil {
		t.Fatal(err)
	}
}
