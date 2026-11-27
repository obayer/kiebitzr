package vulndb

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	grypematch "github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftfile "github.com/anchore/syft/syft/file"
	syftpkg "github.com/anchore/syft/syft/pkg"

	"github.com/obayer/kiebitzr/internal/metrics"
)

const (
	digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	// apkDatabase is what a distribution package's location looks like: the package database,
	// the same path for every apk package in the image.
	apkDatabase = "/lib/apk/db/installed"
)

// finding builds a Grype match the way the matcher hands it over.
func finding(cve, severity string, fix vulnerability.Fix) grypematch.Match {
	m := grypematch.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: cve},
			Fix:       fix,
		},
		Package: grypepkg.Package{
			Name:      "openssl",
			Version:   "3.0.11-r0",
			Type:      syftpkg.ApkPkg,
			Locations: syftfile.NewLocationSet(syftfile.NewLocation(apkDatabase)),
		},
	}
	if severity != "" {
		m.Vulnerability.Metadata = &vulnerability.Metadata{Severity: severity}
	}
	return m
}

func fixedAt(versions ...string) vulnerability.Fix {
	return vulnerability.Fix{Versions: versions, State: vulnerability.FixStateFixed}
}

func TestFindings(t *testing.T) {
	got := policy{}.apply(digest, []grypematch.Match{
		finding("CVE-2024-0001", "High", fixedAt("3.0.12-r0")),
	}, nil)
	want := []metrics.Vulnerability{{
		Digest:        digest,
		CVE:           "CVE-2024-0001",
		Severity:      "High",
		Package:       "openssl",
		SourcePackage: "openssl",
		PackageType:   "apk",
		Installed:     "3.0.11-r0",
		Location:      apkDatabase,
		FixedIn:       "3.0.12-r0",
		FixState:      "fixed",
	}}
	if !slices.Equal(got.Findings, want) {
		t.Fatalf("apply() = %+v, want %+v", got.Findings, want)
	}
	if len(got.Suppressed) != 0 {
		t.Fatalf("apply() suppressed %+v, want nothing with no filter configured", got.Suppressed)
	}
}

// A label must never be empty-but-meaningful: a source that states no severity and a
// vulnerability with no fix record both have to come out as something readable.
func TestFindingsFillsInWhatTheSourceLeavesOut(t *testing.T) {
	got := policy{}.apply(digest, []grypematch.Match{
		finding("CVE-2024-0002", "", vulnerability.Fix{}),
	}, nil).Findings
	if len(got) != 1 {
		t.Fatalf("apply() = %+v, want one entry", got)
	}
	if got[0].Severity != severityUnknown {
		t.Fatalf("severity = %q, want %q", got[0].Severity, severityUnknown)
	}
	if got[0].FixState != string(vulnerability.FixStateUnknown) {
		t.Fatalf("fix_state = %q, want %q", got[0].FixState, vulnerability.FixStateUnknown)
	}
	if got[0].FixedIn != "" {
		t.Fatalf("fixed_in = %q, want empty", got[0].FixedIn)
	}
}

// The same rule for the package type, which arrives in two shapes of non-answer: unset, and
// Syft's own UnknownPackage. Both have to reach the label as one readable value, or a query
// grouping the ecosystems would have to know about three spellings of "no idea".
func TestFindingsNormalisesUnknownPackageTypes(t *testing.T) {
	for name, pkgType := range map[string]syftpkg.Type{
		"unset":      "",
		"syft's own": syftpkg.UnknownPkg,
	} {
		t.Run(name, func(t *testing.T) {
			m := finding("CVE-2024-0003", "High", fixedAt("1"))
			m.Package.Type = pkgType

			got := policy{}.apply(digest, []grypematch.Match{m}, nil).Findings
			if len(got) != 1 {
				t.Fatalf("apply() = %+v, want one entry", got)
			}
			if got[0].PackageType != packageTypeUnknown {
				t.Fatalf("package_type = %q, want %q", got[0].PackageType, packageTypeUnknown)
			}
		})
	}
}

// One advisory against one source package appears once per binary package built from it —
// libssl3 and libcrypto3 are both openssl — so without this label the finding count is a
// multiple of the work. The source package is what somebody actually fixes.
func TestSourcePackageNamesWhatIsFixed(t *testing.T) {
	tests := []struct {
		name      string
		pkg       string
		upstreams []grypepkg.UpstreamPackage
		want      string
	}{
		{"a binary package of a larger source", "libssl3", []grypepkg.UpstreamPackage{{Name: "openssl"}}, "openssl"},
		{"its own source", "curl", nil, "curl"},
		{"an upstream without a name", "zlib", []grypepkg.UpstreamPackage{{Version: "1.3"}}, "zlib"},
		{"several upstreams, the first one", "busybox-binsh", []grypepkg.UpstreamPackage{
			{Name: "busybox"}, {Name: "busybox-extras"},
		}, "busybox"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := finding("CVE-2024-0001", "High", fixedAt("1"))
			m.Package.Name = tt.pkg
			m.Package.Upstreams = tt.upstreams

			got := policy{}.apply(digest, []grypematch.Match{m}, nil).Findings
			if len(got) != 1 {
				t.Fatalf("apply() = %+v, want one entry", got)
			}
			if got[0].SourcePackage != tt.want {
				t.Fatalf("source_package = %q, want %q", got[0].SourcePackage, tt.want)
			}
			if got[0].Package != tt.pkg {
				t.Fatalf("package = %q, want the binary package %q kept beside it", got[0].Package, tt.pkg)
			}
		})
	}
}

// Thirty findings against package="stdlib" name a Go toolchain and not a file, and no query
// could say which binary carried them. The path is that answer — and for a distribution
// package it is the package database, which is honest and uninteresting.
func TestLocationNamesTheArtefact(t *testing.T) {
	tests := []struct {
		name      string
		locations []syftfile.Location
		want      string
	}{
		{"a binary", []syftfile.Location{syftfile.NewLocation("/usr/local/bin/gosu")}, "/usr/local/bin/gosu"},
		{"a distribution package", []syftfile.Location{syftfile.NewLocation(apkDatabase)}, apkDatabase},
		{"none recorded", nil, locationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := finding("CVE-2024-0001", "High", fixedAt("1"))
			m.Package.Locations = syftfile.NewLocationSet(tt.locations...)

			got := policy{}.apply(digest, []grypematch.Match{m}, nil).Findings
			if len(got) != 1 {
				t.Fatalf("apply() = %+v, want one entry", got)
			}
			if got[0].Location != tt.want {
				t.Fatalf("location = %q, want %q", got[0].Location, tt.want)
			}
		})
	}
}

// Syft's own ordering is used rather than the set's iteration order, which is a map's and
// differs between runs. An unstable label would make one finding look like a new one every
// scrape.
func TestLocationIsStableAcrossRuns(t *testing.T) {
	locations := []syftfile.Location{
		syftfile.NewLocation("/usr/local/bin/zzz"),
		syftfile.NewLocation("/usr/local/bin/aaa"),
	}
	m := finding("CVE-2024-0001", "High", fixedAt("1"))
	m.Package.Locations = syftfile.NewLocationSet(locations...)

	first := policy{}.apply(digest, []grypematch.Match{m}, nil).Findings[0].Location
	for range 20 {
		got := policy{}.apply(digest, []grypematch.Match{m}, nil).Findings[0].Location
		if got != first {
			t.Fatalf("location = %q, want %q on every run", got, first)
		}
	}
}

func TestFindingsSeverityThreshold(t *testing.T) {
	matches := []grypematch.Match{
		finding("CVE-2024-0001", "Critical", fixedAt("1")),
		finding("CVE-2024-0002", "High", fixedAt("1")),
		finding("CVE-2024-0003", "Medium", fixedAt("1")),
		finding("CVE-2024-0004", "Low", fixedAt("1")),
		finding("CVE-2024-0005", "Negligible", fixedAt("1")),
		finding("CVE-2024-0006", "", fixedAt("1")),
	}
	tests := []struct {
		threshold string
		want      []string
	}{
		{"", []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005", "CVE-2024-0006"}},
		{"high", []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0006"}},
		{"critical", []string{"CVE-2024-0001", "CVE-2024-0006"}},
		{"negligible", []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005", "CVE-2024-0006"}},
	}
	for _, tt := range tests {
		name := tt.threshold
		if name == "" {
			name = "no threshold"
		}
		t.Run(name, func(t *testing.T) {
			p := policy{minSeverity: vulnerability.ParseSeverity(tt.threshold)}
			if got := cves(p.apply(digest, matches, nil).Findings); !slices.Equal(got, tt.want) {
				t.Fatalf("apply() = %v, want %v (a finding without a severity is always kept)", got, tt.want)
			}
		})
	}
}

func TestFindingsOnlyFixed(t *testing.T) {
	matches := []grypematch.Match{
		finding("CVE-2024-0001", "High", fixedAt("3.0.12-r0")),
		finding("CVE-2024-0002", "High", vulnerability.Fix{State: vulnerability.FixStateNotFixed}),
		finding("CVE-2024-0003", "High", vulnerability.Fix{State: vulnerability.FixStateWontFix}),
		finding("CVE-2024-0004", "High", vulnerability.Fix{}),
	}
	p := policy{onlyFixed: true}
	if got := cves(p.apply(digest, matches, nil).Findings); !slices.Equal(got, []string{"CVE-2024-0001"}) {
		t.Fatalf("apply() = %v, want only the fixed one", got)
	}
}

// Everything a filter removes has to be counted, because nothing else in the run records it:
// an ignore rule that matches half the cluster must read as a large number and not as a clean
// result (kbz:req:00001).
func TestApplyCountsWhatEachFilterRemoved(t *testing.T) {
	matches := []grypematch.Match{
		finding("CVE-2024-0001", "Critical", fixedAt("1")),
		finding("CVE-2024-0002", "Medium", fixedAt("1")),
		finding("CVE-2024-0003", "Low", fixedAt("1")),
		finding("CVE-2024-0004", "Critical", vulnerability.Fix{State: vulnerability.FixStateNotFixed}),
	}
	ignored := []grypematch.IgnoredMatch{
		{Match: finding("CVE-2024-0005", "High", fixedAt("1"))},
		{Match: finding("CVE-2024-0006", "High", fixedAt("1"))},
	}

	p := policy{minSeverity: vulnerability.ParseSeverity("high"), onlyFixed: true}
	got := p.apply(digest, matches, ignored)

	if want := []string{"CVE-2024-0001"}; !slices.Equal(cves(got.Findings), want) {
		t.Fatalf("apply() = %v, want %v", cves(got.Findings), want)
	}
	want := []metrics.Suppressed{
		{Digest: digest, Reason: metrics.SuppressedIgnoreRule, Count: 2},
		{Digest: digest, Reason: metrics.SuppressedMinSeverity, Count: 2},
		{Digest: digest, Reason: metrics.SuppressedOnlyFixed, Count: 1},
	}
	if !slices.Equal(got.Suppressed, want) {
		t.Fatalf("apply() suppressed %+v, want %+v in the order the filters apply", got.Suppressed, want)
	}
}

// A filter that removed nothing gets no series: there is nothing hidden to account for, and a
// zero per digest and filter would be three series per image bought for no answer.
func TestApplyReportsNoSuppressionWhereNothingWasRemoved(t *testing.T) {
	p := policy{minSeverity: vulnerability.ParseSeverity("high"), onlyFixed: true}
	got := p.apply(digest, []grypematch.Match{
		finding("CVE-2024-0001", "Critical", fixedAt("1")),
	}, nil)
	if len(got.Suppressed) != 0 {
		t.Fatalf("apply() suppressed %+v, want no series at all", got.Suppressed)
	}
}

// The suppressed count is read against the number of published series, so it has to be in the
// same unit: two matches that would have collapsed into one series are one suppressed finding.
// Grype produces such pairs itself when it normalises several advisory records onto one CVE.
func TestApplyCountsSeriesAndNotMatches(t *testing.T) {
	duplicate := finding("CVE-2024-0002", "Low", fixedAt("1"))
	p := policy{minSeverity: vulnerability.ParseSeverity("high")}
	got := p.apply(digest, []grypematch.Match{duplicate, duplicate}, nil)

	want := []metrics.Suppressed{{Digest: digest, Reason: metrics.SuppressedMinSeverity, Count: 1}}
	if !slices.Equal(got.Suppressed, want) {
		t.Fatalf("apply() suppressed %+v, want %+v", got.Suppressed, want)
	}
}

// A finding both filters would remove counts once, under the first one that did. Without that
// the reasons would overlap and their sum would be larger than what the run suppressed.
func TestApplyCountsEachSuppressedFindingOnce(t *testing.T) {
	p := policy{minSeverity: vulnerability.ParseSeverity("high"), onlyFixed: true}
	got := p.apply(digest, []grypematch.Match{
		finding("CVE-2024-0001", "Low", vulnerability.Fix{State: vulnerability.FixStateNotFixed}),
	}, nil)

	want := []metrics.Suppressed{{Digest: digest, Reason: metrics.SuppressedMinSeverity, Count: 1}}
	if !slices.Equal(got.Suppressed, want) {
		t.Fatalf("apply() suppressed %+v, want %+v", got.Suppressed, want)
	}
}

func TestFixedIn(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
		want     string
	}{
		{"none", nil, ""},
		{"one", []string{"3.0.12-r0"}, "3.0.12-r0"},
		{"several are sorted for a stable label", []string{"3.1.0", "3.0.12"}, "3.0.12,3.1.0"},
		{"duplicates collapse", []string{"3.0.12", "3.0.12"}, "3.0.12"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fixedIn(tt.versions); got != tt.want {
				t.Fatalf("fixedIn(%v) = %q, want %q", tt.versions, got, tt.want)
			}
		})
	}
}

// fixedIn must not reorder the caller's slice, which belongs to the match.
func TestFixedInLeavesTheInputAlone(t *testing.T) {
	versions := []string{"3.1.0", "3.0.12"}
	fixedIn(versions)
	if !slices.Equal(versions, []string{"3.1.0", "3.0.12"}) {
		t.Fatalf("fixedIn() reordered its input to %v", versions)
	}
}

func TestNewRejects(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"no directory", Config{MinSeverity: "high"}},
		{"unknown severity", Config{Dir: "/var/cache/kiebitzr/db", MinSeverity: "severe"}},
		{"missing ignore file", Config{Dir: "/var/cache/kiebitzr/db", IgnoreFile: "/nonexistent/ignore.yaml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg, "test"); err == nil {
				t.Fatalf("New(%+v) = no error, want one", tt.cfg)
			}
		})
	}
}

func TestNewAcceptsEverySeverityName(t *testing.T) {
	for _, severity := range vulnerability.AllSeverities() {
		t.Run(severity.String(), func(t *testing.T) {
			if _, err := New(Config{Dir: t.TempDir(), MinSeverity: severity.String()}, "test"); err != nil {
				t.Fatalf("New(min-severity=%s) = %v, want no error", severity, err)
			}
		})
	}
}

func TestIgnoreRules(t *testing.T) {
	path := writeIgnoreFile(t, `
ignore:
  - vulnerability: CVE-2024-0001
    reason: the vulnerable code path is not reachable
  - vulnerability: CVE-2024-0002
    fix-state: wont-fix
    package:
      name: openssl
`)
	rules, err := ignoreRules(path)
	if err != nil {
		t.Fatalf("ignoreRules() = %v, want no error", err)
	}
	if len(rules) != 2 {
		t.Fatalf("ignoreRules() = %+v, want two rules", rules)
	}
	if rules[0].Vulnerability != "CVE-2024-0001" || rules[0].Reason == "" {
		t.Fatalf("first rule = %+v, want the CVE and its reason", rules[0])
	}
	if rules[1].FixState != "wont-fix" || rules[1].Package.Name != "openssl" {
		t.Fatalf("second rule = %+v, want fix state and package name", rules[1])
	}
}

func TestIgnoreRulesWithoutAFile(t *testing.T) {
	rules, err := ignoreRules("")
	if err != nil || rules != nil {
		t.Fatalf("ignoreRules(\"\") = %v, %v, want no rules and no error", rules, err)
	}
}

// A file that ignores nothing is a mistake worth reporting: it was mounted to ignore
// something, and a silent no-op would hide a typo in the key.
func TestIgnoreRulesRejects(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"empty file", ""},
		{"no ignore key", "rules:\n  - vulnerability: CVE-2024-0001\n"},
		{"unknown rule field", "ignore:\n  - cve: CVE-2024-0001\n"},
		{"not yaml", "ignore: [unclosed\n"},
		{"list without the key", "- vulnerability: CVE-2024-0001\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ignoreRules(writeIgnoreFile(t, tt.content)); err == nil {
				t.Fatalf("ignoreRules(%q) = no error, want one", tt.content)
			}
		})
	}
}

func writeIgnoreFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ignore.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimPrefix(content, "\n")), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v, want no error", err)
	}
	return path
}

func cves(findings []metrics.Vulnerability) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.CVE)
	}
	return out
}

// With no database in place the update *is* the database, so its failure has to be the
// reported error and has to carry its cause. Grype only does that when RequireUpdateCheck is
// set; otherwise it writes the cause to its own logger, which this process does not consume,
// and reports "database does not exist" — which reads identically whether the cache directory
// was unwritable or the update server unreachable, and sends an operator looking in the wrong
// place.
func TestOpenWithoutDatabaseReportsWhyTheUpdateFailed(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir()}, "test")
	if err != nil {
		t.Fatalf("New() = %v, want no error", err)
	}
	// Unroutable on purpose: nothing listens there, so the check fails at once and this test
	// neither reaches the network nor downloads a database.
	m.distribution.LatestURL = "http://127.0.0.1:1/latest.json"
	m.distribution.CheckTimeout = time.Second

	_, err = m.Open(context.Background())
	if err == nil {
		t.Fatal("Open() = no error, want the failed update reported")
	}
	if !strings.Contains(err.Error(), "unable to update db") {
		t.Fatalf("Open() = %v, want it to name the failed update", err)
	}
	if strings.Contains(err.Error(), "database does not exist") {
		t.Fatalf("Open() = %v, want the cause of the failure, not its consequence", err)
	}
}

// The other half of the same decision: once a database is there, a failed update must not
// stop a run that can still match against it. Grype refuses one too old to trust by itself.
func TestUpdateIsOnlyRequiredWhileThereIsNoDatabase(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir()}, "test")
	if err != nil {
		t.Fatalf("New() = %v, want no error", err)
	}
	if !m.shouldUpdate(nil, false) {
		t.Fatal("shouldUpdate() = false without a database, want the update that is the database")
	}
	if !m.distributionFor(false).RequireUpdateCheck {
		t.Fatal("RequireUpdateCheck = false without a database, want a failed update to be fatal")
	}
	if m.distributionFor(true).RequireUpdateCheck {
		t.Fatal("RequireUpdateCheck = true with a database, want a failed update to be survivable")
	}
}

// -db-max-age exists for write load: an update rewrites the whole database, measured at 3.2 GB
// against a 200 MB download, so on a small node skipping one is worth three days of slightly
// older findings. What must not happen is skipping when there is nothing to skip from.
func TestDatabaseUpdateIsSkippedOnlyWhileItIsYoungEnough(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	built := func(age time.Duration) *v6.Description {
		return &v6.Description{Built: v6.Time{Time: now.Add(-age)}}
	}

	tests := []struct {
		name    string
		maxAge  time.Duration
		current *v6.Description
		exists  bool
		want    bool
	}{
		{"no database at all", 72 * time.Hour, nil, false, true},
		{"unreadable description", 72 * time.Hour, nil, true, true},
		// A file that cannot say when it was built is updated rather than trusted: skipping on
		// an unknown age is how a database quietly ages past the limit Grype enforces.
		{"database without a build time", 72 * time.Hour, &v6.Description{}, true, true},
		{"switched off updates every run", 0, built(1 * time.Hour), true, true},
		{"younger than the budget", 72 * time.Hour, built(1 * time.Hour), true, false},
		{"just younger than the budget", 72 * time.Hour, built(71 * time.Hour), true, false},
		{"exactly at the budget", 72 * time.Hour, built(72 * time.Hour), true, true},
		{"older than the budget", 72 * time.Hour, built(100 * time.Hour), true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := New(Config{Dir: t.TempDir(), MaxAge: tt.maxAge, Interval: time.Hour}, "test")
			if err != nil {
				t.Fatalf("New() = %v, want no error", err)
			}
			m.now = func() time.Time { return now }

			if got := m.shouldUpdate(tt.current, tt.exists); got != tt.want {
				t.Fatalf("shouldUpdate() = %t, want %t", got, tt.want)
			}
		})
	}
}

// The budget is MaxAge *plus* Interval, and that is the part worth a test of its own: a database
// young enough to skip keeps ageing until the next run, so a value that looks legal against the
// five-day limit is not legal once a day of waiting is added to it.
func TestMaxAgeHasToLeaveRoomForOneMoreInterval(t *testing.T) {
	limit := MaxDatabaseAge()

	tests := []struct {
		name     string
		maxAge   time.Duration
		interval time.Duration
		wantErr  bool
	}{
		{"off needs no room", 0, limit * 2, false},
		{"well inside the limit", 72 * time.Hour, 24 * time.Hour, false},
		{"one second inside the limit", limit - 24*time.Hour - time.Second, 24 * time.Hour, false},
		{"exactly at the limit", limit - 24*time.Hour, 24 * time.Hour, true},
		{"inside the limit but not with the interval", limit - time.Hour, 24 * time.Hour, true},
		{"beyond the limit on its own", limit + time.Hour, 24 * time.Hour, true},
		{"interval alone exceeds the limit", time.Hour, limit + time.Hour, true},
		{"negative", -time.Hour, 24 * time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(
				Config{Dir: t.TempDir(), MaxAge: tt.maxAge, Interval: tt.interval}, "test")
			if tt.wantErr && err == nil {
				t.Fatalf("New(max-age=%s, interval=%s) = no error, want one", tt.maxAge, tt.interval)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("New(max-age=%s, interval=%s) = %v, want no error", tt.maxAge, tt.interval, err)
			}
		})
	}
}

// The refusal has to be diagnosable, which is a requirement and not a nicety: the limit is
// Grype's, so a bump can lower it and turn a configuration that started yesterday into a pod
// that will not start today — with nothing in this repository changed and nothing in the
// ConfigMap touched. An operator told only "value too large" has no route to that conclusion.
func TestMaxAgeRefusalNamesTheBorrowedLimit(t *testing.T) {
	_, err := New(Config{Dir: t.TempDir(), MaxAge: 96 * time.Hour, Interval: 24 * time.Hour}, "test")
	if err == nil {
		t.Fatal("New() = no error, want the budget refused")
	}
	got := err.Error()

	for _, want := range []string{
		"96h0m0s",                 // what was asked for
		"24h0m0s",                 // the interval that is part of the budget
		"120h0m0s",                // their sum, so the arithmetic is not left to the reader
		MaxDatabaseAge().String(), // the limit it is measured against
		"MaxAllowedBuiltAge",      // the name to search for in Grype
		grypeModule,               // where it comes from
		"Grype's and not Kiebitzr's",
		"an image update can move it",
		"set -db-max-age below",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("New() = %q, want it to contain %q", got, want)
		}
	}
}

// When the interval alone is past the limit no positive value can work, so the remedy that
// names one would send the operator in a circle.
func TestMaxAgeRefusalAdaptsWhenTheIntervalAloneIsTooLong(t *testing.T) {
	interval := MaxDatabaseAge() + time.Hour
	_, err := New(Config{Dir: t.TempDir(), MaxAge: time.Hour, Interval: interval}, "test")
	if err == nil {
		t.Fatal("New() = no error, want the budget refused")
	}
	got := err.Error()

	if !strings.Contains(got, "no positive -db-max-age can work") {
		t.Fatalf("New() = %q, want it to say that no positive value helps", got)
	}
	if strings.Contains(got, "set -db-max-age below") {
		t.Fatalf("New() = %q, want no bound that cannot be met", got)
	}
}

// Read from Grype rather than written down here, so this guards the assumption that makes the
// whole check meaningful: a limit of zero would refuse every opt-in configuration there is.
func TestMaxDatabaseAgeIsAUsableLimit(t *testing.T) {
	if got := MaxDatabaseAge(); got <= 24*time.Hour {
		t.Fatalf("MaxDatabaseAge() = %s, want a limit a daily interval can fit under", got)
	}
}

// Evidence of exploitation and Grype's risk score were being discarded, and that is the one
// kind of loss nothing downstream can repair: what a run does not publish, no dashboard can
// reconstruct afterwards.
func TestFindingsCarryExploitationEvidence(t *testing.T) {
	m := finding("CVE-2024-0001", "Critical", fixedAt("3.0.12-r0"))
	m.Vulnerability.Metadata.KnownExploited = []vulnerability.KnownExploited{{
		CVE:                        "CVE-2024-0001",
		KnownRansomwareCampaignUse: "known",
	}}
	m.Vulnerability.Metadata.EPSS = []vulnerability.EPSS{{CVE: "CVE-2024-0001", EPSS: 0.9}}

	got := policy{}.apply(digest, []grypematch.Match{m}, nil).Findings
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !got[0].KnownExploited {
		t.Error("KnownExploited = false, want true for a record in the catalogue")
	}
	if got[0].Risk <= 0 {
		t.Errorf("Risk = %v, want a positive score for an exploited critical", got[0].Risk)
	}
	if got[0].Risk > 100 {
		t.Errorf("Risk = %v, want at most 100", got[0].Risk)
	}
}

// A record without metadata must not panic and must not invent a score: severityOf already
// treats that case as Unknown, and the threat side has to agree.
func TestFindingsWithoutMetadataHaveNoThreat(t *testing.T) {
	got := policy{}.apply(digest, []grypematch.Match{
		finding("CVE-2024-0002", "", vulnerability.Fix{}),
	}, nil).Findings
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if got[0].KnownExploited || got[0].Risk != 0 {
		t.Errorf("KnownExploited/Risk = %v/%v, want false/0", got[0].KnownExploited, got[0].Risk)
	}
}
