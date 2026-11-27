// Package metrics owns everything the /metrics endpoint serves. The result of a run is
// swapped in as one immutable snapshot, so a scrape sees either the previous or the new
// result and never a half-built or reset one (ADR 0001).
package metrics

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obayer/kiebitzr/internal/version"
)

// buildInfo is the one series that says which binary is answering: always 1, labelled with the
// version and commit linked into it, and with the database age its vendored Grype will accept.
//
// Version and commit are read by this package itself rather than taken from a caller. That is
// deliberate. A metric somebody can forget to wire up is worse than none here, because its
// absence would mean "an older build" and "nobody called the setter" at the same time — and
// removing exactly that ambiguity is the point.
//
// grypeDBMaxAge is the one value that cannot follow that rule: it lives in Grype, which only
// internal/vulndb may import (depguard), and that package imports this one. So it arrives as a
// parameter — but a required one, not a setter, which is what keeps the rule intact in
// substance: a caller cannot forget it without failing to compile.
//
// It belongs on this metric rather than in a gauge of its own because it is a property of the
// build and never of a run: it changes when the image changes, and a gauge would invite an
// alert on a number that cannot move while the process lives. What it makes answerable is
// "which limit is this binary holding me to" — the limit is Grype's, a bump can lower it, and
// a deployment that would then refuse to start should be visible before somebody restarts it.
//
// It earns its place because a metric set grows: when a label or a metric is added, every
// consumer has to be able to tell "this cluster has nothing to report" from "this cluster runs
// a binary that cannot report it". Diagnosing that from commit dates once was enough (ADR 0010).
func buildInfo(grypeDBMaxAge string) prometheus.Collector {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kiebitzr_build_info",
		Help: "Always 1, labelled with the version and commit of the running binary, and with" +
			" the maximum vulnerability database age its Grype accepts (none for a worker).",
	}, []string{"version", "commit", "grype_db_max_age"})
	g.WithLabelValues(version.Version, version.Commit, grypeDBMaxAge).Set(1)
	return g
}

// dbMaxAgeNone labels a process that holds no vulnerability database, which is every worker. It
// is spelled out for the reason internal/vulndb spells out its own unknowns: an empty label
// value cannot be told from an absent one in Prometheus, so "this process has no database"
// would read as "this build does not have the label" — and "0s" would read worse still, as a
// limit that refuses everything.
const dbMaxAgeNone = "none"

// Reasons for kiebitzr_scan_errors_total. Every series exists from the start, so an alert on
// an increase does not have to cope with a missing series.
const (
	ReasonListPods = "list_pods"
	ReasonImageID  = "unresolved_image_id"
	// ReasonUnreachable covers every way an image can fail before it is even read: a missing
	// credential, a platform the index does not carry, an image that was never pushed. They
	// cannot be told apart — stereoscope formats the registry's typed error with %+v, which
	// destroys the HTTP status — so the metric says what is known and the log line carries
	// the registry's own words.
	ReasonUnreachable = "unreachable_image"
	ReasonCatalogue   = "catalogue"
	ReasonMatch       = "match"
	ReasonDatabase    = "database"
	ReasonCacheWrite  = "cache_write"
)

// States for kiebitzr_images.
const (
	StateScanned = "scanned"
	StateCached  = "cached"
	StateFailed  = "failed"
	// StatePending counts digests a run never got to: cataloguing did not finish within its
	// share of the run budget. They are not failures — nothing is wrong with the image — and
	// they are not clean either, which is why they are counted apart and named individually.
	StatePending = "pending"
)

var reasons = []string{
	ReasonListPods, ReasonImageID, ReasonUnreachable,
	ReasonCatalogue, ReasonMatch, ReasonDatabase, ReasonCacheWrite,
}

// Reasons for kiebitzr_vulnerability_suppressed: the filter that removed a finding before it
// could become a series. One per configurable filter, so what a configuration hides is a
// number somebody can read rather than an absence nobody can.
//
// They are ordered, and the order is the order the filters run in: a finding an ignore rule
// removed never reaches the severity threshold, and one below the threshold is never asked
// whether it has a fix. A finding is therefore counted once, under the first filter that
// removed it — summing the reasons gives what the run suppressed in total, with nothing
// double-counted.
const (
	SuppressedIgnoreRule  = "ignore_rule"
	SuppressedMinSeverity = "min_severity"
	SuppressedOnlyFixed   = "only_fixed"
)

// SuppressionReasons are the reasons in the order the filters apply.
var SuppressionReasons = []string{SuppressedIgnoreRule, SuppressedMinSeverity, SuppressedOnlyFixed}

// Values of the build_access label on kiebitzr_image_info: can anybody here get a build of
// this image (ADR 0013). It is the axis package_type does not cover — that one is a property
// of the finding, this one of the image — and only together do they say whether an action
// exists at all.
const (
	// BuildAccessOwn means the build can be triggered inside the operator's own responsibility
	// boundary, without asking anybody outside it. The boundary is a team, not a person, which
	// is what makes it survive a holiday and change at a handover.
	BuildAccessOwn = "own"
	// BuildAccessReachable means a build needs a decision by somebody outside that boundary,
	// and that somebody can be reached with a reasonable expectation of being heard. An issue
	// tracker is not reachability: every open-source project has one, and a class that covers
	// everything says nothing.
	BuildAccessReachable = "reachable"
	// BuildAccessNone means there is nobody to ask in that sense, so the only remedy is a
	// different image.
	BuildAccessNone = "none"
	// BuildAccessUnknown means nobody has classified this image. It is a work item, not a
	// verdict, and it is deliberately not the same value as BuildAccessNone: "nobody has
	// looked" and "somebody decided there is nobody to ask" are opposite states, and an
	// installation with no rules file at all is in the first.
	BuildAccessUnknown = "unknown"
)

// IsReason reports whether reason is one this service publishes.
//
// It is exported because a reason now arrives over the network: a worker reports the stage an
// image failed at (ADR 0009), and a reason becomes a label value. Accepting an unknown one
// would let a caller invent series, which is the cardinality rule of ADR 0001 broken from
// outside.
func IsReason(reason string) bool {
	return slices.Contains(reasons, reason)
}

// ImageInfo describes one container running one image digest — the labels of
// kiebitzr_image_info. Several namespaces or workloads sharing a digest each keep their own
// series; the digest is still analysed once.
type ImageInfo struct {
	Digest    string
	Image     string
	Namespace string
	OwnerKind string
	OwnerName string
	Container string
	// BuildAccess says whether anybody here can get a build of this image: "own", "reachable",
	// "none", or "unknown" where no rule classified it. It is declared configuration, because
	// the difference between an image one's own team builds and one another team builds is not
	// in the image — same registry, same CI, same signing identity (ADR 0013).
	//
	// Empty is normalised to "unknown" at publish time rather than reaching a label: this
	// service never publishes an empty label value that means something, and an unconfigured
	// installation has to be a stated classification rather than a gap.
	BuildAccess string
}

// Vulnerability is one finding for one image digest — the labels of kiebitzr_vulnerability.
// There is no pod or container here on purpose: cardinality follows the images, not the
// cluster's replica count.
type Vulnerability struct {
	Digest   string
	CVE      string
	Severity string
	Package  string
	// SourcePackage is the package the affected one was built from — `openssl` for `libssl3`
	// and `libcrypto3`, `curl` for `curl` and `libcurl`. One advisory against one source
	// package otherwise appears once per binary package built from it, which multiplies the
	// finding count by something that is one thing to fix: a cluster-side analysis of one
	// image produced about 1,200 series for 135 advisories across 9 binary packages.
	//
	// A package that is its own source carries its own name here rather than an empty value,
	// so `count by (cve, source_package)` is correct for every finding and not only for the
	// distribution ones. Prometheus does not distinguish an empty label from an absent one,
	// and that ambiguity has cost a diagnosis here before.
	SourcePackage string
	// PackageType is the ecosystem the package was catalogued from — "apk", "deb",
	// "go-module", "python" and so on. It is what separates a finding a newer image of the
	// same lineage is likely to carry a fix for, because the base image's maintainer tracks
	// the distribution's advisories, from one that is compiled into a binary and moves only
	// when whoever publishes the image bumps a dependency and rebuilds. FixState cannot tell
	// those apart: it says a fixed *version* exists, not that it can reach this container.
	PackageType string
	Installed   string
	// Location is the path of the artefact inside the image — the file that carries the
	// finding. For a distribution package it is the package database and says nothing; for a
	// binary or a language package it names the thing to rebuild or remove. An analysis that
	// could not get past "about thirty findings on package=stdlib, and no way to tell which
	// binary" is what this exists for.
	//
	// It is the one label here that adds series. Two binaries in one image built with the same
	// toolchain produce two package records with identical labels, which would collapse into
	// one series without the path; with it they become one each. That split is the answer the
	// label exists to give, and it is also its price — measured at 344 series of about 11,100
	// on one cluster, 3 %, concentrated in a handful of images (ADR 0012).
	Location string
	FixedIn  string
	FixState string
	// KnownExploited is whether the vulnerability appears in a known-exploited catalogue.
	// It is a label, because "critical and exploited in the wild" is the set an operator
	// patches tonight and two label values cost nothing.
	KnownExploited bool
	// Risk is Grype's own score, 0 to 100, from the likelihood of exploitation and the
	// severity. It is deliberately *not* a label — a float label would give every finding
	// its own series — and reaches the metrics only aggregated per digest.
	Risk float64
}

// Suppressed is how many findings of one image digest one filter removed in the last run — the
// labels and value of kiebitzr_vulnerability_suppressed.
//
// It exists because the filters are the one place where this service produces silence on
// purpose. `-min-severity`, `-only-fixed` and an ignore rule all make findings disappear, and
// without this nothing said how many: an ignore rule written for one noisy package and matching
// half the cluster would read exactly like a cluster with nothing to report. The leading
// principle requires the opposite — a configuration that hides a lot has to show up as a large
// number, not as a clean screen (kbz:req:00001).
//
// Count is the number of *series* the filter removed, deduplicated exactly as the published
// findings are, so suppressed and published are in the same unit and their ratio means
// something.
type Suppressed struct {
	Digest string
	Reason string
	Count  int
}

// Failure is one digest a run could not analyse, with the stage it failed at. The count
// alone (Counts.Failed) says how many, which is the question nobody has: an operator needs
// to know which image and roughly why, and the log line then carries the registry's own
// message.
type Failure struct {
	Digest string
	Reason string
}

// Upgrade is the answer to "is there an image I could deploy that clears this" for one running
// digest — the labels and value of kiebitzr_image_upgrade_candidate.
type Upgrade struct {
	Digest string
	// Tag is the candidate that cleared the most, empty when no candidate existed because the
	// running image is already the newest build.
	Tag string
	// Cleared is how many in-scope findings that candidate removes. **Zero is a statement, not
	// an absence**: checked, clears nothing. The series therefore exists at zero, unlike
	// kiebitzr_image_risk_score where absence was the honest answer (ADR 0011).
	Cleared int
}

// UpgradeUnknown is a digest whose candidate question could not be answered, with the reason.
// It is a separate metric from Upgrade because **unknown is not "no fix"**: a run that could
// not look must not read like a run that looked and found nothing.
type UpgradeUnknown struct {
	Digest string
	Reason string
}

// Counts is how many digests a run catalogued, served from the cache, failed on and never got
// to.
type Counts struct {
	Scanned int
	Cached  int
	Failed  int
	Pending int
}

// Result is everything one run produces. It is published as a whole.
type Result struct {
	Images          []ImageInfo
	Vulnerabilities []Vulnerability
	Failures        []Failure
	// Suppressions are the findings the configured filters removed, per digest and filter. A
	// digest whose findings all survived gets no series, which is the honest shape: there is
	// nothing hidden to account for. Which filters are configured at all is in the start-up log.
	Suppressions []Suppressed
	// Pending are the digests that have no SBOM yet because cataloguing ran out of time. A run
	// publishes with them outstanding rather than publishing nothing, and naming them is what
	// keeps that honest: without this, a digest nobody has looked at yet would be
	// indistinguishable from one that has no findings.
	Pending []string
	Counts  Counts
	// Upgrades answers the deployability question per digest, and Unknowns names the digests
	// where it could not be answered. Both are empty when the check is switched off, which is
	// the default — and then neither metric has any series at all, which is the honest shape
	// for a feature nobody asked for.
	Upgrades []Upgrade
	Unknowns []UpgradeUnknown
}

// labelImageDigest is named once because it now appears in four descriptors: it is the join
// key between a finding, where that image runs, its risk and its failure — "The one join you
// need" in the metrics runbook.
const labelImageDigest = "image_digest"

// labelReason is named once for the same reason: it is the stage or cause label of three
// metrics now — what failed, what could not be answered, and what went wrong how often.
const labelReason = "reason"

var (
	imageInfoDesc = prometheus.NewDesc(
		"kiebitzr_image_info",
		"One for every container running an image digest, carrying where it runs.",
		[]string{
			labelImageDigest, "image", "namespace", "owner_kind", "owner_name", "container",
			"build_access",
		}, nil,
	)
	vulnerabilityDesc = prometheus.NewDesc(
		"kiebitzr_vulnerability",
		"One for every known vulnerability found in a running image digest.",
		[]string{
			labelImageDigest, "cve", "severity", "package", "source_package", "package_type",
			"installed", "location", "fixed_in", "fix_state", "known_exploited",
		}, nil,
	)
	vulnerabilitySuppressedDesc = prometheus.NewDesc(
		"kiebitzr_vulnerability_suppressed",
		"How many findings of an image digest a configured filter removed in the last run, by filter.",
		[]string{labelImageDigest, labelReason}, nil,
	)
	imageRiskScoreDesc = prometheus.NewDesc(
		"kiebitzr_image_risk_score",
		"Highest risk score among the findings of an image digest, 0 to 100, as Grype computes it.",
		[]string{labelImageDigest}, nil,
	)
	imageFailedDesc = prometheus.NewDesc(
		"kiebitzr_image_failed",
		"One for every image digest the last run could not analyse, carrying the stage it failed at.",
		[]string{labelImageDigest, labelReason}, nil,
	)
	imagePendingDesc = prometheus.NewDesc(
		"kiebitzr_image_pending",
		"One for every image digest the last run had not catalogued yet when it published.",
		[]string{labelImageDigest}, nil,
	)
	imageUpgradeCandidateDesc = prometheus.NewDesc(
		"kiebitzr_image_upgrade_candidate",
		"How many of a digest's in-scope findings the best candidate image clears; 0 means checked and clears nothing.",
		[]string{labelImageDigest, "tag"}, nil,
	)
	imageUpgradeUnknownDesc = prometheus.NewDesc(
		"kiebitzr_image_upgrade_unknown",
		"One for every image digest whose deployable-fix question could not be answered, carrying why. Unknown is not no-fix.",
		[]string{labelImageDigest, labelReason}, nil,
	)
	imagesDesc = prometheus.NewDesc(
		"kiebitzr_images",
		"Number of image digests the last run catalogued, took from the cache, failed on or did not reach.",
		[]string{"state"}, nil,
	)
)

// Exporter holds the published result and the counters around it, and serves them.
type Exporter struct {
	registry *prometheus.Registry
	result   atomic.Pointer[Result]

	lastSuccess prometheus.Gauge
	dbBuilt     prometheus.Gauge
	runDuration prometheus.Gauge
	errors      *prometheus.CounterVec
}

// New returns an Exporter whose result is empty: no images, no findings, and a last-success
// timestamp of zero — which is what makes "never finished a run" alertable.
//
// grypeDBMaxAge is published as a label on kiebitzr_build_info; see buildInfo for why it is a
// parameter when version and commit are not.
func New(grypeDBMaxAge time.Duration) *Exporter {
	e := &Exporter{
		registry: prometheus.NewRegistry(),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kiebitzr_last_success_timestamp_seconds",
			Help: "Unix time of the last run that completed without a fatal error.",
		}),
		dbBuilt: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kiebitzr_db_built_timestamp_seconds",
			Help: "Unix time the vulnerability database in use was built.",
		}),
		runDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kiebitzr_run_duration_seconds",
			Help: "Wall-clock duration of the last completed run.",
		}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kiebitzr_scan_errors_total",
			Help: "Errors during runs by reason; a run that fails never terminates the process.",
		}, []string{labelReason}),
	}
	e.result.Store(&Result{})

	for _, reason := range reasons {
		e.errors.WithLabelValues(reason)
	}
	e.registry.MustRegister(
		e.lastSuccess, e.dbBuilt, e.runDuration, e.errors,
		snapshotCollector{e},
		buildInfo(grypeDBMaxAge.String()),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return e
}

// Handler serves the registry of this exporter and nothing else; no global default registry
// is involved.
func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	})
}

// Publish swaps in the result of a completed run. Series that are gone from the new result
// disappear with the swap; nothing is ever reset to zero in between.
func (e *Exporter) Publish(r Result) {
	published := Result{
		Images:          dedupBy(classified(r.Images), func(i ImageInfo) ImageInfo { return i }),
		Vulnerabilities: dedupBy(r.Vulnerabilities, vulnerabilityLabels),
		Failures:        dedupBy(r.Failures, func(f Failure) Failure { return f }),
		Suppressions:    dedupBy(r.Suppressions, suppressedLabels),
		Pending:         dedupBy(r.Pending, func(d string) string { return d }),
		Counts:          r.Counts,
		Upgrades:        dedupBy(r.Upgrades, upgradeLabels),
		Unknowns:        dedupBy(r.Unknowns, func(u UpgradeUnknown) UpgradeUnknown { return u }),
	}
	e.result.Store(&published)
}

// RunSucceeded records a completed run: the duration it took and the time it finished.
func (e *Exporter) RunSucceeded(finished time.Time, took time.Duration) {
	e.runDuration.Set(took.Seconds())
	e.lastSuccess.Set(float64(finished.Unix()))
}

// RunFailed counts an error by reason and leaves the last-success timestamp and the
// published result untouched, so the previous findings keep being served.
func (e *Exporter) RunFailed(reason string) { e.ErrorsBy(reason, 1) }

// ErrorsBy counts n errors of one reason, for the per-run error tallies.
func (e *Exporter) ErrorsBy(reason string, n int) {
	if n > 0 {
		e.errors.WithLabelValues(reason).Add(float64(n))
	}
}

// DatabaseBuilt records when the vulnerability database in use was built, which is what
// makes a stale database alertable even while runs keep succeeding.
func (e *Exporter) DatabaseBuilt(built time.Time) {
	e.dbBuilt.Set(float64(built.Unix()))
}

// QueueDepth makes depth the source of kiebitzr_catalogue_queue_depth, the amount of
// cataloguing work not yet accounted for. It takes a function rather than a value because the
// depth moves during a run, not at publish time — and it is the signal a worker pool is scaled
// on, since a worker is network-bound on the registry pull and its CPU says nothing.
//
// Call it once, during start-up and before the endpoint is served.
func (e *Exporter) QueueDepth(depth func() int) error {
	gauge := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "kiebitzr_catalogue_queue_depth",
		Help: "Image digests waiting to be catalogued or handed to a worker and not yet answered.",
	}, func() float64 { return float64(depth()) })
	if err := e.registry.Register(gauge); err != nil {
		return fmt.Errorf("register queue depth: %w", err)
	}
	return nil
}

// snapshotCollector turns the currently published result into metrics on every scrape. It
// reads one pointer, so a scrape never blocks a run and a run never blocks a scrape.
type snapshotCollector struct{ e *Exporter }

// Describe announces every metric built from the published result.
func (c snapshotCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- imageInfoDesc
	ch <- vulnerabilityDesc
	ch <- vulnerabilitySuppressedDesc
	ch <- imagesDesc
	ch <- imageRiskScoreDesc
	ch <- imageFailedDesc
	ch <- imagePendingDesc
	ch <- imageUpgradeCandidateDesc
	ch <- imageUpgradeUnknownDesc
}

// Collect emits the published result. It reads one pointer, so a scrape never blocks a run
// and a run never blocks a scrape.
func (c snapshotCollector) Collect(ch chan<- prometheus.Metric) {
	r := c.e.result.Load()
	for _, img := range r.Images {
		ch <- prometheus.MustNewConstMetric(imageInfoDesc, prometheus.GaugeValue, 1,
			img.Digest, img.Image, img.Namespace, img.OwnerKind, img.OwnerName, img.Container,
			img.BuildAccess)
	}
	risk := make(map[string]float64, len(r.Images))
	for _, v := range r.Vulnerabilities {
		ch <- prometheus.MustNewConstMetric(vulnerabilityDesc, prometheus.GaugeValue, 1,
			v.Digest, v.CVE, v.Severity, v.Package, v.SourcePackage, v.PackageType, v.Installed,
			v.Location, v.FixedIn, v.FixState, strconv.FormatBool(v.KnownExploited))
		// The maximum, not the sum: triage starts at the worst single finding of an image,
		// and a sum would rank an image with many harmless findings above one with a single
		// exploited critical. A digest without findings gets no series at all — absence is
		// the honest answer there, and kiebitzr_image_failed covers the other reason for it.
		if v.Risk > risk[v.Digest] {
			risk[v.Digest] = v.Risk
		}
	}
	for digest, score := range risk {
		ch <- prometheus.MustNewConstMetric(imageRiskScoreDesc, prometheus.GaugeValue, score, digest)
	}
	for _, s := range r.Suppressions {
		ch <- prometheus.MustNewConstMetric(vulnerabilitySuppressedDesc, prometheus.GaugeValue,
			float64(s.Count), s.Digest, s.Reason)
	}
	for _, f := range r.Failures {
		ch <- prometheus.MustNewConstMetric(imageFailedDesc, prometheus.GaugeValue, 1, f.Digest, f.Reason)
	}
	for _, digest := range r.Pending {
		ch <- prometheus.MustNewConstMetric(imagePendingDesc, prometheus.GaugeValue, 1, digest)
	}
	for _, u := range r.Upgrades {
		ch <- prometheus.MustNewConstMetric(imageUpgradeCandidateDesc, prometheus.GaugeValue,
			float64(u.Cleared), u.Digest, u.Tag)
	}
	for _, u := range r.Unknowns {
		ch <- prometheus.MustNewConstMetric(imageUpgradeUnknownDesc, prometheus.GaugeValue, 1,
			u.Digest, u.Reason)
	}
	for state, count := range map[string]int{
		StateScanned: r.Counts.Scanned,
		StateCached:  r.Counts.Cached,
		StateFailed:  r.Counts.Failed,
		StatePending: r.Counts.Pending,
	} {
		ch <- prometheus.MustNewConstMetric(imagesDesc, prometheus.GaugeValue, float64(count), state)
	}
}

// vulnerabilityLabels is the part of a finding that becomes a label set. Risk is not in it
// on purpose: it is a value, and keying the deduplication on it would let two findings with
// the same labels and different scores both survive — which is precisely the duplicate
// series the deduplication exists to prevent.
func vulnerabilityLabels(v Vulnerability) Vulnerability {
	v.Risk = 0
	return v
}

// classified fills in the build access of images that arrived without one, before the
// deduplication keys on it. An unconfigured installation publishes "unknown" on every series
// rather than an empty label, because an empty label value cannot be told from an absent one —
// and because "nobody has classified this" is a statement, not a gap.
func classified(images []ImageInfo) []ImageInfo {
	out := make([]ImageInfo, 0, len(images))
	for _, img := range images {
		if img.BuildAccess == "" {
			img.BuildAccess = BuildAccessUnknown
		}
		out = append(out, img)
	}
	return out
}

// suppressedLabels is the part of a Suppressed that becomes a label set — the same reason Risk
// and Cleared are zeroed in their siblings: the count is the value, and keying the
// deduplication on it would let two tallies for one digest and filter both survive.
func suppressedLabels(s Suppressed) Suppressed {
	s.Count = 0
	return s
}

// upgradeLabels is the part of an Upgrade that becomes a label set. Cleared is the value, so it
// is cleared here for the same reason Risk is in vulnerabilityLabels: keying the deduplication
// on it would let two answers for one digest both survive and make the scrape fail.
func upgradeLabels(u Upgrade) Upgrade {
	u.Cleared = 0
	return u
}

// dedupBy keeps the first element for each key. Two equal label sets would make a scrape
// fail as a duplicate series, so the guard sits here rather than in every caller.
func dedupBy[T any, K comparable](in []T, key func(T) K) []T {
	seen := make(map[K]struct{}, len(in))
	out := make([]T, 0, len(in))
	for _, v := range in {
		k := key(v)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	return out
}
