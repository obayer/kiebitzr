// Package vulndb owns the vulnerability database and the matching of cached SBOMs against
// it, using Grype as a library. The matching policy — severity threshold, "only with a fix"
// and ignore rules — is runtime configuration, never compiled in (ADR 0001).
package vulndb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	grypematch "github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftpkg "github.com/anchore/syft/syft/pkg"
	"gopkg.in/yaml.v3"

	"github.com/obayer/kiebitzr/internal/anchorelog"
	"github.com/obayer/kiebitzr/internal/metrics"
)

// SetLogger routes what Grype has to say into log. Grype keeps a package-level logger that
// discards everything until it is set, which is why a failed database update used to leave no
// trace: it reports the reason there and then returns the state the database is in.
//
// It lives here because this package is where Grype is allowed to be imported, enforced by
// depguard. Process-wide and not safe to interleave with use: call it once during start-up.
func SetLogger(log *slog.Logger) {
	grype.SetLogger(anchorelog.New(log.With("library", "grype")))
}

// severityUnknown labels a finding whose source states no severity.
const severityUnknown = "Unknown"

// locationUnknown labels a finding whose package Syft recorded no path for. Spelled out for
// the same reason as packageTypeUnknown: an empty label value cannot be told from an absent
// one in Prometheus, so "nobody recorded a path" would read as "this label does not exist in
// the running build".
const locationUnknown = "unknown"

// packageTypeUnknown labels a finding whose package Syft could not place in an ecosystem.
// Syft spells its own unknown type "UnknownPackage", and an unset type is the empty string;
// both collapse here, so the label carries one value meaning "no answer" rather than three —
// and never the empty one, which would read as a package type nobody has a name for.
const packageTypeUnknown = "unknown"

// Config is the matching policy a deployment supplies.
type Config struct {
	// Dir is where the database is kept; it is managed by Grype's curator.
	Dir string
	// MinSeverity drops findings below this severity. Empty keeps every finding.
	MinSeverity string
	// OnlyFixed keeps only findings that have a fix available.
	OnlyFixed bool
	// IgnoreFile is a YAML file of Grype ignore rules. Empty means none.
	IgnoreFile string
}

// Matcher holds the matching policy and opens the database for a run.
type Matcher struct {
	distribution v6dist.Config
	installation v6inst.Config
	matchers     []grypematch.Matcher
	ignoreRules  []grypematch.IgnoreRule
	policy       policy
}

// policy is the part of the configuration that is applied to the findings of a match.
type policy struct {
	minSeverity vulnerability.Severity
	onlyFixed   bool
}

// New validates the configuration and prepares the matcher. It touches neither the network
// nor the disk, so a wrong severity or an unreadable ignore file fails at startup rather than
// in the first run.
func New(cfg Config, userAgent string) (*Matcher, error) {
	if cfg.Dir == "" {
		return nil, errors.New("database directory must not be empty")
	}

	minSeverity := vulnerability.UnknownSeverity
	if cfg.MinSeverity != "" {
		minSeverity = vulnerability.ParseSeverity(cfg.MinSeverity)
		if minSeverity == vulnerability.UnknownSeverity {
			return nil, fmt.Errorf("unknown severity %q", cfg.MinSeverity)
		}
	}

	rules, err := ignoreRules(cfg.IgnoreFile)
	if err != nil {
		return nil, err
	}

	id := clio.Identification{Name: "kiebitzr", Version: userAgent}
	distConfig := v6dist.DefaultConfig()
	distConfig.ID = id
	installConfig := v6inst.DefaultConfig(id)
	installConfig.DBRootDir = cfg.Dir

	return &Matcher{
		distribution: distConfig,
		installation: installConfig,
		matchers:     matcher.NewDefaultMatchers(matcher.Config{}),
		ignoreRules:  rules,
		policy:       policy{minSeverity: minSeverity, onlyFixed: cfg.OnlyFixed},
	}, nil
}

// Open updates the database if a newer one has been published and opens it for matching. The
// caller closes the session.
//
// Grype refuses a database that is too old to be trusted, so an installation that has been
// cut off from the update server long enough fails here. That is deliberate: the run fails,
// the previous findings keep being served and the freshness metrics stop moving, which is an
// alertable condition rather than quietly stale results.
func (m *Matcher) Open(_ context.Context) (Session, error) {
	provider, status, err := grype.LoadVulnerabilityDB(m.distributionFor(m.databaseExists()), m.installation, true)
	if err != nil {
		return nil, fmt.Errorf("open vulnerability database: %w", err)
	}
	return &session{
		matcher: &grype.VulnerabilityMatcher{
			VulnerabilityProvider: provider,
			Matchers:              m.matchers,
			IgnoreRules:           m.ignoreRules,
			NormalizeByCVE:        true,
		},
		provider: provider,
		status:   status,
		policy:   m.policy,
	}, nil
}

// databaseExists reports whether a readable database is already in place, asking the same
// question Grype's curator asks of the same file.
func (m *Matcher) databaseExists() bool {
	_, err := v6.ReadDescription(m.installation.DBFilePath())
	return err == nil
}

// distributionFor decides whether a failed update is an error or a warning.
//
// Grype only returns the real reason an update failed when RequireUpdateCheck is set;
// otherwise it writes it to its own logger — which this process does not consume — and then
// reports whatever state the database is in. With no database that state is "database does
// not exist", which is the consequence and not the cause: it reads the same whether the
// cache directory was unwritable or the update server unreachable, and sends an operator
// looking in the wrong place. So on a first run, where the update *is* the database, a
// failure has to be fatal and carry its reason.
//
// With a database already in place the opposite is right. A transient failure must not stop
// a run that can still match against what is there, and a database too old to be trusted is
// already refused by Grype itself.
func (m *Matcher) distributionFor(databaseExists bool) v6dist.Config {
	cfg := m.distribution
	cfg.RequireUpdateCheck = !databaseExists
	return cfg
}

// MatchResult is what matching one SBOM yields: the findings that survived the policy, and how
// many the policy removed, by filter. The second half is not a detail of the first — it is what
// keeps a filter's silence accountable, since a finding the policy drops leaves no other trace.
type MatchResult struct {
	Findings   []metrics.Vulnerability
	Suppressed []metrics.Suppressed
}

// Session is an open database, used for all images of one run. It is an interface so the run
// loop can be exercised without a database.
type Session interface {
	// Match returns the findings for one cached SBOM, and what the policy removed from them.
	Match(ctx context.Context, digest string, sbom io.ReadSeeker) (MatchResult, error)
	// Built is when the database in use was built, and whether that is known at all.
	Built() (time.Time, bool)
	// Close releases the database.
	Close() error
}

type session struct {
	matcher  *grype.VulnerabilityMatcher
	provider vulnerability.Provider
	status   *vulnerability.ProviderStatus
	policy   policy
}

// Built is when the database in use was built, which is what makes a stale database visible.
func (s *session) Built() (time.Time, bool) {
	if s.status == nil || s.status.Built.IsZero() {
		return time.Time{}, false
	}
	return s.status.Built, true
}

// Match matches one cached SBOM and returns the findings for its image digest.
//
// The ignored matches Grype returns are the second half of the answer rather than something to
// discard: they are what the operator's own ignore rules removed, and nothing else in the run
// knows about them. Grype applies only the rules handed to it here — matcher-side suppressions
// stay out, because IncludeMatcherSuppressions is not set — so the count is attributable to the
// configuration and not to Grype's internals.
func (s *session) Match(ctx context.Context, digest string, sbom io.ReadSeeker) (MatchResult, error) {
	pkgs, pkgContext, _, err := grypepkg.ProvideFromReader(sbom, grypepkg.ProviderConfig{})
	if err != nil {
		return MatchResult{}, fmt.Errorf("read sbom of %s: %w", digest, err)
	}

	matches, ignored, err := s.matcher.FindMatchesContext(ctx, pkgs, pkgContext)
	if err != nil {
		return MatchResult{}, fmt.Errorf("match %s: %w", digest, err)
	}
	return s.policy.apply(digest, matches.Sorted(), ignored), nil
}

// Close releases the database.
func (s *session) Close() error {
	if err := s.provider.Close(); err != nil {
		return fmt.Errorf("close vulnerability database: %w", err)
	}
	return nil
}

// apply maps Grype matches onto the labels of kiebitzr_vulnerability, keeps what the policy
// allows and counts what it removed. A finding without a stated severity is kept even when a
// threshold is set: nothing proves it is below the bar, and silently dropping it would be the
// wrong default for a detection tool.
//
// What is removed is counted in series rather than in matches, deduplicated by the same label
// set the exporter deduplicates on. Two matches that would have collapsed into one series must
// not be reported as two suppressed findings — the number is read against the number of series
// that survived, and a unit that only agrees sometimes is worse than no number.
func (p policy) apply(
	digest string, matches []grypematch.Match, ignored []grypematch.IgnoredMatch,
) MatchResult {
	out := make([]metrics.Vulnerability, 0, len(matches))
	tally := make(map[string]int, len(metrics.SuppressionReasons))
	counted := make(map[metrics.Vulnerability]struct{})

	// suppress tallies one removed series. The first filter that removed a label set owns it,
	// which is what keeps the reasons disjoint and their sum equal to the total removed.
	suppress := func(reason string, v metrics.Vulnerability) {
		v.Risk = 0
		if _, dup := counted[v]; dup {
			return
		}
		counted[v] = struct{}{}
		tally[reason]++
	}

	for _, m := range ignored {
		suppress(metrics.SuppressedIgnoreRule, vulnerabilityOf(digest, m.Match))
	}
	for _, m := range matches {
		v := vulnerabilityOf(digest, m)
		switch {
		case p.belowThreshold(v.Severity):
			suppress(metrics.SuppressedMinSeverity, v)
		case p.onlyFixed && v.FixState != string(vulnerability.FixStateFixed):
			suppress(metrics.SuppressedOnlyFixed, v)
		default:
			out = append(out, v)
		}
	}

	return MatchResult{Findings: out, Suppressed: suppressions(digest, tally)}
}

// belowThreshold reports whether a severity is under a configured minimum. An unparseable or
// absent severity never is: see apply.
func (p policy) belowThreshold(severity string) bool {
	if p.minSeverity == vulnerability.UnknownSeverity {
		return false
	}
	parsed := vulnerability.ParseSeverity(severity)
	return parsed != vulnerability.UnknownSeverity && parsed < p.minSeverity
}

// suppressions turns the tally into series, in the fixed order the filters apply, and only for
// what was actually removed. A filter that removed nothing gets no series: there is nothing
// hidden to account for, and a zero per digest and filter would be three series per image
// bought for no answer.
func suppressions(digest string, tally map[string]int) []metrics.Suppressed {
	out := make([]metrics.Suppressed, 0, len(tally))
	for _, reason := range metrics.SuppressionReasons {
		if count := tally[reason]; count > 0 {
			out = append(out, metrics.Suppressed{Digest: digest, Reason: reason, Count: count})
		}
	}
	return out
}

// vulnerabilityOf maps one Grype match onto the labels of kiebitzr_vulnerability. It runs for
// suppressed matches too, because a removed finding has to be counted in the same unit as a
// published one.
func vulnerabilityOf(digest string, m grypematch.Match) metrics.Vulnerability {
	fixState := m.Vulnerability.Fix.State
	if fixState == "" {
		fixState = vulnerability.FixStateUnknown
	}
	knownExploited, risk := threatOf(m)
	return metrics.Vulnerability{
		Digest:        digest,
		CVE:           m.Vulnerability.ID,
		Severity:      severityOf(m),
		Package:       m.Package.Name,
		SourcePackage: sourcePackageOf(m),
		PackageType:   packageTypeOf(m),
		Installed:     m.Package.Version,
		Location:      locationOf(m),
		FixedIn:       fixedIn(m.Vulnerability.Fix.Versions),
		FixState:      string(fixState),

		KnownExploited: knownExploited,
		Risk:           risk,
	}
}

// threatOf reads the evidence of exploitation a record carries: whether it appears in a
// known-exploited catalogue, and Grype's own risk score.
//
// The score is Grype's and not ours on purpose. Its formula is documented and maintained
// with the data it reads — the likelihood of exploitation from EPSS, the severity from the
// CVSS base scores, a boost for a vulnerability known to be exploited and a larger one for
// a known ransomware campaign. Inventing a second number here would mean maintaining a
// risk model as a side line of a metrics exporter, and an operator who sorts by it would
// have no way to find out what it meant.
//
// Both were being discarded until now, and that is the part that cannot be undone later:
// what a run does not publish, no dashboard and no page can reconstruct afterwards.
func threatOf(m grypematch.Match) (knownExploited bool, risk float64) {
	md := m.Vulnerability.Metadata
	if md == nil {
		return false, 0
	}
	return len(md.KnownExploited) > 0, md.RiskScore()
}

// severityOf is the severity the source states, or Unknown.
func severityOf(m grypematch.Match) string {
	if m.Vulnerability.Metadata == nil || m.Vulnerability.Metadata.Severity == "" {
		return severityUnknown
	}
	return m.Vulnerability.Metadata.Severity
}

// sourcePackageOf is the package the affected one was built from: `openssl` for `libssl3`,
// `curl` for `libcurl`. Grype derives it while matching — a dpkg `Source` field, an rpm's
// source RPM, an apk's origin package — so this reads a value that is already there rather
// than parsing package metadata a second time.
//
// A package that is its own source gets its own name, not an empty label. Only some of the
// sources state an origin at all: dpkg omits the field when it equals the package name, and
// rpm's is dropped by Grype in that case, so an empty value would mean "same as the package"
// for a deb and "no idea" for a Go module. One label value cannot carry both, and the
// fallback makes `count by (cve, source_package)` correct for every finding instead of only
// for the distribution ones.
//
// The first upstream only where there are several. More than one is rare, and a label that
// sometimes holds a list is worse to query than one that names the first.
func sourcePackageOf(m grypematch.Match) string {
	if len(m.Package.Upstreams) > 0 && m.Package.Upstreams[0].Name != "" {
		return m.Package.Upstreams[0].Name
	}
	return m.Package.Name
}

// locationOf is where in the image the affected artefact sits: the file Syft catalogued the
// package from.
//
// For a distribution package that is the package database — `/var/lib/dpkg/status`,
// `/lib/apk/db/installed` — and says nothing beyond "this image has dpkg". For a binary or a
// language package it is the answer to the question the metrics could not answer before:
// thirty findings against `package="stdlib"` name a Go toolchain, and nothing said which
// binary was built with it, so the only moves were guessing or going into the image by hand.
//
// The first location only, from Syft's own stable ordering, so the label does not change
// between runs for an unchanged image. Several locations mean several files led to the same
// package record, not several affected artefacts — those are separate records and get their
// own series.
func locationOf(m grypematch.Match) string {
	for _, location := range m.Package.Locations.ToSlice() {
		if location.RealPath != "" {
			return location.RealPath
		}
	}
	return locationUnknown
}

// packageTypeOf is the ecosystem a finding's package was catalogued from, as Syft's own type
// string.
//
// It is passed through rather than interpreted. The question an operator asks of it — "can a
// newer image fix this, or only a rebuild by whoever publishes it" — is answered by grouping
// the type values, and that grouping belongs in a query, where it is visible and arguable.
// Deriving an "os" / "app" label here would bake our reading of some forty package types into
// the metric, where a consumer could neither see nor dispute it; ADR 0008 rejected the same
// shape of decision for the risk score, and for the same reason.
func packageTypeOf(m grypematch.Match) string {
	if m.Package.Type == "" || m.Package.Type == syftpkg.UnknownPkg {
		return packageTypeUnknown
	}
	return string(m.Package.Type)
}

// fixedIn joins the fixed versions into one label value. Several records can name different
// fixed versions for one finding; all of them are reported, sorted so the label is stable
// across runs.
func fixedIn(versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	sorted := slices.Clone(versions)
	slices.Sort(sorted)
	return strings.Join(slices.Compact(sorted), ",")
}

// ignoreFile is the shape of the ignore file, matching Grype's own configuration so an
// operator can copy a rule over unchanged.
type ignoreFile struct {
	Ignore []grypematch.IgnoreRule `yaml:"ignore"`
}

func ignoreRules(path string) ([]grypematch.IgnoreRule, error) {
	if path == "" {
		return nil, nil
	}
	content, err := os.ReadFile(path) //nolint:gosec // the path is operator-supplied configuration
	if err != nil {
		return nil, fmt.Errorf("read ignore file: %w", err)
	}

	// Unknown keys are rejected: a typo in a rule would otherwise silently ignore nothing.
	var file ignoreFile
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse ignore file %s: %w", path, err)
	}
	if len(file.Ignore) == 0 {
		return nil, fmt.Errorf("ignore file %s contains no rules under `ignore:`", path)
	}
	return file.Ignore, nil
}
