package runner

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/upgrade"
	"github.com/obayer/kiebitzr/internal/vulndb"
)

// Selecting finds the candidate images worth checking against a running digest. internal/upgrade
// implements it; keeping it an interface is what holds the registry client out of this package.
type Selecting interface {
	// Select returns the candidates, newest first. An empty slice with no error is an answer —
	// the running image is already the newest build — and not a gap.
	Select(ctx context.Context, repository, runningDigest string) ([]upgrade.Build, error)
}

// Scopes a candidate check can run with. They mirror config.Scope*, which this package does not
// import: a runner is configured, it does not read configuration.
const (
	ScopeExploited = "exploited"
	ScopeFixable   = "fixable"
)

// finding identifies a vulnerability independently of which image it was found in, which is
// what makes "is it still there in the candidate" answerable. The package matters beside the
// CVE: one advisory can affect several packages, and a candidate may fix one and not another.
type finding struct {
	cve     string
	pkg     string
	pkgType string
}

// inScope reports whether a finding gets a candidate check.
//
// The default scope is the findings that could ever page: an alarm has to be clearable by
// whoever it wakes, so only something exploited in the wild with a fix available is worth
// waking anybody for (kbz:req:00001). The wide scope is roughly three times the work for
// findings nobody acts on tonight, which is why it is chosen and not inherited.
func inScope(v metrics.Vulnerability, scope string) bool {
	if v.FixState != "fixed" {
		return false
	}
	if scope == ScopeFixable {
		return v.Severity == "High" || v.Severity == "Critical"
	}
	return v.KnownExploited
}

// checkUpgrades answers, for every digest with in-scope findings, whether an image exists that
// this cluster could deploy instead and that clears some of them.
//
// It returns the candidate digests it catalogued, because those have to survive the cache
// prune. Without that they would be deleted at the end of every run and rebuilt the next day,
// which turns a one-off cost into a daily one (ADR 0011).
func (r *Runner) checkUpgrades(
	ctx context.Context, session vulndb.Session, refs map[string]string, result *metrics.Result,
) []string {
	if r.selector == nil {
		return nil
	}

	scoped := make(map[string][]finding)
	for _, v := range result.Vulnerabilities {
		if inScope(v, r.opts.UpgradeScope) {
			scoped[v.Digest] = append(scoped[v.Digest],
				finding{cve: v.CVE, pkg: v.Package, pkgType: v.PackageType})
		}
	}

	var catalogued []string
	for _, digest := range slices.Sorted(maps.Keys(scoped)) {
		// Candidates are the last thing a run does and the first thing it gives up. A cluster
		// that cannot keep up with its own images keeps its primary metrics, and the digests
		// left over say so rather than going silent.
		if err := ctx.Err(); err != nil {
			result.Unknowns = append(result.Unknowns,
				metrics.UpgradeUnknown{Digest: digest, Reason: upgrade.ReasonNotCatalogued})
			continue
		}

		repository := upgrade.Repository(refs[digest])
		if repository == "" {
			continue
		}
		builds, err := r.selector.Select(ctx, repository, digest)
		if err != nil {
			reason := upgrade.ReasonOf(err)
			if reason == "" {
				// An unexplained failure gets no series rather than a plausible-looking wrong
				// one, as everywhere else in this service. The log still carries it.
				r.log.Warn("candidate lookup failed", "digest", digest,
					"repository", repository, "err", err)
				continue
			}
			result.Unknowns = append(result.Unknowns,
				metrics.UpgradeUnknown{Digest: digest, Reason: reason})
			r.log.Debug("candidate question unanswered", "digest", digest,
				"repository", repository, "reason", reason, "err", err)
			continue
		}
		if len(builds) == 0 {
			// An answer: nothing newer exists, so there is nothing to deploy. Published at
			// zero rather than left absent, because absent would mean "nobody looked".
			result.Upgrades = append(result.Upgrades, metrics.Upgrade{Digest: digest})
			continue
		}

		best, tag, used := r.bestCandidate(ctx, session, builds, scoped[digest])
		catalogued = append(catalogued, used...)
		result.Upgrades = append(result.Upgrades,
			metrics.Upgrade{Digest: digest, Tag: tag, Cleared: best})
	}
	return catalogued
}

// bestCandidate catalogues and matches each candidate and returns the one that clears the most,
// along with the digests it managed to catalogue.
//
// Every candidate is checked rather than stopping at the first that clears something: the
// operator is told which tag clears the *most*, and the newest build is not reliably the one
// that does.
func (r *Runner) bestCandidate(
	ctx context.Context, session vulndb.Session, builds []upgrade.Build, want []finding,
) (cleared int, tag string, catalogued []string) {
	// The newest build names the answer even where nothing clears anything, so an operator can
	// see which tag was actually looked at.
	tag = builds[0].Tag

	for _, build := range builds {
		if ctx.Err() != nil {
			return cleared, tag, catalogued
		}
		remaining, err := r.remainingIn(ctx, session, build, want)
		if err != nil {
			r.log.Warn("candidate not checked", "candidate", build.Digest,
				"tag", build.Tag, "err", err)
			continue
		}
		catalogued = append(catalogued, build.Digest)

		if got := len(want) - remaining; got > cleared {
			cleared, tag = got, build.Tag
		}
	}
	return cleared, tag, catalogued
}

// remainingIn is how many of want are still present in one candidate image.
//
// The candidate is catalogued and matched exactly like a running image, by the pipeline that
// already exists. That is deliberate rather than convenient: the verdict has to be a
// measurement this service made, because an unverified claim cannot carry a page in either
// direction — a wrong positive wakes somebody who then has nothing to do (ADR 0011).
func (r *Runner) remainingIn(
	ctx context.Context, session vulndb.Session, build upgrade.Build, want []finding,
) (int, error) {
	if !r.store.Has(build.Digest) {
		report := r.catalogue.Catalogue(ctx, []Work{{Digest: build.Digest, Ref: build.Ref()}})
		if report.Scanned == 0 {
			return 0, fmt.Errorf("catalogue candidate %s: %d failed, %d pending",
				build.Digest, len(report.Failures), len(report.Pending))
		}
	}

	// What the policy suppressed in a candidate is deliberately dropped: the comparison is
	// between what is in scope for the running image and what is still there, and both sides
	// go through the same filters. A suppression series here would name a digest nobody runs.
	matched, err := r.match(ctx, session, build.Digest)
	if err != nil {
		return 0, fmt.Errorf("match candidate %s: %w", build.Digest, err)
	}

	present := make(map[finding]struct{}, len(matched.Findings))
	for _, v := range matched.Findings {
		present[finding{cve: v.CVE, pkg: v.Package, pkgType: v.PackageType}] = struct{}{}
	}
	var remaining int
	for _, f := range want {
		if _, still := present[f]; still {
			remaining++
		}
	}
	return remaining, nil
}
