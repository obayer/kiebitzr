// Package runner drives the periodic run: take the inventory of the cluster, catalogue every
// digest that is new, match everything against the vulnerability database, and publish the
// result as a whole. A run that fails never terminates the process — it counts an error,
// leaves the freshness timestamp alone and keeps the previous result on the endpoint
// (ADR 0001).
//
// Cataloguing is a stage rather than a step of the loop, because it is the one part that can
// run somewhere else: in this process, or in a pool of workers (ADR 0009). Matching is not —
// it needs the vulnerability database, and there is one of those.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/obayer/kiebitzr/internal/buildaccess"
	"github.com/obayer/kiebitzr/internal/inventory"
	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/vulndb"
)

// Work is one digest that needs an SBOM, with the reference it can be pulled by.
type Work struct {
	Digest string
	Ref    string
}

// Report is what a cataloguing stage achieved. It returns no error: a digest that could not be
// catalogued is reported, never fatal, because the rest of the run is still worth publishing.
type Report struct {
	// Scanned is how many digests gained an SBOM.
	Scanned int
	// Failures are the digests that could not be catalogued, with the stage they failed at.
	Failures []metrics.Failure
	// Pending are the digests the stage never got to. Not failures — nothing is known to be
	// wrong with them — and not clean either.
	Pending []string
}

// Cataloguing makes sure every digest it is given has an SBOM in the cache.
type Cataloguing interface {
	Catalogue(ctx context.Context, work []Work) Report
}

// Opener opens the vulnerability database for one run.
type Opener interface {
	Open(ctx context.Context) (vulndb.Session, error)
}

// SBOMStore is the part of the cache a run needs: asking whether a digest already has an SBOM,
// reading it, and dropping the SBOMs of digests that are no longer running.
type SBOMStore interface {
	Has(digest string) bool
	Open(digest string) (io.ReadSeekCloser, error)
	Prune(keep map[string]struct{}) (int, error)
}

// Options are the timings of the run loop.
type Options struct {
	// Interval is the time between the start of two runs.
	Interval time.Duration
	// Timeout bounds a single run. A run that is cut short while matching publishes nothing, so
	// this has to be generous enough for a cold start — it is not the interval.
	Timeout time.Duration
	// CatalogueTimeout bounds the cataloguing stage, and is deliberately shorter than Timeout:
	// a cold start that cannot catalogue everything must still leave time to match and publish
	// what it has. The digests it did not reach are reported as pending.
	//
	// Zero means cataloguing may use the whole run budget, in which case running out of time
	// fails the run instead of producing pending digests. config.Config never leaves it at
	// zero; the behaviour is defined so that Options is usable on its own.
	CatalogueTimeout time.Duration
	// ExcludeNamespaces are namespaces whose pods are ignored completely.
	ExcludeNamespaces []string
	// UpgradeScope is which findings get a candidate check, ScopeExploited or ScopeFixable.
	// Only read when a Selecting was supplied; empty behaves as ScopeExploited.
	UpgradeScope string
	// BuildAccess classifies images by whether anybody here can get a build of them. Nil is
	// the default and classifies everything as unknown, which is the honest state for an
	// installation that has declared nothing — not "nobody can fix any of this" (ADR 0013).
	BuildAccess *buildaccess.Rules
}

// Runner owns one run loop.
type Runner struct {
	pods      inventory.PodLister
	store     SBOMStore
	catalogue Cataloguing
	database  Opener
	exporter  *metrics.Exporter
	log       *slog.Logger
	opts      Options
	now       func() time.Time
	// selector is nil when the deployability check is switched off, which is the default. A nil
	// here is why neither upgrade metric has any series in that case: a feature nobody asked
	// for should publish nothing rather than publish zeroes that look like answers.
	selector Selecting
}

// New returns a Runner wired to one cluster, one cache, one cataloguing stage and one
// vulnerability database.
func New(
	pods inventory.PodLister,
	store SBOMStore,
	catalogue Cataloguing,
	database Opener,
	exporter *metrics.Exporter,
	log *slog.Logger,
	opts Options,
) *Runner {
	return &Runner{
		pods:      pods,
		store:     store,
		catalogue: catalogue,
		database:  database,
		exporter:  exporter,
		log:       log,
		opts:      opts,
		now:       time.Now,
	}
}

// WithCandidates switches the deployability check on, using selector to find the images worth
// checking. Without it the check does not run and neither of its metrics has a series.
//
// It is a separate call rather than another parameter of New because it is the only optional
// collaborator: every other one is required for a run to mean anything.
func (r *Runner) WithCandidates(selector Selecting) *Runner {
	r.selector = selector
	return r
}

// Loop runs once immediately and then every interval, until ctx is cancelled. Runs never
// overlap: a run that takes longer than the interval simply delays the next one.
func (r *Runner) Loop(ctx context.Context) {
	ticker := time.NewTicker(r.opts.Interval)
	defer ticker.Stop()
	for {
		r.Run(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Run performs a single run. It reports nothing: everything a run has to say, it says in the
// metrics and in the log.
func (r *Runner) Run(ctx context.Context) {
	started := r.now()

	// A stuck registry or API call must not block the loop forever. The bound is the
	// configured run timeout, not the interval: a cold start catalogues every image it finds.
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()

	result, err := r.scan(ctx)
	if err != nil {
		r.log.Error("run failed", "err", err, "duration_seconds", r.now().Sub(started).Seconds())
		return
	}

	r.exporter.Publish(*result)
	finished := r.now()
	r.exporter.RunSucceeded(finished, finished.Sub(started))
	r.log.Info("run finished",
		"images", result.Counts.Scanned+result.Counts.Cached,
		"upgrades_checked", len(result.Upgrades),
		"upgrades_unknown", len(result.Unknowns),
		"catalogued", result.Counts.Scanned,
		"cached", result.Counts.Cached,
		"failed", result.Counts.Failed,
		"pending", result.Counts.Pending,
		"containers", len(result.Images),
		"findings", len(result.Vulnerabilities),
		"duration_seconds", finished.Sub(started).Seconds(),
	)
}

// scan produces the result of one run, in three stages: the inventory, cataloguing what is
// new, and matching everything that has an SBOM.
//
// The errors it returns are the ones that make a published result a lie: without an inventory
// or without a database, publishing would claim that nothing is running or that nothing is
// vulnerable. An image that could not be catalogued is not one of them — it is reported per
// digest and the run still publishes.
func (r *Runner) scan(ctx context.Context) (*metrics.Result, error) {
	snapshot, err := inventory.Collect(ctx, r.pods, r.opts.ExcludeNamespaces)
	if err != nil {
		r.exporter.RunFailed(metrics.ReasonListPods)
		return nil, fmt.Errorf("inventory: %w", err)
	}
	r.exporter.ErrorsBy(metrics.ReasonImageID, snapshot.Unresolved())

	session, err := r.database.Open(ctx)
	if err != nil {
		r.exporter.RunFailed(metrics.ReasonDatabase)
		return nil, fmt.Errorf("vulnerability database: %w", err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			r.log.Warn("closing the vulnerability database failed", "err", closeErr)
		}
	}()

	if built, ok := session.Built(); ok {
		r.exporter.DatabaseBuilt(built)
	}

	if skipped := snapshot.Skipped(); skipped > 0 {
		r.log.Debug("pods skipped by namespace exclusion", "pods", skipped)
	}

	digests := snapshot.Digests()
	work := r.outstanding(digests, snapshot.Refs())

	report := r.runCatalogue(ctx, work)
	result := &metrics.Result{
		Images:   r.imageInfos(snapshot.Occurrences()),
		Failures: report.Failures,
		Pending:  report.Pending,
		Counts: metrics.Counts{
			Scanned: report.Scanned,
			Cached:  len(digests) - len(work),
			Failed:  len(report.Failures),
			Pending: len(report.Pending),
		},
	}
	for _, failure := range report.Failures {
		r.exporter.RunFailed(failure.Reason)
	}
	if result.Counts.Pending > 0 {
		r.log.Warn("cataloguing did not finish within its budget",
			"pending", result.Counts.Pending, "catalogued", report.Scanned)
	}

	if err := r.matchAll(ctx, session, digests, result); err != nil {
		return nil, err
	}

	// Last, and the first thing to be given up when the budget runs out: the primary metrics
	// are already complete at this point, and a candidate check that does not finish costs
	// nothing but its own answers.
	candidates := r.checkUpgrades(ctx, session, snapshot.Refs(), result)

	r.prune(append(slices.Clone(digests), candidates...))
	return result, nil
}

// runCatalogue hands the work list to the cataloguing stage under its own deadline. The
// deadline is what turns "the run ran out of time" from a failure that publishes nothing into
// a set of pending digests beside a published result.
func (r *Runner) runCatalogue(ctx context.Context, work []Work) Report {
	if len(work) == 0 {
		return Report{}
	}
	if r.opts.CatalogueTimeout <= 0 {
		return r.catalogue.Catalogue(ctx, work)
	}
	catalogueCtx, cancel := context.WithTimeout(ctx, r.opts.CatalogueTimeout)
	defer cancel()
	return r.catalogue.Catalogue(catalogueCtx, work)
}

// outstanding is the work list: the running digests that have no SBOM yet. A digest that is
// already catalogued is never handed to the cataloguing stage, which is what makes a
// steady-state run a diff rather than a rescan (ADR 0001).
func (r *Runner) outstanding(digests []string, refs map[string]string) []Work {
	work := make([]Work, 0, len(digests))
	for _, digest := range digests {
		if r.store.Has(digest) {
			continue
		}
		work = append(work, Work{Digest: digest, Ref: refs[digest]})
	}
	return work
}

// matchAll matches every digest that has an SBOM and collects the findings into result.
//
// Being cut short here is fatal to the run, unlike in cataloguing: a digest whose SBOM exists
// but was not matched would be published with no findings, which reads as "clean". There is no
// metric for that, so the run fails and the previous result keeps being served.
func (r *Runner) matchAll(
	ctx context.Context, session vulndb.Session, digests []string, result *metrics.Result,
) error {
	for _, digest := range digests {
		if err := ctx.Err(); err != nil {
			r.exporter.RunFailed(metrics.ReasonMatch)
			return fmt.Errorf("run cut short after matching %d of %d images: %w",
				len(result.Vulnerabilities), len(digests), err)
		}
		// Pending and failed digests have no SBOM. They are accounted for already, by
		// kiebitzr_image_pending and kiebitzr_image_failed.
		if !r.store.Has(digest) {
			continue
		}

		matched, err := r.match(ctx, session, digest)
		if err != nil {
			result.Counts.Failed++
			// The counter lives here rather than in match(), so one failed image is counted
			// once, in the same place where it is recorded and logged. A stage that is not
			// known produces neither series: an empty reason label would be a lie in two
			// metrics at once, and the log still carries the error itself.
			reason := reasonOf(err)
			if reason != "" {
				r.exporter.RunFailed(reason)
				result.Failures = append(result.Failures,
					metrics.Failure{Digest: digest, Reason: reason})
			}
			r.log.Warn("image failed", "digest", digest, "reason", reason, "err", err)
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, matched.Findings...)
		// Only for the running images: the candidate check matches images nobody runs, and a
		// suppression series for one of those would name a digest that appears nowhere else.
		result.Suppressions = append(result.Suppressions, matched.Suppressed...)
	}
	return nil
}

// match reads the cached SBOM of a digest and matches it. Every error it returns is a
// stageError, because which stage failed is known only here and the caller has to report it
// per digest rather than only count it.
func (r *Runner) match(ctx context.Context, session vulndb.Session, digest string) (vulndb.MatchResult, error) {
	sbom, err := r.store.Open(digest)
	if err != nil {
		return vulndb.MatchResult{}, stageError{metrics.ReasonCatalogue, fmt.Errorf("read sbom: %w", err)}
	}
	defer func() { _ = sbom.Close() }()

	matched, err := session.Match(ctx, digest, sbom)
	if err != nil {
		return vulndb.MatchResult{}, stageError{metrics.ReasonMatch, fmt.Errorf("match: %w", err)}
	}
	return matched, nil
}

// stageError names the stage an image failed at, so a failure can be reported with its
// digest and not only counted.
type stageError struct {
	reason string
	err    error
}

func (e stageError) Error() string { return e.err.Error() }
func (e stageError) Unwrap() error { return e.err }

// reasonOf is the stage an error came from, or empty when an error carries none. Empty is
// not guessed at: a failure whose stage is unknown is still counted and logged, but it gets
// no kiebitzr_image_failed series rather than a plausible-looking wrong one.
func reasonOf(err error) string {
	if stage, ok := errors.AsType[stageError](err); ok {
		return stage.reason
	}
	return ""
}

// prune drops the SBOMs of digests that are neither running nor a candidate that was checked.
//
// Candidates belong in the keep set, and leaving them out was a real cost: their SBOMs would be
// deleted at the end of every run and rebuilt the next day, turning a one-off price into a
// daily one. A cache that cannot be pruned only costs disk space, so it is counted and logged
// but does not fail the run.
func (r *Runner) prune(keepDigests []string) {
	keep := make(map[string]struct{}, len(keepDigests))
	for _, digest := range keepDigests {
		keep[digest] = struct{}{}
	}
	removed, err := r.store.Prune(keep)
	if err != nil {
		r.exporter.RunFailed(metrics.ReasonCacheWrite)
		r.log.Warn("pruning the cache failed", "err", err)
	}
	if removed > 0 {
		r.log.Info("pruned cached sboms", "removed", removed)
	}
}

// imageInfos maps the inventory onto the labels of kiebitzr_image_info. The mapping is
// explicit so the metric's label set can change without touching the inventory.
//
// The classification is applied per occurrence, against the reference that occurrence was
// pulled by. One digest reached under two references — a vendor's and an internal mirror's —
// therefore keeps one classification per reference, each correct for what it describes; a
// query that wants one answer per digest aggregates, and the runbook says the more generous
// one wins (ADR 0013).
func (r *Runner) imageInfos(occurrences []inventory.Occurrence) []metrics.ImageInfo {
	out := make([]metrics.ImageInfo, 0, len(occurrences))
	for _, occ := range occurrences {
		out = append(out, metrics.ImageInfo{
			Digest:      occ.Digest,
			Image:       occ.Image,
			Namespace:   occ.Namespace,
			OwnerKind:   occ.OwnerKind,
			OwnerName:   occ.OwnerName,
			Container:   occ.Container,
			BuildAccess: r.opts.BuildAccess.For(occ.Image),
		})
	}
	return out
}
