package upgrade

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Reasons the candidate question has no answer, beyond those in upgrade.go.
const (
	// ReasonNoTags means the repository offered no tag list — the registry does not permit it,
	// or there is nothing there. Not the same as "nothing newer exists", which is an answer.
	ReasonNoTags = "no_tags"
	// ReasonUnorderable means the builds of a repository cannot be put in time order, so
	// "newer than what runs" has no meaning there.
	//
	// It exists because reproducible builds set the image's creation time to a fixed value on
	// purpose — ko, Bazel and Nix all do — and comparing those tells you nothing. Reporting
	// that as "no newer build" would be a negative nobody measured, and a negative suppresses
	// a page (ADR 0011).
	ReasonUnorderable = "unorderable_builds"
)

// usableFrom is the earliest creation time treated as real. Reproducible builders write the
// Unix epoch; a handful write a fixed date in the early 2000s. Anything before this is taken
// as "no timestamp" rather than as a very old image, because an image genuinely built in the
// nineties is not a case worth serving and a zeroed one is.
var usableFrom = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// Build is one tag of a repository, resolved to the configured platform, with the time its
// image says it was built.
type Build struct {
	// Repository is where this build lives, so a Build can name its own pull reference.
	Repository string
	Tag        string
	Digest     string
	Created    time.Time
}

// Ref is the pull reference of this build, `repository@digest` — the shape the cataloguing
// stage already takes, so nothing downstream needs to know a candidate from any other image.
func (b Build) Ref() string { return b.Repository + "@" + b.Digest }

// orderable reports whether this build's timestamp carries information.
func (b Build) orderable() bool { return b.Created.After(usableFrom) }

// Selector finds the candidate images of a repository worth checking against a running digest.
type Selector struct {
	resolver *Resolver
	limit    int
	options  []remote.Option
}

// NewSelector returns a Selector for one platform, checking at most limit candidates per
// repository. The platform is given as `os/arch[/variant]`.
//
// limit is above one on purpose. The newest build is not reliably the newest *content*: a
// publisher maintaining two release lines can ship a backport after the next minor, and a
// repository with a nightly tag has its newest build be something nobody would deploy. Looking
// at the next few costs one SBOM each and removes both failure modes (ADR 0011).
func NewSelector(platform string, limit int) (*Selector, error) {
	if limit < 1 {
		return nil, fmt.Errorf("candidate limit %d must be at least one", limit)
	}
	// The tag is irrelevant here — this Selector resolves many — but Resolver owns the
	// platform parsing and the per-manifest platform selection, which is what is wanted.
	resolver, err := NewResolver("latest", platform)
	if err != nil {
		return nil, err
	}
	return &Selector{
		resolver: resolver,
		limit:    limit,
		options:  []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
	}, nil
}

// Select returns the candidates of repository worth checking against the image running at
// runningDigest: the newest builds that are newer than it, newest first, at most limit of them.
//
// An empty slice with no error is an answer and not a gap: it means nothing newer exists, so
// there is nothing to deploy. A gap is an *UnresolvedError with its reason.
func (s *Selector) Select(ctx context.Context, repository, runningDigest string) ([]Build, error) {
	tags, err := s.tags(ctx, repository)
	if err != nil {
		return nil, err
	}

	running, err := s.build(ctx, repository, runningDigest, "")
	if err != nil {
		return nil, &UnresolvedError{
			ReasonUnreachable,
			fmt.Errorf("read the running image's build time: %w", err),
		}
	}

	builds := make([]Build, 0, len(tags))
	var examinable int
	for _, tag := range tags {
		build, err := s.buildOfTag(ctx, repository, tag)
		if err != nil {
			// A tag that cannot be read is skipped rather than fatal: an index without our
			// platform, an attestation manifest, a tag pointing at a deleted blob. What
			// matters is whether *any* tag could be read at all.
			continue
		}
		examinable++
		builds = append(builds, build)
	}
	if examinable == 0 {
		return nil, &UnresolvedError{ReasonUnreachable, fmt.Errorf(
			"none of the %d tags of %s could be read for %s",
			len(tags), repository, s.resolver.platform)}
	}

	return newerThan(builds, running, s.limit)
}

// tags lists the repository's tags.
func (s *Selector) tags(ctx context.Context, repository string) ([]string, error) {
	repo, err := name.NewRepository(repository)
	if err != nil {
		return nil, &UnresolvedError{ReasonUnreachable, fmt.Errorf("repository: %w", err)}
	}
	options := append([]remote.Option{remote.WithContext(ctx)}, s.options...)
	tags, err := remote.List(repo, options...)
	if err != nil {
		return nil, &UnresolvedError{reasonForGet(err), fmt.Errorf("list tags of %s: %w", repository, err)}
	}
	if len(tags) == 0 {
		return nil, &UnresolvedError{ReasonNoTags, fmt.Errorf("%s has no tags", repository)}
	}
	return tags, nil
}

// buildOfTag resolves one tag to the platform manifest and reads when it was built.
func (s *Selector) buildOfTag(ctx context.Context, repository, tag string) (Build, error) {
	candidate, err := s.resolver.resolveTag(ctx, repository, tag)
	if err != nil {
		return Build{}, err
	}
	return s.build(ctx, repository, candidate.Digest, tag)
}

// build reads the creation time out of an image's config. It is the cheapest reliable source of
// build order the OCI model offers: a small JSON, no layers.
func (s *Selector) build(ctx context.Context, repository, digest, tag string) (Build, error) {
	ref, err := name.NewDigest(repository + "@" + digest)
	if err != nil {
		return Build{}, fmt.Errorf("digest reference: %w", err)
	}
	options := append([]remote.Option{remote.WithContext(ctx)}, s.options...)
	image, err := remote.Image(ref, options...)
	if err != nil {
		return Build{}, fmt.Errorf("read image %s: %w", digest, err)
	}
	config, err := image.ConfigFile()
	if err != nil {
		return Build{}, fmt.Errorf("read config of %s: %w", digest, err)
	}
	return Build{Repository: repository, Tag: tag, Digest: digest, Created: config.Created.Time}, nil
}

// newerThan is the selection itself, and it is pure so that the rule can be tested without a
// registry: the builds newer than running, newest first, at most limit of them.
//
// It refuses to answer where the timestamps carry no information. The rule is deliberately
// strict — *any* unusable timestamp makes the whole repository unorderable — because the
// alternative errs in the dangerous direction. A repository where half the builds have no
// timestamp could hide a newer one, and silently returning the orderable half would publish a
// negative that was never measured.
func newerThan(builds []Build, running Build, limit int) ([]Build, error) {
	if !running.orderable() {
		return nil, &UnresolvedError{ReasonUnorderable, fmt.Errorf(
			"the running image states no build time (%s)", running.Created)}
	}
	for _, build := range builds {
		if !build.orderable() {
			return nil, &UnresolvedError{ReasonUnorderable, fmt.Errorf(
				"tag %s states no build time (%s)", build.Tag, build.Created)}
		}
	}

	newer := make([]Build, 0, len(builds))
	for _, build := range builds {
		// The running digest can carry several tags; it is not a candidate for itself.
		if build.Digest == running.Digest || !build.Created.After(running.Created) {
			continue
		}
		newer = append(newer, build)
	}
	slices.SortFunc(newer, func(a, b Build) int {
		if c := b.Created.Compare(a.Created); c != 0 {
			return c
		}
		// Same instant: order by tag so a run is reproducible rather than map-ordered.
		return cmp.Compare(a.Tag, b.Tag)
	})
	return slices.Clip(newer[:min(len(newer), limit)]), nil
}

// resolveTag is Resolve for a tag other than the one this Resolver was built with, which is
// what a Selector needs: it asks a repository about many tags.
func (r *Resolver) resolveTag(ctx context.Context, repository, tag string) (Candidate, error) {
	ref, err := name.NewTag(repository + ":" + tag)
	if err != nil {
		return Candidate{}, &UnresolvedError{ReasonUnreachable, fmt.Errorf("reference: %w", err)}
	}
	options := append([]remote.Option{remote.WithContext(ctx)}, r.options...)
	desc, err := remote.Get(ref, options...)
	if err != nil {
		return Candidate{}, &UnresolvedError{reasonForGet(err), fmt.Errorf("get %s: %w", ref, err)}
	}
	digest, err := r.platformDigest(desc)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{Repository: repository, Tag: tag, Digest: digest}, nil
}
