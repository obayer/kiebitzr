// Package upgrade answers one question about a running image: is there an image this cluster
// could deploy instead — for the platform it runs on — that clears some of its findings?
//
// It exists because `fix_state="fixed"` cannot answer it. That label says a fixed *version of a
// package* is named in an advisory, which is a different namespace from the one a registry
// speaks: there is no image tag called `8.7.1-r0`, and `app:1.5.0` says nothing about its
// libcurl. Nor does the OCI metadata model carry a package inventory at any level — an index
// lists per-platform manifests, a manifest lists layer digests, and a layer is a compressed tar
// with no table of contents. The only way to know what an image contains is to look inside it
// (ADR 0011).
//
// This package does the half that is cheap: turning a running image's repository into one
// candidate digest for the configured platform. Whether that candidate actually clears a finding
// is decided by cataloguing and matching it, which is the pipeline that already exists.
package upgrade

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Reasons the candidate question has no answer. Each is a label value of
// kiebitzr_image_upgrade_unknown, and they are kept apart on purpose: **unknown is not "no
// fix"**. Collapsing them would publish a silence that reads like good news, which is the
// failure mode kiebitzr_image_pending already exists to avoid.
const (
	// ReasonNoCandidateTag means the repository has no such tag. Common and unremarkable:
	// plenty of vendor and distroless repositories publish version tags only.
	ReasonNoCandidateTag = "no_candidate_tag"
	// ReasonPlatformMissing means the candidate exists but its index carries no manifest for
	// the configured platform. An image that is only built for linux/amd64 is no fix for an
	// arm64 node, and saying "no upgrade" there would be the wrong answer to the wrong
	// question.
	ReasonPlatformMissing = "platform_missing"
	// ReasonUnreachable means the registry could not be asked: refused, unauthenticated,
	// rate limited, or a reference that cannot be built at all. The metric says this much and
	// the log line carries the registry's own words.
	ReasonUnreachable = "unreachable"
	// ReasonNotCatalogued means a candidate was resolved but never catalogued, because the run
	// ran out of its budget. Nothing is known about it — which is exactly why it is not
	// silence.
	ReasonNotCatalogued = "not_catalogued"
)

// Candidate is a candidate image resolved to one platform.
type Candidate struct {
	// Repository is the repository both the running image and the candidate live in.
	Repository string
	// Tag is the tag the candidate was found at, and it travels onwards as a label: "a fix
	// exists" without "and it is over there" is not actionable.
	Tag string
	// Digest is the platform-specific manifest digest, `sha256:<hex>`. Not the index digest:
	// an index has no packages of its own, which is the same reason cataloguing resolves a
	// platform before reading an image.
	Digest string
}

// Ref is the pull reference of the candidate, `repository@digest` — the same shape the
// cataloguing stage already takes for a running image, so nothing downstream needs to know a
// candidate from any other image.
func (c Candidate) Ref() string { return c.Repository + "@" + c.Digest }

// UnresolvedError is returned when the candidate question cannot be answered, carrying which
// of the reasons applies. It is a typed error rather than a (Candidate, string) pair so that a
// caller that forgets to look still propagates a failure instead of a zero Candidate.
type UnresolvedError struct {
	Reason string
	Err    error
}

func (u *UnresolvedError) Error() string {
	return fmt.Sprintf("candidate unresolved (%s): %v", u.Reason, u.Err)
}

func (u *UnresolvedError) Unwrap() error { return u.Err }

// ReasonOf is the reason an error carries, or empty when it carries none. Empty is never
// guessed at: an unexplained failure gets no kiebitzr_image_upgrade_unknown series rather than
// a plausible-looking wrong one, which is the rule kiebitzr_image_failed already follows.
func ReasonOf(err error) string {
	if unresolved, ok := errors.AsType[*UnresolvedError](err); ok {
		return unresolved.Reason
	}
	return ""
}

// Repository is the repository part of a pull reference, `repository@digest` or
// `repository:tag`. A pod pinned by digest still names its repository, which is what makes the
// candidate question answerable there too.
func Repository(ref string) string {
	if repo, _, found := strings.Cut(ref, "@"); found {
		return repo
	}
	// A colon only separates a tag when it follows the last slash; before that it is a
	// registry port.
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[:i]
	}
	return ref
}

// Resolver resolves repositories at one tag, for one platform.
type Resolver struct {
	tag      string
	platform v1.Platform
	options  []remote.Option
}

// NewResolver returns a Resolver for one candidate tag and one platform, given as
// `os/arch[/variant]`.
//
// Credentials come from the Docker config file the kubelet mounts, through the default
// keychain — the same source and the same mechanism cataloguing already uses, so this service
// still never reads a Secret itself and needs no Kubernetes rights beyond reading pods
// (ADR 0001).
func NewResolver(tag, platform string) (*Resolver, error) {
	if tag == "" {
		return nil, errors.New("candidate tag must not be empty")
	}
	p, err := v1.ParsePlatform(platform)
	if err != nil {
		return nil, fmt.Errorf("platform %q: %w", platform, err)
	}
	if p.OS == "" || p.Architecture == "" {
		return nil, fmt.Errorf("platform %q is not of the form os/arch[/variant]", platform)
	}
	return &Resolver{
		tag:      tag,
		platform: *p,
		options:  []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
	}, nil
}

// Tag is the candidate tag this Resolver asks for.
func (r *Resolver) Tag() string { return r.tag }

// Resolve turns a repository into the candidate's platform-specific digest.
//
// It reads manifests only — no layer is downloaded here, so the cost is one request per
// repository. What the candidate *contains* is a separate and much more expensive question,
// and this deliberately does not answer it.
func (r *Resolver) Resolve(ctx context.Context, repository string) (Candidate, error) {
	ref, err := name.NewTag(repository + ":" + r.tag)
	if err != nil {
		// A reference that cannot even be built means the question cannot be asked, which from
		// an operator's side is indistinguishable from a registry that will not answer.
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
	return Candidate{Repository: repository, Tag: r.tag, Digest: digest}, nil
}

// platformDigest picks the manifest for the configured platform out of what the registry
// returned: one entry of an index, or a single manifest that has to match on its own.
func (r *Resolver) platformDigest(desc *remote.Descriptor) (string, error) {
	if !desc.MediaType.IsIndex() {
		return r.singleManifestDigest(desc)
	}

	index, err := desc.ImageIndex()
	if err != nil {
		return "", &UnresolvedError{ReasonUnreachable, fmt.Errorf("read index: %w", err)}
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return "", &UnresolvedError{ReasonUnreachable, fmt.Errorf("read index manifest: %w", err)}
	}
	return pickPlatform(manifest.Manifests, r.platform)
}

// pickPlatform chooses the manifest for want out of an index's entries.
//
// It is separate from the request that fetched them, and pure, because this is the part that
// decides correctness: returning the index digest here instead of a platform manifest would
// produce an SBOM of nothing, since an index carries no packages of its own.
func pickPlatform(entries []v1.Descriptor, want v1.Platform) (string, error) {
	for _, entry := range entries {
		// An entry with no platform is an attestation or an attached artefact, not an image
		// for some architecture. Skipping it is not the same as rejecting it.
		if entry.Platform == nil {
			continue
		}
		// Satisfies reads "have satisfies want", so the index entry is the receiver. An entry
		// without a variant satisfies a request without one, which is what makes linux/arm64
		// match an index that does not spell its variant out.
		if entry.Platform.Satisfies(want) {
			return entry.Digest.String(), nil
		}
	}
	return "", &UnresolvedError{ReasonPlatformMissing, fmt.Errorf(
		"no manifest for %s among %d entries", want, len(entries))}
}

// singleManifestDigest handles a repository whose tag points at one image rather than an index.
// There is no platform list to search, so the image's own config has to match: a single-arch
// image for the wrong architecture is a missing platform, not an upgrade.
func (r *Resolver) singleManifestDigest(desc *remote.Descriptor) (string, error) {
	image, err := desc.Image()
	if err != nil {
		return "", &UnresolvedError{ReasonUnreachable, fmt.Errorf("read manifest: %w", err)}
	}
	config, err := image.ConfigFile()
	if err != nil {
		return "", &UnresolvedError{ReasonUnreachable, fmt.Errorf("read config: %w", err)}
	}
	have := v1.Platform{OS: config.OS, Architecture: config.Architecture, Variant: config.Variant}
	return matchSingle(have, r.platform, desc.Digest.String())
}

// matchSingle accepts a lone manifest only if the platform it was built for satisfies the one
// asked for. Pure, for the same reason as pickPlatform: a single-architecture image for the
// wrong architecture is a missing platform, not an upgrade, and getting that backwards would
// send an operator to deploy something their nodes cannot run.
func matchSingle(have, want v1.Platform, digest string) (string, error) {
	if !have.Satisfies(want) {
		return "", &UnresolvedError{ReasonPlatformMissing, fmt.Errorf(
			"%s is built for %s, not %s", digest, have, want)}
	}
	return digest, nil
}

// reasonForGet separates "there is no such tag" from "the registry would not answer".
//
// The difference matters more than it looks: a repository that publishes version tags only has
// no `latest`, and that is an unremarkable fact about the repository. A registry that rate
// limits or rejects a credential is a problem with this installation, and the two must not land
// in the same bucket.
func reasonForGet(err error) string {
	var transportErr *transport.Error
	if errors.As(err, &transportErr) && transportErr.StatusCode == http.StatusNotFound {
		return ReasonNoCandidateTag
	}
	return ReasonUnreachable
}
