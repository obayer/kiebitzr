//go:build integration

package upgrade

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// This is a measurement, not a test of this package. It answers one question before anybody
// implements against it: **how many real repositories ship an SBOM with their images?**
//
// It matters because reading an attached SBOM is one request where cataloguing a candidate is a
// full pull plus a Syft run. If attached SBOMs are common, that shortcut is worth having. If
// they are rare, implementing it would be code written for a case that does not occur — and
// ADR 0011 deliberately leaves it out of the first version until this says otherwise.
//
// Run it against the repositories you actually run:
//
//	KIEBITZR_TEST_REPOSITORIES=registry.example/app,registry.example/proxy \
//	  mise run test:integration
//
// The repository list comes from the environment on purpose: the ones that matter are an
// installation's own, and those do not belong in this repository.

// sbomMediaTypes are the media and artifact types that carry a package list. Several
// conventions coexist: the SPDX and CycloneDX documents themselves, cosign's wrapper, and
// in-toto attestations whose predicate is an SBOM — BuildKit produces the last of these.
var sbomMediaTypes = []string{
	"application/spdx+json",
	"application/vnd.cyclonedx+json",
	"application/vnd.dev.cosign.artifact.sbom.v1+json",
	"text/spdx",
	// in-toto predicate types, which is where BuildKit says what an attestation is *about*.
	"https://spdx.dev/Document",
	"https://cyclonedx.org/bom",
}

// notSBOMMediaTypes are types that mean "there are attestations here" without saying a package
// list is among them. Counting them is how the measurement would overstate its case: every
// BuildKit-built image carries provenance, and almost none of that is an SBOM. The attestation
// manifest has to be opened to find out, which is what attestationPredicates does.
var notSBOMMediaTypes = []string{
	"application/vnd.docker.attestation.manifest.v1+json",
	"application/vnd.in-toto+json",
	"https://slsa.dev/provenance",
}

// defaultProbeRepositories are public examples, so the measurement runs on a fresh checkout and
// says something with nothing configured. They are a smoke test of the probe itself; the
// numbers that decide anything come from an installation's own repositories.
//
// This project's own image is first on the list deliberately: the release workflow builds with
// `ko build --sbom=spdx`, so it is a known positive, and a probe that cannot see that one is
// broken rather than informative.
var defaultProbeRepositories = []string{
	"ghcr.io/obayer/kiebitzr",
	"ghcr.io/anchore/syft",
	"ghcr.io/anchore/grype",
}

// notRepositories returns the entries that are registry hosts or otherwise cannot name a
// repository. Checked before anything is requested, because a bad entry would otherwise be
// reported as `unreachable` — which reads as a network or credential problem and sends whoever
// ran the measurement looking in the wrong place. The same confusion, one level up, that the
// unknown reasons exist to prevent.
func notRepositories(entries []string) []string {
	var invalid []string
	for _, entry := range entries {
		switch {
		case strings.Contains(entry, "://"):
			invalid = append(invalid, entry+" (drop the scheme)")
		case !strings.Contains(entry, "/"):
			invalid = append(invalid, entry+" (a registry host, not a repository)")
		case strings.HasSuffix(entry, "/"):
			invalid = append(invalid, entry+" (no repository after the host)")
		}
	}
	return invalid
}

// findings is what the probe learned about one repository.
type findings struct {
	repository string
	// digest is the platform manifest the candidate tag resolved to, empty when it did not.
	digest string
	// unresolved is the reason the candidate could not be resolved, empty when it was.
	unresolved string
	// referrers are the artifact types attached to the platform manifest via the referrers API.
	referrers []string
	// attestations are the artifact types carried as entries of the index itself, which is how
	// BuildKit attaches them — not through the referrers API at all.
	attestations []string
	// sbomTag is what sits at the `sha256-<hex>.sbom` tag, the convention cosign established
	// and ko still uses. A third route, predating the referrers API and not replaced by it.
	sbomTag []string
	// predicates are what the attestation manifests found by either route actually contain.
	// Without these the measurement stops at "attestations exist", which says nothing: an
	// attestation manifest holds provenance and an SBOM side by side, and most hold only the
	// former.
	predicates []string
}

// hasSBOM reports whether any route produced something that carries a package list.
func (f findings) hasSBOM() bool {
	for _, types := range [][]string{f.referrers, f.attestations, f.sbomTag, f.predicates} {
		for _, t := range types {
			for _, want := range sbomMediaTypes {
				if strings.Contains(t, want) {
					return true
				}
			}
		}
	}
	return false
}

func TestAttachedSBOMAvailability(t *testing.T) {
	repositories := defaultProbeRepositories
	if configured := os.Getenv("KIEBITZR_TEST_REPOSITORIES"); configured != "" {
		repositories = nil
		for r := range strings.SplitSeq(configured, ",") {
			if trimmed := strings.TrimSpace(r); trimmed != "" {
				repositories = append(repositories, trimmed)
			}
		}
	}
	if invalid := notRepositories(repositories); len(invalid) > 0 {
		t.Fatalf("not repositories: %v\n\n"+
			"KIEBITZR_TEST_REPOSITORIES takes repositories, not registry hosts:\n"+
			"  wrong: ghcr.io,docker.io\n"+
			"  right: ghcr.io/obayer/kiebitzr,index.docker.io/library/nginx\n\n"+
			"The list your cluster actually runs is in the metrics:\n"+
			"  count by (image) (kiebitzr_image_info)\n"+
			"and the repository is that label with any tag or digest cut off.", invalid)
	}

	platform := os.Getenv("KIEBITZR_TEST_PLATFORM")
	if platform == "" {
		platform = "linux/arm64"
	}
	tag := os.Getenv("KIEBITZR_TEST_UPGRADE_CANDIDATE")
	if tag == "" {
		tag = "latest"
	}

	// A measurement whose result is its output needs the output to survive. Test runners
	// summarise logs; KIEBITZR_TEST_REPORT names a file to write the same lines to.
	var report strings.Builder
	say := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		t.Log(line)
		report.WriteString(line + "\n")
	}
	t.Cleanup(func() {
		path := os.Getenv("KIEBITZR_TEST_REPORT")
		if path == "" {
			return
		}
		if err := os.WriteFile(path, []byte(report.String()), 0o600); err != nil {
			t.Errorf("write report to %s: %v", path, err)
		}
	})

	resolver, err := NewResolver(tag, platform)
	if err != nil {
		t.Fatalf("NewResolver(%q, %q) = %v", tag, platform, err)
	}

	say("probing %d repositories at :%s for %s", len(repositories), tag, platform)
	results := make([]findings, 0, len(repositories))
	for _, repository := range repositories {
		results = append(results, probe(t, resolver, repository))
	}

	var withSBOM, resolved int
	unresolvedBy := map[string]int{}
	for _, f := range results {
		if f.unresolved != "" {
			unresolvedBy[f.unresolved]++
			say("%-28s unresolved: %s", f.repository, f.unresolved)
			continue
		}
		resolved++
		if f.hasSBOM() {
			withSBOM++
		}
		say("%-28s sbom=%-5v predicates=%v referrers=%v index=%v sbom-tag=%v",
			f.repository, f.hasSBOM(), f.predicates, f.referrers, f.attestations, f.sbomTag)
	}

	for reason, count := range unresolvedBy {
		say("UNRESOLVED %-20s %d", reason, count)
	}

	say("RESULT: %d of %d repositories resolved; %d of those ship an SBOM",
		resolved, len(repositories), withSBOM)
	if resolved == 0 {
		t.Skip("nothing resolved, so nothing was measured — check credentials and the candidate tag")
	}
}

// probe resolves one repository's candidate and asks both routes what is attached to it.
func probe(t *testing.T, resolver *Resolver, repository string) findings {
	t.Helper()
	out := findings{repository: repository}

	candidate, err := resolver.Resolve(t.Context(), repository)
	if err != nil {
		out.unresolved = ReasonOf(err)
		if out.unresolved == "" {
			out.unresolved = err.Error()
		}
		return out
	}
	out.digest = candidate.Digest

	out.referrers = referrerTypes(t.Context(), repository, candidate.Digest)
	out.attestations = indexAttestationTypes(t.Context(), repository, resolver.Tag())
	out.predicates = append(out.predicates,
		attestationPredicates(t.Context(), repository, candidate.Digest)...)
	if indexDigest := resolveIndexDigest(t.Context(), repository, resolver.Tag()); indexDigest != "" {
		out.predicates = append(out.predicates,
			attestationPredicates(t.Context(), repository, indexDigest)...)
	}

	// Both digests, because the convention is written against whichever the publisher signed:
	// ko attaches to the index for a multi-platform build, cosign to the manifest it was
	// pointed at. Asking only one of the two is how a probe goes blind.
	out.sbomTag = cosignSBOMTypes(t.Context(), repository, candidate.Digest)
	if indexDigest := resolveIndexDigest(t.Context(), repository, resolver.Tag()); indexDigest != "" &&
		indexDigest != candidate.Digest {
		out.sbomTag = append(out.sbomTag,
			cosignSBOMTypes(t.Context(), repository, indexDigest)...)
	}
	return out
}

// attestationPredicates opens every attestation manifest attached to a digest and reports what
// each of its layers is *about*.
//
// This is the step without which the measurement lies. BuildKit attaches one manifest holding
// provenance and, optionally, an SBOM — as in-toto layers distinguished only by the
// `in-toto.io/predicate-type` annotation. Seeing the manifest therefore proves attestations
// exist and nothing more, and reporting that as "no SBOM" is as wrong as reporting it as "has
// one". Measured against quay.io/metallb and quay.io/prometheus, which is where this was missed.
func attestationPredicates(ctx context.Context, repository, digest string) []string {
	var out []string
	for _, entry := range attestationEntries(ctx, repository, digest) {
		ref, err := name.NewDigest(repository + "@" + entry.String())
		if err != nil {
			continue
		}
		desc, err := remote.Get(ref,
			remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			continue
		}
		image, err := desc.Image()
		if err != nil {
			continue
		}
		manifest, err := image.Manifest()
		if err != nil {
			continue
		}
		for _, layer := range manifest.Layers {
			if predicate := layer.Annotations["in-toto.io/predicate-type"]; predicate != "" {
				out = append(out, predicate)
				continue
			}
			out = append(out, string(layer.MediaType))
		}
	}
	return out
}

// attestationEntries are the digests of attestation manifests attached to one digest, by either
// route: as referrers, or as non-platform entries of the index it belongs to.
func attestationEntries(ctx context.Context, repository, digest string) []v1.Hash {
	var out []v1.Hash

	if ref, err := name.NewDigest(repository + "@" + digest); err == nil {
		if index, err := remote.Referrers(ref,
			remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain)); err == nil {
			if manifest, err := index.IndexManifest(); err == nil {
				for _, entry := range manifest.Manifests {
					out = append(out, entry.Digest)
				}
			}
		}
	}

	if ref, err := name.NewDigest(repository + "@" + digest); err == nil {
		if desc, err := remote.Get(ref,
			remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain)); err == nil &&
			desc.MediaType.IsIndex() {
			if index, err := desc.ImageIndex(); err == nil {
				if manifest, err := index.IndexManifest(); err == nil {
					for _, entry := range manifest.Manifests {
						if entry.Platform != nil &&
							entry.Platform.OS != "" && entry.Platform.OS != "unknown" {
							continue
						}
						out = append(out, entry.Digest)
					}
				}
			}
		}
	}
	return out
}

// resolveIndexDigest is the digest of whatever the tag points at directly — the index for a
// multi-platform repository, which is a different digest from any of its platform manifests.
func resolveIndexDigest(ctx context.Context, repository, tag string) string {
	ref, err := name.NewTag(repository + ":" + tag)
	if err != nil {
		return ""
	}
	desc, err := remote.Get(ref,
		remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return ""
	}
	return desc.Digest.String()
}

// cosignSBOMTypes looks at the `sha256-<hex>.sbom` tag, the convention cosign established and
// ko still writes: the SBOM is pushed as an ordinary image whose layer is the document. It
// predates the referrers API and was not replaced by it, so a probe that only asks for
// referrers misses every image built this way — including this project's own.
func cosignSBOMTypes(ctx context.Context, repository, digest string) []string {
	ref, err := name.NewTag(repository + ":" + strings.Replace(digest, ":", "-", 1) + ".sbom")
	if err != nil {
		return nil
	}
	desc, err := remote.Get(ref,
		remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil
	}
	image, err := desc.Image()
	if err != nil {
		return []string{string(desc.MediaType)}
	}
	layers, err := image.Layers()
	if err != nil || len(layers) == 0 {
		return []string{string(desc.MediaType)}
	}
	// The layer's media type is what names the document: ko writes
	// text/spdx+json, cosign writes the SPDX or CycloneDX type directly.
	var out []string
	for _, layer := range layers {
		mediaType, err := layer.MediaType()
		if err != nil {
			continue
		}
		out = append(out, string(mediaType))
	}
	return out
}

// referrerTypes lists the artifact types attached to a manifest through the referrers API.
// A registry that does not implement it simply returns nothing, which is itself part of the
// measurement.
func referrerTypes(ctx context.Context, repository, digest string) []string {
	ref, err := name.NewDigest(repository + "@" + digest)
	if err != nil {
		return nil
	}
	index, err := remote.Referrers(ref,
		remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil
	}
	return describe(manifest.Manifests)
}

// indexAttestationTypes lists what the *index* carries beside the platform images. BuildKit
// attaches its SBOM and provenance here rather than through the referrers API, as entries whose
// platform is `unknown/unknown` and whose annotations point back at the image they describe —
// which is also why pickPlatform never mistakes one for an image.
func indexAttestationTypes(ctx context.Context, repository, tag string) []string {
	ref, err := name.NewTag(repository + ":" + tag)
	if err != nil {
		return nil
	}
	desc, err := remote.Get(ref,
		remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil || !desc.MediaType.IsIndex() {
		return nil
	}
	index, err := desc.ImageIndex()
	if err != nil {
		return nil
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil
	}

	var out []v1.Descriptor
	for _, entry := range manifest.Manifests {
		// A real platform image is not an attestation. Everything else in an index is.
		if entry.Platform != nil &&
			entry.Platform.OS != "" && entry.Platform.OS != "unknown" {
			continue
		}
		out = append(out, entry)
	}
	return describe(out)
}

// describe names what each descriptor is, preferring the artifact type and falling back to the
// media type and the annotation BuildKit uses.
func describe(entries []v1.Descriptor) []string {
	var out []string
	for _, entry := range entries {
		switch {
		case entry.ArtifactType != "":
			out = append(out, entry.ArtifactType)
		case entry.Annotations["vnd.docker.reference.type"] != "":
			out = append(out, "docker-ref:"+entry.Annotations["vnd.docker.reference.type"]+
				" ("+string(entry.MediaType)+")")
		default:
			out = append(out, string(entry.MediaType))
		}
	}
	return out
}

// The probe's own control, and it is driven by the two lists so neither can drift away from
// it. Every type in sbomMediaTypes must be recognised; every type in notSBOMMediaTypes must
// not be.
//
// The second half is the one that matters, and it is the half an earlier version of this
// control got wrong. It fed hasSBOM the media types of attestation *layers* and concluded the
// detection worked — while the real world presents the enclosing *manifest*, which says
// attestations exist and nothing about whether a package list is among them. Measured against
// quay.io/metallb and quay.io/prometheus: six attestation manifests each, reported as
// "ships no SBOM", and neither answer was earned.
func TestHasSBOMRecognisesEachConvention(t *testing.T) {
	for _, mediaType := range sbomMediaTypes {
		t.Run("carries/"+mediaType, func(t *testing.T) {
			for name, f := range map[string]findings{
				"referrer":  {referrers: []string{mediaType}},
				"index":     {attestations: []string{mediaType}},
				"sbom-tag":  {sbomTag: []string{mediaType}},
				"predicate": {predicates: []string{mediaType}},
			} {
				if !f.hasSBOM() {
					t.Errorf("%s route: hasSBOM() = false for %q, want true", name, mediaType)
				}
			}
		})
	}

	for _, mediaType := range notSBOMMediaTypes {
		t.Run("does-not-carry/"+mediaType, func(t *testing.T) {
			for name, f := range map[string]findings{
				"referrer":  {referrers: []string{mediaType}},
				"index":     {attestations: []string{mediaType}},
				"predicate": {predicates: []string{mediaType}},
			} {
				if f.hasSBOM() {
					t.Errorf("%s route: hasSBOM() = true for %q, want false — "+
						"an attestation wrapper is not a package list", name, mediaType)
				}
			}
		})
	}

	// The exact strings quay.io returned, so a regression is caught against reality and not
	// only against the lists above.
	t.Run("metallb as measured", func(t *testing.T) {
		f := findings{
			referrers:    []string{"application/vnd.docker.attestation.manifest.v1+json"},
			attestations: []string{"docker-ref:attestation-manifest (application/vnd.oci.image.manifest.v1+json)"},
		}
		if f.hasSBOM() {
			t.Fatal("hasSBOM() = true from attestation manifests alone: " +
				"the predicates inside them are what decides")
		}
		f.predicates = []string{"https://slsa.dev/provenance/v0.2"}
		if f.hasSBOM() {
			t.Fatal("hasSBOM() = true for provenance: provenance is not a package list")
		}
		f.predicates = append(f.predicates, "https://spdx.dev/Document")
		if !f.hasSBOM() {
			t.Fatal("hasSBOM() = false with an SPDX predicate present")
		}
	})

	if (findings{}).hasSBOM() {
		t.Fatal("empty findings must report nothing")
	}
}
