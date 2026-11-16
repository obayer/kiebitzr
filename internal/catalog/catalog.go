// Package catalog turns a running image's reference into an SBOM, using Syft as a library. It
// reads an image from a registry and writes syft-json; where that SBOM is kept, and whether it
// was needed at all, is the caller's business (ADR 0001).
//
// Keeping the cache out of here is what lets the same code run in a process that has no cache:
// a worker catalogues an image and streams the result to whoever asked for it, while the
// matcher catalogues into its own store (ADR 0009).
//
// Requirement on the binary: Syft reads the RPM database of newer Red Hat images through
// database/sql and fails the whole catalogue unless a driver is registered under the name
// `sqlite`. Registering a driver is the binary's business, not a library's, so every binary
// using this package has to import one — see cmd/kiebitzr.
package catalog

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/syftjson"

	"github.com/obayer/kiebitzr/internal/anchorelog"
)

// SetLogger routes what Syft and Stereoscope have to say into log. Both keep a
// package-level logger that discards everything until it is set, so a registry that refuses
// a manifest or a layer that will not unpack says nothing at all until this is called.
//
// It lives here rather than in the binary because this package is where Syft and Stereoscope
// are allowed to be imported — the rest of the service compiles without them, and that is
// enforced (see .golangci.yaml, depguard). Process-wide and not safe to interleave with use:
// call it once during start-up.
func SetLogger(log *slog.Logger) {
	syft.SetLogger(anchorelog.New(log.With("library", "syft")))
	stereoscope.SetLogger(anchorelog.New(log.With("library", "stereoscope")))
}

// parallelism is deliberately one. Cataloguing in parallel multiplies peak memory, and the
// service is meant to run on small nodes; raise it once the pilot has measured what the
// largest image actually costs (ADR 0001, open questions).
const parallelism = 1

// ResolveError means the image could not be reached for the configured platform at all, as
// opposed to failing while it was catalogued. The two have different causes and different
// fixes, so they are counted separately.
//
// It is recognised structurally, through the ResolveFailed method, so the run loop can tell
// the two apart without importing this package and Syft with it.
type ResolveError struct {
	Ref      string
	Platform string
	Err      error
}

func (e *ResolveError) Error() string {
	return fmt.Sprintf("resolve %s for %s: %v", e.Ref, e.Platform, e.Err)
}

// Unwrap exposes the underlying registry or platform error.
func (e *ResolveError) Unwrap() error { return e.Err }

// ResolveFailed marks this error as a failure to reach the image.
func (e *ResolveError) ResolveFailed() bool { return true }

// Cataloguer creates SBOMs for one platform.
type Cataloguer struct {
	platform *image.Platform
}

// New returns a Cataloguer for one platform, given as `os/arch[/variant]`. The platform
// selects which manifest of a multi-arch index is catalogued: what the kubelet reports is the
// digest of the index, which has no packages of its own.
func New(platform string) (*Cataloguer, error) {
	p, err := image.NewPlatform(platform)
	if err != nil {
		return nil, fmt.Errorf("platform %q: %w", platform, err)
	}
	return &Cataloguer{platform: p}, nil
}

// CatalogueTo reads the image at ref and encodes its SBOM to w as syft-json. ref is the pull
// reference of a digest, `repository@digest`.
//
// The image is read straight from the registry — no container runtime and no Docker daemon is
// involved. Registry credentials come from the Docker config file the kubelet mounts, which
// Syft picks up through the default keychain; this service never reads a Secret itself.
//
// Nothing is written to w before Syft has produced the whole SBOM, so a failure here leaves w
// untouched rather than half-written.
func (c *Cataloguer) CatalogueTo(ctx context.Context, ref string, w io.Writer) (err error) {
	src, err := syft.GetSource(ctx, ref, syft.DefaultGetSourceConfig().
		WithSources(image.OciRegistrySource).
		WithPlatform(c.platform))
	if err != nil {
		// Reaching the image at all is a different problem from cataloguing it — a missing
		// platform in the index, a registry that refuses the pull, an image that was never
		// pushed. Reported as its own kind so the metrics can tell them apart.
		return &ResolveError{Ref: ref, Platform: c.platform.String(), Err: err}
	}
	defer func() {
		if closeErr := src.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("release image %s: %w", ref, closeErr)
		}
	}()

	// Files are not catalogued: the file digests and contents Syft would collect cost time and
	// memory, and nothing downstream matches on them.
	sbom, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig().
		WithoutFiles().
		WithParallelism(parallelism))
	if err != nil {
		return fmt.Errorf("catalogue %s: %w", ref, err)
	}

	if err := syftjson.NewFormatEncoder().Encode(w, *sbom); err != nil {
		return fmt.Errorf("encode sbom of %s: %w", ref, err)
	}
	return nil
}
