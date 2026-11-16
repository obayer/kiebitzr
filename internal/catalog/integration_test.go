//go:build integration

package catalog

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	// This test binary links Syft without the vulnerability database, so it has to register
	// the `sqlite` driver itself — the production binary does the same in cmd/kiebitzr.
	_ "github.com/glebarez/go-sqlite"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/obayer/kiebitzr/internal/cache"
)

// defaultImage is a small, public, multi-arch image. It stands in for what the cluster
// actually runs: the point of this test is the path through Syft, the registry and the cache,
// not this particular image. Override it with KIEBITZR_TEST_IMAGE to catalogue something
// from your own registry instead.
const defaultImage = "ghcr.io/anchore/syft:v1.56.0"

// TestCatalogueFromRegistry catalogues a real image from a real registry. It needs network
// access to that registry and is therefore behind the `integration` build tag.
func TestCatalogueFromRegistry(t *testing.T) {
	image := os.Getenv("KIEBITZR_TEST_IMAGE")
	if image == "" {
		image = defaultImage
	}

	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatalf("cache.New() = %v, want no error", err)
	}
	cataloguer, err := New(platformOrDefault())
	if err != nil {
		t.Fatalf("New() = %v, want no error", err)
	}

	// The digest a kubelet reports is the digest of the image reference; here the reference
	// carries a tag, which the registry resolves the same way.
	digest, ref := resolve(t, image)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Cataloguing and storing are separate steps now, and this is the pairing the matcher
	// uses: produce into the store's writer, so the entry appears only once it is complete.
	if err := store.Write(digest, func(w io.Writer) error {
		return cataloguer.CatalogueTo(ctx, ref, w)
	}); err != nil {
		t.Fatalf("CatalogueTo(%s) = %v, want no error", ref, err)
	}
	if !store.Has(digest) {
		t.Fatal("the SBOM was not stored under its digest")
	}

	// The SBOM has to be the syft-json a later run hands to the matcher, with packages in it.
	r, err := store.Open(digest)
	if err != nil {
		t.Fatalf("Open() = %v, want no error", err)
	}
	defer func() { _ = r.Close() }()

	content, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() = %v, want no error", err)
	}
	var sbom struct {
		Artifacts []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifacts"`
		Source struct {
			Type string `json:"type"`
		} `json:"source"`
	}
	if err := json.Unmarshal(content, &sbom); err != nil {
		t.Fatalf("the cached SBOM is not valid syft-json: %v", err)
	}
	if len(sbom.Artifacts) == 0 {
		t.Fatalf("the SBOM of %s contains no packages", ref)
	}
	t.Logf("catalogued %s: %d packages, %d bytes, source type %q",
		ref, len(sbom.Artifacts), len(content), sbom.Source.Type)
}

// resolve asks the registry for the digest of a reference, which is what the kubelet reports
// for a running container: the digest of the multi-arch index, plus the repository to pull it
// from.
func resolve(t *testing.T, image string) (digest, ref string) {
	t.Helper()
	parsed, err := name.ParseReference(image)
	if err != nil {
		t.Fatalf("ParseReference(%q) = %v, want no error", image, err)
	}
	desc, err := remote.Head(parsed, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		t.Fatalf("Head(%q) = %v, want no error (is the registry reachable?)", image, err)
	}
	return desc.Digest.String(), parsed.Context().Name() + "@" + desc.Digest.String()
}

func platformOrDefault() string {
	if platform := os.Getenv("KIEBITZR_TEST_PLATFORM"); platform != "" {
		return platform
	}
	return "linux/arm64"
}
