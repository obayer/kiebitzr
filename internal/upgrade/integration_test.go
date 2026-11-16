//go:build integration

package upgrade

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// These exercise the whole round trip against a real registry — go-containerregistry's
// in-memory one, over loopback. The selection logic they cover is already unit-tested as
// pickPlatform and matchSingle; what only these can show is that a real manifest, a real index
// and a real 404 arrive as the code expects them to.
//
// They are tagged `integration` because they need to listen on and connect to a loopback port,
// which the development sandbox denies (`connect: operation not permitted`). They need no
// outbound network: `mise run test:integration` runs them, and so does any environment that
// allows loopback.

// serveRegistry starts an in-memory OCI registry and returns its host. go-containerregistry
// treats a loopback host as plain http, so nothing here needs insecure options.
func serveRegistry(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse %q = %v", server.URL, err)
	}
	return parsed.Host
}

// pushIndex publishes a multi-platform index and returns the digest of the manifest for each
// platform, so a test can assert which one was picked.
func pushIndex(t *testing.T, repository, tag string, platforms ...v1.Platform) map[string]string {
	t.Helper()
	index := v1.ImageIndex(empty.Index)
	digests := make(map[string]string, len(platforms))
	for _, platform := range platforms {
		image, err := random.Image(64, 1)
		if err != nil {
			t.Fatalf("random.Image() = %v", err)
		}
		digest, err := image.Digest()
		if err != nil {
			t.Fatalf("Digest() = %v", err)
		}
		digests[platform.String()] = digest.String()
		index = mutate.AppendManifests(index, mutate.IndexAddendum{
			Add:        image,
			Descriptor: v1.Descriptor{Platform: &platform}, //nolint:modernize // naming the embedded type reads better here
		})
	}

	ref, err := name.NewTag(repository + ":" + tag)
	if err != nil {
		t.Fatalf("NewTag() = %v", err)
	}
	if err := remote.WriteIndex(ref, index); err != nil {
		t.Fatalf("WriteIndex() = %v", err)
	}
	return digests
}

func TestResolvePicksThePlatformManifest(t *testing.T) {
	host := serveRegistry(t)
	repository := host + "/app"
	digests := pushIndex(t, repository, "latest",
		v1.Platform{OS: "linux", Architecture: "amd64"},
		v1.Platform{OS: "linux", Architecture: "arm64"},
	)

	resolver, err := NewResolver("latest", "linux/arm64")
	if err != nil {
		t.Fatalf("NewResolver() = %v", err)
	}
	candidate, err := resolver.Resolve(t.Context(), repository)
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}

	want := digests["linux/arm64"]
	if candidate.Digest != want {
		t.Fatalf("Digest = %q, want the arm64 manifest %q", candidate.Digest, want)
	}
	if candidate.Digest == digests["linux/amd64"] {
		t.Fatal("Digest is the amd64 manifest: the wrong platform was picked")
	}
	if got, wantRef := candidate.Ref(), repository+"@"+want; got != wantRef {
		t.Fatalf("Ref() = %q, want %q", got, wantRef)
	}
	if candidate.Tag != "latest" {
		t.Fatalf("Tag = %q, want latest", candidate.Tag)
	}
}

func TestResolveReportsAMissingPlatform(t *testing.T) {
	host := serveRegistry(t)
	repository := host + "/app"
	pushIndex(t, repository, "latest", v1.Platform{OS: "linux", Architecture: "amd64"})

	resolver, err := NewResolver("latest", "linux/arm64")
	if err != nil {
		t.Fatalf("NewResolver() = %v", err)
	}
	if _, err := resolver.Resolve(t.Context(), repository); ReasonOf(err) != ReasonPlatformMissing {
		t.Fatalf("ReasonOf(%v) = %q, want %q", err, ReasonOf(err), ReasonPlatformMissing)
	}
}

func TestResolveReportsAMissingTag(t *testing.T) {
	host := serveRegistry(t)
	repository := host + "/app"
	pushIndex(t, repository, "1.4.0", v1.Platform{OS: "linux", Architecture: "arm64"})

	resolver, err := NewResolver("latest", "linux/arm64")
	if err != nil {
		t.Fatalf("NewResolver() = %v", err)
	}
	if _, err := resolver.Resolve(t.Context(), repository); ReasonOf(err) != ReasonNoCandidateTag {
		t.Fatalf("ReasonOf(%v) = %q, want %q", err, ReasonOf(err), ReasonNoCandidateTag)
	}
}

// A single-architecture repository publishes a manifest where a multi-arch one publishes an
// index, and the whole code path through desc.Image() and its config file is different.
func TestResolveSingleManifest(t *testing.T) {
	host := serveRegistry(t)
	repository := host + "/single"

	image, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	image, err = mutate.ConfigFile(image, &v1.ConfigFile{OS: "linux", Architecture: "arm64"})
	if err != nil {
		t.Fatalf("ConfigFile() = %v", err)
	}
	ref, err := name.NewTag(repository + ":latest")
	if err != nil {
		t.Fatalf("NewTag() = %v", err)
	}
	if err := remote.Write(ref, image); err != nil {
		t.Fatalf("Write() = %v", err)
	}

	resolver, err := NewResolver("latest", "linux/arm64")
	if err != nil {
		t.Fatalf("NewResolver() = %v", err)
	}
	candidate, err := resolver.Resolve(t.Context(), repository)
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	digest, err := image.Digest()
	if err != nil {
		t.Fatalf("Digest() = %v", err)
	}
	if candidate.Digest != digest.String() {
		t.Fatalf("Digest = %q, want %q", candidate.Digest, digest)
	}
}

// An unreachable registry must not read as "no such tag": one is this installation's problem,
// the other is a fact about the repository.
func TestResolveReportsAnUnreachableRegistry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse %q = %v", server.URL, err)
	}

	resolver, err := NewResolver("latest", "linux/arm64")
	if err != nil {
		t.Fatalf("NewResolver() = %v", err)
	}
	_, err = resolver.Resolve(t.Context(), parsed.Host+"/app")
	if ReasonOf(err) != ReasonUnreachable {
		t.Fatalf("ReasonOf(%v) = %q, want %q", err, ReasonOf(err), ReasonUnreachable)
	}
}
