package catalog

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNewAcceptsPlatforms(t *testing.T) {
	for _, platform := range []string{"linux/arm64", "linux/amd64", "linux/arm/v7"} {
		t.Run(platform, func(t *testing.T) {
			if _, err := New(platform); err != nil {
				t.Fatalf("New(%q) = %v, want no error", platform, err)
			}
		})
	}
}

func TestNewRejectsAnUnusablePlatform(t *testing.T) {
	if _, err := New("not a platform"); err == nil {
		t.Fatal("New(\"not a platform\") = no error, want one")
	}
}

// An image that cannot be reached has to stay distinguishable from one that could not be
// catalogued, and it has to be recognisable without importing this package: the run loop
// matches structurally on the ResolveFailed method (see internal/runner). The registry here is
// in the reserved .invalid domain, so this never leaves the machine.
func TestUnreachableImageReportsAResolveFailure(t *testing.T) {
	cataloguer, err := New("linux/arm64")
	if err != nil {
		t.Fatalf("New() = %v, want no error", err)
	}

	var out strings.Builder
	err = cataloguer.CatalogueTo(context.Background(),
		"registry.invalid/app@sha256:"+strings.Repeat("1", 64), &out)
	if err == nil {
		t.Fatal("CatalogueTo() = no error for an unreachable registry, want one")
	}

	var failure interface{ ResolveFailed() bool }
	if !errors.As(err, &failure) || !failure.ResolveFailed() {
		t.Fatalf("CatalogueTo() = %v, want an error reporting ResolveFailed", err)
	}
	// Nothing may reach the writer when the image was never read: the caller commits what it
	// got, and half an SBOM must not be commitable.
	if out.Len() != 0 {
		t.Fatalf("CatalogueTo() wrote %d bytes for an unreachable image, want none", out.Len())
	}
}
