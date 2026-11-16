package upgrade

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func TestRepository(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{"pinned by digest", "registry.example/app@sha256:abc", "registry.example/app"},
		{"tagged", "registry.example/app:1.4.0", "registry.example/app"},
		{"registry port and tag", "registry.example:5000/app:1.4.0", "registry.example:5000/app"},
		// The hard case: a colon that is a port and not a tag. Cutting at the last colon
		// regardless would turn this into "registry.example".
		{"registry port, no tag", "registry.example:5000/app", "registry.example:5000/app"},
		{"bare", "app", "app"},
		{"digest wins over a tag", "registry.example/app:1.4.0@sha256:abc", "registry.example/app:1.4.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Repository(tt.ref); got != tt.want {
				t.Fatalf("Repository(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func TestCandidateRef(t *testing.T) {
	c := Candidate{Repository: "registry.example/app", Tag: "latest", Digest: "sha256:abc"}
	if got, want := c.Ref(), "registry.example/app@sha256:abc"; got != want {
		t.Fatalf("Ref() = %q, want %q", got, want)
	}
}

// The reason has to survive wrapping, because it travels up through a run that adds context at
// every level, and an unexplained failure must produce no series rather than a wrong one.
func TestReasonOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"typed", &UnresolvedError{ReasonNoCandidateTag, errors.New("boom")}, ReasonNoCandidateTag},
		{
			"wrapped",
			fmt.Errorf("candidate of app: %w",
				&UnresolvedError{ReasonPlatformMissing, errors.New("boom")}),
			ReasonPlatformMissing,
		},
		{"plain", errors.New("boom"), ""},
		{"nil", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReasonOf(tt.err); got != tt.want {
				t.Fatalf("ReasonOf(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestNewResolverRejects(t *testing.T) {
	tests := []struct{ name, tag, platform string }{
		{"empty tag", "", "linux/arm64"},
		{"platform without arch", "latest", "linux"},
		{"empty platform", "latest", ""},
		{"too many parts", "latest", "linux/arm64/v8/extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewResolver(tt.tag, tt.platform); err == nil {
				t.Fatalf("NewResolver(%q, %q) = nil error, want one", tt.tag, tt.platform)
			}
		})
	}
}

// A 404 means the repository simply has no such tag, which is an unremarkable fact about plenty
// of vendor repositories. Anything else is a problem with this installation, and the two must
// not land in the same bucket.
func TestReasonForGet(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"not found", &transport.Error{StatusCode: http.StatusNotFound}, ReasonNoCandidateTag},
		{"unauthorized", &transport.Error{StatusCode: http.StatusUnauthorized}, ReasonUnreachable},
		{"rate limited", &transport.Error{StatusCode: http.StatusTooManyRequests}, ReasonUnreachable},
		{
			"wrapped not found",
			fmt.Errorf("get: %w", &transport.Error{StatusCode: http.StatusNotFound}),
			ReasonNoCandidateTag,
		},
		{"not a transport error", errors.New("dial tcp: no route to host"), ReasonUnreachable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reasonForGet(tt.err); got != tt.want {
				t.Fatalf("reasonForGet(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

// hash turns a readable digest into a v1.Hash for a table entry.
func hash(t *testing.T, s string) v1.Hash {
	t.Helper()
	h, err := v1.NewHash(s)
	if err != nil {
		t.Fatalf("NewHash(%q) = %v", s, err)
	}
	return h
}

const (
	amd64Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	arm64Digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	armV7Digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// The property that matters most: what comes out is the digest of a *platform manifest*, never
// the index's own. The kubelet reports the index digest, and an index has no packages of its
// own — cataloguing it would produce an SBOM of nothing.
func TestPickPlatform(t *testing.T) {
	entries := []v1.Descriptor{
		{Digest: hash(t, amd64Digest), Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
		{Digest: hash(t, arm64Digest), Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
		{Digest: hash(t, armV7Digest), Platform: &v1.Platform{
			OS: "linux", Architecture: "arm", Variant: "v7",
		}},
		// An attestation or an attached artefact. Skipping it is not the same as rejecting it,
		// and treating it as an image would hand back the digest of something unreadable.
		{Digest: hash(t, "sha256:4444444444444444444444444444444444444444444444444444444444444444")},
	}

	tests := []struct {
		name       string
		want       v1.Platform
		wantDigest string
		wantReason string
	}{
		{
			name:       "exact architecture",
			want:       v1.Platform{OS: "linux", Architecture: "arm64"},
			wantDigest: arm64Digest,
		},
		{
			name:       "the other architecture in the same index",
			want:       v1.Platform{OS: "linux", Architecture: "amd64"},
			wantDigest: amd64Digest,
		},
		{
			name:       "variant asked for and present",
			want:       v1.Platform{OS: "linux", Architecture: "arm", Variant: "v7"},
			wantDigest: armV7Digest,
		},
		{
			// An entry without a variant satisfies a request without one, which is what makes
			// a plain linux/arm64 request match an index that does not spell a variant out.
			name:       "no variant asked for",
			want:       v1.Platform{OS: "linux", Architecture: "arm64", Variant: ""},
			wantDigest: arm64Digest,
		},
		{
			name:       "architecture absent",
			want:       v1.Platform{OS: "linux", Architecture: "riscv64"},
			wantReason: ReasonPlatformMissing,
		},
		{
			name:       "operating system absent",
			want:       v1.Platform{OS: "windows", Architecture: "amd64"},
			wantReason: ReasonPlatformMissing,
		},
		{
			// The variant narrows, so asking for one the index does not carry is a miss even
			// though the architecture is there.
			name:       "variant absent",
			want:       v1.Platform{OS: "linux", Architecture: "arm", Variant: "v8"},
			wantReason: ReasonPlatformMissing,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pickPlatform(entries, tt.want)
			if tt.wantReason != "" {
				if reason := ReasonOf(err); reason != tt.wantReason {
					t.Fatalf("ReasonOf(%v) = %q, want %q", err, reason, tt.wantReason)
				}
				if got != "" {
					t.Fatalf("digest = %q, want empty on a miss", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("pickPlatform() = %v", err)
			}
			if got != tt.wantDigest {
				t.Fatalf("digest = %q, want %q", got, tt.wantDigest)
			}
		})
	}
}

// An index with nothing in it is a missing platform rather than an error of its own: the
// question was asked and the answer is no.
func TestPickPlatformEmptyIndex(t *testing.T) {
	_, err := pickPlatform(nil, v1.Platform{OS: "linux", Architecture: "arm64"})
	if got := ReasonOf(err); got != ReasonPlatformMissing {
		t.Fatalf("ReasonOf(%v) = %q, want %q", err, got, ReasonPlatformMissing)
	}
}

// A single-architecture repository publishes a manifest where a multi-arch one publishes an
// index. There is no platform list to search, so the image's own config has to answer — and
// getting this backwards would send an operator to deploy something their nodes cannot run.
func TestMatchSingle(t *testing.T) {
	want := v1.Platform{OS: "linux", Architecture: "arm64"}
	tests := []struct {
		name       string
		have       v1.Platform
		wantReason string
	}{
		{name: "same architecture", have: v1.Platform{OS: "linux", Architecture: "arm64"}},
		{
			name: "variant present but not asked for",
			have: v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"},
		},
		{
			name:       "other architecture",
			have:       v1.Platform{OS: "linux", Architecture: "amd64"},
			wantReason: ReasonPlatformMissing,
		},
		{
			name:       "other operating system",
			have:       v1.Platform{OS: "windows", Architecture: "arm64"},
			wantReason: ReasonPlatformMissing,
		},
		{
			// A config that states no platform at all cannot be shown to run here, and
			// assuming it does is the dangerous direction.
			name:       "no platform stated",
			have:       v1.Platform{},
			wantReason: ReasonPlatformMissing,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchSingle(tt.have, want, arm64Digest)
			if tt.wantReason != "" {
				if reason := ReasonOf(err); reason != tt.wantReason {
					t.Fatalf("ReasonOf(%v) = %q, want %q", err, reason, tt.wantReason)
				}
				return
			}
			if err != nil {
				t.Fatalf("matchSingle() = %v", err)
			}
			if got != arm64Digest {
				t.Fatalf("digest = %q, want %q", got, arm64Digest)
			}
		})
	}
}
