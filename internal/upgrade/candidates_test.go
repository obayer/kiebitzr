package upgrade

import (
	"testing"
	"time"
)

// at is a readable build time.
func at(day int) time.Time {
	return time.Date(2026, time.October, day, 12, 0, 0, 0, time.UTC)
}

// build names a candidate compactly.
func build(tag string, day int) Build {
	return Build{Tag: tag, Digest: "sha256:" + tag, Created: at(day)}
}

func tagsOf(builds []Build) []string {
	out := make([]string, 0, len(builds))
	for _, b := range builds {
		out = append(out, b.Tag)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNewerThan(t *testing.T) {
	running := Build{Tag: "v1.4.0", Digest: "sha256:running", Created: at(10)}

	tests := []struct {
		name   string
		builds []Build
		limit  int
		want   []string
	}{
		{
			name:   "newest first",
			builds: []Build{build("v1.4.1", 11), build("v1.6.0", 20), build("v1.5.0", 15)},
			limit:  3,
			want:   []string{"v1.6.0", "v1.5.0", "v1.4.1"},
		},
		{
			name:   "older builds are not candidates",
			builds: []Build{build("v1.3.0", 5), build("v1.5.0", 15)},
			limit:  3,
			want:   []string{"v1.5.0"},
		},
		{
			// The point of the whole ordering: a backport released after the next minor is a
			// candidate, and the tag string would have put it behind.
			name:   "a backport built after a newer minor is included",
			builds: []Build{build("v1.5.0", 15), build("v1.4.3", 18)},
			limit:  3,
			want:   []string{"v1.4.3", "v1.5.0"},
		},
		{
			// And the reason the limit is above one: a nightly takes the first slot and the
			// releases behind it are still looked at.
			name:   "a nightly consumes a slot rather than the answer",
			builds: []Build{build("nightly", 25), build("v1.6.0", 20), build("v1.5.0", 15)},
			limit:  3,
			want:   []string{"nightly", "v1.6.0", "v1.5.0"},
		},
		{
			name:   "capped at the limit",
			builds: []Build{build("a", 25), build("b", 20), build("c", 15), build("d", 12)},
			limit:  2,
			want:   []string{"a", "b"},
		},
		{
			name:   "same instant orders by tag, so a run repeats itself",
			builds: []Build{build("z", 20), build("a", 20), build("m", 20)},
			limit:  3,
			want:   []string{"a", "m", "z"},
		},
		{
			// Not a gap: the operator runs the newest build, so there is nothing to deploy.
			name:   "nothing newer is an answer",
			builds: []Build{build("v1.3.0", 5), build("v1.2.0", 1)},
			limit:  3,
			want:   []string{},
		},
		{
			// The running digest usually carries a tag of its own. It is not a candidate for
			// itself, even where its timestamp ties.
			name: "the running digest is not its own candidate",
			builds: []Build{
				{Tag: "v1.4.0", Digest: "sha256:running", Created: at(10)},
				build("v1.5.0", 15),
			},
			limit: 3,
			want:  []string{"v1.5.0"},
		},
		{
			name:   "equal timestamps are not newer",
			builds: []Build{build("other", 10)},
			limit:  3,
			want:   []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newerThan(tt.builds, running, tt.limit)
			if err != nil {
				t.Fatalf("newerThan() = %v", err)
			}
			if !equal(tagsOf(got), tt.want) {
				t.Fatalf("tags = %v, want %v", tagsOf(got), tt.want)
			}
		})
	}
}

// The case that decides whether this feature lies. Reproducible builders write a fixed creation
// time on purpose, so comparing those tells you nothing — and returning "nothing newer" there
// would be a negative nobody measured, which suppresses a page.
func TestNewerThanRefusesUnorderableBuilds(t *testing.T) {
	good := Build{Tag: "v1.4.0", Digest: "sha256:running", Created: at(10)}

	tests := []struct {
		name    string
		builds  []Build
		running Build
	}{
		{
			name:    "the running image has no build time",
			builds:  []Build{build("v1.5.0", 15)},
			running: Build{Tag: "v1.4.0", Digest: "sha256:running"},
		},
		{
			name:    "the running image was built at the epoch",
			builds:  []Build{build("v1.5.0", 15)},
			running: Build{Digest: "sha256:running", Created: time.Unix(0, 0).UTC()},
		},
		{
			// Strict on purpose: one unusable timestamp among the candidates could hide a
			// newer build, and answering with the orderable remainder would publish a
			// negative that was never measured.
			name: "one candidate has no build time",
			builds: []Build{
				build("v1.5.0", 15),
				{Tag: "v1.6.0", Digest: "sha256:v1.6.0", Created: time.Unix(0, 0).UTC()},
			},
			running: good,
		},
		{
			name: "every candidate was built at the epoch",
			builds: []Build{
				{Tag: "a", Digest: "sha256:a", Created: time.Unix(0, 0).UTC()},
				{Tag: "b", Digest: "sha256:b", Created: time.Unix(0, 0).UTC()},
			},
			running: good,
		},
		{
			// A fixed date in the early 2000s is the other shape reproducible builders write.
			name: "a fixed date before the usable floor",
			builds: []Build{
				{Tag: "a", Digest: "sha256:a", Created: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
			running: good,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newerThan(tt.builds, tt.running, 3)
			if reason := ReasonOf(err); reason != ReasonUnorderable {
				t.Fatalf("ReasonOf(%v) = %q, want %q", err, reason, ReasonUnorderable)
			}
			if got != nil {
				t.Fatalf("candidates = %v, want none when the order is unknown", tagsOf(got))
			}
		})
	}
}

func TestNewSelectorRejects(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		limit    int
	}{
		{"zero candidates", "linux/arm64", 0},
		{"negative candidates", "linux/arm64", -1},
		{"platform without arch", "linux", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSelector(tt.platform, tt.limit); err == nil {
				t.Fatalf("NewSelector(%q, %d) = nil error, want one", tt.platform, tt.limit)
			}
		})
	}
}

// The floor exists so that a zeroed timestamp is read as "no timestamp" rather than as a very
// old image. An image genuinely built in the nineties is not a case worth serving; a zeroed one
// is the common case for ko, Bazel and Nix.
func TestOrderable(t *testing.T) {
	tests := []struct {
		name    string
		created time.Time
		want    bool
	}{
		{"zero value", time.Time{}, false},
		{"unix epoch", time.Unix(0, 0).UTC(), false},
		{"1999", time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC), false},
		{"2026", at(10), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Build{Created: tt.created}).orderable(); got != tt.want {
				t.Fatalf("orderable(%s) = %v, want %v", tt.created, got, tt.want)
			}
		})
	}
}
