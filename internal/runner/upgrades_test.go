package runner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/upgrade"
)

const (
	candidateA = "sha256:aaaa111111111111111111111111111111111111111111111111111111111111"
	candidateB = "sha256:bbbb222222222222222222222222222222222222222222222222222222222222"
)

// fakeSelector answers the candidate question without a registry.
type fakeSelector struct {
	builds map[string][]upgrade.Build
	errs   map[string]error
	asked  []string
}

func (f *fakeSelector) Select(_ context.Context, repository, _ string) ([]upgrade.Build, error) {
	f.asked = append(f.asked, repository)
	if err := f.errs[repository]; err != nil {
		return nil, err
	}
	return f.builds[repository], nil
}

// exploited is a finding that is in the default scope: known-exploited, with a fix.
func exploited(digest, cve string) metrics.Vulnerability {
	v := vuln(digest, cve)
	v.KnownExploited = true
	v.Severity = "Critical"
	return v
}

func candidate(tag, digest string) upgrade.Build {
	return upgrade.Build{Repository: "registry.example/app", Tag: tag, Digest: digest}
}

// Off is the default, and off means no series at all. Zeroes would read like answers.
func TestRunPublishesNoUpgradeMetricsWhenSwitchedOff(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0",
		"registry.example/app@"+digestA))
	h.store.sboms[digestA] = `{"artifacts":[]}`
	h.session.findings[digestA] = []metrics.Vulnerability{exploited(digestA, "CVE-2024-0001")}

	h.runner.Run(context.Background())

	body := h.scrape(t)
	for _, forbidden := range []string{
		"kiebitzr_image_upgrade_candidate", "kiebitzr_image_upgrade_unknown",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("%s is published although the check is off:\n%s", forbidden, body)
		}
	}
}

// The promise the whole feature exists for: a candidate that removes the finding is reported
// with the tag to go to, because "a fix exists" without "it is over there" cannot be acted on.
func TestRunReportsACandidateThatClearsTheFinding(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0",
		"registry.example/app@"+digestA))
	h.store.sboms[digestA] = `{"artifacts":[]}`
	h.store.sboms[candidateA] = `{"artifacts":[]}`
	h.session.findings[digestA] = []metrics.Vulnerability{
		exploited(digestA, "CVE-2024-0001"), exploited(digestA, "CVE-2024-0002"),
	}
	// The candidate still has one of the two.
	h.session.findings[candidateA] = []metrics.Vulnerability{exploited(candidateA, "CVE-2024-0002")}

	selector := &fakeSelector{builds: map[string][]upgrade.Build{
		"registry.example/app": {candidate("v1.5.0", candidateA)},
	}}
	h.runner.WithCandidates(selector).Run(context.Background())

	mustContain(t, h.scrape(t),
		`kiebitzr_image_upgrade_candidate{image_digest="`+digestA+`",tag="v1.5.0"} 1`)
	if len(selector.asked) != 1 || selector.asked[0] != "registry.example/app" {
		t.Fatalf("asked = %v, want the running image's repository once", selector.asked)
	}
}

// A candidate is matched through the same policy as a running image, so it suppresses findings
// too — but nobody runs it. Publishing that would put a digest in the suppression metric that
// appears in no other series, where it reads as a running image whose findings are being
// hidden.
func TestRunDoesNotPublishSuppressionsOfACandidate(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0",
		"registry.example/app@"+digestA))
	h.store.sboms[digestA] = `{"artifacts":[]}`
	h.store.sboms[candidateA] = `{"artifacts":[]}`
	h.session.findings[digestA] = []metrics.Vulnerability{exploited(digestA, "CVE-2024-0001")}
	h.session.suppressed[candidateA] = []metrics.Suppressed{
		{Digest: candidateA, Reason: metrics.SuppressedIgnoreRule, Count: 4},
	}

	selector := &fakeSelector{builds: map[string][]upgrade.Build{
		"registry.example/app": {candidate("v1.5.0", candidateA)},
	}}
	h.runner.WithCandidates(selector).Run(context.Background())

	if body := h.scrape(t); strings.Contains(body, "kiebitzr_vulnerability_suppressed") {
		t.Fatalf("a candidate's suppressions are published:\n%s", body)
	}
}

// Nothing newer existing is an answer, not a gap — so the series exists at zero rather than
// being absent, because absent would mean nobody looked.
func TestRunReportsZeroWhenNothingNewerExists(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0",
		"registry.example/app@"+digestA))
	h.store.sboms[digestA] = `{"artifacts":[]}`
	h.session.findings[digestA] = []metrics.Vulnerability{exploited(digestA, "CVE-2024-0001")}

	selector := &fakeSelector{builds: map[string][]upgrade.Build{"registry.example/app": {}}}
	h.runner.WithCandidates(selector).Run(context.Background())

	mustContain(t, h.scrape(t),
		`kiebitzr_image_upgrade_candidate{image_digest="`+digestA+`",tag=""} 0`)
}

// Checked and clears nothing is also an answer, and it has to be told apart from "could not
// look" — which is the whole reason the two metrics are separate.
func TestRunReportsZeroWhenNoCandidateClearsIt(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0",
		"registry.example/app@"+digestA))
	h.store.sboms[digestA] = `{"artifacts":[]}`
	h.store.sboms[candidateA] = `{"artifacts":[]}`
	h.session.findings[digestA] = []metrics.Vulnerability{exploited(digestA, "CVE-2024-0001")}
	h.session.findings[candidateA] = []metrics.Vulnerability{exploited(candidateA, "CVE-2024-0001")}

	selector := &fakeSelector{builds: map[string][]upgrade.Build{
		"registry.example/app": {candidate("v1.5.0", candidateA)},
	}}
	h.runner.WithCandidates(selector).Run(context.Background())

	body := h.scrape(t)
	mustContain(t, body,
		`kiebitzr_image_upgrade_candidate{image_digest="`+digestA+`",tag="v1.5.0"} 0`)
	if strings.Contains(body, "kiebitzr_image_upgrade_unknown") {
		t.Fatalf("a checked answer was published as unknown:\n%s", body)
	}
}

// The tag reported is the one that clears the most, which is not reliably the newest build.
func TestRunReportsTheCandidateThatClearsTheMost(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0",
		"registry.example/app@"+digestA))
	h.store.sboms[digestA] = `{"artifacts":[]}`
	h.store.sboms[candidateA] = `{"artifacts":[]}`
	h.store.sboms[candidateB] = `{"artifacts":[]}`
	h.session.findings[digestA] = []metrics.Vulnerability{
		exploited(digestA, "CVE-2024-0001"), exploited(digestA, "CVE-2024-0002"),
	}
	// The newest build clears one; the next one clears both.
	h.session.findings[candidateA] = []metrics.Vulnerability{exploited(candidateA, "CVE-2024-0002")}
	h.session.findings[candidateB] = nil

	selector := &fakeSelector{builds: map[string][]upgrade.Build{
		"registry.example/app": {
			candidate("nightly", candidateA),
			candidate("v1.5.0", candidateB),
		},
	}}
	h.runner.WithCandidates(selector).Run(context.Background())

	mustContain(t, h.scrape(t),
		`kiebitzr_image_upgrade_candidate{image_digest="`+digestA+`",tag="v1.5.0"} 2`)
}

// Unknown is not "no fix". A reason that travels with the error becomes its own series; an
// unexplained failure gets none rather than a plausible-looking wrong one.
func TestRunReportsUnknownWithItsReason(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantSeries string
		wantNone   bool
	}{
		{
			name:       "unorderable builds",
			err:        &upgrade.UnresolvedError{Reason: upgrade.ReasonUnorderable, Err: errors.New("epoch")},
			wantSeries: `reason="` + upgrade.ReasonUnorderable + `"`,
		},
		{
			name:       "no tags",
			err:        &upgrade.UnresolvedError{Reason: upgrade.ReasonNoTags, Err: errors.New("none")},
			wantSeries: `reason="` + upgrade.ReasonNoTags + `"`,
		},
		{
			name:     "an error carrying no reason",
			err:      errors.New("something else"),
			wantNone: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0",
				"registry.example/app@"+digestA))
			h.store.sboms[digestA] = `{"artifacts":[]}`
			h.session.findings[digestA] = []metrics.Vulnerability{exploited(digestA, "CVE-2024-0001")}

			selector := &fakeSelector{errs: map[string]error{"registry.example/app": tt.err}}
			h.runner.WithCandidates(selector).Run(context.Background())

			body := h.scrape(t)
			if tt.wantNone {
				if strings.Contains(body, "kiebitzr_image_upgrade_unknown") {
					t.Fatalf("an unexplained failure produced a series:\n%s", body)
				}
				return
			}
			mustContain(t, body, "kiebitzr_image_upgrade_unknown", tt.wantSeries)
		})
	}
}

// Candidate SBOMs have to survive the prune. Without this they are deleted at the end of every
// run and rebuilt the next day, which turns the feature's one-off cost into a daily one.
func TestRunKeepsCandidateSBOMsInTheCache(t *testing.T) {
	h := newHarness(t, runningPod("web-0", "registry.example/app:1.4.0",
		"registry.example/app@"+digestA))
	h.store.sboms[digestA] = `{"artifacts":[]}`
	h.store.sboms[candidateA] = `{"artifacts":[]}`
	h.session.findings[digestA] = []metrics.Vulnerability{exploited(digestA, "CVE-2024-0001")}
	h.session.findings[candidateA] = nil

	selector := &fakeSelector{builds: map[string][]upgrade.Build{
		"registry.example/app": {candidate("v1.5.0", candidateA)},
	}}
	h.runner.WithCandidates(selector).Run(context.Background())

	if !h.store.Has(candidateA) {
		t.Fatal("the candidate's SBOM was pruned, so the next run pays for it again")
	}
	if !h.store.Has(digestA) {
		t.Fatal("the running image's SBOM was pruned")
	}
}

// The scope is the cost lever, so what it includes has to be exact.
func TestInScope(t *testing.T) {
	fixed := func(severity string, exploited bool) metrics.Vulnerability {
		return metrics.Vulnerability{
			Severity: severity, FixState: "fixed", KnownExploited: exploited,
		}
	}
	tests := []struct {
		name     string
		v        metrics.Vulnerability
		scope    string
		expected bool
	}{
		{"exploited and fixable", fixed("Critical", true), ScopeExploited, true},
		{"exploited but low severity still counts", fixed("Low", true), ScopeExploited, true},
		{"not exploited", fixed("Critical", false), ScopeExploited, false},
		{
			name:  "exploited without a fix is out of every scope",
			v:     metrics.Vulnerability{Severity: "Critical", FixState: "wont-fix", KnownExploited: true},
			scope: ScopeExploited,
		},
		{"wide scope takes critical", fixed("Critical", false), ScopeFixable, true},
		{"wide scope takes high", fixed("High", false), ScopeFixable, true},
		{"wide scope stops at medium", fixed("Medium", false), ScopeFixable, false},
		{"empty scope behaves as exploited", fixed("Critical", false), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inScope(tt.v, tt.scope); got != tt.expected {
				t.Fatalf("inScope(%+v, %q) = %v, want %v", tt.v, tt.scope, got, tt.expected)
			}
		})
	}
}
