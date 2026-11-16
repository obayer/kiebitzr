//go:build integration

package vulndb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/grype/grype"
	grypepkg "github.com/anchore/grype/grype/pkg"
)

// diagnosticSBOMs bounds how many cached SBOMs this matches. The question is whether the
// threat data arrives at all, and a handful of images answers it; the whole cache would take
// minutes and say the same thing.
const diagnosticSBOMs = 5

// TestThreatDataArrives answers one question: does the exploitation evidence of ADR 0008
// actually reach a finding, against a real database and real SBOMs?
//
// It exists because the absence of that evidence is indistinguishable from good news. An
// installation where kiebitzr_image_risk_score has no series and known_exploited is false
// everywhere looks like a cluster with nothing exploited, and reads identically to a database
// carrying no EPSS records at all. No query can tell the two apart — only this can.
//
// It needs a populated cache, so it skips rather than fails where there is none: on a fresh
// checkout there is nothing to diagnose. Run it after `mise run dev` has completed a run.
func TestThreatDataArrives(t *testing.T) {
	root := filepath.Join("..", "..", ".cache", "kiebitzr")
	sbomDir := filepath.Join(root, "sboms")
	entries, err := os.ReadDir(sbomDir)
	if err != nil || len(entries) == 0 {
		t.Skipf("no SBOM cache at %s to diagnose (%v)", sbomDir, err)
	}

	m, err := New(Config{Dir: filepath.Join(root, "db")}, "diagnostic")
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	// The age guard is switched off here and nowhere else. The service refuses a database
	// older than five days on purpose and must keep doing so; this is about what the database
	// already on disk carries, and refusing to open it would defeat the measurement. Opening
	// without an update is deliberate for the same reason: the subject is the database that
	// produced the metrics being diagnosed, not whatever is current.
	install := m.installation
	install.ValidateAge = false

	provider, status, err := grype.LoadVulnerabilityDB(m.distributionFor(true), install, false)
	if err != nil {
		t.Fatalf("LoadVulnerabilityDB() = %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	if status != nil {
		t.Logf("database built %s", status.Built)
	}

	// The matcher is assembled exactly as Open does it, rather than through a session: the
	// subject is the metadata on a raw match, which Match() has already reduced to a bool and
	// a float by the time it returns.
	matcher := &grype.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              m.matchers,
		IgnoreRules:           m.ignoreRules,
		NormalizeByCVE:        true,
	}

	var images, total, withMetadata, withEPSS, withKEV, withRisk int
	var maxRisk float64
	for _, entry := range entries {
		if entry.IsDir() || images >= diagnosticSBOMs {
			continue
		}
		images++

		f, err := os.Open(filepath.Join(sbomDir, entry.Name()))
		if err != nil {
			t.Fatalf("open %s = %v", entry.Name(), err)
		}
		pkgs, pkgContext, _, err := grypepkg.ProvideFromReader(f, grypepkg.ProviderConfig{})
		_ = f.Close()
		if err != nil {
			t.Logf("skipping %s: %v", entry.Name(), err)
			continue
		}

		matches, _, err := matcher.FindMatchesContext(t.Context(), pkgs, pkgContext)
		if err != nil {
			t.Fatalf("FindMatchesContext() = %v", err)
		}
		for _, match := range matches.Sorted() {
			total++
			md := match.Vulnerability.Metadata
			if md == nil {
				continue
			}
			withMetadata++
			if len(md.EPSS) > 0 {
				withEPSS++
			}
			if len(md.KnownExploited) > 0 {
				withKEV++
			}
			if risk := md.RiskScore(); risk > 0 {
				withRisk++
				maxRisk = max(maxRisk, risk)
			}
		}
	}

	t.Logf("images=%d findings=%d metadata=%d epss=%d kev=%d risk>0=%d maxRisk=%.2f",
		images, total, withMetadata, withEPSS, withKEV, withRisk, maxRisk)

	if total == 0 {
		t.Skip("no findings to diagnose")
	}
	if withMetadata == 0 {
		t.Fatalf("no finding of %d carries metadata at all: severity is blind too, not just risk", total)
	}
	// EPSS is the one that decides whether the risk score can ever be non-zero: grype's
	// threat() returns 0 without an EPSS record and without a KEV hit, and the score is a
	// product, so no EPSS means a score of exactly 0 however severe the finding is.
	if withEPSS == 0 {
		t.Errorf("no finding of %d carries EPSS data: the threat dimension is blind, "+
			"kiebitzr_image_risk_score stays absent and known_exploited reads false everywhere", total)
	}
}
