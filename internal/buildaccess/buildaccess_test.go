package buildaccess

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/obayer/kiebitzr/internal/metrics"
)

// The case the whole design rests on: two repositories in one namespace, one built by the
// operator's own team and one by another. Nothing in the images distinguishes them, so the
// rules have to be able to, and the more specific one has to win over the namespace default.
func TestTheMoreSpecificRuleWins(t *testing.T) {
	rules := load(t, `
build-access:
  - repository: registry.example/org/*
    access: reachable
  - repository: registry.example/org/platform/*
    access: own
  - repository: registry.example/org/platform/mirrored-upstream
    access: none
`)
	tests := map[string]string{
		"registry.example/org/billing/api:1.2":              metrics.BuildAccessReachable,
		"registry.example/org/platform/kiebitzr:v1":         metrics.BuildAccessOwn,
		"registry.example/org/platform/mirrored-upstream:3": metrics.BuildAccessNone,
		"registry.example/other/thing:1":                    metrics.BuildAccessUnknown,
		"ghcr.io/someone/tool:2":                            metrics.BuildAccessUnknown,
	}
	for ref, want := range tests {
		t.Run(ref, func(t *testing.T) {
			if got := rules.For(ref); got != want {
				t.Fatalf("For(%q) = %q, want %q", ref, got, want)
			}
		})
	}
}

// One image has several spellings — a pod may name it any of these — and a rule written once
// has to catch all of them. Matching therefore happens against the normalised repository, not
// against what the pod spec says.
func TestMatchingIsAgainstTheNormalisedRepository(t *testing.T) {
	rules := load(t, `
build-access:
  - repository: index.docker.io/library/*
    access: none
`)
	for _, ref := range []string{
		"nginx:1.2",
		"nginx",
		"docker.io/library/nginx:1.2",
		"index.docker.io/library/nginx:1.2",
		"index.docker.io/library/nginx@sha256:" + strings.Repeat("a", 64),
	} {
		t.Run(ref, func(t *testing.T) {
			if got := rules.For(ref); got != metrics.BuildAccessNone {
				t.Fatalf("For(%q) = %q, want %q", ref, got, metrics.BuildAccessNone)
			}
		})
	}
}

// No file is not a declaration that nothing can be fixed: it is "nobody has looked", and the
// label has to say so rather than be empty.
func TestWithoutRulesEverythingIsUnknown(t *testing.T) {
	var rules *Rules
	if got := rules.For("registry.example/org/app:1"); got != metrics.BuildAccessUnknown {
		t.Fatalf("For() = %q on nil rules, want %q", got, metrics.BuildAccessUnknown)
	}
	loaded, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") = %v, want no error", err)
	}
	if got := loaded.For("registry.example/org/app:1"); got != metrics.BuildAccessUnknown {
		t.Fatalf("For() = %q without a file, want %q", got, metrics.BuildAccessUnknown)
	}
}

// A reference nothing can parse must not fail the run, and must not be classified either.
func TestAnUnparseableReferenceIsUnknown(t *testing.T) {
	rules := load(t, "build-access:\n  - repository: registry.example/org/*\n    access: own\n")
	if got := rules.For("not a reference"); got != metrics.BuildAccessUnknown {
		t.Fatalf("For() = %q, want %q", got, metrics.BuildAccessUnknown)
	}
}

// A `/*` rule covers what is below it, not the bare prefix — otherwise a rule meant for a
// team's repositories would also claim a repository that happens to be named like the team.
func TestDescendantRulesDoNotMatchThePrefixItself(t *testing.T) {
	rules := load(t, "build-access:\n  - repository: registry.example/org/*\n    access: own\n")
	if got := rules.For("registry.example/org:1"); got != metrics.BuildAccessUnknown {
		t.Fatalf("For(prefix itself) = %q, want %q", got, metrics.BuildAccessUnknown)
	}
}

// The confusion this file invites, and the one that cost a diagnosis: every rule in the
// runbook's example is a namespace, so a `/*` is copied along with the shape — but a
// repository published without sub-paths is the path itself, not a namespace. `ko --bare` and
// most CI produce exactly that. The suffixed rule is then a valid file that classifies
// nothing, which is indistinguishable from no file at all, and the three forms are pinned here
// side by side because the difference is invisible everywhere else.
func TestASuffixedRuleDoesNotMatchARepositoryPublishedWithoutSubPaths(t *testing.T) {
	const running = "registry.example/org/app:1.4.0"
	tests := map[string]struct {
		pattern string
		want    string
	}{
		"the repository with a /* suffix": {"registry.example/org/app/*", metrics.BuildAccessUnknown},
		"the repository named exactly":    {"registry.example/org/app", metrics.BuildAccessOwn},
		"the namespace above it with /*":  {"registry.example/org/*", metrics.BuildAccessOwn},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rules := load(t, "build-access:\n  - repository: "+test.pattern+"\n    access: own\n")
			if got := rules.For(running); got != test.want {
				t.Fatalf("For(%q) under rule %q = %q, want %q", running, test.pattern, got, test.want)
			}
		})
	}
}

// Everything a rule could mean in two ways is a start-up error. A misclassification is
// invisible in the metrics — nothing else can check it — so it has to be caught here or never.
func TestLoadRejects(t *testing.T) {
	tests := map[string]string{
		"empty file":          "",
		"no build-access key": "rules:\n  - repository: registry.example/org/*\n    access: own\n",
		"unknown field":       "build-access:\n  - repo: registry.example/org/*\n    access: own\n",
		"not yaml":            "build-access: [unclosed\n",
		"no repository":       "build-access:\n  - access: own\n",
		"no access":           "build-access:\n  - repository: registry.example/org/*\n",
		"unknown access":      "build-access:\n  - repository: registry.example/org/*\n    access: maybe\n",
		// unknown is what no rule matching means; declaring it would conflate "nobody looked"
		// with "somebody decided there is nobody to ask".
		"declares unknown": "build-access:\n  - repository: registry.example/org/*\n    access: unknown\n",
		// `foo/bar*` would also match `foo/barbaz`.
		"partial segment wildcard": "build-access:\n  - repository: registry.example/org/plat*\n    access: own\n",
		"wildcard in the middle":   "build-access:\n  - repository: registry.example/*/app\n    access: own\n",
		"names a tag":              "build-access:\n  - repository: registry.example/org/app:1.2\n    access: own\n",
		"names a digest":           "build-access:\n  - repository: registry.example/org/app@sha256:abc\n    access: own\n",
		// Patterns are not normalised: a short form would be a guess about which registry was
		// meant, and a guess that silently matches nothing is worse than a refusal.
		"not fully qualified": "build-access:\n  - repository: library/nginx\n    access: none\n",
		// Equal specificity on one repository, so the answer would depend on file order.
		"declared twice": "build-access:\n  - repository: registry.example/org/*\n    access: own\n" +
			"  - repository: registry.example/org/*\n    access: none\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, content)); err == nil {
				t.Fatalf("Load(%q) = no error, want one", content)
			}
		})
	}
}

// A registry with a port is a registry, not a repository with a tag.
func TestAPortIsNotATag(t *testing.T) {
	rules := load(t, "build-access:\n  - repository: registry.example:5000/org/*\n    access: own\n")
	if got := rules.For("registry.example:5000/org/app:1.2"); got != metrics.BuildAccessOwn {
		t.Fatalf("For() = %q, want %q", got, metrics.BuildAccessOwn)
	}
}

func load(t *testing.T, content string) *Rules {
	t.Helper()
	rules, err := Load(write(t, content))
	if err != nil {
		t.Fatalf("Load() = %v, want no error", err)
	}
	return rules
}

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "build-access.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimPrefix(content, "\n")), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v, want no error", err)
	}
	return path
}
