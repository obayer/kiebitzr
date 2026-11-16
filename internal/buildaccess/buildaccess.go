// Package buildaccess answers one question about a running image: can anybody here get a
// build of it?
//
// It is the axis `package_type` does not cover. That one is a property of the finding — would
// a newer tag carry the fix, or does it take a rebuild by whoever publishes the image. This one
// is a property of the image: is there a person who decides what goes in, and do we reach them.
// Only together do they say whether an action exists at all (ADR 0013).
//
// The answer is **declared, never detected**, and that is not a preference. Two repositories in
// one namespace of one registry — one built by the operator's own team, one by another team —
// are published by the same CI and carry the same signing identity. Nothing in or around the
// image distinguishes them. The difference is which humans decide, and no amount of reading
// manifests recovers it.
package buildaccess

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"gopkg.in/yaml.v3"

	"github.com/obayer/kiebitzr/internal/metrics"
)

// declarable are the values a rule may carry. The vocabulary itself lives in internal/metrics
// beside the other label vocabularies, because that is where a consumer of the metric looks
// for it.
//
// metrics.BuildAccessUnknown is deliberately not in this list: it is what "no rule matched"
// means, and letting it be declared would conflate "nobody has looked at this image" with
// "somebody decided there is nobody to ask".
var declarable = []string{
	metrics.BuildAccessOwn, metrics.BuildAccessReachable, metrics.BuildAccessNone,
}

// Rules classify repositories. The zero value is useless; a nil *Rules is not — it answers
// unknown for everything, which is exactly what an installation without a rules file gets.
type Rules struct {
	rules []rule
}

// rule is one pattern and the access it declares.
type rule struct {
	// repository is the fully qualified repository, without any trailing wildcard.
	repository string
	// descendants is true for a `/*` pattern, which matches below repository but not
	// repository itself.
	descendants bool
	// segments is the specificity: how many path segments the pattern names. The most
	// specific match wins, so a namespace-wide rule is a default that one repository can
	// override — which is what a fleet with one team's repository among another's needs.
	segments int
	access   string
}

// file is the shape of the rules file.
type file struct {
	BuildAccess []entry `yaml:"build-access"`
}

type entry struct {
	Repository string `yaml:"repository"`
	Access     string `yaml:"access"`
}

// Load reads and validates a rules file. An empty path returns empty rules, which classify
// everything as unknown — the state of an installation that has declared nothing, and not a
// declaration that nothing can be fixed.
//
// Every rejection here is a start-up error rather than a skipped rule (ADR 0007): a
// misclassification is invisible in the metrics — the whole point of this axis is that nothing
// else can check it — so a rule that does not do what it says has to be caught before the
// process serves anything.
func Load(path string) (*Rules, error) {
	if path == "" {
		return &Rules{}, nil
	}
	content, err := os.ReadFile(path) //nolint:gosec // the path is operator-supplied configuration
	if err != nil {
		return nil, fmt.Errorf("read build access file: %w", err)
	}

	// Unknown keys are rejected: a typo in a key would otherwise declare nothing at all, and
	// the result — everything Unknown — looks exactly like a file nobody mounted.
	var parsed file
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&parsed); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse build access file %s: %w", path, err)
	}
	if len(parsed.BuildAccess) == 0 {
		return nil, fmt.Errorf("build access file %s contains no rules under `build-access:`", path)
	}
	return compile(parsed.BuildAccess)
}

// compile turns the entries into rules, rejecting everything ambiguous.
func compile(entries []entry) (*Rules, error) {
	rules := make([]rule, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		r, err := compileOne(e)
		if err != nil {
			return nil, err
		}
		// Two patterns of equal specificity can only both match one repository if they are the
		// same pattern — every segment but a trailing `*` is literal — so rejecting duplicates
		// is exactly the ambiguity check and needs no overlap analysis.
		key := r.repository
		if r.descendants {
			key += "/*"
		}
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("build access rule %q is declared twice", key)
		}
		seen[key] = struct{}{}
		rules = append(rules, r)
	}
	return &Rules{rules: rules}, nil
}

func compileOne(e entry) (rule, error) {
	pattern := strings.TrimSpace(e.Repository)
	if pattern == "" {
		return rule{}, errors.New("build access rule without a repository")
	}
	access := strings.TrimSpace(e.Access)
	if access == metrics.BuildAccessUnknown {
		return rule{}, fmt.Errorf(
			"build access rule %q declares %q, which is what no rule matching means and cannot be declared",
			pattern, metrics.BuildAccessUnknown)
	}
	if !slices.Contains(declarable, access) {
		return rule{}, fmt.Errorf("build access rule %q has access %q, want one of %s",
			pattern, access, strings.Join(declarable, ", "))
	}

	repository, descendants := strings.CutSuffix(pattern, "/*")
	if strings.Contains(repository, "*") {
		// `foo/bar*` would also match `foo/barbaz`. A near-miss nobody notices until it
		// classifies the wrong image, so only a whole trailing segment may be a wildcard.
		return rule{}, fmt.Errorf(
			"build access rule %q: `*` is only allowed as a whole trailing segment, as in `registry.example/org/*`",
			pattern)
	}
	// A colon only separates a tag when it follows the last slash; before that it is a
	// registry port.
	if strings.Contains(repository, "@") || strings.LastIndex(repository, ":") > strings.LastIndex(repository, "/") {
		return rule{}, fmt.Errorf("build access rule %q names a tag or digest; a rule is about a repository",
			pattern)
	}
	// Patterns must be fully qualified, because the alternative is guessing. Matching happens
	// against the normalised repository — `nginx` in a pod spec is `index.docker.io/library/nginx`
	// — and silently normalising the pattern the same way would turn a mistyped registry into a
	// Docker Hub rule that quietly matches nothing.
	if !isRegistry(firstSegment(repository)) {
		return rule{}, fmt.Errorf(
			"build access rule %q is not fully qualified; write the registry out, as in `index.docker.io/library/nginx`",
			pattern)
	}

	return rule{
		repository:  repository,
		descendants: descendants,
		segments:    strings.Count(repository, "/") + 1,
		access:      access,
	}, nil
}

// For is the access declared for an image reference, or metrics.BuildAccessUnknown.
//
// The reference is normalised first: a pod may say `nginx:1.2`, `docker.io/library/nginx:1.2`
// or `index.docker.io/library/nginx@sha256:…` for one image, and a rule written once has to
// catch all three. A reference that cannot be parsed is Unknown rather than an error — one odd
// reference must not fail a run, and "could not classify" is the honest answer for it.
func (r *Rules) For(ref string) string {
	if r == nil || len(r.rules) == 0 {
		return metrics.BuildAccessUnknown
	}
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return metrics.BuildAccessUnknown
	}
	repository := parsed.Context().Name()

	best := rule{segments: -1}
	for _, candidate := range r.rules {
		if candidate.matches(repository) && candidate.segments > best.segments {
			best = candidate
		}
	}
	if best.access == "" {
		return metrics.BuildAccessUnknown
	}
	return best.access
}

// matches reports whether a rule covers one normalised repository.
func (r rule) matches(repository string) bool {
	if r.descendants {
		return strings.HasPrefix(repository, r.repository+"/")
	}
	return repository == r.repository
}

// firstSegment is the part before the first slash — the registry, in a fully qualified
// reference.
func firstSegment(repository string) string {
	segment, _, _ := strings.Cut(repository, "/")
	return segment
}

// isRegistry applies the same rule the OCI tooling does: a first segment is a registry when it
// carries a dot or a port, or is localhost. Anything else is a Docker Hub namespace.
func isRegistry(segment string) bool {
	return segment == "localhost" || strings.ContainsAny(segment, ".:")
}
