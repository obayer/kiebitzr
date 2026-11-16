// Command licenseguard collects the license texts of everything linked into the kiebitzr
// binary and keeps the collected file from going stale.
//
// Distributing a Go binary distributes its dependencies: the code is linked in, and the
// permissive licenses it arrives under — Apache-2.0, MIT, BSD — all require the license text
// and the copyright notice to travel with a *binary* distribution too, not only with source.
// That obligation falls on whoever ships the image. The SPDX SBOM that `ko --sbom=spdx`
// attaches does not discharge it: an SBOM lists components and license *names*, and a name is
// not a notice.
//
// So this walks the real link set and copies the texts verbatim:
//
//	go list -deps -json ./cmd/kiebitzr   — every package that ends up in the binary
//	package directory → module root      — the nearest LICENSE, COPYING or NOTICE file
//
// Deliberately no license classifier. Classification is where the usual tools break: measured
// on this tree, two modules carry a perfectly valid license file that no classifier would
// name, and the generated notice then listed them with no text at all — a document that looks
// complete and is not. Names are what the SBOM is for; texts are what the licenses ask for,
// and a text needs no interpretation.
//
// Two modes, like `fmt` and `fmt:check`: with -write the file is rewritten, without it the
// file is compared and a difference fails. A package with no license file anywhere up to its
// module root fails in both modes and is named, because silently omitting one is the failure
// this exists to prevent.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// noticesPath is inside the main package's kodata directory, which is how ko embeds a file in
// the image: everything under kodata is copied in and reachable at $KO_DATA_PATH. One file
// therefore serves both halves of the obligation — it is in the repository for anybody reading
// it, and in the image for whoever receives the binary.
const noticesPath = "cmd/kiebitzr/kodata/THIRD_PARTY_NOTICES"

// mainModule is excluded: its own terms are LICENSE and NOTICE at the repository root.
const mainModule = "github.com/obayer/kiebitzr"

// koConfigPath is where the platforms come from. Reading them rather than repeating them is
// what keeps the notice covering exactly what is released: if .ko.yaml gains a platform, the
// next run picks it up and the gate reports the file as out of date.
const koConfigPath = ".ko.yaml"

// koConfig is the part of ko's configuration this needs.
type koConfig struct {
	DefaultPlatforms []string `yaml:"defaultPlatforms"`
	Builds           []struct {
		ID        string   `yaml:"id"`
		Platforms []string `yaml:"platforms"`
	} `yaml:"builds"`
}

// releasePlatforms reads the platforms the release is built for, sorted so the generated file
// does not depend on their order in the configuration.
func releasePlatforms(path string) ([]platform, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a constant repository-relative path
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg koConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// A per-build `platforms` key would override defaultPlatforms for that build, and this
	// would then describe the wrong artefact. Refuse rather than guess: nothing in this
	// repository uses one today, and if that changes it has to be handled deliberately.
	for _, b := range cfg.Builds {
		if len(b.Platforms) > 0 {
			return nil, fmt.Errorf("%s: build %q overrides platforms; teach licenseguard to read it", path, b.ID)
		}
	}
	if len(cfg.DefaultPlatforms) == 0 {
		return nil, fmt.Errorf("%s: no defaultPlatforms — the notice cannot say what it covers", path)
	}

	platforms := make([]platform, 0, len(cfg.DefaultPlatforms))
	for _, entry := range cfg.DefaultPlatforms {
		os, arch, found := strings.Cut(entry, "/")
		if !found || os == "" || arch == "" {
			return nil, fmt.Errorf("%s: %q is not a GOOS/GOARCH pair", path, entry)
		}
		platforms = append(platforms, platform{OS: os, Arch: arch})
	}
	slices.SortFunc(platforms, func(a, b platform) int { return strings.Compare(a.String(), b.String()) })
	return platforms, nil
}

// licenseName matches the names a license text is kept under: LICENSE, LICENCE, UNLICENSE,
// COPYING, NOTICE, PATENTS, with the suffixes those pick up (LICENSE.md, LICENSE-APACHE,
// COPYING.LESSER). README is deliberately not among them — a readme that mentions a license is
// not the license.
var licenseName = regexp.MustCompile(`(?i)^((un)?licen[sc]es?|copying|notices?|patents)([._-].*)?$`)

// codeExtension rejects what the pattern above would otherwise swallow. `license.go` and
// `licenses.go` are real files in this dependency tree — Syft has both — and reading one as a
// license text would put Go source into a legal notice.
var codeExtension = map[string]bool{
	".go": true, ".js": true, ".ts": true, ".py": true, ".rb": true, ".sh": true,
	".c": true, ".h": true, ".cc": true, ".s": true, ".rs": true, ".java": true,
	".json": true, ".yaml": true, ".yml": true, ".toml": true, ".mod": true, ".sum": true,
	".tmpl": true, ".tpl": true, ".proto": true, ".bzl": true,
}

// isLicenseFile reports whether a directory entry's name is a license text.
func isLicenseFile(name string) bool {
	return licenseName.MatchString(name) && !codeExtension[strings.ToLower(filepath.Ext(name))]
}

func main() {
	write := flag.Bool("write", false, "rewrite "+noticesPath+" instead of checking it")
	flag.Parse()

	ctx := context.Background()
	std := func() ([]component, error) { return standardLibrary(ctx) }

	if err := run(ctx, *write, os.Stdout, goList, std); err != nil {
		fmt.Fprintf(os.Stderr, "licenseguard: %v\n", err)
		os.Exit(1)
	}
}

// lister returns the output of `go list -deps -json` for one pattern on one platform. Injected
// so the tests do not need a module to resolve.
type lister func(ctx context.Context, pattern string, p platform) ([]byte, error)

// platform is one GOOS/GOARCH pair the release is built for.
type platform struct {
	OS   string
	Arch string
}

func (p platform) String() string { return p.OS + "/" + p.Arch }

// stdlibSource returns the toolchain's own license components. Injected for the same reason.
type stdlibSource func() ([]component, error)

// pkg is the part of `go list -json` this needs. The tags are go list's own field names,
// written out rather than relied upon by case so the mapping is visible.
type pkg struct {
	ImportPath string   `json:"ImportPath"`
	Dir        string   `json:"Dir"`
	Standard   bool     `json:"Standard"`
	Module     *modinfo `json:"Module"`
}

// modinfo is the module a package belongs to. Absent for the standard library.
type modinfo struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
}

// component is one license text, with what it belongs to. Several components may share a
// module when a subdirectory carries its own license, which is common in forked code.
type component struct {
	// Module is the module path, or "go" for the standard library.
	Module string
	// Version is the module version, or the toolchain version for the standard library.
	Version string
	// Subdir is the path below the module root the license was found in, empty at the root.
	// It is what distinguishes a forked subdirectory's license from its module's.
	Subdir string
	// File is the license file's name, kept so the notice says which file it reproduces.
	File string
	Text string
}

func run(ctx context.Context, write bool, out io.Writer, list lister, std stdlibSource) error {
	// The link set depends on the platform, so the notice has to be taken over the platforms
	// that are actually shipped rather than over whichever one the generator runs on. Measured:
	// a Linux build links github.com/prometheus/procfs and a macOS build does not, while macOS
	// links github.com/ncruces/go-strftime instead — so a file generated on a workstation both
	// omitted a component of the image and listed one that is not in it.
	targets, err := releasePlatforms(koConfigPath)
	if err != nil {
		return err
	}

	// No build tags: the release build is what is distributed, and the `dev` build links a
	// kubeconfig loader that never ships (ADR 0004). Notices follow what is shipped.
	raws := make([][]byte, 0, len(targets))
	for _, target := range targets {
		raw, listErr := list(ctx, "./cmd/kiebitzr", target)
		if listErr != nil {
			return listErr
		}
		raws = append(raws, raw)
	}

	components, missing, err := collect(raws, std)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("no license file found for %d package(s), up to their module root:\n  %s\n"+
			"Each one is linked into the binary, so its terms have to travel with it. Find the\n"+
			"text upstream and say where it is, or drop the dependency — this cannot be skipped",
			len(missing), strings.Join(missing, "\n  "))
	}

	rendered := render(components, targets)

	if write {
		if err := os.WriteFile(noticesPath, rendered, 0o644); err != nil { //nolint:gosec // a notices file is world-readable on purpose
			return fmt.Errorf("write %s: %w", noticesPath, err)
		}
		return report(out, "licenseguard: wrote %s, %d components", noticesPath, len(components))
	}

	committed, err := os.ReadFile(noticesPath)
	if err != nil {
		return fmt.Errorf("read %s: %w — run `mise run licenses`", noticesPath, err)
	}
	if !bytes.Equal(committed, rendered) {
		return fmt.Errorf("%s is out of date: %d components in the link set.\n"+
			"Run `mise run licenses` and commit the result", noticesPath, len(components))
	}
	return report(out, "licenseguard: %s is current, %d components", noticesPath, len(components))
}

// report writes one status line and does not drop the error, because a gate that cannot say
// what it concluded has concluded nothing.
func report(out io.Writer, format string, args ...any) error {
	if _, err := fmt.Fprintf(out, format+"\n", args...); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// collect turns `go list -deps -json` output into the components to reproduce, plus the import
// paths that have no license text anywhere.
func collect(raws [][]byte, std stdlibSource) (components []component, missing []string, err error) {
	// A license directory is reached from many packages, and from more than one platform;
	// collecting by directory keeps one entry per text rather than one per importer, and makes
	// the result the union over the platforms instead of whichever was listed last.
	seen := map[string]component{}
	var stdlib bool

	for _, raw := range raws {
		dec := json.NewDecoder(bytes.NewReader(raw))
		for {
			var p pkg
			if decErr := dec.Decode(&p); errors.Is(decErr, io.EOF) {
				break
			} else if decErr != nil {
				return nil, nil, fmt.Errorf("parse go list output: %w", decErr)
			}

			switch {
			case p.Standard:
				// The standard library is linked in as much as any dependency, and its terms
				// are the toolchain's own. One entry covers all of it.
				stdlib = true
				continue
			case p.Module == nil:
				return nil, nil, fmt.Errorf("%s belongs to no module", p.ImportPath)
			case p.Module.Path == mainModule:
				continue
			}

			dir, files := findLicense(p.Dir, p.Module.Dir)
			if len(files) == 0 {
				missing = append(missing, p.ImportPath)
				continue
			}
			subdir, relErr := filepath.Rel(p.Module.Dir, dir)
			if relErr != nil {
				return nil, nil, fmt.Errorf("%s: %w", p.ImportPath, relErr)
			}
			if subdir == "." {
				subdir = ""
			}
			for _, name := range files {
				text, readErr := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // the directory comes from `go list`, the name from a directory listing
				if readErr != nil {
					return nil, nil, fmt.Errorf("read license of %s: %w", p.ImportPath, readErr)
				}
				seen[filepath.Join(dir, name)] = component{
					Module:  p.Module.Path,
					Version: p.Module.Version,
					Subdir:  subdir,
					File:    name,
					Text:    string(text),
				}
			}
		}
	}

	if stdlib {
		toolchain, stdErr := std()
		if stdErr != nil {
			return nil, nil, stdErr
		}
		components = append(components, toolchain...)
	}
	for _, c := range seen {
		components = append(components, c)
	}

	slices.SortFunc(components, func(a, b component) int {
		if n := strings.Compare(a.Module, b.Module); n != 0 {
			return n
		}
		if n := strings.Compare(a.Subdir, b.Subdir); n != 0 {
			return n
		}
		return strings.Compare(a.File, b.File)
	})
	slices.Sort(missing)
	missing = slices.Compact(missing)
	return components, missing, nil
}

// findLicense walks from a package directory up to its module root and returns the first
// directory that holds license files, with their names sorted. Walking up is what catches a
// forked subdirectory carrying terms of its own: it is found before the module's.
func findLicense(packageDir, moduleDir string) (dir string, files []string) {
	for current := packageDir; ; current = filepath.Dir(current) {
		entries, err := os.ReadDir(current)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() && isLicenseFile(e.Name()) {
					files = append(files, e.Name())
				}
			}
		}
		if len(files) > 0 {
			slices.Sort(files)
			return current, files
		}
		if current == moduleDir || current == filepath.Dir(current) {
			return "", nil
		}
	}
}

// standardLibrary returns the toolchain's own terms. Go ships LICENSE and PATENTS, and the
// second is not optional — it is part of the grant the first refers to.
func standardLibrary(ctx context.Context) ([]component, error) {
	out, err := exec.CommandContext(ctx, "go", "env", "GOROOT", "GOVERSION").Output()
	if err != nil {
		return nil, fmt.Errorf("go env GOROOT GOVERSION: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 {
		return nil, fmt.Errorf("go env GOROOT GOVERSION returned %q", string(out))
	}
	root, version := fields[0], fields[1]

	var components []component
	for _, name := range []string{"LICENSE", "PATENTS"} {
		text, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // GOROOT as go itself reports it, with two constant file names
		if err != nil {
			return nil, fmt.Errorf("read the toolchain's %s: %w", name, err)
		}
		components = append(components, component{Module: "go", Version: version, File: name, Text: string(text)})
	}
	return components, nil
}

// render writes the notice. It carries no timestamp and no absolute path on purpose: the file
// is committed, so anything that changes without the link set changing would make the gate
// fail on noise and teach everybody to regenerate without reading.
func render(components []component, targets []platform) []byte {
	names := make([]string, 0, len(targets))
	for _, t := range targets {
		names = append(names, t.String())
	}

	var b strings.Builder
	b.WriteString(`Third-party notices for Kiebitzr
===============================

Kiebitzr is distributed as a single statically linked binary, so every component below is
part of what you received. Each entry reproduces that component's own license text verbatim,
which is what those licenses require of a binary distribution.

Kiebitzr's own terms are not here: see LICENSE and NOTICE.

Generated from the release build configuration of ./cmd/kiebitzr by ` + "`mise run licenses`" + `,
checked by ` + "`mise run licenses:check`" + `. Component names and license identifiers are also in
the SPDX SBOM attached to every release image.

The set of linked packages depends on the target, so this is the union over the platforms the
release is built for, taken from .ko.yaml rather than from whichever machine generated it.

Platforms: `)
	fmt.Fprintf(&b, "%s\nComponents: %d\n", strings.Join(names, ", "), len(components))

	rule := strings.Repeat("-", 96)
	for _, c := range components {
		fmt.Fprintf(&b, "\n%s\n%s", rule, c.Module)
		if c.Version != "" {
			fmt.Fprintf(&b, " %s", c.Version)
		}
		if c.Subdir != "" {
			fmt.Fprintf(&b, " (%s)", c.Subdir)
		}
		fmt.Fprintf(&b, "\n%s\n\n", rule)
		text := strings.ReplaceAll(c.Text, "\r\n", "\n")
		fmt.Fprintf(&b, "%s\n", strings.TrimRight(text, "\n"))
	}
	return []byte(b.String())
}

func goList(ctx context.Context, pattern string, p platform) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-json", pattern) //nolint:gosec // fixed command, pattern is a constant from this file
	// The target decides which files the build constraints admit, and CGO decides it too — both
	// are pinned here rather than inherited, so the result does not depend on the caller's
	// environment. CGO_ENABLED=0 is what .ko.yaml builds with.
	cmd.Env = append(os.Environ(), "GOOS="+p.OS, "GOARCH="+p.Arch, "CGO_ENABLED=0")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -deps -json %s for %s: %w: %s", pattern, p, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
