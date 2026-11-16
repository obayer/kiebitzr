package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tree builds a fake module cache and returns the `go list -deps -json` output for it. files
// maps a path below the temporary root to its content; packages are described by the entries
// in pkgs, whose Dir and Module.Dir are made absolute against that root.
func tree(t *testing.T, files map[string]string, pkgs ...pkg) (listed []byte) {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var b strings.Builder
	enc := json.NewEncoder(&b)
	for _, p := range pkgs {
		if p.Dir != "" {
			p.Dir = filepath.Join(root, p.Dir)
		}
		if p.Module != nil && p.Module.Dir != "" {
			p.Module.Dir = filepath.Join(root, p.Module.Dir)
		}
		if err := enc.Encode(p); err != nil {
			t.Fatal(err)
		}
	}
	return []byte(b.String())
}

// module describes one dependency package in the fake tree.
func module(importPath, dir, modPath, modDir, version string) pkg {
	return pkg{
		ImportPath: importPath,
		Dir:        dir,
		Module:     &modinfo{Path: modPath, Version: version, Dir: modDir},
	}
}

// noStdlib stands in for the toolchain's own licenses, which no test needs to read off disk.
func noStdlib() ([]component, error) { return nil, nil }

func TestLicenseAtTheModuleRootIsFound(t *testing.T) {
	listed := tree(t,
		map[string]string{"dep/LICENSE": "MIT text"},
		module("example.com/dep/sub", "dep/sub", "example.com/dep", "dep", "v1.2.3"),
	)
	components, missing, err := collect([][]byte{listed}, noStdlib)
	if err != nil || len(missing) > 0 {
		t.Fatalf("collect() = %v, missing %v", err, missing)
	}
	if len(components) != 1 {
		t.Fatalf("got %d components, want 1: %+v", len(components), components)
	}
	got := components[0]
	if got.Module != "example.com/dep" || got.Version != "v1.2.3" || got.Text != "MIT text" || got.Subdir != "" {
		t.Errorf("unexpected component: %+v", got)
	}
}

// A subdirectory carrying its own terms is the forked-code case, and it is why the search runs
// from the package upwards rather than from the module root downwards: measured on the real
// tree, 70-odd dependencies have one.
func TestASubdirectoryLicenseWinsOverTheModuleRoot(t *testing.T) {
	listed := tree(t,
		map[string]string{
			"dep/LICENSE":             "module terms",
			"dep/third_party/LICENSE": "forked terms",
		},
		module("example.com/dep/third_party/x", "dep/third_party/x", "example.com/dep", "dep", "v1"),
	)
	components, _, err := collect([][]byte{listed}, noStdlib)
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 {
		t.Fatalf("got %d components, want 1", len(components))
	}
	if components[0].Text != "forked terms" || components[0].Subdir != "third_party" {
		t.Errorf("the module's own terms shadowed the fork's: %+v", components[0])
	}
}

// NOTICE is not optional: Apache-2.0 section 4(d) requires its content to travel with a
// derivative work, so it is collected beside the license rather than instead of it.
func TestNoticeAndLicenseAreBothCollected(t *testing.T) {
	listed := tree(t,
		map[string]string{"dep/LICENSE": "apache text", "dep/NOTICE": "attribution"},
		module("example.com/dep", "dep", "example.com/dep", "dep", "v1"),
	)
	components, _, err := collect([][]byte{listed}, noStdlib)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, c := range components {
		files = append(files, c.File)
	}
	if len(files) != 2 || files[0] != "LICENSE" || files[1] != "NOTICE" {
		t.Errorf("collected %v, want LICENSE and NOTICE", files)
	}
}

// The name pattern would otherwise match Go source: `license.go` and `licenses.go` are real
// files in this dependency tree, and reading one would put source code into a legal notice.
func TestGoSourceIsNotMistakenForALicense(t *testing.T) {
	for _, name := range []string{"license.go", "licenses.go", "notice.json", "copying.yaml"} {
		if isLicenseFile(name) {
			t.Errorf("isLicenseFile(%q) = true, want false", name)
		}
	}
	for _, name := range []string{"LICENSE", "LICENCE", "licence.txt", "LICENSE.md", "COPYING", "COPYING.LESSER", "UNLICENSE", "NOTICE", "LICENSE-APACHE", "PATENTS"} {
		if !isLicenseFile(name) {
			t.Errorf("isLicenseFile(%q) = false, want true", name)
		}
	}
	// A readme that mentions a license is not the license.
	if isLicenseFile("README.md") {
		t.Error(`isLicenseFile("README.md") = true, want false`)
	}
}

// A dependency with no license text anywhere must fail loudly. Omitting it would produce a
// document that looks complete and is not — the failure this tool exists to prevent.
func TestAPackageWithoutALicenseIsReported(t *testing.T) {
	listed := tree(t,
		map[string]string{"dep/code.go": "package dep"},
		module("example.com/dep", "dep", "example.com/dep", "dep", "v1"),
	)
	_, missing, err := collect([][]byte{listed}, noStdlib)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0] != "example.com/dep" {
		t.Errorf("missing = %v, want [example.com/dep]", missing)
	}
}

func TestTheMainModuleAndTheStandardLibraryAreHandledSeparately(t *testing.T) {
	listed := tree(t,
		map[string]string{"own/LICENSE": "ours"},
		pkg{ImportPath: "fmt", Standard: true},
		module(mainModule+"/internal/x", "own/internal/x", mainModule, "own", ""),
	)
	toolchain := func() ([]component, error) {
		return []component{{Module: "go", Version: "go1.27.4", File: "LICENSE", Text: "bsd"}}, nil
	}
	components, missing, err := collect([][]byte{listed}, toolchain)
	if err != nil || len(missing) > 0 {
		t.Fatalf("collect() = %v, missing %v", err, missing)
	}
	// The main module's own terms are LICENSE and NOTICE at the root, not a third-party
	// notice; the standard library is linked in and needs its own entry.
	if len(components) != 1 || components[0].Module != "go" {
		t.Errorf("components = %+v, want only the toolchain", components)
	}
}

func TestAPackageWithoutAModuleIsAnError(t *testing.T) {
	listed := tree(t, nil, pkg{ImportPath: "example.com/x", Dir: "x"})
	if _, _, err := collect([][]byte{listed}, noStdlib); err == nil {
		t.Fatal("collect() = nil, want an error for a package with no module")
	}
}

// The rendered file is committed, so two runs over the same link set have to produce the same
// bytes — a timestamp or an absolute path would make the gate fail on noise and teach everybody
// to regenerate without reading.
func TestRenderIsDeterministicAndCarriesNoPaths(t *testing.T) {
	components := []component{
		{Module: "example.com/b", Version: "v2", File: "LICENSE", Text: "b text\n\n"},
		{Module: "example.com/a", Version: "v1", Subdir: "sub", File: "LICENSE", Text: "a text"},
	}
	targets := []platform{{OS: "linux", Arch: "amd64"}, {OS: "linux", Arch: "arm64"}}
	first := string(render(components, targets))
	if second := string(render(components, targets)); first != second {
		t.Fatal("render() is not deterministic")
	}
	for _, want := range []string{"example.com/a v1 (sub)", "example.com/b v2", "a text", "b text", "Components: 2", "linux/amd64, linux/arm64"} {
		if !strings.Contains(first, want) {
			t.Errorf("render() does not contain %q", want)
		}
	}
	if strings.Contains(first, string(filepath.Separator)+"Users") || strings.Contains(first, "/tmp") {
		t.Error("render() leaked an absolute path")
	}
}

// koYAML is the minimum .ko.yaml run() needs: the platforms the notice covers.
const koYAML = "defaultPlatforms:\n  - linux/arm64\n  - linux/amd64\n"

func TestWriteThenCheckPasses(t *testing.T) {
	// The paths the tool reads and writes are repository-relative, so the test runs from a
	// directory of its own.
	t.Chdir(t.TempDir())
	if err := os.MkdirAll(filepath.Dir(noticesPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(koConfigPath, []byte(koYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	listed := tree(t,
		map[string]string{"dep/LICENSE": "MIT text"},
		module("example.com/dep", "dep", "example.com/dep", "dep", "v1"),
	)
	list := func(context.Context, string, platform) ([]byte, error) { return listed, nil }

	if err := run(context.Background(), true, io.Discard, list, noStdlib); err != nil {
		t.Fatalf("run(write) = %v", err)
	}
	if err := run(context.Background(), false, io.Discard, list, noStdlib); err != nil {
		t.Fatalf("run(check) after write = %v, want nil", err)
	}

	// A dependency added without regenerating must fail the gate.
	grown := tree(t,
		map[string]string{"dep/LICENSE": "MIT text", "other/LICENSE": "BSD text"},
		module("example.com/dep", "dep", "example.com/dep", "dep", "v1"),
		module("example.com/other", "other", "example.com/other", "other", "v1"),
	)
	stale := func(context.Context, string, platform) ([]byte, error) { return grown, nil }
	err := run(context.Background(), false, io.Discard, stale, noStdlib)
	if err == nil || !strings.Contains(err.Error(), "out of date") {
		t.Fatalf("run(check) with a new dependency = %v, want an out-of-date error", err)
	}
}

// The defect the first CI run found: the link set depends on the target, so a file generated
// on one platform both omits components of the image and lists components that are not in it.
// Measured on this tree — a Linux build links github.com/prometheus/procfs, a macOS build
// links github.com/ncruces/go-strftime instead. The notice therefore has to be the union over
// the platforms that are released, and must not depend on where it was generated.
func TestTheResultIsTheUnionOverThePlatforms(t *testing.T) {
	onePlatform := tree(t,
		map[string]string{"linuxonly/LICENSE": "linux terms"},
		module("example.com/linuxonly", "linuxonly", "example.com/linuxonly", "linuxonly", "v1"),
	)
	other := tree(t,
		map[string]string{"darwinonly/LICENSE": "darwin terms"},
		module("example.com/darwinonly", "darwinonly", "example.com/darwinonly", "darwinonly", "v1"),
	)

	components, missing, err := collect([][]byte{onePlatform, other}, noStdlib)
	if err != nil || len(missing) > 0 {
		t.Fatalf("collect() = %v, missing %v", err, missing)
	}
	if len(components) != 2 {
		t.Fatalf("got %d components, want both platforms' dependencies: %+v", len(components), components)
	}
	// And the order must not depend on which platform was listed first.
	reversed, _, err := collect([][]byte{other, onePlatform}, noStdlib)
	if err != nil {
		t.Fatal(err)
	}
	if components[0].Module != reversed[0].Module || components[1].Module != reversed[1].Module {
		t.Errorf("the order depends on the platform order: %+v vs %+v", components, reversed)
	}
}

func TestReleasePlatformsComeFromTheKoConfig(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), ".ko.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// Sorted, so the generated file does not depend on the order in the configuration.
	got, err := releasePlatforms(write(t, koYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].String() != "linux/amd64" || got[1].String() != "linux/arm64" {
		t.Errorf("releasePlatforms() = %v, want linux/amd64 then linux/arm64", got)
	}

	for name, body := range map[string]string{
		"no platforms at all":    "builds:\n  - id: kiebitzr\n",
		"not a GOOS/GOARCH pair": "defaultPlatforms:\n  - linux\n",
		"a per-build override":   "defaultPlatforms:\n  - linux/amd64\nbuilds:\n  - id: kiebitzr\n    platforms:\n      - linux/arm64\n",
		"not even valid YAML":    "defaultPlatforms: [\n",
	} {
		if _, err := releasePlatforms(write(t, body)); err == nil {
			t.Errorf("releasePlatforms() accepted %s", name)
		}
	}

	if _, err := releasePlatforms(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("releasePlatforms() accepted a missing file")
	}
}
