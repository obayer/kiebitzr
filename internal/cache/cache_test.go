package cache

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	digestA = "sha256:" + hexA
	digestB = "sha256:" + hexB
	hexA    = "1111111111111111111111111111111111111111111111111111111111111111"
	hexB    = "2222222222222222222222222222222222222222222222222222222222222222"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New() = %v, want no error", err)
	}
	return store
}

func save(t *testing.T, store *Store, digest, content string) {
	t.Helper()
	w, err := store.Create(digest)
	if err != nil {
		t.Fatalf("Create(%s) = %v, want no error", digest, err)
	}
	defer func() { _ = w.Close() }()

	if _, err := io.WriteString(w, content); err != nil {
		t.Fatalf("Write() = %v, want no error", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit() = %v, want no error", err)
	}
}

func load(t *testing.T, store *Store, digest string) string {
	t.Helper()
	r, err := store.Open(digest)
	if err != nil {
		t.Fatalf("Open(%s) = %v, want no error", digest, err)
	}
	defer func() { _ = r.Close() }()

	content, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() = %v, want no error", err)
	}
	return string(content)
}

func TestNewCreatesTheLayout(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() = %v, want no error", err)
	}
	for _, sub := range []string{filepath.Join(dir, sbomDir), store.DatabaseDir()} {
		info, err := os.Stat(sub)
		if err != nil || !info.IsDir() {
			t.Fatalf("%s is not a directory: %v", sub, err)
		}
	}
}

func TestNewIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	store := mustNew(t, dir)
	save(t, store, digestA, `{"artifacts":[]}`)

	// A restart must find its cache again, not clear it.
	if got := load(t, mustNew(t, dir), digestA); got != `{"artifacts":[]}` {
		t.Fatalf("after reopening, SBOM = %q, want it preserved", got)
	}
}

func TestNewRejectsAnEmptyDirectory(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("New(\"\") = no error, want one")
	}
}

func TestSaveAndLoad(t *testing.T) {
	store := newStore(t)
	if store.Has(digestA) {
		t.Fatal("Has() = true on an empty cache, want false")
	}

	save(t, store, digestA, `{"artifacts":[]}`)

	if !store.Has(digestA) {
		t.Fatal("Has() = false after Commit, want true")
	}
	if got := load(t, store, digestA); got != `{"artifacts":[]}` {
		t.Fatalf("Open() = %q, want the written SBOM", got)
	}
}

// The file name is part of the ADR, and an operator has to recognise it on the volume.
func TestSaveUsesTheDocumentedFileName(t *testing.T) {
	dir := t.TempDir()
	save(t, mustNew(t, dir), digestA, "{}")

	if _, err := os.Stat(filepath.Join(dir, "sboms", "sha256_"+hexA+".json")); err != nil {
		t.Fatalf("sboms/sha256_<digest>.json missing: %v", err)
	}
}

func TestOpenReportsAMissingDigest(t *testing.T) {
	if _, err := newStore(t).Open(digestA); !errors.Is(err, ErrNotCached) {
		t.Fatalf("Open() = %v, want ErrNotCached", err)
	}
}

// An interrupted run must not leave something behind that the next run mistakes for a
// complete SBOM.
func TestUncommittedWriteStaysInvisible(t *testing.T) {
	store := newStore(t)
	w, err := store.Create(digestA)
	if err != nil {
		t.Fatalf("Create() = %v, want no error", err)
	}
	if _, err := io.WriteString(w, `{"artifa`); err != nil {
		t.Fatalf("Write() = %v, want no error", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v, want no error", err)
	}

	if store.Has(digestA) {
		t.Fatal("Has() = true for a discarded write, want false")
	}
	if _, err := store.Open(digestA); !errors.Is(err, ErrNotCached) {
		t.Fatalf("Open() = %v, want ErrNotCached", err)
	}
	if digests, err := store.Digests(); err != nil || len(digests) != 0 {
		t.Fatalf("Digests() = %v, %v, want none", digests, err)
	}
}

// A deferred Close after a successful Commit must not delete the entry.
func TestCloseAfterCommitKeepsTheEntry(t *testing.T) {
	store := newStore(t)
	w, err := store.Create(digestA)
	if err != nil {
		t.Fatalf("Create() = %v, want no error", err)
	}
	if _, err := io.WriteString(w, "{}"); err != nil {
		t.Fatalf("Write() = %v, want no error", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit() = %v, want no error", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() after Commit = %v, want no error", err)
	}
	if !store.Has(digestA) {
		t.Fatal("Has() = false after Commit and Close, want true")
	}
}

func TestWriteCommitsWhatTheFunctionWrote(t *testing.T) {
	store := newStore(t)
	if err := store.Write(digestA, func(w io.Writer) error {
		_, err := io.WriteString(w, `{"artifacts":[]}`)
		return err
	}); err != nil {
		t.Fatalf("Write() = %v, want no error", err)
	}
	if got := load(t, store, digestA); got != `{"artifacts":[]}` {
		t.Fatalf("Write() stored %q", got)
	}
}

// Whatever fn has already written is discarded when fn fails. Half an SBOM that a later run
// trusted would be worse than no SBOM at all, because nothing would ever re-catalogue it.
func TestWriteDiscardsThePartialEntryWhenTheFunctionFails(t *testing.T) {
	store := newStore(t)
	sentinel := errors.New("catalogue failed halfway")

	err := store.Write(digestA, func(w io.Writer) error {
		if _, err := io.WriteString(w, `{"artifa`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write() = %v, want the error fn returned", err)
	}
	if store.Has(digestA) {
		t.Fatal("Has() = true after a failed Write, want false")
	}
	if digests, err := store.Digests(); err != nil || len(digests) != 0 {
		t.Fatalf("Digests() = %v, %v, want none", digests, err)
	}
}

func TestWriteRejectsADigestThatIsNotOne(t *testing.T) {
	store := newStore(t)
	called := false
	err := store.Write("../../etc/passwd", func(io.Writer) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("Write() = nil, want an error for a digest that is not one")
	}
	// The guard has to come before anything is produced: this is what stops a hostile digest
	// arriving over the network from being catalogued at all.
	if called {
		t.Fatal("Write() called fn for an invalid digest")
	}
}

func TestDigests(t *testing.T) {
	store := newStore(t)
	save(t, store, digestA, "{}")
	save(t, store, digestB, "{}")

	got, err := store.Digests()
	if err != nil {
		t.Fatalf("Digests() = %v, want no error", err)
	}
	slices.Sort(got)
	if want := []string{digestA, digestB}; !slices.Equal(got, want) {
		t.Fatalf("Digests() = %v, want %v", got, want)
	}
}

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	store := mustNew(t, dir)
	save(t, store, digestA, "{}")
	save(t, store, digestB, "{}")

	// A leftover temporary file from a killed run, and a file that is none of our business.
	writeFile(t, filepath.Join(dir, sbomDir, "sha256_"+hexA+".json"+tempSuffix+"123"), "partial")
	writeFile(t, filepath.Join(dir, sbomDir, "README"), "not ours")

	removed, err := store.Prune(map[string]struct{}{digestA: {}})
	if err != nil {
		t.Fatalf("Prune() = %v, want no error", err)
	}
	if removed != 2 {
		t.Fatalf("Prune() removed %d, want 2 (the stale SBOM and the leftover)", removed)
	}
	if !store.Has(digestA) {
		t.Fatal("Prune() removed a digest that is still running")
	}
	if store.Has(digestB) {
		t.Fatal("Prune() kept a digest that stopped running")
	}
	if _, err := os.Stat(filepath.Join(dir, sbomDir, "README")); err != nil {
		t.Fatalf("Prune() touched a foreign file: %v", err)
	}
}

func TestPruneOnAnEmptyKeepSetClearsTheCache(t *testing.T) {
	store := newStore(t)
	save(t, store, digestA, "{}")

	if removed, err := store.Prune(nil); err != nil || removed != 1 {
		t.Fatalf("Prune(nil) = %d, %v, want 1, no error", removed, err)
	}
	if store.Has(digestA) {
		t.Fatal("Prune(nil) left an SBOM behind")
	}
}

// A digest reaches this package from a pod status, so anything that is not a plain digest has
// to be refused before it becomes a path.
func TestRejectsDigestsThatAreNotDigests(t *testing.T) {
	tests := []struct {
		name   string
		digest string
	}{
		{"empty", ""},
		{"no algorithm", hexA},
		{"unknown algorithm", "md5:" + hexA},
		{"too short", "sha256:1111"},
		{"upper case hex", "sha256:" + strings.Repeat("AB", 32)},
		{"path traversal", "sha256:../../etc/passwd"},
		{"separator in hex", "sha256:" + hexA[:32] + "/" + hexA[33:]},
		{"tagged reference", "registry.example/app:1.4.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newStore(t)
			if _, err := store.Create(tt.digest); err == nil {
				t.Fatalf("Create(%q) = no error, want one", tt.digest)
			}
			if _, err := store.Open(tt.digest); err == nil {
				t.Fatalf("Open(%q) = no error, want one", tt.digest)
			}
			if store.Has(tt.digest) {
				t.Fatalf("Has(%q) = true, want false", tt.digest)
			}
		})
	}
}

func TestHasRejectsAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	store := mustNew(t, dir)
	writeFile(t, filepath.Join(dir, sbomDir, "sha256_"+hexA+".json"), "")

	if store.Has(digestA) {
		t.Fatal("Has() = true for an empty file, want false so the digest is catalogued again")
	}
}

func mustNew(t *testing.T, dir string) *Store {
	t.Helper()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New(%s) = %v, want no error", dir, err)
	}
	return store
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) = %v, want no error", path, err)
	}
}
