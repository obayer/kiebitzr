// Package cache is the digest-addressed store for SBOMs. A digest that has an SBOM is never
// catalogued again, and SBOMs of digests that stopped running are deleted. The whole
// directory is rebuildable: losing it costs one slow run, never data (ADR 0001).
package cache

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Layout of the cache directory. The vulnerability database lives next to the SBOMs, so one
// mounted volume holds everything that is expensive to rebuild.
const (
	sbomDir     = "sboms"
	databaseDir = "db"
	sbomSuffix  = ".json"
	tempSuffix  = ".tmp"
)

// dirMode is private to this service; nothing else reads the cache.
const dirMode = 0o700

// ErrNotCached is returned when a digest has no SBOM.
var ErrNotCached = errors.New("digest not in cache")

// Store is a cache directory. It is safe for a single process; two processes must not share
// one directory.
type Store struct {
	dir string
}

// New prepares the cache directory and returns the store. It creates the directory tree if
// it is missing, which is the normal case on a fresh volume.
func New(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("cache directory must not be empty")
	}
	for _, sub := range []string{sbomDir, databaseDir} {
		if err := os.MkdirAll(filepath.Join(dir, sub), dirMode); err != nil {
			return nil, fmt.Errorf("prepare cache directory: %w", err)
		}
	}
	return &Store{dir: dir}, nil
}

// DatabaseDir is where the vulnerability database is kept.
func (s *Store) DatabaseDir() string { return filepath.Join(s.dir, databaseDir) }

// Has reports whether the digest already has an SBOM. An unreadable entry counts as absent,
// so a damaged cache leads to re-cataloguing rather than to an error.
func (s *Store) Has(digest string) bool {
	path, err := s.path(digest)
	if err != nil {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

// Open returns the cached SBOM of a digest. The caller closes it. It is seekable because the
// matcher hands the reader to Grype, which rewinds it while sniffing the SBOM format.
func (s *Store) Open(digest string) (io.ReadSeekCloser, error) {
	path, err := s.path(digest)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // path is built from a validated digest
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotCached, digest)
	}
	if err != nil {
		return nil, fmt.Errorf("open cached sbom: %w", err)
	}
	return f, nil
}

// Create returns a writer for the SBOM of a digest. The entry becomes visible only when
// Commit succeeds, so an interrupted run never leaves a truncated SBOM that a later run
// would trust.
func (s *Store) Create(digest string) (*Writer, error) {
	path, err := s.path(digest)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+tempSuffix)
	if err != nil {
		return nil, fmt.Errorf("create cached sbom: %w", err)
	}
	return &Writer{file: f, final: path}, nil
}

// Write stores the SBOM of a digest, as whatever fn writes to the writer it is handed. The
// entry becomes visible only once fn has returned without error and the commit succeeded, so
// neither a failed write nor a cancelled one leaves a truncated SBOM behind.
//
// It exists so that the two ways an SBOM can arrive — produced here from an image, or received
// from a worker over the network — commit through the same path. Neither caller sees the
// temporary file or has to remember the order of Commit and Close.
func (s *Store) Write(digest string, fn func(io.Writer) error) error {
	w, err := s.Create(digest)
	if err != nil {
		return err
	}
	defer func() { _ = w.Close() }()

	if err := fn(w); err != nil {
		return err
	}
	return w.Commit()
}

// Digests lists the digests that have an SBOM. Files that do not belong to the layout are
// ignored rather than reported: the cache is allowed to contain a leftover temporary file.
func (s *Store) Digests() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, sbomDir))
	if err != nil {
		return nil, fmt.Errorf("read cache directory: %w", err)
	}
	digests := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if digest, ok := digestFromName(entry.Name()); ok {
			digests = append(digests, digest)
		}
	}
	return digests, nil
}

// Prune deletes the SBOMs of digests that are not in keep, and any leftover temporary file.
// It returns how many entries it removed. A digest that is still running is never touched.
func (s *Store) Prune(keep map[string]struct{}) (int, error) {
	dir := filepath.Join(s.dir, sbomDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read cache directory: %w", err)
	}

	removed := 0
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		digest, ok := digestFromName(entry.Name())
		if ok {
			if _, wanted := keep[digest]; wanted {
				continue
			}
		} else if !strings.Contains(entry.Name(), tempSuffix) {
			// Not an SBOM and not our leftover: leave it alone.
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			errs = append(errs, fmt.Errorf("prune %s: %w", entry.Name(), err))
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

// path turns a digest into its file name, `sboms/sha256_<hex>.json`. The digest is validated
// here, which is also what keeps a hostile imageID from escaping the cache directory.
func (s *Store) path(digest string) (string, error) {
	alg, hex, ok := splitDigest(digest)
	if !ok {
		return "", fmt.Errorf("not a usable digest: %q", digest)
	}
	return filepath.Join(s.dir, sbomDir, alg+"_"+hex+sbomSuffix), nil
}

// digestFromName is the inverse of path for one file name.
func digestFromName(name string) (string, bool) {
	base, ok := strings.CutSuffix(name, sbomSuffix)
	if !ok {
		return "", false
	}
	alg, hex, found := strings.Cut(base, "_")
	if !found {
		return "", false
	}
	digest := alg + ":" + hex
	if _, _, ok := splitDigest(digest); !ok {
		return "", false
	}
	return digest, true
}

// splitDigest accepts `<algorithm>:<lowercase hex>` and nothing else — no path separators, no
// upper case, no unknown algorithm.
func splitDigest(digest string) (alg, hex string, ok bool) {
	alg, hex, found := strings.Cut(digest, ":")
	if !found {
		return "", "", false
	}
	var want int
	switch alg {
	case "sha256":
		want = 64
	case "sha512":
		want = 128
	default:
		return "", "", false
	}
	if len(hex) != want {
		return "", "", false
	}
	for _, r := range hex {
		if !isLowerHex(r) {
			return "", "", false
		}
	}
	return alg, hex, true
}

func isLowerHex(r rune) bool {
	return '0' <= r && r <= '9' || 'a' <= r && r <= 'f'
}

// Writer writes one SBOM into the cache.
type Writer struct {
	file      *os.File
	final     string
	committed bool
}

// Write appends to the pending entry.
func (w *Writer) Write(p []byte) (int, error) {
	n, err := w.file.Write(p)
	if err != nil {
		return n, fmt.Errorf("write cached sbom: %w", err)
	}
	return n, nil
}

// Commit flushes the entry to disk and publishes it under its digest.
func (w *Writer) Commit() error {
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("flush cached sbom: %w", err)
	}
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close cached sbom: %w", err)
	}
	if err := os.Rename(w.file.Name(), w.final); err != nil {
		return fmt.Errorf("publish cached sbom: %w", err)
	}
	w.committed = true
	return nil
}

// Close discards an entry that was not committed. It is safe to call after Commit, so a
// deferred Close is always correct.
func (w *Writer) Close() error {
	if w.committed {
		return nil
	}
	err := w.file.Close()
	if rmErr := os.Remove(w.file.Name()); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		err = errors.Join(err, rmErr)
	}
	if err != nil {
		return fmt.Errorf("discard pending sbom: %w", err)
	}
	return nil
}
