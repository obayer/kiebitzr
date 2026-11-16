package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/obayer/kiebitzr/internal/metrics"
)

func newSerial(t *testing.T) (*Serial, *fakeProducer, *fakeStore) {
	t.Helper()
	producer := &fakeProducer{errs: map[string]error{}}
	store := &fakeStore{sboms: map[string]string{}, openErrs: map[string]error{}}
	return NewSerial(producer, store, slog.New(slog.DiscardHandler)), producer, store
}

func work(digests ...string) []Work {
	out := make([]Work, 0, len(digests))
	for _, digest := range digests {
		out = append(out, Work{Digest: digest, Ref: "registry.example/app@" + digest})
	}
	return out
}

func TestSerialCataloguesEverythingItIsGiven(t *testing.T) {
	stage, producer, store := newSerial(t)

	report := stage.Catalogue(context.Background(), work(digestA, digestB))

	if report.Scanned != 2 {
		t.Fatalf("Scanned = %d, want 2", report.Scanned)
	}
	if len(report.Failures) != 0 || len(report.Pending) != 0 {
		t.Fatalf("report = %+v, want no failures and nothing pending", report)
	}
	if len(producer.called) != 2 {
		t.Fatalf("produced %v, want both digests", producer.called)
	}
	if !store.Has(digestA) || !store.Has(digestB) {
		t.Fatal("the SBOMs were not committed to the store")
	}
}

// Out of budget is not a failure. The digests that were not reached say nothing about those
// images, and the next run picks them up because what was catalogued stays in the cache.
func TestSerialReportsWhatItDidNotReachAsPending(t *testing.T) {
	_, _, store := newSerial(t)

	// The budget expires while the first digest is being catalogued, which from in here is
	// exactly a cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	stage := NewSerial(producerFunc(func(_ context.Context, _ string, w io.Writer) error {
		cancel()
		_, err := io.WriteString(w, "{}")
		return err
	}), store, slog.New(slog.DiscardHandler))

	report := stage.Catalogue(ctx, work(digestA, digestB))

	if report.Scanned != 1 {
		t.Fatalf("Scanned = %d, want the one digest that finished", report.Scanned)
	}
	if len(report.Pending) != 1 || report.Pending[0] != digestB {
		t.Fatalf("Pending = %v, want only %s", report.Pending, digestB)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("Failures = %+v, want none: running out of time is not a failure", report.Failures)
	}
	// What was catalogued is kept, so the next run starts from there.
	if !store.Has(digestA) {
		t.Fatal("the SBOM catalogued before the budget ran out was not kept")
	}
}

// One image that cannot be catalogued must not cost the others, and the reason has to
// distinguish an image that could not be reached from one whose contents broke the cataloguer.
func TestSerialSeparatesUnreachableFromBrokenImages(t *testing.T) {
	stage, producer, _ := newSerial(t)
	producer.errs[digestA] = fmt.Errorf("resolve: %w", unreachableImageError{})
	producer.errs[digestB] = errors.New("malformed package database")

	report := stage.Catalogue(context.Background(), work(digestA, digestB))

	if report.Scanned != 0 {
		t.Fatalf("Scanned = %d, want 0", report.Scanned)
	}
	want := []metrics.Failure{
		{Digest: digestA, Reason: metrics.ReasonUnreachable},
		{Digest: digestB, Reason: metrics.ReasonCatalogue},
	}
	if len(report.Failures) != len(want) {
		t.Fatalf("Failures = %+v, want %+v", report.Failures, want)
	}
	for i, failure := range report.Failures {
		if failure != want[i] {
			t.Fatalf("Failures[%d] = %+v, want %+v", i, failure, want[i])
		}
	}
}

// A store that cannot be written is reported per digest, not as a reason to stop: a full
// volume costs the findings of that image, not of the cluster.
func TestSerialReportsAStoreThatCannotBeWritten(t *testing.T) {
	stage, _, store := newSerial(t)
	store.writeErr = errors.New("no space left on device")

	report := stage.Catalogue(context.Background(), work(digestA))

	if report.Scanned != 0 || len(report.Failures) != 1 {
		t.Fatalf("report = %+v, want one failure and nothing scanned", report)
	}
	if report.Failures[0].Reason != metrics.ReasonCatalogue {
		t.Fatalf("reason = %q, want %q", report.Failures[0].Reason, metrics.ReasonCatalogue)
	}
}

// producerFunc adapts a function to Producer.
type producerFunc func(ctx context.Context, ref string, w io.Writer) error

func (f producerFunc) CatalogueTo(ctx context.Context, ref string, w io.Writer) error {
	return f(ctx, ref, w)
}
