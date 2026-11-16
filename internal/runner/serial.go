package runner

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/obayer/kiebitzr/internal/metrics"
)

// Producer turns one image reference into an SBOM, writing it to w. internal/catalog
// implements it; keeping it an interface is what holds Syft out of this package, which the
// depguard rule in .golangci.yaml enforces.
type Producer interface {
	CatalogueTo(ctx context.Context, ref string, w io.Writer) error
}

// SBOMWriter commits an SBOM under its digest, atomically. internal/cache implements it.
type SBOMWriter interface {
	Write(digest string, fn func(io.Writer) error) error
}

// Serial catalogues in this process, one image at a time. It is the stage a single-pod
// installation uses and the behaviour ADR 0001 describes — one image at a time on purpose,
// because cataloguing in parallel multiplies peak memory.
type Serial struct {
	producer Producer
	store    SBOMWriter
	log      *slog.Logger
}

// NewSerial returns the in-process cataloguing stage.
func NewSerial(producer Producer, store SBOMWriter, log *slog.Logger) *Serial {
	return &Serial{producer: producer, store: store, log: log}
}

// Catalogue works through the list in order until it is done or out of time. Everything it did
// not reach is pending rather than failed: running out of budget says nothing about those
// images, and the next run picks them up because the SBOMs it did write stay in the cache.
func (s *Serial) Catalogue(ctx context.Context, work []Work) Report {
	var report Report
	for i, item := range work {
		if ctx.Err() != nil {
			for _, left := range work[i:] {
				report.Pending = append(report.Pending, left.Digest)
			}
			return report
		}

		err := s.store.Write(item.Digest, func(w io.Writer) error {
			return s.producer.CatalogueTo(ctx, item.Ref, w)
		})
		if err != nil {
			reason := CatalogueReason(err)
			report.Failures = append(report.Failures,
				metrics.Failure{Digest: item.Digest, Reason: reason})
			s.log.Warn("image failed", "digest", item.Digest, "reason", reason, "err", err)
			continue
		}
		report.Scanned++
	}
	return report
}

// resolveFailure is implemented by an error that means the image could not be reached for the
// configured platform. It is matched structurally so this package stays free of the scanner
// libraries (see the depguard rule in .golangci.yaml).
type resolveFailure interface {
	ResolveFailed() bool
}

// CatalogueReason separates "could not reach the image" from "could not catalogue it". The
// first is usually a wrong platform, a missing credential or an image that was never pushed;
// the second is a problem with the image's contents. An operator needs to know which.
//
// It is exported because a worker has to make the same judgement in its own process: the error
// type does not survive the trip to the matcher, so the reason travels as a string and both
// sides have to derive it the same way (ADR 0009).
func CatalogueReason(err error) string {
	var failure resolveFailure
	if errors.As(err, &failure) && failure.ResolveFailed() {
		return metrics.ReasonUnreachable
	}
	return metrics.ReasonCatalogue
}
