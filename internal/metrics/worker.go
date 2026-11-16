package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Outcomes for kiebitzr_worker_images_total.
const (
	OutcomeCatalogued = "catalogued"
	OutcomeFailed     = "failed"
)

// WorkerExporter is the metric set of a cataloguing worker, and it deliberately shares nothing
// with Exporter.
//
// That separation is the point. A worker serving the matcher's metrics would publish
// kiebitzr_last_success_timestamp_seconds as 0 and kiebitzr_images as all zeroes — which reads
// exactly like a matcher that has never completed a run. Every KiebitzrNotScanning alert in
// the metrics runbook would then fire once per worker, and the one that matters would be lost
// among them. A worker reports what a worker knows: how many images it catalogued, and how
// many it could not.
type WorkerExporter struct {
	registry *prometheus.Registry
	images   *prometheus.CounterVec
}

// NewWorker returns the exporter of a worker process, with both series present from the start
// so an alert on an increase does not have to cope with a missing one.
func NewWorker() *WorkerExporter {
	e := &WorkerExporter{
		registry: prometheus.NewRegistry(),
		images: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kiebitzr_worker_images_total",
			Help: "Images this worker catalogued, by outcome.",
		}, []string{"outcome"}),
	}
	for _, outcome := range []string{OutcomeCatalogued, OutcomeFailed} {
		e.images.WithLabelValues(outcome)
	}
	e.registry.MustRegister(
		e.images,
		// A worker publishes this too: a pool where one pod lags behind the others is exactly
		// the case that is invisible otherwise, and it carries none of the matcher's state, so
		// it cannot make a worker look like a matcher that never finished a run.
		buildInfo(),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return e
}

// Handler serves this worker's registry and nothing else.
func (e *WorkerExporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	})
}

// Image counts one image this worker finished with, catalogued or failed.
func (e *WorkerExporter) Image(outcome string) {
	e.images.WithLabelValues(outcome).Inc()
}
