package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obayer/kiebitzr/internal/metrics"
)

func TestHealthz(t *testing.T) {
	tests := []struct {
		method string
		want   int
	}{
		{http.MethodGet, http.StatusOK},
		{http.MethodPost, http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux().ServeHTTP(rec, httptest.NewRequest(tt.method, "/healthz", nil))
			if rec.Code != tt.want {
				t.Fatalf("%s /healthz = %d, want %d", tt.method, rec.Code, tt.want)
			}
		})
	}
}

func TestMetrics(t *testing.T) {
	rec := httptest.NewRecorder()
	mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "kiebitzr_last_success_timestamp_seconds") {
		t.Fatalf("GET /metrics does not serve the exporter:\n%s", body)
	}
}

// A worker must not serve the matcher's metric set. It would publish
// kiebitzr_last_success_timestamp_seconds as 0 and kiebitzr_images as all zeroes, which reads
// exactly like a matcher that has never completed a run — so KiebitzrNotScanning would fire
// once per worker and bury the one case that matters.
func TestWorkerMetricsAreNotTheMatchersMetrics(t *testing.T) {
	rec := httptest.NewRecorder()
	newMux(metrics.NewWorker().Handler()).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{
		"kiebitzr_last_success_timestamp_seconds",
		"kiebitzr_images",
		"kiebitzr_db_built_timestamp_seconds",
		"kiebitzr_vulnerability",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("a worker serves %s, which makes it look like a broken matcher:\n%s",
				forbidden, body)
		}
	}
	if !strings.Contains(body, "kiebitzr_worker_images_total") {
		t.Fatalf("a worker does not report what it catalogued:\n%s", body)
	}
}

func mux() *http.ServeMux { return newMux(metrics.New().Handler()) }
