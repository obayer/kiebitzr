package anchorelog

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/anchore/go-logger"
)

// record decodes the single JSON record written by fn.
func record(t *testing.T, fn func(l logger.Logger)) map[string]any {
	t.Helper()

	var buf bytes.Buffer
	fn(New(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: traceLevel}))))

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode %q: %v", buf.String(), err)
	}
	return got
}

func TestLevelsAndMessages(t *testing.T) {
	tests := []struct {
		name  string
		write func(l logger.Logger)
		level string
		msg   string
	}{
		{"error", func(l logger.Logger) { l.Error("boom") }, "ERROR", "boom"},
		{"errorf", func(l logger.Logger) { l.Errorf("boom %d", 2) }, "ERROR", "boom 2"},
		{"warn", func(l logger.Logger) { l.Warn("careful") }, "WARN", "careful"},
		{"warnf", func(l logger.Logger) { l.Warnf("%s missing", "db") }, "WARN", "db missing"},
		{"info", func(l logger.Logger) { l.Info("downloading") }, "INFO", "downloading"},
		{"infof", func(l logger.Logger) { l.Infof("%d images", 50) }, "INFO", "50 images"},
		{"debug", func(l logger.Logger) { l.Debug("detail") }, "DEBUG", "detail"},
		{"trace", func(l logger.Logger) { l.Trace("noisy") }, "DEBUG-4", "noisy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := record(t, tt.write)
			if got["level"] != tt.level {
				t.Errorf("level = %v, want %v", got["level"], tt.level)
			}
			if got["msg"] != tt.msg {
				t.Errorf("msg = %v, want %v", got["msg"], tt.msg)
			}
		})
	}
}

// Trace is below Debug so that the per-file output of the libraries stays off at the level a
// service runs at, while remaining reachable for someone who asks for it.
func TestTraceIsBelowDebug(t *testing.T) {
	var buf bytes.Buffer
	l := New(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	l.Trace("noisy")
	l.Debug("detail")

	if bytes.Contains(buf.Bytes(), []byte("noisy")) {
		t.Errorf("trace was written at debug level: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("detail")) {
		t.Errorf("debug was dropped at debug level: %s", buf.String())
	}
}

// The libraries pass key/value pairs, a Fields map, or both at once — and in the mixed case
// the pairs must not shift by one. This is the behaviour of their own adapter, mirrored.
func TestFields(t *testing.T) {
	tests := []struct {
		name   string
		fields []any
		want   map[string]any
	}{
		{
			name:   "pairs",
			fields: []any{"digest", "sha256:1234", "attempt", 2.0},
			want:   map[string]any{"digest": "sha256:1234", "attempt": 2.0},
		},
		{
			name:   "map",
			fields: []any{logger.Fields{"error": "no route to host"}},
			want:   map[string]any{"error": "no route to host"},
		},
		{
			name:   "a map between pairs",
			fields: []any{"from", "cache", logger.Fields{"built": "yesterday"}, "to", "update"},
			want:   map[string]any{"from": "cache", "built": "yesterday", "to": "update"},
		},
		{
			name:   "key that is not a string",
			fields: []any{7, "seven"},
			want:   map[string]any{"7": "seven"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := record(t, func(l logger.Logger) { l.WithFields(tt.fields...).Warn("message") })
			for key, want := range tt.want {
				if got[key] != want {
					t.Errorf("field %q = %v (%T), want %v (%T)", key, got[key], got[key], want, want)
				}
			}
		})
	}
}

// Nested returns a full logger, so a library can keep nesting; the fields have to survive it.
func TestNestedKeepsFields(t *testing.T) {
	got := record(t, func(l logger.Logger) {
		l.Nested("library", "grype").Nested("phase", "update").Info("downloading")
	})
	if got["library"] != "grype" || got["phase"] != "update" {
		t.Errorf("fields = %v, want both nested fields present", got)
	}
}
