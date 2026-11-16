// Package anchorelog puts what Syft, Grype and Stereoscope have to say into this process's
// log. Each of them keeps a package-level logger that discards everything until it is set,
// so without this adapter the libraries are mute — and they are the part of this service
// that talks to registries, unpacks images and downloads the vulnerability database, which
// is exactly where the interesting failures are.
//
// The need is not theoretical. Grype reports a failed database update through its logger and
// then returns the state the database is in; with no logger, an operator saw "database does
// not exist" and nothing about the cause (ADR 0001 keeps the libraries as libraries, so there
// is no CLI to fall back on). A download of several gigabytes also announced itself nowhere,
// which made a working run indistinguishable from a hung one.
package anchorelog

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/anchore/go-logger"
)

// traceLevel sits below slog.LevelDebug. The libraries trace per package and per file, which
// is far too much for a service log, so it stays off unless a handler is deliberately set
// that low — rather than being dropped here, where it could not be turned back on.
const traceLevel = slog.LevelDebug - 4

// New adapts log to the logger interface the Anchore libraries accept.
//
// This package deliberately installs nothing itself. Syft and Stereoscope stay behind
// internal/catalog and Grype behind internal/vulndb, so each of them wires its own library
// through its own SetLogger and the rest of the service keeps compiling without any of them.
func New(log *slog.Logger) logger.Logger {
	return &adapter{log: log}
}

type adapter struct {
	log *slog.Logger
}

var _ logger.Logger = (*adapter)(nil)

// Errorf logs a formatted message at error level.
func (a *adapter) Errorf(format string, args ...any) {
	a.emit(slog.LevelError, fmt.Sprintf(format, args...))
}

// Error logs a message at error level.
func (a *adapter) Error(args ...any) { a.emit(slog.LevelError, fmt.Sprint(args...)) }

// Warnf logs a formatted message at warning level.
func (a *adapter) Warnf(format string, args ...any) {
	a.emit(slog.LevelWarn, fmt.Sprintf(format, args...))
}

// Warn logs a message at warning level.
func (a *adapter) Warn(args ...any) { a.emit(slog.LevelWarn, fmt.Sprint(args...)) }

// Infof logs a formatted message at info level.
func (a *adapter) Infof(format string, args ...any) {
	a.emit(slog.LevelInfo, fmt.Sprintf(format, args...))
}

// Info logs a message at info level.
func (a *adapter) Info(args ...any) { a.emit(slog.LevelInfo, fmt.Sprint(args...)) }

// Debugf logs a formatted message at debug level.
func (a *adapter) Debugf(format string, args ...any) {
	a.emit(slog.LevelDebug, fmt.Sprintf(format, args...))
}

// Debug logs a message at debug level.
func (a *adapter) Debug(args ...any) { a.emit(slog.LevelDebug, fmt.Sprint(args...)) }

// Tracef logs a formatted message below debug level.
func (a *adapter) Tracef(format string, args ...any) {
	a.emit(traceLevel, fmt.Sprintf(format, args...))
}

// Trace logs a message below debug level.
func (a *adapter) Trace(args ...any) { a.emit(traceLevel, fmt.Sprint(args...)) }

// WithFields returns a message logger carrying the given fields.
func (a *adapter) WithFields(fields ...any) logger.MessageLogger {
	return &adapter{log: a.log.With(attrs(fields...)...)}
}

// Nested returns a full logger carrying the given fields, so a library can nest further.
// It differs from WithFields only in its return type: this adapter has no state beyond
// the fields themselves.
func (a *adapter) Nested(fields ...any) logger.Logger {
	return &adapter{log: a.log.With(attrs(fields...)...)}
}

// emit writes one record. The libraries log from their own goroutines and hand over no
// context, so there is none to pass on; slog wants one, and Background is the honest answer
// rather than inventing a cancellation that does not exist.
func (a *adapter) emit(level slog.Level, msg string) {
	//nolint:sloglint // forwarding a library's own message is the point; it cannot be a literal
	a.log.Log(context.Background(), level, msg)
}

// attrs reads fields the way the Anchore libraries write them: a logger.Fields map may appear
// at any position, and everything else is alternating key and value. Following their reading
// exactly is what keeps the pairs from shifting by one when a map is passed alongside them —
// the offset below is why, and it mirrors the libraries' own adapter.
//
// Map keys are sorted so that a record is the same from one run to the next.
func attrs(fields ...any) []any {
	out := make([]any, 0, len(fields))
	offset := 0
	for i, value := range fields {
		if m, ok := value.(logger.Fields); ok {
			for _, key := range slices.Sorted(maps.Keys(m)) {
				out = append(out, key, m[key])
			}
			offset++
			continue
		}
		if (i-offset)%2 != 0 {
			out = append(out, name(fields[i-1]), value)
		}
	}
	return out
}

// name is the attribute key for whatever was passed as one. Anything that is not a string is
// rendered rather than dropped: a malformed pair should still show up in the log.
func name(key any) string {
	if s, ok := key.(string); ok {
		return s
	}
	return fmt.Sprint(key)
}
