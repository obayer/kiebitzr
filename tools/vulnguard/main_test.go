package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stream builds a govulncheck JSON stream: concatenated objects, the way the scanner emits
// them.
func stream(objects ...string) string { return strings.Join(objects, "\n") }

const (
	osvCalled = `{"osv":{"id":"GO-1","summary":"panic on a crafted header"}}`
	osvQuiet  = `{"osv":{"id":"GO-2","summary":"memory exhaustion"}}`

	// A reachable finding's trace runs from the vulnerable symbol outwards to our own code,
	// so the module to report is the first frame, not the last.
	findingCalled = `{"finding":{"osv":"GO-1","trace":[
		{"module":"example.com/vulnerable","function":"Reader.Read"},
		{"module":"github.com/obayer/kiebitzr","function":"catalog.Catalogue"}]}}`
	findingUncalled = `{"finding":{"osv":"GO-2","fixed_version":"v1.2.7","trace":[
		{"module":"example.com/quiet"}]}}`
)

var today = time.Date(2026, time.November, 6, 0, 0, 0, 0, time.UTC)

func analyseOrFail(t *testing.T, raw string, exceptions []exception) report {
	t.Helper()
	rep, err := analyse(strings.NewReader(raw), exceptions, today)
	if err != nil {
		t.Fatalf("analyse() = %v, want no error", err)
	}
	return rep
}

func TestReachableVulnerabilityBlocks(t *testing.T) {
	rep := analyseOrFail(t, stream(osvCalled, findingCalled), nil)

	if len(rep.blocking) != 1 || rep.blocking[0].ID != "GO-1" {
		t.Fatalf("blocking = %+v, want GO-1", rep.blocking)
	}
	if rep.blocking[0].Summary != "panic on a crafted header" {
		t.Fatalf("summary = %q, want the one from the osv entry", rep.blocking[0].Summary)
	}
	// The vulnerable module, not the one that reaches it.
	if rep.blocking[0].Module != "example.com/vulnerable" {
		t.Fatalf("module = %q, want the module the vulnerability lives in", rep.blocking[0].Module)
	}
	if rep.blocking[0].Fixed != "" {
		t.Fatalf("fixed = %q, want empty for a vulnerability without a fix", rep.blocking[0].Fixed)
	}
	if err := rep.write(io.Discard); err == nil {
		t.Fatal("write() = no error, want the build to fail")
	}
}

// A vulnerability that is only present in the build, not reached, is reported and nothing
// more — that is govulncheck's own distinction and the reason this tool keeps it.
func TestUncalledVulnerabilityDoesNotBlock(t *testing.T) {
	rep := analyseOrFail(t, stream(osvQuiet, findingUncalled), nil)

	if len(rep.blocking) != 0 {
		t.Fatalf("blocking = %+v, want none", rep.blocking)
	}
	if len(rep.uncalled) != 1 || rep.uncalled[0].Fixed != "v1.2.7" {
		t.Fatalf("uncalled = %+v, want GO-2 fixed in v1.2.7", rep.uncalled)
	}
	if err := rep.write(io.Discard); err != nil {
		t.Fatalf("write() = %v, want no error", err)
	}
}

func TestAcceptedVulnerabilityPasses(t *testing.T) {
	rep := analyseOrFail(t, stream(osvCalled, findingCalled), []exception{{
		ID:     "GO-1",
		Reason: "no fix exists and the panic is contained",
		Review: "2026-12-15",
	}})

	if len(rep.blocking) != 0 || len(rep.problems) != 0 {
		t.Fatalf("blocking = %+v, problems = %v, want neither", rep.blocking, rep.problems)
	}
	if len(rep.accepted) != 1 || rep.accepted[0].ID != "GO-1" {
		t.Fatalf("accepted = %+v, want GO-1", rep.accepted)
	}
	if err := rep.write(io.Discard); err != nil {
		t.Fatalf("write() = %v, want no error", err)
	}
}

// The whole point of the review date: an exception stops working on its own.
func TestExpiredExceptionBlocks(t *testing.T) {
	rep := analyseOrFail(t, stream(osvCalled, findingCalled), []exception{{
		ID:     "GO-1",
		Reason: "accepted last month",
		Review: "2026-11-05",
	}})

	if len(rep.accepted) != 0 {
		t.Fatalf("accepted = %+v, want none once the review date has passed", rep.accepted)
	}
	if len(rep.problems) != 1 || !strings.Contains(rep.problems[0], "overdue") {
		t.Fatalf("problems = %v, want one about the overdue review", rep.problems)
	}
	if err := rep.write(io.Discard); err == nil {
		t.Fatal("write() = no error, want the build to fail")
	}
}

// An exception for something that is no longer reported is not diligence, it is clutter —
// and it would silently cover a future finding of the same id.
func TestStaleExceptionBlocks(t *testing.T) {
	rep := analyseOrFail(t, stream(osvQuiet, findingUncalled), []exception{{
		ID:     "GO-1",
		Reason: "fixed in the meantime",
		Review: "2026-12-15",
	}})

	if len(rep.problems) != 1 || !strings.Contains(rep.problems[0], "delete the exception") {
		t.Fatalf("problems = %v, want one asking for the exception to be deleted", rep.problems)
	}
}

// The review date is honoured up to and including the day itself.
func TestExceptionIsValidOnItsReviewDay(t *testing.T) {
	rep := analyseOrFail(t, stream(osvCalled, findingCalled), []exception{{
		ID:     "GO-1",
		Reason: "still being looked at",
		Review: today.Format(time.DateOnly),
	}})

	if len(rep.accepted) != 1 || len(rep.problems) != 0 {
		t.Fatalf("accepted = %+v, problems = %v, want it accepted on the review day",
			rep.accepted, rep.problems)
	}
}

// govulncheck reports one id several times, once per trace. A single reachable trace makes
// the whole id reachable.
func TestOneReachableTraceIsEnough(t *testing.T) {
	alsoUncalled := `{"finding":{"osv":"GO-1","trace":[{"module":"example.com/vulnerable"}]}}`
	rep := analyseOrFail(t, stream(osvCalled, alsoUncalled, findingCalled), nil)

	if len(rep.blocking) != 1 {
		t.Fatalf("blocking = %+v, want GO-1 once", rep.blocking)
	}
	if len(rep.uncalled) != 0 {
		t.Fatalf("uncalled = %+v, want none: the id is reachable", rep.uncalled)
	}
}

func TestEmptyStreamPasses(t *testing.T) {
	rep := analyseOrFail(t, "", nil)
	if err := rep.write(io.Discard); err != nil {
		t.Fatalf("write() = %v, want no error for a clean scan", err)
	}
}

func TestLoadExceptions(t *testing.T) {
	path := writeFile(t, `
accepted:
  - id: GO-2026-6905
    module: github.com/example/unmaintained
    review: 2026-12-15
    reason: >
      No fix exists upstream and the failure is contained.
`)
	exceptions, err := loadExceptions(path)
	if err != nil {
		t.Fatalf("loadExceptions() = %v, want no error", err)
	}
	if len(exceptions) != 1 || exceptions[0].ID != "GO-2026-6905" {
		t.Fatalf("loadExceptions() = %+v, want one entry for GO-2026-6905", exceptions)
	}
}

func TestLoadExceptionsWithoutAFile(t *testing.T) {
	exceptions, err := loadExceptions(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil || exceptions != nil {
		t.Fatalf("loadExceptions(absent) = %+v, %v, want none and no error", exceptions, err)
	}
}

// An exception has to carry its justification, or the file is just a mute list.
func TestLoadExceptionsRejects(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"no id", "accepted:\n  - reason: because\n    review: 2026-12-15\n"},
		{"no reason", "accepted:\n  - id: GO-1\n    review: 2026-12-15\n"},
		{"blank reason", "accepted:\n  - id: GO-1\n    reason: \"  \"\n    review: 2026-12-15\n"},
		{"no review date", "accepted:\n  - id: GO-1\n    reason: because\n"},
		{"review date is not a date", "accepted:\n  - id: GO-1\n    reason: because\n    review: soon\n"},
		{"review date in the wrong format", "accepted:\n  - id: GO-1\n    reason: because\n    review: 15.12.2026\n"},
		{"unknown field", "accepted:\n  - id: GO-1\n    reason: because\n    review: 2026-12-15\n    forever: true\n"},
		{"not yaml", "accepted: [unclosed\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := loadExceptions(writeFile(t, tt.content)); err == nil {
				t.Fatalf("loadExceptions(%q) = no error, want one", tt.content)
			}
		})
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnguard.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimPrefix(content, "\n")), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v, want no error", err)
	}
	return path
}
