// Command vulnguard runs govulncheck and decides what its findings mean for this repository.
//
// govulncheck has no way to accept a finding, and it needs one: a vulnerability in a
// transitive dependency may have no fix at all, and a gate that is red forever is a gate
// nobody reads. So every vulnerability whose code this module actually calls fails the build,
// unless it is listed in the exceptions file with a reason and a review date.
//
// Two further rules keep an exception from becoming a hole. An exception whose review date
// has passed fails the build, so somebody has to look again. An exception that no longer
// matches any finding fails as well, so the file cannot fill up with entries that only look
// like diligence.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "vulnguard: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vulnguard", flag.ContinueOnError)
	fs.SetOutput(out)
	exceptionsPath := fs.String("exceptions", ".vulnguard.yaml", "path to the exceptions file")
	pattern := fs.String("pattern", "./...", "package pattern to scan")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	exceptions, err := loadExceptions(*exceptionsPath)
	if err != nil {
		return err
	}

	stream, err := govulncheck(ctx, *pattern)
	if err != nil {
		return err
	}

	report, err := analyse(strings.NewReader(stream), exceptions, time.Now())
	if err != nil {
		return err
	}
	return report.write(out)
}

// govulncheck runs the scanner and returns its JSON stream. In JSON mode govulncheck always
// exits 0 and leaves the verdict to its caller, which is exactly what this command is for.
func govulncheck(ctx context.Context, pattern string) (string, error) {
	var stdout, stderr strings.Builder
	cmd := exec.CommandContext(ctx, "govulncheck", "-format", "json", pattern) //nolint:gosec // fixed command, pattern is operator input
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("run govulncheck: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// exception is one accepted vulnerability.
type exception struct {
	ID     string `yaml:"id"`
	Module string `yaml:"module"`
	Reason string `yaml:"reason"`
	Review string `yaml:"review"`
}

type exceptionsFile struct {
	Accepted []exception `yaml:"accepted"`
}

func loadExceptions(path string) ([]exception, error) {
	content, err := os.ReadFile(path) //nolint:gosec // repository-local configuration
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var file exceptionsFile
	decoder := yaml.NewDecoder(strings.NewReader(string(content)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	for i, accepted := range file.Accepted {
		switch {
		case accepted.ID == "":
			return nil, fmt.Errorf("%s: entry %d has no id", path, i+1)
		case strings.TrimSpace(accepted.Reason) == "":
			return nil, fmt.Errorf("%s: %s has no reason", path, accepted.ID)
		case accepted.Review == "":
			return nil, fmt.Errorf("%s: %s has no review date", path, accepted.ID)
		}
		if _, err := time.Parse(time.DateOnly, accepted.Review); err != nil {
			return nil, fmt.Errorf("%s: %s has review date %q, want YYYY-MM-DD",
				path, accepted.ID, accepted.Review)
		}
	}
	return file.Accepted, nil
}

// The subset of govulncheck's JSON stream this command needs.
type message struct {
	OSV     *osv     `json:"osv"`
	Finding *finding `json:"finding"`
}

type osv struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []frame `json:"trace"`
}

type frame struct {
	Module   string `json:"module"`
	Function string `json:"function"`
}

// called reports whether this finding names a function, which is what distinguishes code that
// is actually reached from a module that merely appears in the build.
func (f finding) called() bool {
	return len(f.Trace) > 0 && f.Trace[0].Function != ""
}

// module is the module the vulnerability lives in. govulncheck orders a trace from the
// vulnerable symbol outwards to the code that reaches it, so that is the first frame — the
// last one is this module itself.
func (f finding) module() string {
	if len(f.Trace) == 0 {
		return "unknown"
	}
	return f.Trace[0].Module
}

// vulnerability is one OSV entry as it affects this module.
type vulnerability struct {
	ID      string
	Module  string
	Fixed   string
	Summary string
}

type report struct {
	// blocking are called vulnerabilities without an exception.
	blocking []vulnerability
	// accepted are called vulnerabilities covered by a valid exception.
	accepted []vulnerability
	// uncalled are present in the build but not reached.
	uncalled []vulnerability
	// problems are faults in the exceptions file itself: expired or no longer needed.
	problems []string
}

func analyse(stream io.Reader, exceptions []exception, now time.Time) (report, error) {
	summaries := make(map[string]string)
	called := make(map[string]vulnerability)
	uncalled := make(map[string]vulnerability)

	decoder := json.NewDecoder(stream)
	for {
		var msg message
		if err := decoder.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return report{}, fmt.Errorf("read govulncheck output: %w", err)
		}
		switch {
		case msg.OSV != nil:
			summaries[msg.OSV.ID] = msg.OSV.Summary
		case msg.Finding != nil:
			found := vulnerability{
				ID:     msg.Finding.OSV,
				Module: msg.Finding.module(),
				Fixed:  msg.Finding.FixedVersion,
			}
			if msg.Finding.called() {
				called[found.ID] = found
				continue
			}
			if _, alsoCalled := called[found.ID]; !alsoCalled {
				uncalled[found.ID] = found
			}
		}
	}

	var rep report
	for id, found := range called {
		found.Summary = summaries[id]
		index := slices.IndexFunc(exceptions, func(e exception) bool { return e.ID == id })
		if index < 0 {
			rep.blocking = append(rep.blocking, found)
			continue
		}

		accepted := exceptions[index]
		review, err := time.Parse(time.DateOnly, accepted.Review)
		if err != nil {
			return report{}, fmt.Errorf("exception %s: %w", id, err)
		}
		if now.After(review) {
			rep.problems = append(rep.problems, fmt.Sprintf(
				"%s was accepted until %s — the exception is overdue for review", id, accepted.Review))
			continue
		}
		rep.accepted = append(rep.accepted, found)
	}

	for id, found := range uncalled {
		if _, isCalled := called[id]; isCalled {
			continue
		}
		found.Summary = summaries[id]
		rep.uncalled = append(rep.uncalled, found)
	}

	for _, accepted := range exceptions {
		if _, matched := called[accepted.ID]; !matched {
			rep.problems = append(rep.problems,
				accepted.ID+" is accepted but no longer reported — delete the exception")
		}
	}

	sortByID(rep.blocking)
	sortByID(rep.accepted)
	sortByID(rep.uncalled)
	slices.Sort(rep.problems)
	return rep, nil
}

func sortByID(found []vulnerability) {
	slices.SortFunc(found, func(a, b vulnerability) int { return strings.Compare(a.ID, b.ID) })
}

// write prints the report and returns an error if the build must fail.
func (r report) write(out io.Writer) error {
	if _, err := io.WriteString(out, strings.Join(r.lines(), "\n")+"\n"); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return r.verdict()
}

// lines is the report as an operator reads it: what is present, what was accepted and, last,
// what has to be dealt with.
func (r report) lines() []string {
	lines := make([]string, 0, len(r.uncalled)+len(r.accepted)+len(r.blocking)+len(r.problems)+1)
	for _, found := range r.uncalled {
		lines = append(lines, fmt.Sprintf("present, not called: %s %s (%s)",
			found.ID, found.Module, fixedText(found)))
	}
	for _, found := range r.accepted {
		lines = append(lines, fmt.Sprintf("accepted:            %s %s (%s) — %s",
			found.ID, found.Module, fixedText(found), found.Summary))
	}
	for _, found := range r.blocking {
		lines = append(lines, fmt.Sprintf("REACHABLE:           %s %s (%s) — %s",
			found.ID, found.Module, fixedText(found), found.Summary))
	}
	for _, problem := range r.problems {
		lines = append(lines, "EXCEPTION:           "+problem)
	}
	if len(r.blocking) == 0 && len(r.problems) == 0 {
		lines = append(lines, fmt.Sprintf(
			"no reachable vulnerabilities (%d accepted, %d present but not called)",
			len(r.accepted), len(r.uncalled)))
	}
	return lines
}

// verdict is the reason the build fails, or nil.
func (r report) verdict() error {
	switch {
	case len(r.blocking) > 0 && len(r.problems) > 0:
		return fmt.Errorf("%d reachable vulnerabilities without an exception, %d exceptions to fix",
			len(r.blocking), len(r.problems))
	case len(r.blocking) > 0:
		return fmt.Errorf("%d reachable vulnerabilities without an exception", len(r.blocking))
	case len(r.problems) > 0:
		return fmt.Errorf("%d exceptions to fix", len(r.problems))
	}
	return nil
}

func fixedText(found vulnerability) string {
	if found.Fixed == "" {
		return "no fix"
	}
	return "fixed in " + found.Fixed
}
