package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// fakeGit answers the three commands the tool runs. history is what `git log` returns; empty
// history means HEAD does not resolve, which is a repository without a commit.
type fakeGit struct {
	author    string
	committer string
	history   []string
}

func (f fakeGit) run(args ...string) (string, error) {
	switch {
	case args[0] == "var" && args[1] == "GIT_AUTHOR_IDENT":
		return "A Name <" + f.author + "> 1763200000 +0100", nil
	case args[0] == "var" && args[1] == "GIT_COMMITTER_IDENT":
		committer := f.committer
		if committer == "" {
			committer = f.author
		}
		return "A Name <" + committer + "> 1763200000 +0100", nil
	case args[0] == "rev-parse":
		if len(f.history) == 0 {
			return "", errors.New("fatal: Needed a single revision")
		}
		return "deadbeef", nil
	case args[0] == "log":
		return strings.Join(f.history, "\n"), nil
	}
	return "", errors.New("unexpected git " + strings.Join(args, " "))
}

const mine = "1+user@users.noreply.github.com"

func TestKnownAddressPasses(t *testing.T) {
	g := fakeGit{author: mine, history: []string{mine, mine}}
	if err := run(io.Discard, false, g.run); err != nil {
		t.Fatalf("run() = %v, want nil", err)
	}
}

func TestAddressNewToTheHistoryIsRefused(t *testing.T) {
	g := fakeGit{author: "user@employer.example", history: []string{mine}}
	err := run(io.Discard, false, g.run)
	if err == nil {
		t.Fatal("run() = nil, want a refusal")
	}
	// The hook's output is all the author sees, so the message has to carry the address, the
	// remedy and the override.
	for _, want := range []string{"user@employer.example", "git config user.email", allowNewEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q:\n%v", want, err)
		}
	}
}

// The override is what makes a first contribution possible without a policy file naming
// anybody.
func TestNewAddressPassesWhenConfirmed(t *testing.T) {
	g := fakeGit{author: "newcomer@example.test", history: []string{mine}}
	var out strings.Builder
	if err := run(&out, true, g.run); err != nil {
		t.Fatalf("run() = %v, want nil with the override set", err)
	}
	if !strings.Contains(out.String(), "new to this repository") {
		t.Errorf("the override passed silently:\n%s", out.String())
	}
}

// A rebase or a cherry-pick keeps the author and replaces the committer. Checking the author
// alone would let exactly that case through.
func TestCommitterIsCheckedToo(t *testing.T) {
	g := fakeGit{author: mine, committer: "user@employer.example", history: []string{mine}}
	err := run(io.Discard, false, g.run)
	if err == nil {
		t.Fatal("run() = nil, want a refusal for the committer")
	}
	if !strings.Contains(err.Error(), "GIT_COMMITTER_IDENT") {
		t.Errorf("refusal does not name the committer:\n%v", err)
	}
}

// git stores the address as it was given, so a difference in case is not a different person.
func TestComparisonIsCaseInsensitive(t *testing.T) {
	g := fakeGit{author: "User@Users.Noreply.GitHub.com", history: []string{"user@users.noreply.github.com"}}
	if err := run(io.Discard, false, g.run); err != nil {
		t.Fatalf("run() = %v, want nil for the same address in another case", err)
	}
}

// The first commit of a repository has nothing to compare against. Refusing it would make the
// tool impossible to adopt, so it passes and says that it did.
func TestEmptyHistoryPassesAndSaysSo(t *testing.T) {
	g := fakeGit{author: mine}
	var out strings.Builder
	if err := run(&out, false, g.run); err != nil {
		t.Fatalf("run() = %v, want nil on an empty history", err)
	}
	if !strings.Contains(out.String(), "no history to compare against") {
		t.Errorf("an unchecked pass was not reported:\n%s", out.String())
	}
}

func TestIdentWithoutAnAddressIsAnError(t *testing.T) {
	broken := func(args ...string) (string, error) { return "A Name 1763200000 +0100", nil }
	err := run(io.Discard, false, broken)
	if err == nil || !strings.Contains(err.Error(), "no e-mail address") {
		t.Fatalf("run() = %v, want an error about a missing address", err)
	}
}

func TestGitFailureIsReported(t *testing.T) {
	failing := func(args ...string) (string, error) { return "", errors.New("git exploded") }
	if err := run(io.Discard, false, failing); err == nil {
		t.Fatal("run() = nil, want the git error")
	}
}
