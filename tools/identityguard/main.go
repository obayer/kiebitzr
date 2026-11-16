// Command identityguard refuses a commit whose author or committer address has never
// committed to this repository, unless that is confirmed deliberately.
//
// The problem it solves is a split configuration. A repository-local `user.email` lives in
// `.git/config`, which is not versioned and does not travel: a fresh clone, a new worktree or
// a checkout on another machine falls back to the global identity, and the first commit made
// there carries whatever address that is — into a public history, where it cannot be taken
// back. A private address gets harvested, an employer address attributes a personal project to
// an organisation that has nothing to do with it, and rotating the address afterwards is no
// remedy, because the commit stays.
//
// The rule is deliberately *not* an allowlist of addresses in a file. An allowlist in a
// published repository would either refuse every contribution but the maintainer's, or turn
// into a register of other people's e-mail addresses — and nobody should have to send a pull
// request against a policy file to be allowed to commit. The history already knows which
// addresses this repository publishes, so that is what is compared against: an address that is
// new here is a question, and answering it is one environment variable.
//
// It therefore runs in the pre-commit hook and not in CI: a first contribution is new by
// definition, and a gate that fails every newcomer's pull request would be removed within a
// week. What CI cannot fix, a commit hook can prevent.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// allowNewEnv confirms an address the history does not know. It is read from the environment
// rather than taken as a flag so it can be set on the git invocation itself:
//
//	IDENTITYGUARD_ALLOW_NEW=1 git commit -m "…"
const allowNewEnv = "IDENTITYGUARD_ALLOW_NEW"

func main() {
	if err := run(os.Stdout, os.Getenv(allowNewEnv) != "", gitCommand(context.Background())); err != nil {
		fmt.Fprintf(os.Stderr, "identityguard: %v\n", err)
		os.Exit(1)
	}
}

// git runs one git command and returns its standard output. Injected so the tests do not need
// a repository with a history.
type git func(args ...string) (string, error)

func run(out io.Writer, allowNew bool, run git) error {
	// Author and committer, because they differ: a rebase, a cherry-pick or a commit made
	// with --author keeps the author and replaces the committer, and the committer is just as
	// published. `git var` resolves each exactly as `git commit` would, rather than reading a
	// configuration file and re-implementing the precedence rules.
	identities := map[string]string{}
	for _, variable := range []string{"GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"} {
		ident, err := run("var", variable)
		if err != nil {
			return err
		}
		email, err := emailOf(ident)
		if err != nil {
			return fmt.Errorf("%s: %w", variable, err)
		}
		identities[variable] = email
	}

	known, err := knownAddresses(run)
	if err != nil {
		return err
	}

	// An empty history cannot answer the question. Saying so is the honest outcome: there is
	// nothing to compare against, and refusing the very first commit of a repository would
	// make the tool impossible to adopt.
	if len(known) == 0 {
		return write(out, fmt.Sprintf("identityguard: no history to compare against — %s and %s pass unchecked",
			identities["GIT_AUTHOR_IDENT"], identities["GIT_COMMITTER_IDENT"]))
	}

	var notices []string
	for _, variable := range []string{"GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"} {
		email := identities[variable]
		if known[strings.ToLower(email)] {
			continue
		}
		if allowNew {
			notices = append(notices, fmt.Sprintf("identityguard: %s is <%s>, new to this repository, allowed by %s",
				variable, email, allowNewEnv))
			continue
		}
		return refusal(variable, email, known)
	}

	if len(notices) == 0 {
		notices = []string{"identityguard: author and committer have committed here before"}
	}
	return write(out, notices...)
}

func write(out io.Writer, lines ...string) error {
	if _, err := io.WriteString(out, strings.Join(lines, "\n")+"\n"); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// knownAddresses is every author and committer address in the history reachable from HEAD,
// lowercased: addresses are compared case-insensitively, because git stores what it was given
// and a difference in case is not a different person.
func knownAddresses(run git) (map[string]bool, error) {
	// A repository without a commit has no HEAD, which git reports as an error rather than as
	// empty output. That is the empty history, not a failure, and an empty set says it.
	if !hasCommits(run) {
		return map[string]bool{}, nil
	}
	out, err := run("log", "--format=%ae%n%ce", "HEAD")
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		if address := strings.ToLower(strings.TrimSpace(line)); address != "" {
			known[address] = true
		}
	}
	return known, nil
}

// emailOf takes the address out of a git ident string, which is
// `Name <address> 1763200000 +0100`.
func emailOf(ident string) (string, error) {
	open := strings.LastIndex(ident, "<")
	closing := strings.LastIndex(ident, ">")
	if open < 0 || closing < open {
		return "", fmt.Errorf("no e-mail address in %q", ident)
	}
	email := ident[open+1 : closing]
	if email == "" {
		return "", errors.New("empty e-mail address")
	}
	return email, nil
}

func refusal(variable, email string, known map[string]bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s is <%s>, which has never committed to this repository.\n\n", variable, email)
	b.WriteString("This repository is published, so the address goes public with the commit and stays\n")
	b.WriteString("there. The usual cause is a checkout without a repository-local identity, falling\n")
	b.WriteString("back to the global one — set it where it belongs:\n\n")
	b.WriteString("  git config user.email '<the address you publish under>'\n\n")
	fmt.Fprintf(&b, "If the address is right and simply new here — a first contribution — say so:\n\n")
	fmt.Fprintf(&b, "  %s=1 git commit …\n", allowNewEnv)
	if len(known) <= 3 {
		b.WriteString("\nAddresses this repository already publishes:\n")
		for address := range known {
			fmt.Fprintf(&b, "  %s\n", address)
		}
	}
	return errors.New(b.String())
}

func hasCommits(run git) bool {
	_, err := run("rev-parse", "--verify", "HEAD")
	return err == nil
}

// gitCommand returns a runner bound to ctx, so a signal ends a git call rather than leaving it
// behind.
func gitCommand(ctx context.Context) git {
	return func(args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, "git", args...).Output() //nolint:gosec // fixed command, and every argument is a literal from this file
		if err != nil {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return strings.TrimSpace(string(out)), nil
	}
}
