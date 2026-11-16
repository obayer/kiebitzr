---
id: kbz:adr:00003
title: Format with gofumpt and Lint with a Strict, Idiomatic Set
date: 2026-11-05
status: accepted
tags:
  - tooling
  - ci
  - linting
  - conventions
related:
  - id: kbz:adr:00002
    reason: The CI gates this policy defines are the ones that pipeline runs
---

# Format with gofumpt and Lint with a Strict, Idiomatic Set

## Status

`accepted`, and in force since the configuration landed. Unlike the other two ADRs this one
needs no pilot: its subject is the repository itself, and the pinned tool version plus
`.golangci.yaml` are the decision in executable form.

## Context

`gofmt` ends most formatting arguments but not all of them: it tolerates a blank line after
an assignment operator, leaves import grouping to the author, and accepts `0777` next to
`0o777`. What it leaves open comes back as review comments.

Linting has the opposite problem. golangci-lint ships well over a hundred linters, and the
usual "strict" configuration enables as many as will pass. That fails for a specific reason:
the set mixes two different kinds of linter. Some find defects or enforce a rule Go documents
about itself. Others encode one project's taste, and several of those contradict documented
Go practice — `noinlineerr` forbids `if err := f(); err != nil`, the form Effective Go uses;
`varnamelen` demands long names where Go Code Review Comments ties name length to scope;
`lll` imposes a line limit that the same document says does not exist. A configuration that
argues with the language gets worked around with `nolint`, and then the suppressions are the
thing nobody reviews.

A third, duller trap: two tools formatting the same file. An editor running a `gofumpt`
binary and a gate running golangci-lint's own linked copy will disagree as soon as the two
versions differ, and the diff lands on whoever saved last.

### Options considered

- **`gofmt` alone** — the baseline, and not strict enough: the decisions it declines to make
  are exactly the ones that recur in review.
- **`gofumpt` as a standalone binary, `gofmt` inside golangci-lint** — two formatters, two
  versions, one file. Rejected for the skew described above.
- **Everything golangci-lint offers** — rejected: the taste linters above, plus
  `exhaustruct` (which turns Go's zero values into a change in every caller),
  `nonamedreturns` (which bans the construct that lets a deferred `Close` report its error)
  and the complexity linters, whose thresholds nobody can defend.
- **The default set only** — rejected in the other direction: it sees nothing about error
  wrapping, context propagation, `log/slog` misuse or Prometheus metric naming, all of which
  this service depends on.

## Decision

### Formatting

- **gofumpt**, a strict superset of gofmt, plus **gci** for import groups in a fixed order:
  standard library, other modules, our own packages. gofumpt's experimental rules are on.
- Both run through **`golangci-lint fmt`**, which is the only formatting entry point. There
  is no second tool and therefore no skew: `mise run fmt` rewrites, `mise run fmt:check`
  prints the diff and fails.
- The standalone `gofumpt` in `mise.toml` is pinned to **the version golangci-lint links**,
  so an editor formatting on save produces what the gate expects. A golangci-lint bump has to
  move that pin with it.

### Which linters are allowed in

One admission rule: **a linter earns its place if it finds defects, or enforces a rule Go
documents about itself** — Effective Go, Go Code Review Comments, the Google Go style guide,
the practice of the standard library. A linter that only encodes a preference is rejected,
however popular.

That yields 62 linters beyond the five golangci-lint enables by default, grouped in
`.golangci.yaml` by what they are for: defects, security, modern Go, naming and
documentation, project rules, tests.

**The rejection list is part of the decision, not a leftover.** Thirty-three linters are
listed at the end of `.golangci.yaml` with the reason each is off. Without that list the
configuration drifts toward taste every time somebody meets a new linter, and the argument
has to be had again.

Three narrower exceptions, each written out at the setting:

- `govet`'s `shadow` is off: it reports every `if err := f(); err != nil`.
- `gocritic`'s `hugeParam` and `rangeValCopy` are off: they measure struct size and nothing
  else, and fire on loops over hundreds of items where the advice would buy aliasing.
- `gocritic`'s `style` tag is off; `diagnostic` and `performance` are on.

Where two linters own the same subject, one of them is silenced: staticcheck's naming and
doc-comment checks are off because `revive` owns those rules. Two reports of one problem only
teach people to skim.

### Rules that are specific to this repository

- **`depguard`** keeps Syft, Grype and stereoscope importable only from `internal/catalog` and
  `internal/vulndb`. Those libraries are most of the binary, and their encapsulation is now
  checked rather than merely intended.
- **`forbidigo`** keeps the standard `log` package and `fmt.Print*` out: the service emits
  structured JSON, and `log.Fatal` would skip every deferred release. It matches identifiers
  rather than the import, because denying `log` would deny `log/slog` with it.
- **`promlinter`** checks metric and label naming, which is a published interface of this
  service.
- **`nolintlint`** requires every suppression to name its linter and give a reason, and fails
  on a suppression that no longer suppresses anything.

### Gates run over every build configuration

Build tags decide which files exist, so a single run cannot see the whole repository. `vet`
runs over the release, `dev` and `integration` configurations; `lint` runs twice; the tests
run in the release configuration and again with `dev`. A path that is not built by default
cannot rot unnoticed.

## Consequences

- Formatting stops being a review subject: one command fixes every file, and the gate shows a
  diff rather than an opinion.
- The policy is pinned to a tool version. A golangci-lint bump can surface new findings, so it
  is a reviewed change — Renovate opens it, and the findings are part of that review.
- `check` spends roughly twice as long linting, because it lints twice.
- Applying the set to the existing code found one real defect — `os.Exit` skipping a deferred
  release of the signal context — along with about twenty mechanical modernisations. That is
  the expected yield: the value is in what it prevents from here on.

## Open questions

- Whether `gocritic`'s `style` tag earns its place once there is more code to judge it on.
- Whether complexity thresholds become useful later. They are rejected as conventions, but a
  generous ceiling may still catch sprawl that review misses.
