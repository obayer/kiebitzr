---
id: kbz:adr:00006
title: Version Releases with CalVer, in a Shape Go Accepts
date: 2026-11-09
status: accepted
tags:
  - release
  - conventions
  - tooling
related:
  - id: kbz:adr:00002
    reason: Decides the version string the pipeline of that ADR tags and signs
  - id: kbz:adr:00007
    reason: Another interface this scheme cannot warn about when it is renamed
---

# Version Releases with CalVer, in a Shape Go Accepts

## Status

`accepted`. In force from the first release, `v2026.1109.0`.

## Context

The first release exists to run Kiebitzr in a cluster, and that forced a question the
repository had not answered: what a version number here means.

What consumes the version is narrow. The release workflow triggers on `tags: ["v*"]` and
accepts any shape. ko writes the string unchanged into two image tags, `${VERSION}` and
`${VERSION}-<short-commit>`. The weekly rebuild selects its ref with
`git describe --tags --abbrev=0`, which picks the nearest tag in the commit history rather
than sorting versions, so the scheme cannot mislead it. The string also reaches the binary
through `-ldflags -X …/internal/version.Version`.

One constraint is not negotiable. This repository is a Go module, so a release tag is also a
module version, and Go validates those against SemVer. Measured with
`golang.org/x/mod/semver`, the library Go itself uses:

| Tag | `IsValid` | `Canonical` |
|---|---|---|
| `v2026.11.09` | false | `""` |
| `v2026.11.9` | true | `v2026.11.9` |
| `v2026.1109.0` | true | `v2026.1109.0` |
| `v2026.11.0` | true | `v2026.11.0` |

`v2026.11.09` is rejected: SemVer forbids leading zeroes in a numeric identifier, so `09`
makes the whole version invalid and the tag would not exist for any tool that reads module
versions. A date written the obvious way is therefore not available.

### Options considered

**SemVer (`v0.1.0`, then `v1.0.0`).** Rejected as the primary scheme. SemVer communicates
compatibility to people who depend on an interface, and what this project ships is a
container image that its own operator deploys — not a library someone imports. The question
asked of a vulnerability scanner in production is how old it is, because its value decays
with its data; a version that answers that without a lookup is worth more here than one that
encodes compatibility. SemVer's real advantage, the `v0.x` signal for "not stable yet", is
given up and recorded under consequences.

**`vYYYY.MM.DD` (`v2026.11.09`).** Rejected: not a valid version, as measured above.

**`vYYYY.MM.D` (`v2026.11.9`).** Valid, and the closest to a plain date, but it has no room
for a second release on the same day — the next number would be `v2026.11.10`, which reads
as the tenth of November. A first cluster release in particular is likely to be replaced
within hours.

**`vYYYY.MM.N` (`v2026.11.0`).** Valid and orders correctly, but drops the day, which is the
part that carries the information.

## Decision

Release tags are `vYYYY.MMDD.N`:

- `YYYY` — four-digit year.
- `MMDD` — month and day, each zero-padded to two digits, as one number. The padding sits
  inside the field rather than at its start, so no numeric identifier begins with a zero and
  the version stays valid.
- `N` — counts releases of the same day, from `0`.

The first release is `v2026.1109.0`. A correction on the same day is `v2026.1109.1`.

## Consequences

- Tags are canonical SemVer, so `go list`, `go install` and anything else reading module
  versions see them.
- Ordering is correct under version comparison: `1109 < 1110 < 1201`, and the year dominates.
  Lexical sorting of tag names also happens to agree, because every field is fixed-width.
- The minor number jumps between months (`1109` to `1201`). That is cosmetic; nothing derives
  meaning from the distance between two versions.
- Nothing in the release pipeline changes. The trigger, the image tags and the weekly rebuild
  are indifferent to the scheme, and `git describe` keeps resolving the newest release.
- The version carries no stability signal. Maturity is stated in release notes and in the
  status of the ADRs that govern a feature, not in the number — `v2026.1109.0` looks exactly
  as final as every release after it, and nothing should be read into that.
- Metric and flag names are an interface that a version in this scheme cannot warn about. A
  change that breaks a dashboard or an alert rule has to be announced in the release notes,
  and a deprecation window is the right instrument if this ever has consumers beyond the
  repository that deploys it.
