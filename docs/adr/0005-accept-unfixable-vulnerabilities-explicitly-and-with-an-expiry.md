---
id: kbz:adr:00005
title: Accept Unfixable Vulnerabilities Explicitly and With an Expiry
date: 2026-11-06
status: accepted
tags:
  - ci
  - security
  - supply-chain
  - vulnerability-scanning
  - tooling
related:
  - id: kbz:adr:00001
    reason: Embedding Syft and Grype is what brings the dependency surface this governs
  - id: kbz:adr:00002
    reason: Adds the rule the vulnerability gate of that pipeline follows
---

# Accept Unfixable Vulnerabilities Explicitly and With an Expiry

## Status

`accepted`. In force: `mise run vuln` runs `tools/vulnguard`, and `.vulnguard.yaml` currently
holds one accepted finding.

## Context

`govulncheck` is one of the gates of `check` and of CI. It distinguishes vulnerabilities whose
code this module actually calls from those merely present in the build, and fails on the
former. That is the right default, and it worked until it met a case it has no answer for.

Embedding Syft and Grype means depending on roughly 2100 packages (ADR 0001). Among them,
`github.com/blakesmith/ar` — the archive reader Syft's deb cataloger uses — has a reachable
advisory, GO-2026-6905: `Reader.Read` panics on a member with a negative size. There is **no
fixed version**: the library is effectively unmaintained, and Syft would have to replace it.

`govulncheck` v1.9.0 has no way to accept a finding. So the gate fails, and keeps failing, for
a condition nobody in this repository can resolve.

### Options considered

- **Leave the gate red.** Rejected: a gate that is always red is a gate nobody reads, and it
  would hide the next finding completely.
- **Drop `vuln` from `check`.** Rejected for the same reason, more so: it hides every future
  vulnerability, not just this one.
- **A `replace` directive to a patched fork.** Rejected: no fork exists, maintaining one is
  worse than the risk, and `gomoddirectives` (ADR 0003) forbids `replace` on purpose.
- **Remove Syft's deb cataloger**, so the code is never called. Rejected: it would blind a
  vulnerability scanner to Debian packages, which is most of what a cluster runs.
- **A wrapper that accepts named findings.** Chosen.

## Decision

`mise run vuln` runs `tools/vulnguard`, which calls `govulncheck -format json` and decides the
verdict itself:

- A **reachable** vulnerability fails the build unless `.vulnguard.yaml` lists it.
- An entry needs an **id, a reason and a review date**; a missing one is an error.
- An entry whose **review date has passed** fails the build, so a decision cannot outlive the
  thinking behind it.
- An entry that **no longer matches any finding** fails as well, so the file cannot fill up
  with entries that only look like diligence — and so a stale entry cannot silently cover a
  future finding with the same id.
- Vulnerabilities that are present but not called are printed, never fail. That is
  `govulncheck`'s own distinction and worth keeping.

An exception is not a way to silence a finding. It is a record of a decision somebody has to
defend, which is why the reason has to say why the risk is bearable — not that it is.

### The current exception

GO-2026-6905 is accepted until 2026-12-15 because **the failure is contained, and that was
verified rather than assumed**: Syft recovers panics at three levels — per task, per package
processor and per parsed file (`syft/pkg/cataloger/generic/cataloger.go` in syft v1.56.0). A
crafted `.deb` therefore costs one unparsed file in one image. The run continues, the image is
counted in `kiebitzr_images{state="failed"}`, and the previous result keeps being served.

## Consequences

- The gate stays meaningful: one known hole, named, reasoned and dated, and everything else
  still fails the build.
- Exceptions expire by construction. The review is not a reminder somebody has to remember.
- One more tool to maintain, with its own tests. It is the price of keeping the gate.
- The reachability judgement is ours. "Contained because Syft recovers" has to be re-checked
  when Syft changes how it handles deb archives — which is exactly what the review date is for.
- `govulncheck` in JSON mode always exits 0 and leaves the verdict to its caller, so the tool
  owns the exit code. A bug in the tool could therefore hide a finding; its tests cover the
  blocking, accepting, expiring and stale cases for that reason.

## Open questions

- Whether to also pin the vulnerability database date in CI, so a scheduled rebuild cannot fail
  on an advisory published between a merge and a release. It would trade timeliness for
  reproducibility, and timeliness is the point of the weekly rebuild.
