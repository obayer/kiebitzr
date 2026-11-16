---
id: kbz:adr:00010
title: Label Findings with Their Package Ecosystem
date: 2026-11-11
status: accepted
tags:
  - metrics
  - prometheus
  - vulnerability-scanning
  - sbom
related:
  - id: kbz:adr:00008
    reason: Extends the same metric and follows its rule that a judgement of ours is not a label
  - id: kbz:adr:00001
    reason: Adds a label under the cardinality rule that ADR defines
  - id: kbz:runbook:00001
    reason: The triage section and the alert set there are what this label exists to make writable
  - id: kbz:adr:00012
    reason: Closes the binary-versus-source-package double counting this ADR records as unresolved
---

# Label Findings with Their Package Ecosystem

## Status

`accepted`. In force: `kiebitzr_vulnerability` carries `package_type`.

## Context

An operator asks two questions of this service, and only two: **must I patch tonight**, and
**can I patch it at all**. The metric set answered the first — `known_exploited` and
`kiebitzr_image_risk_score` exist for it (ADR 0008) — and answered the second wrongly.

On the pilot cluster, 41 of 50 running digests carried at least one Critical finding. That
reads as a cluster in ruins and is in fact the expected baseline: an image with a full
distribution userland carries a few hundred packages, so the probability of "at least one
Critical" approaches 1 and the indicator saturates. The first instinct — alert on
`severity="Critical"` — produces an alert that is permanently red, and ADR 0005 already
records what a permanently red gate is worth.

Narrowing to `fix_state="fixed"` looked like the answer and was not. Of 357 fixable Critical
findings, the package breakdown was:

| Package | Findings |
|---|---|
| `stdlib` | 76 |
| `golang.org/x/crypto` | 56 |
| `libcurl` | 55 |
| `libcrypto3`, `libssl3` | 32 each |
| `golang.org/x/net` | 31 |
| `curl` | 31 |
| `zlib` | 16 |
| remainder | ~28 |

Roughly half — 168 findings — are Go code compiled into a binary. Nothing an operator does to
a cluster changes them: they move only when whoever publishes the image bumps a dependency and
rebuilds. They are nevertheless reported as `fix_state="fixed"`, because that label states
that a fixed *version of the package* exists, which is true and is not the question. **Half of
what the metrics called fixed was not actionable by the person reading the metrics**, and no
label distinguished the two halves.

The distinction is not exotic. It is whether a newer image of the same lineage is likely to
carry the fix: a base image's maintainer tracks the distribution's advisories, an application
dependency waits for its publisher. Syft records exactly what is needed to tell them apart —
`pkg.Package.Type`, a bounded enumeration of about forty ecosystem names — and
`policy.findings()` was dropping it.

### Options considered

**Leave it; select on package names.** `package=~"stdlib|golang.org/.*|google.golang.org/.*"`
separates the two halves today with no code change, no metric contract change and no ADR.
Rejected: the regex is tribal knowledge with the lifetime of the current image inventory. It
does not know the next Go module under a vanity domain, `deb` when a Debian-based image
arrives, or `npm` when a Node service does — and it fails in the dangerous direction, sorting
findings into the "you can fix this" bucket that belong in the other one.

**Derive an `os` / `app` label.** Tempting, because it is literally the question. Rejected for
the reason ADR 0008 rejected our own risk score: it would bake our reading of forty package
types into the metric, where a consumer can neither see the classification nor argue with it.
Several types are genuinely ambiguous — `binary` is whatever the binary cataloger found,
`java-archive` can sit anywhere in a filesystem — and a two-valued label would hide that
rather than expose it. The grouping belongs in a query, where it is visible and editable by
whoever disagrees with it.

**A second metric, `kiebitzr_image_actionable`, counting fixable findings per digest.**
Rejected for now: it bakes in the same judgement as the derived label, one aggregation deep,
and it cannot be re-cut. A label can be grouped any way a later question needs.

**Pass Syft's type through as a label.** Chosen.

## Decision

`kiebitzr_vulnerability` carries **`package_type`**, Syft's own type string for the package the
finding is against: `apk`, `deb`, `rpm`, `go-module`, `python`, `npm`, `java-archive` and so on.

It is **passed through, not interpreted**. Grouping the values into "a newer image fixes this"
and "only a rebuild fixes this" happens in PromQL, and the grouping that answers the
can-I-patch question is documented in the metrics runbook rather than compiled in.

An unset type and Syft's own `UnknownPackage` both collapse to **`unknown`**. The label never
carries the empty string, which would read as an ecosystem nobody has a name for, and the two
non-answers do not get separate spellings — a query grouping ecosystems would otherwise have
to know about three ways of saying "no idea".

**It costs no cardinality.** The type is functionally determined by the package it describes,
so it splits no series that `package` did not already split. This is what distinguishes it from
the float-label trap ADR 0008 names: a label whose value is derived from an existing label adds
information per series, not series.

## Consequences

- The question "can I patch this at all" becomes one selector instead of a package-name regex
  that silently rots. On the pilot data it cuts the actionable Critical backlog from 357
  findings to about 180.
- `kiebitzr_vulnerability` gained a label for the second time. Queries matching on a subset of
  labels are unaffected; queries pinning the full label set have to be updated. Per ADR 0006
  the version number cannot warn about this, so it belongs in the release notes — the same
  consequence ADR 0008 carried, and the second occurrence is a hint that the full label set is
  not a stable thing to pin.
- The alert set in the metrics runbook is rebuilt around urgency and actionability. There is
  deliberately no alert on severity alone and none on the non-actionable half of the backlog:
  an alert nobody reading it can act on trains people to ignore the ones they can.
- Grouping distribution package types in a query means enumerating them
  (`apk|deb|rpm|alpm|portage|nix`). A distribution whose type is missing from that list falls
  into the "not your move" bucket, which is the safe direction but is still wrong. The runbook
  names the list in one place so it is corrected in one place.
- Syft is now imported by `internal/vulndb` as well as `internal/catalog`. depguard already
  exempts both; the import is for the `UnknownPkg` constant only, so no Syft behaviour reaches
  the matching path.
- The finding count still double-counts a distribution's binary and library packages for one
  source package (`curl` and `libcurl`; `libssl3` and `libcrypto3` from openssl). `package_type`
  does not fix that and is not meant to — Grype matches per package, and collapsing to source
  packages would be a second inventory. The runbook warns about it instead.

## Amendment: the pilot's missing threat data was neither

This was written with `kiebitzr_image_risk_score` absent on the pilot cluster and recorded as
an open question — whether the database carried no EPSS records or the code failed to read
them. It was neither. The commit that added the metric and the `known_exploited` label is not
contained in any release tag, so **no released version publishes either of them**. Nothing was
broken; the feature had not shipped.

`TestThreatDataArrives` in `internal/vulndb` was written to settle it and now guards it. Against
the pilot's own database and SBOMs: 610 findings over five images, 601 carrying EPSS data, one
in a known-exploited catalogue, and a highest risk score of 98.7 — a near-maximal finding that
was invisible for want of a release.

The lesson generalises beyond this metric, which is why it is recorded here rather than dropped
as a non-issue: **absent exploitation evidence reads exactly like good news.** An operator
seeing no risk scores and no known-exploited findings concludes the cluster is calm, and that
conclusion is identical whether the data is missing, the database lacks it, or the binary never
emitted it. The metrics runbook alerts on it with `KiebitzrThreatDataMissing`.

The structural half of the fix is **`kiebitzr_build_info`**, added here: a gauge of 1 labelled
with the version and commit linked into the running binary, served by matchers and workers
alike. Until it existed, `/metrics` could not say which build was answering — the version was
only in the start-up log line, gone after a restart — so the question had to be settled from
commit timestamps. One series, no cardinality, and it makes every future metric-set extension
diagnosable: a consumer can now distinguish "nothing to report" from "a binary that cannot
report it". Both exporters register it unconditionally and read the build metadata directly,
because a setter a caller can forget would reintroduce the same ambiguity one level down.

## Open questions

- Whether `kiebitzr_image_actionable` should exist after all, once the runbook's funnel has
  been used for a while. The argument for it is that the useful number currently takes a
  three-level nested query; the argument against is that it fixes one reading of the data as
  the published one.
