# TODO

Open improvements, and why each is where it is.

**How an item earns a place in *Ready to build*.** The same four things a proposal has to show
(`docs/req/0001-the-decisions-this-service-has-to-serve.md`): which decision it serves, evidence
that the decision is unserved rather than a plausible story, its cost in registry requests,
SBOMs and series per image, and the number that should move. An item missing any of them sits in
*Needs a decision or evidence first* until it has it.

Two sections exist to stop work repeating itself. **Rejected** keeps reasons attached to ideas,
so a good-sounding one does not come back every quarter. **Reported missing but already there**
keeps the answer for the next report that lands.

**An item never just disappears.** When the work lands it moves to *Done* with the commit that
did it; when it is dropped it moves to *Rejected* with the reason. A local agent `Stop` hook
asks for exactly that when a change touched code or docs and left this file alone — the
reminder fires at the moment it applies rather than riding along in every
request. A file where finished items
are quietly deleted and abandoned ones quietly linger is a file nobody trusts after a month —
and an untrustworthy list is the same failure this service is built against, one directory up.
Item numbers are referenced in discussion, so a `T3` that leads nowhere is worse than a `T3`
marked done.

---

## Ready to build

Both items below are defects in shipped behaviour rather than extensions, found by running the
candidate check against a rate-limited registry. Everything further down still needs a decision
or a measurement before it can move up here.

| | Item | Decision served, evidence, cost, and the number that should move |
|---|---|---|
| T16 | **A candidate that could not be catalogued has to be `unknown`, not `0`.** When every candidate of a digest fails to catalogue, `bestCandidate` returns `cleared = 0` with the newest tag and the run publishes `kiebitzr_image_upgrade_candidate{tag} 0` — a series whose help says *checked and clears nothing*. It should publish `kiebitzr_image_upgrade_unknown{reason="unreachable"}`, and the failures the candidate stage currently drops should reach `kiebitzr_scan_errors_total` | Serves the deployability question of ADR 0011 and `req/0001`, and serves it **wrongly today**, which is worse than not at all: the dashboard row "the candidate check looked and found nothing newer" fills with images nobody looked at, and a fix that exists is hidden behind a zero. ADR 0011 says it itself — unknown is not no-fix. **Measured 2026-11-13 on the cluster:** the candidate stage ran into Docker Hub's unauthenticated pull limit, logged `candidate not checked` for every candidate of several digests, and those digests were published at `0`. `kiebitzr_scan_errors_total{reason="unreachable_image"}` stayed at **0** the whole time, because `bestCandidate` logs the failure and discards the `Report` (`internal/runner/upgrades.go:141-144`) where the main path books it (`runner.go:233-235`). Cost: no registry request, no SBOM, no new series per image — a digest carries either the candidate series or the unknown series, never both. The number that should move: digests published as `candidate == 0` without a single catalogued candidate, to zero |
| T17 | **One candidate digest, one attempt per run.** Several tags of a repository routinely resolve to the same digest, and `remainingIn` guards only with `store.Has(digest)` — which a failed catalogue never satisfies. The same unreachable digest is fetched once per tag | Serves the same decision as T16 by making it affordable exactly where it fails: against a rate-limited registry the repeated attempts are what sustains the limit. **Measured 2026-11-13:** one public Docker Hub repository, two tags on one digest, attempted separately eleven seconds apart, both refused with `TOOMANYREQUESTS`. Cost: negative — strictly fewer registry requests, no new series, one set of attempted digests per run. The number that should move: registry requests per run at `-upgrade-candidates=3`, down by the number of duplicate tag-to-digest pairs |

---

## Before the repository goes public

Not product items, and deliberately exempt from the four things above: they serve no decision
in `req/0001` and have no number that should move. They are here because each is irreversible
once the repository is public, and a list of those belongs where nothing disappears.

| | Item | Where it stands |
|---|---|---|
| P1 | **The history.** The measurements and the named inventory were removed from the working tree, not from the 95 commits behind it, and publishing that history would have published them anyway — a force-push would not have helped, because an unreachable commit stays reachable by hash and the release images carry their own commit SHA | **Done, 2026-11-16.** The 95 commits live on privately in `kiebitzr-archive`; this repository starts from one commit of the cleaned tree and never carried the rest. No tags: the three `v2026.1109.x` point at commits that do not exist here, the images they produced stay verifiable through the workflow identity, and public releases start at a new tag |
| P2 | **Repository settings**, none of which are files: require approval for workflow runs from *all* external contributors (the default covers first-time ones only), decide the visibility of the `ghcr.io` package separately from the repository, protect the `v*` tags so a release signature cannot be produced from a stray push, and enable private vulnerability reporting for `SECURITY.md` to point at | Open. Each is one setting or one `gh api` call |
| P3 | **The work API is unauthenticated** (ADR 0009, `internal/dispatch`), bounded by network policy alone. `SECURITY.md` now says so, which turns an internal assumption into a documented one. Whether it should carry a shared secret is a separate decision | Open, and a decision rather than a defect: the protocol being public does not weaken it, but a reader who deploys the worker pool without a network policy gets a queue anybody in the cluster can drain |
| P4 | **Nothing keeps dependencies current.** `renovate.json` is complete and correct, and Renovate has never run: not one commit in the repository's history is from it, and `helpers:pinGitHubActionDigests` would have opened a pull request on its first pass — all seven action references were still on moving tags. The pins are now set by hand, so the gap is no longer silent, but it is still a gap **Decided 2026-11-16: the hosted app**, because only it and a self-hosted workflow see `mise.toml` — and the tool versions there, `go`, `golangci-lint`, `betterleaks`, `ko`, are the gates themselves — while the workflow would need a long-lived write token in Actions secrets, where an app installation is a click to revoke. A self-hosted workflow using the built-in `GITHUB_TOKEN` was ruled out for a different reason: pull requests it creates do not trigger workflows, so `check` would never run on them. Remaining: **install it**. Batching is already configured (weekly window, three open pull requests, vulnerability alerts exempt) |

---

## Needs a decision or evidence first

| | Item | What is missing |
|---|---|---|
| T5 | **`match_source` and `vendor_build`** — show how Grype matched, and flag a third-party build of a distro package | The problem is real: ~1,200 false positives where a vendor's own apt packages, carrying a vendor suffix in the version, were matched against the distribution's feed. But `vendor_build` is a suffix heuristic, and this project's recent history with heuristics is poor. Measure how often the suffix list fires, and how often it is right, before it becomes a default |
| T6 | **Filter defaults** — `min_severity: high` and `only_fixed: true` instead of reporting everything | A direct conflict with ADR 0001, which chose the full inventory and narrowing at the service, and with the runbook's argument that an excluded finding is unexamined rather than absent. Changeable, but it is a decision to take knowingly, not a gap to close |
| T7 | **Tolerate a bad configuration instead of refusing to start** | ADR 0007 decided the opposite: a malformed value is a start-up error, not a silently kept default. The counter-argument — a ConfigMap typo should not take the service down — is good. Needs a decision, and probably a split: a malformed *flag* stays fatal, a malformed *ignore rule* does not |
| T8 | **VEX input** — OpenVEX `not_affected` and `fixed` statements | Grype supports it. No evidence yet that anybody here has VEX documents to feed it. The accounting half is settled: T2 exists, and a VEX suppression would need its own `reason` there rather than being folded into `ignore_rule` — Grype returns VEX-ignored matches in the same list |
| T9 | **Registry-side staleness** beyond T4 — is the registry's digest newer than every digest running | Partly answered by ADR 0011 already, which catalogues newer builds and says whether they clear anything. What is left is the cheaper signal "something newer exists at all, regardless of findings", and the mission says this is a vulnerability exporter and not an update tracker. The boundary is in `req/0001`; this would move it |
| T10 | **Worker pool for candidate cataloguing** | Candidates share the catalogue budget today but go through whatever stage is configured, so a pool already absorbs them. Whether anything further is needed is unmeasured, and the pilot cluster is one pod |

---

## Open from accepted decisions

| | Item | Where |
|---|---|---|
| T11 | A fallback for repositories whose builds cannot be ordered — check all tags, read `buildFinishedOn` from a provenance attestation, or a per-repository override | ADR 0011, open questions. The degradation is accepted and documented; the measurement that would rank the three is the probe in `internal/upgrade` |
| T12 | Whether an attached SBOM may be trusted at all, and what verifying its signature would require | ADR 0011. Currently rejected outright: a page fires on a positive, so an unverified claim cannot carry one in either direction |
| T13 | How often "a fix exists only as a package version" actually blocks | `req/0001`, open measurements. One data point so far and it fell the other way — a fix existed and had been missed |
| T14 | Whether the alert set causes fatigue | `req/0001`. Only time answers it. It now matters more than when it was written: all but one rule is about the scanner's own health, and the exception — `KiebitzrExploitedAndDeployable` — is the first rule in this project's life that wakes somebody about a finding. If any rule turns out to be ignored, that is the one to watch |
| T15 | The secret gates allowlist the git-ignored token files with betterleaks' deprecated `[[allowlists]]`, because its documented replacement does not work: measured on 1.10.0, a global Expr `prefilter` has no effect on a `dir` scan at all. Re-measure on every upgrade, and before 2.x, where allowlists are gone | `.betterleaks.toml`, header comment. The measurement is `betterleaks dir --config <cfg> .` with the same paths expressed each way: 116 MB scanned and 8 findings via `prefilter`, 3 MB and 0 via `[[allowlists]]` |

---

## Reported missing but already there

Kept so the next report does not re-raise them, and because each has a lesson.

| | Report | What is actually the case |
|---|---|---|
| — | **`fixed_in` is missing** | It has been published since ADR 0008. **Prometheus does not distinguish an empty label from an absent one**, and the findings examined were all `fix_state=not-fixed`, where there is no fixed version to name. The label is there on everything that has a fix |
| — | **`scan_errors_total` carries no reason, and nothing says which image failed** | Both exist: `reason` from the start, and `kiebitzr_image_failed{image_digest, reason}` since ADR 0008. A `count()` over the latter returns the number and hides the labels |
| — | **The ADR filters are not implemented** | `-min-severity`, `-only-fixed` and `-ignore-file` all exist, the last taking Grype's own ignore-rule schema, and every flag is settable as `KIEBITZR_*` from a ConfigMap. The report's own context names the cause: the deployment passes no configuration at all. A deployment gap, not a code gap. The condition on telling anyone to use them is met: since `7ba02a3` every filter says how many findings it removed |

---

## Done

All four landed in one commit rather than four. They share the runbook, the dashboard and two
Go files, and splitting interleaved edits in those would have produced commits that each told
half a story. The ADR is where the reasoning is; the commit names the items.

| | Item | Commit |
|---|---|---|
| T1 | **`source_package`** — one advisory against one source package counts once instead of once per binary package built from it. `package` kept beside it; a package that is its own source carries its own name. **Measured on the cluster: 3,635 → 1,223**, a third of what it was, where the item predicted a half | `7ba02a3`, ADR 0012 |
| T2 | **Suppression accounting** — `kiebitzr_vulnerability_suppressed{image_digest, reason}` counts what `-min-severity`, `-only-fixed` and an ignore rule removed. Reasons disjoint and ordered, counts in series rather than matches, no series where nothing was removed | `7ba02a3`, ADR 0012 |
| T3 | **`location`** — the path of the artefact inside the image. **The cost this item was proposed with — "one label, no new series" — was wrong**, and the correction was then too pessimistic: measured on the cluster it cost **344 series of 11,099, 3.2 %** — 2.5× in the worst single image, 2.0× for four, under 1.16× for the rest. It also settled the question that produced the item: the unplaceable `stdlib` findings all sat in one helper binary under `/usr/local/bin`, in three images | `7ba02a3`, ADR 0012 |
| T4 | **Node-level digest drift documented** — triage section in the metrics runbook, a dashboard table, and the correction that the drift is between nodes and not in the registry | `7ba02a3` |
| T15 | **`build_access`** — `kiebitzr_image_info` says whether anybody here can get a build of an image, declared in `-build-access-file`. It splits the old "nothing can be done" bucket into a dead end and a morning queue: the images where no newer build exists *because nobody has built one yet*. No file means `unknown` everywhere, which is "nobody has looked" and not a verdict. It deliberately does not page — ADR 0013, and the sharpening in `req/0001` that a request is not a clearance | ADR 0013 |
| — | *Older than this file.* What came before `TODO.md` is in the git history and in the ADRs. | — |

---

## Rejected, with the reason

| Idea | Why not |
|---|---|
| Order candidate tags by comparing version strings | Tag strings are arbitrary — SemVer beside CalVer beside `3.1-alpine` beside `stable`. Every attempt during the ADR 0011 design became a heuristic that eventually picked wrong. Build time is a number; that is what is used |
| Answer deployability from a single registry metadata call | `fixed_in` is a package version and a registry speaks image tags. The OCI model carries no package inventory at any level, so the question cannot be posed. ADR 0011 records this at length because everybody re-derives it |
| Read `config.history[].created_by` to learn package versions from metadata | With BuildKit, squashed layers, `COPY`-based installs and multi-stage builds the line is absent or describes another stage. A guess dressed as a fact, and a wrong negative suppresses a page |
| Trust a publisher's attached SBOM | A page fires on a positive, so a wrong positive wakes somebody who then has nothing to do. An unverified third-party claim cannot carry a page in either direction |
| An alert on `severity="Critical"` | It fired on 41 of 50 images on the pilot cluster. A severity rollup per image saturates and gets worse as images grow |
| A finding-based pager alert before deployability is verified | An alarm must be clearable by whoever it wakes. `fix_state="fixed"` cannot promise a deployable image, so such a rule burns for weeks and gets silenced |
