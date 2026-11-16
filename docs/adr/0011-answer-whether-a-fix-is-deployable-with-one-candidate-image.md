---
id: kbz:adr:00011
title: Answer Whether a Fix Is Deployable, with One Candidate Image
date: 2026-11-11
status: accepted
tags:
  - architecture
  - vulnerability-scanning
  - sbom
  - metrics
  - supply-chain
related:
  - id: kbz:adr:00010
    reason: Completes the can-I-patch question that ADR left answerable only as a likelihood
  - id: kbz:adr:00008
    reason: The urgency half of triage, whose alert this would gate on deployability
  - id: kbz:adr:00001
    reason: Reuses the cataloguing pipeline and the cardinality rule it defines
  - id: kbz:adr:00009
    reason: Candidate cataloguing is work the pool has to absorb without crowding out running images
  - id: kbz:runbook:00001
    reason: Documents this as the third of three meanings of "a patch exists", and the one nothing answers
  - id: kbz:req:00001
    reason: The test this proposal is held to, and the evidence it is still missing
---

# Answer Whether a Fix Is Deployable, with One Candidate Image

## Status

`accepted`. In force: `-upgrade-candidates` and `-upgrade-scope` exist,
`kiebitzr_image_upgrade_candidate` and `kiebitzr_image_upgrade_unknown` are published when the
check is switched on, and candidate digests survive the cache prune. Off by default.

**No longer held.** It was held for failing the evidence requirement of `kbz:req:00001` — nobody
had measured how often "a fix exists as a package version but in no deployable image" blocks
anyone. The clearability test adopted since supplies the evidence in a different and stronger
form: the frequency does not matter, because **no finding may page until deployability can be
verified.** One occurrence is enough to wake somebody who then has no move, and an alarm like
that gets silenced.

So the question is no longer whether this is worth building. It is whether this service should
ever page about a finding at all, or whether urgency belongs on a dashboard permanently. That
decision is not recorded here yet.

## Context

ADR 0010 split findings by the ecosystem their package comes from, which turned "can I patch
this at all" from a guess into a query. It answers a *likelihood*: an `apk` finding with a fix
is probably cleared by a newer tag of the same image, a `go-module` finding probably is not.
Probably is where it stops.

The question an operator actually holds is narrower and harder: **I run this digest, it has a
known-exploited finding with a fixed version named — is there an image I can deploy, for the
platform these nodes run, that resolves it?** The metrics runbook records this as the third of
three meanings of "a patch exists", and the only one nothing in this service answers.

It is not a nicety. An alert that fires for a finding nobody can deploy a fix for is the
always-firing alert this project has now removed twice: ADR 0005 on a gate that stays red, ADR
0010 on a severity rollup that saturates at four images in five. A rule gated on
`fix_state="fixed"` keeps out what is *unfixable in principle* but still fires where the fix
exists only as a version number in an advisory — and a rule like that shipped here once, as
`KiebitzrExploitedAndFixable`, before it was withdrawn.

### The category confusion that makes this look trivial

It looks like one registry call, and the reason it is not deserves recording, because everyone
who meets this problem re-derives it:

**`fixed_in` is a package version. A registry speaks image tags.** A finding of
`package=libcurl, installed=8.5.0-r0, fixed_in=8.7.1-r0` inside `registry.example/app:1.4.0`
has no counterpart in the registry's namespace — there is no tag `8.7.1-r0`, and
`app:1.5.0` says nothing about its libcurl. The OCI metadata model carries no package
inventory at any level: an index lists per-platform manifests, a manifest lists layer digests
and media types, a config lists env, entrypoint and `rootfs.diff_ids`, and a layer is a
compressed tar with no table of contents.

Nor does reasoning per layer help, which is the intuition this usually arrives as. A library
does not belong to one layer in any useful sense: a later layer can overwrite the same path and
a whiteout entry can delete it. What a package list describes is the **flattened** filesystem,
which is why Syft catalogues that and not layers individually.

### What is already in place

Registry access is not a new capability class, and this is what makes the proposal small:
`internal/catalog` already reads images straight from a registry (`image.OciRegistrySource`),
already takes credentials from the Docker config the kubelet mounts via Syft's default keychain
without ever reading a Secret itself, and already resolves an index to the configured
`-platform`, reporting a missing platform as its own error kind. **No additional Kubernetes
rights are involved, so the read-only rule of ADR 0001 is untouched.**

`github.com/google/go-containerregistry` is already a direct dependency, and its
`remote.Referrers` implements the OCI referrers lookup including the tag-schema fallback for
registries without the endpoint.

## Options considered

**One registry metadata call.** The shape everyone reaches for first: ask the registry whether
an image exists that has the fixed version, for this platform. Rejected because the question
cannot be posed — see the category confusion above. The call *can* answer "a newer digest
exists under this tag, carrying your platform", which is useful and is part of the chosen
option, but it does not say the fix is in it.

**Parse `config.history[].created_by`.** Build lines sometimes read literally
`RUN apk add --no-cache curl=8.7.1-r0`, which would make a package version readable from
metadata alone. Rejected: with BuildKit, squashed layers, `COPY`-based installs and multi-stage
builds the line is absent or describes a different stage. It is a guess dressed as a fact, and
a wrong negative here suppresses an alert.

**Order tag strings and take the newer one.** Rejected twice over. Tag strings are arbitrary —
SemVer beside CalVer beside `3.1-alpine` beside `stable` — so any ordering is an opinionated
heuristic, and a wrong one manufactures exactly the false alarms this work exists to remove.
More fundamentally it answers the wrong question: ordering tags is a detour around "does the
candidate resolve the finding", which is a version comparison *within one package's* scheme and
is something Grype already performs on every match.

**Enumerate every tag and catalogue each.** The thorough version: list the repository's tags,
catalogue all of them, find any that clears the finding. Rejected on cost for no gain in
answer — a repository can carry hundreds of tags, and a single candidate already answers "is
there anything deployable at all". If the candidate does not clear it, the useful conclusion
("nobody has published a fix, do not wake anyone") is already in hand.

**Inspect layers individually.** Rejected: layers are not an index, and per-layer attribution
is wrong in principle because later layers overwrite earlier ones.

**Trust an attached SBOM.** Rejected outright, and more firmly than an earlier draft of this
ADR managed. That draft called it "the cheap path" on the grounds that its failure directions
are asymmetric — a wrong "a fix is available" costing an operator a look, a wrong "no fix"
suppressing an alert. Under the clearability test they are symmetric: the page fires on the
positive, so a wrong positive wakes somebody who then has nothing to do, which is exactly the
alarm the test exists to forbid. A publisher's SBOM is a claim made at build time and
unverified here; it cannot carry a page in either direction.

**Resolve one candidate, prefer its attached SBOM, fall back to cataloguing, and decide by
matching.** Chosen.

## Decision

Rewritten after the discussion recorded in the amendment below, and after the data from the
first cluster to run the metrics. The earlier draft of this section asked for one candidate at
a configured tag; that does not survive a cluster where every image is pinned.

**A finding may page only if a deployable fix has been verified.** Nothing else in this service
gates a page on a finding, and until this exists, none does (`kbz:req:00001`).

**Scope is configurable, because it is the cost lever.** `-upgrade-scope` takes `exploited`
(default) or `fixable`. The default checks only findings that are known-exploited *and* carry a
fixed version — on the pilot cluster 16 images rather than 41 — because those are the only ones
that could page. The wider mode is chosen, never inherited.

**Candidates are the newest builds that are newer than the running image.** Ordering is by
`created` from the image config, which is a number, and deliberately not by tag string: tag
strings are arbitrary, and every attempt to order them during this design turned into a
heuristic that manufactured wrong answers. "Newer than what runs" covers a pinned tag and a
floating one with the same rule, and it shrinks the candidate set by construction. The newest
`-upgrade-candidates` of them are checked, default 3 — more than one because a recently built
backport is then included, and because a `nightly` consuming a slot no longer distorts the
answer.

**The verdict is an existence proof, not a ranking.** One candidate that clears the finding is
enough: it is definitive, the alarm is valid, and the operator has somewhere to go. The tag is
a label, because "a fix exists" without "and it is over there" cannot be acted on.

**A negative is only as strong as the search.** If no checked candidate clears the finding, that
is published as "none of the candidates checked clears it", with the tags named — never as "no
fix exists". A reader who sees that `nightly` was checked knows what the statement is worth.

**Where the builds cannot be ordered, the answer is `unknown`.** Reproducible builds set
`created` to a fixed value on purpose — ko, Bazel and Nix all do, and this project's own image
is built by ko with nothing overriding it, so it is almost certainly affected. When the running
image's timestamp is the epoch, or every candidate carries the same one, the ordering holds no
information. **That must not become a negative**, because a negative suppresses a page: it is
reported as unknown with its own reason, which says "these builds cannot be ordered, look
yourself".

This degradation is accepted rather than worked around. Measured on five repositories the pilot
installation actually runs — a GitOps controller, a backup operator, an application image and
this service's own two scanners — all five carry usable timestamps, so the exception is real but
not the common case. The fallbacks that would close it are recorded as open questions rather
than built.

### Two layers, and only one of them can be made cheaper

Worth separating, because they look like alternatives and are not — a draft of this decision
presented them side by side and the confusion was immediate:

| | Question | Cost | Can it be made cheaper? |
|---|---|---|---|
| **A** | Which candidates do I check? | the config fetch per tag, small JSON | this is already the floor: `created` sits in a config we fetch anyway. A provenance timestamp is *more* expensive, not less, and is only better where `created` is zeroed |
| **B** | Does a candidate clear the finding? | one SBOM per candidate | no — see below |

Layer B cannot be replaced by an SBOM the publisher attached, and the clearability test makes
that argument stronger than it was. **The page fires on a positive.** A wrong "this tag clears
it" wakes somebody who deploys and finds the finding still there — the promise is broken just
as thoroughly as by a wrong negative. An unverified third-party claim therefore cannot carry a
page in *either* direction, and the only thing that can is a measurement this service made.

So the 19–34 minutes in the cost table are the price of the feature, not an implementation
detail to optimise away. What can be optimised is layer A, and `created` is already its floor.

**Metrics**, one series per digest each, so cardinality keeps following the images (ADR 0001):

- `kiebitzr_image_upgrade_candidate{image_digest, tag}` — how many of that digest's in-scope
  findings the candidate clears. **Zero is a statement, not an absence**: checked, clears
  nothing. The series therefore exists at zero, unlike `kiebitzr_image_risk_score`, where
  absence was the honest answer.
- `kiebitzr_image_upgrade_unknown{image_digest, reason}` — the question could not be answered:
  no tags listable, the index lacks the platform, the registry refused, the builds cannot be
  ordered, or the run ran out of budget. **Unknown is not "no fix".**

**Candidate digests join the cache's keep set.** `prune` currently retains only the digests
that are *running*, so a candidate SBOM would be deleted at the end of every run and rebuilt
the next day. Without this the cost below is paid daily rather than once, which is the
difference between an acceptable feature and an unacceptable one. The consequence is that the
cache grows by the candidates: roughly 2 MB per candidate on the measured figures.

**Candidate work never goes ahead of a running image.** It shares the catalogue budget and the
worker pool of ADR 0009; running images are catalogued first and candidates take what is left,
reporting unknown for the rest. A cluster that cannot keep up with its own images must not lose
its primary metrics to a secondary question.


## Consequences

- A finding could page for the first time. Today none may: an alarm has to be clearable by
  whoever it wakes (`kbz:req:00001`), and `fix_state="fixed"` cannot promise an image anybody
  can roll out, so the urgency signal lives on a dashboard. Verifying deployability is what
  turns "a fix exists somewhere" into "patch tonight" — and it is the only thing that does.
- Cataloguing roughly doubles on a cold start: one extra SBOM per distinct repository, about
  fifty on the pilot cluster, where cataloguing is already the dominant cost. After that the
  digest cache absorbs it, and a candidate only costs again when it moves.
- Registry load gains one tag resolution per distinct image reference per run. Against a rate
  limited registry — Docker Hub above all — that is a real constraint and an argument for a
  long `-interval`, not a reason to skip the feature.
- An unverified third-party claim enters a decision path for the first time in this service. It
  is confined to the candidate question and never touches the published findings of a running
  image, which stay a measurement this service made itself.
- Candidate resolution fails for reasons that have nothing to do with the running image, so it
  gets its own unknown metric rather than more `kiebitzr_scan_errors_total` reasons. A broken
  candidate lookup must not read as a problem with the image in the cluster.
- A candidate that is several major versions ahead is still reported as clearing the finding.
  That is deliberate: the metric states what would fix it, the upgrade decision is not its to
  make.

## How this decision changed

Kept because the wrong turns are the useful part of this record: anybody revisiting candidate
selection will be tempted by the same two detours, and both are named here.

### The candidate tag is the weak point, not the cataloguing

Written before the metrics it depends on were running anywhere. They now are, and the first
real work list says something this decision was not built for.

Every image in the pilot installation is **pinned to an exact version**, and the pins live in
Git and are reconciled by a GitOps controller. Not one image tracks a floating tag.

That undermines `latest` as the candidate in two ways:

- **It often does not exist.** Measured across 55 repositories, 32 of 55 did not resolve at
  all: a publisher that ships version tags only has no `latest`, and the candidate is reported
  as `no_candidate_tag`.
- **Where it exists, it is the wrong question.** The remediation in a GitOps cluster is not
  pulling an image, it is raising a pin in a repository. An operator does not need to know
  whether `latest` is clean; they need to know which *next* tag is, so they can write it down.

This ADR rejected tag ordering as an opinionated detour around "does the candidate clear the
finding". That reasoning still holds — ordering arbitrary tag strings is a heuristic, and the
criterion is a version comparison inside one package's scheme. But the pinning finding moves
candidate *selection* from a detail the decision could avoid to the thing it stands or falls
on. One candidate answers the question only if that candidate is the one an operator would
actually deploy.

**And the cluster may already own the answer.** Image-automation controllers — Flux's
image-reflector and image-automation are the worked example — list tags and order them by a
declared policy, semver, numerical or alphabetical, which is exactly the problem this ADR
called hard, solved by a component whose job it is. A
vulnerability exporter re-deriving it would be the wrong place for it, and a second, weaker
ordering beside an existing one is worse than none.

What remains genuinely valuable, and is not covered by image automation, is the question this
ADR opened with: **would an upgrade help at all, or has the publisher not rebuilt?** On this
cluster 46 % of fixable High and Critical findings sit in application dependencies, where the
answer decides between a tag bump and a vendor conversation. That part does not need a tag
ordering — it needs one named candidate and the existing matcher.

No decision is changed here. The consequence is that **the first increment must not be built on
`latest` as a default**, and that whether the check earns its cost on a pinned cluster is now an
open question rather than an assumption.

## What it costs, in measured units

From the figures in the running runbook: 50 digests cold-start in 20–35 minutes on a Cortex-A72
and produce ~108 MB of SBOMs, so **24–42 s and ~2 MB per image**.

| | SBOMs per run | Cataloguing time | Cache |
|---|---|---|---|
| **Chosen: 3 newest, 16 repositories in scope** | 48 | **19–34 min** | 96 MB |
| Wider scope (`-upgrade-scope=fixable`, ~41 repos) | 123 | 49–86 min | 246 MB |
| Deferred fallback, all tags, 10 tags/repo | 160 | 64–112 min | 320 MB |
| Deferred fallback, 30 tags/repo | 480 | **3.2–5.6 h** | 960 MB |
| Deferred fallback, 100 tags/repo | 1600 | **10.7–18.7 h** | 3.2 GB |

The chosen shape costs about one extra cold start, once, and then only when a candidate moves.
The default scope is what keeps it there.

Registry requests are not the constraint: one tag listing per repository plus a config fetch per
tag, all small JSON and no layers. Cataloguing is.

**The fallback's cost is unknown, not merely high.** It scales with tags per repository, and
nobody has measured that for a real cluster. At 30 tags per repository it already exceeds the
two-hour `-run-timeout` on the hardware this service is sized for, which is why it is deferred
rather than offered as an option. Measuring tags per repository is the prerequisite for
reconsidering it, and the probe in `internal/upgrade` is where that measurement belongs.

## Amendment: the page this was the precondition for now exists

This ADR's argument was that no finding may page until deployability can be verified, and that
verifying it is therefore not an efficiency improvement but a precondition. The check has been
in force since `565fdca`; the consequence has now been taken, and it belongs here rather than
only in a runbook.

`KiebitzrExploitedAndDeployable` is in the metrics runbook's alert set: exploited in the wild, a
fix available, and `kiebitzr_image_upgrade_candidate > 0` — a candidate that was catalogued and
matched and does clear it. The `tag` label is the move, which is what makes the condition
clearable by whoever it wakes.

Three properties of that rule follow from this ADR and are not incidental:

- **It cannot fire where the check is off**, because the metric then has no series. No
  verification, no page.
- **`unknown` does not fire it.** A digest nobody could look at is not a negative, which is why
  it is a separate metric and not a zero.
- **It still needs `known_exploited`**, independently of the candidate. Under
  `-upgrade-scope=fixable` a candidate may clear High findings nobody is exploiting, and a
  backlog getting smaller is not a reason to wake anybody.

`KiebitzrExploitedAndFixable`, the rule this replaces, stays withdrawn in its old form: it
asked the same question of an advisory instead of of an image.

## Open questions

- **Trust in a foreign SBOM, particularly a negative answer.** Letting an attached SBOM
  establish "no fix available" would let a publisher's omission silence an alert. The
  conservative rule — a referrer SBOM may establish a fix, but only our own cataloguing may
  establish its absence — costs most of the saving and should be measured before it is adopted.
- **Which tag a pinned cluster should be asked about**, now the decisive question rather than a
  detail — see the amendment. Candidates worth weighing: a per-repository tag, the tag the pod
  already asks for re-resolved (which catches a moved tag and nothing else), or deferring
  selection to the image automation that a GitOps cluster already runs and only answering
  "does this named candidate clear it".
- **Whether the check earns its cost at all where every image is pinned.** If the upgrade path
  is a pull request against a Git repository and image automation already proposes it, the
  remaining value is narrower than this ADR assumed: it is the vendor question — has anybody
  published a fix — and not the deployability question. Narrower is not zero, but it is a
  different feature and should be costed as one before increment 4 is built.
- **Whether one candidate is enough.** If `latest` lags, or a repository's convention puts
  current builds elsewhere, a single candidate answers "no" where "yes" was true. Whether a
  second candidate earns its cost is a question for real data, not for this document.
- **The fallback for repositories whose builds cannot be ordered.** The degradation is accepted
  for now: unknown, with a reason. Three ways out are recorded rather than built, in the order
  I would weigh them: check *all* tags where ordering fails, which is definitive but costs what
  the table above shows; read `buildFinishedOn` from a BuildKit provenance attestation, which
  orders reliably where `created` is zeroed but costs *more* than `created` rather than less,
  and only exists where attestations do — the probe already measures that; or a
  per-repository candidate override, which costs nothing to build and some maintenance to use.
  Comparing tag strings as versions was weighed and rejected: it reintroduces exactly the
  semantics every other part of this decision avoids.
- **Whether to verify the signature of an attached SBOM**, and what trust roots that would
  require in a service that currently holds none.
- **Whether `no_candidate_tag` can be told from `unreachable` at all on every registry.** It is
  decided by the HTTP status, and that only works where a registry answers `404` for an unknown
  tag. `ghcr.io` answers `401` for an unknown tag, an unreadable package and an absent package
  alike — measured against it, not assumed — so a missing tag there arrives as `unreachable`
  and sends an operator looking for a credential that is fine. Whether the error codes inside
  the response body (`MANIFEST_UNKNOWN`, `NAME_UNKNOWN`) are carried consistently enough to
  recover the distinction is worth finding out before adding a reason for it.
- **How this interacts with digest-pinned pods** in practice. The repository is known, so a
  candidate resolves, but an operator who pins by digest may want the question asked against a
  tag family rather than against `latest`.
