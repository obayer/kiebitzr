---
id: kbz:adr:00013
title: Declare Whether a Rebuild Can Be Asked For, Per Image
date: 2026-11-13
status: proposed
tags:
  - metrics
  - prometheus
  - vulnerability-scanning
  - architecture
related:
  - id: kbz:adr:00010
    reason: The other ownership axis — package_type is a property of the finding, this is one of the image
  - id: kbz:adr:00011
    reason: Its candidate answer is what splits a reachable image into "roll it" and "go and ask"
  - id: kbz:adr:00007
    reason: The configuration shape this follows, including a malformed file being a start-up error
  - id: kbz:req:00001
    reason: Adds a decision to its table, and relies on the sharpening that a request is not a clearance
  - id: kbz:runbook:00001
    reason: Its "not your move" bucket is the one this splits, and where the example rules would live
---

# Declare Whether a Rebuild Can Be Asked For, Per Image

## Status

`accepted`. The requirements come from a working session with the operator of the pilot
cluster. What remains under *Open questions* is deliberately deferred: none of it decides a line
of code, and each would be answered better after operating this than before.

## Context

An operator's images fall into two groups that this service currently treats as one.

**Images nobody here can influence.** Pulled in by a Helm chart or a manifest, built by a
project or a vendor with no relationship to the cluster. The only remedy is a different image:
raise the tag, or replace the component. For these, what matters is whether a fix exists
somewhere — which is what ADR 0011 answers.

**Images somebody here can get a build of.** Built by the operator's own team, or by a team in
the same organisation. Here a rebuild is an available action even when no newer image exists
yet, because the action is *causing* one to exist.

`package_type` (ADR 0010) does not separate these. It is a property of the **finding** — would
a tag bump carry the fix, or does it take a rebuild by whoever publishes the image. The group
above is a property of the **image** — can anybody here get that rebuild. The two are
orthogonal, and only together do they answer whether an action exists at all:

| | distro package | application dependency |
|---|---|---|
| **nobody reachable** | raise the tag | nothing — wait for the publisher |
| **somebody reachable** | raise the tag | ask for a rebuild, then roll it |

Today the whole right-hand column is one bucket. The metrics runbook spells it out — *"Not your
move, unless you publish that image. Chase the vendor, or your own CI"* — and so knows the case
exists, while giving it the same treatment as a finding in a public database image. For an
operator whose own organisation publishes a meaningful share of what runs, that is wrong for
half the fleet, and it is wrong in the direction that produces inaction.

### The fact this rests on

Two repositories from the operator's own fleet, in one namespace of one registry:

- `registry.example/org/platform/*` — built by the operator's own team.
- `registry.example/org/billing/*` — built by another team in the same organisation, reachable
  by walking over in the morning.

They are published by the same organisation, by the same CI, and would carry the same signing
identity. **Nothing in or around the image distinguishes them.** The difference is which humans
decide what goes in, and that is not a property this service can read, derive or verify. It can
only be declared — and the design follows from that, not from a preference for configuration.

## Options considered

**Classify by registry host.** `registry.example` is ours, everything else is not. Rejected on
the operator's own counter-example: an organisation that publishes open-source software uses
the same public registry it pulls third-party images from. The host says nothing about who
decides.

**Classify by organisation or namespace prefix.** One level finer, and still wrong: the two
repositories above share a namespace and belong in different classes. Keeping a namespace rule
as a *default* while allowing more specific rules to override is part of the decision below;
using it as the only granularity is not.

**Derive it from the signing identity.** The images here are built with keyless signing
(ADR 0002), so "built by our CI" is in principle verifiable rather than asserted, and a verified
classification cannot rot. Rejected for two independent reasons. It would get the load-bearing
case wrong — both repositories above are signed by the same identity, so it cannot tell `own`
from `reachable` at all. And signing cannot be relied on across a fleet: an unsigned image would
be indistinguishable from an unreachable one, which turns a missing signature into a silent
demotion.

**A derived metric, `kiebitzr_image_actionable`.** Rejected for the reason ADR 0010 rejected the
same shape: it compiles our reading into a number a consumer can neither see nor dispute, and it
cannot be re-cut when the question changes. A label can be grouped any way a later question
needs.

**A flag deciding whether these images may page.** Rejected, and this one corrects the
first draft of this proposal. The service reports and does not decide (mission in
`kbz:req:00001`). Whether a class of images is worth waking somebody for is a property of an
installation, expressed where alerting is expressed — in the rule. Several metrics form an
indicator; the indicator carries the alert. Putting it in a flag here would move a Prometheus
decision into a Go binary and make it un-overridable by the person it belongs to.

**A declaration, carried as a label on `kiebitzr_image_info`.** Chosen.

## Decision

### The label

`kiebitzr_image_info` carries **`build_access`**, with four values:

| Value | The test | What it means operationally |
|---|---|---|
| `own` | the build can be triggered inside my own responsibility boundary, without asking anybody outside it | rebuild and roll |
| `reachable` | a build needs a decision by somebody outside that boundary, and I can reach that somebody with a reasonable expectation of being heard | ask, then roll |
| `none` | there is nobody I can ask in that sense | a newer tag, or replace the component |
| `unknown` | nobody has classified this image | classify it |

The boundary in `own` is **organisational, not personal**: a team, not a person. That is what
makes it survive someone going on holiday or leaving, and what makes it change exactly when a
component is handed to another team — an event people notice, which is the only reliable trigger
for reclassifying.

**What `reachable` is not.** A public issue tracker is not reachability. The operator's own
example is a large open-source project whose images they run: they could file an issue, and the
class is still `none`. The test is whether an obligation or a relationship exists, not whether a
channel exists. Without that line the class covers everything and says nothing.

**It is not `owner`.** `kiebitzr_image_info` already carries `owner_kind` and `owner_name`,
which mean the Kubernetes controller of the pod. A second "owner" with an unrelated meaning in
the same metric would be a trap for every query written after it.

### The configuration

A file of rules, named by `-build-access-file`, in the shape `-ignore-file` established:

```yaml
build-access:
  - repository: registry.example/org/platform/*
    access: own
  - repository: registry.example/org/billing/*
    access: reachable
  - repository: registry.example/org/platform/legacy-service
    access: none
```

- **A pattern is a repository path**, either exact or ending in `/*`. Matching is **by path
  segment**. Partial-segment globs are deliberately not supported: `…/foo/bar*` would also match
  `…/foo/barbaz`, which is the kind of near-miss nobody notices until it misclassifies.
- **The most specific match wins**, measured in segments. A namespace-wide rule is therefore a
  default that individual repositories override, which is what the fleet above needs.
- **Two patterns of equal specificity matching one repository are a start-up error**, not a
  silent first-wins. ADR 0007's rule: a malformed configuration fails loudly rather than being
  quietly reinterpreted. (TODO T7 questions that rule in general; if it changes, this changes
  with it.)
- **What no rule matches is `unknown`**, never `none`.
- **Matching is against the normalised repository** — what this service would pull from, not the
  spelling in the pod spec. A pod may say `nginx:1.2`, `docker.io/library/nginx:1.2` or
  `index.docker.io/library/nginx@sha256:…` for one image; a rule written once has to catch all
  three. The `image` label keeps the spelling the pod asked for, because that is what makes a
  drifted tag visible; the classification does not use it.
- **A `/*` pattern matches descendants, not the prefix itself.** A detail with no product
  content, settled by a test rather than by a reader's assumption.

**Broad catch-all rules to `none` are documented as an anti-pattern.** Writing
`registry.example/* → none` buys a quiet dashboard by declaring ignorance to be a decision: every
image pulled in afterwards falls silently into "nothing can be done here". Leaving it `unknown`
makes new arrivals a short, visible work queue instead — the same reason
`kiebitzr_image_pending` is a series rather than an absence. The honest list declares only what
has actually been decided.

### With no configuration at all

Every image is `unknown`, and the label is on every `kiebitzr_image_info` series regardless.

The tempting alternative — leave the label out until a file is configured, the way the upgrade
metrics have no series at all while switched off (ADR 0011) — does not work here and should not
be attempted. `kiebitzr_image_info` exists for every running container whether this axis is in
use or not, and a metric's label set is fixed by its descriptor. Making it depend on
configuration would mean one metric with two schemas, so a query would have to cope with a
label that exists in one installation and not in another. `unknown` carries that meaning
without the ambiguity.

**That makes the upkeep measurable, which is the honest trade.** This axis is declared and not
detected, so it is worth exactly as much as its maintenance — and in exchange it costs no
requests, no SBOMs and no start-up time, and an installation that wants none of it simply has
`unknown` everywhere and loses nothing it had before:

```promql
# The classification backlog: images nobody has sorted yet.
count(kiebitzr_image_info{build_access="unknown"})

# Which ones, so the list is actionable rather than a number.
count by (image, namespace, owner_name) (kiebitzr_image_info{build_access="unknown"})
```

It is also the first number here about the *operator's* diligence rather than the scanner's
health, and it belongs in daylight for that reason: it is clearable — by editing a file — but
nobody edits a classification file at 03:00.

One limit, so it is not oversold: `unknown` catches images **nobody has classified**, which is
mostly new arrivals. It cannot catch a classification that was right and has quietly gone wrong
— a team dissolved, a component handed over. That is what the expiry question under *Open
questions* is about.

### What this does not do

**It does not decide what pages.** The metric states a fact about an image. The runbook will
carry example rules, as it does today, and an installation combines the facts it wants into an
indicator and puts an alert on that.

The operator's own reading, recorded because it is what the examples below assume: a page is
worth it only where *they* can end the condition by deploying a different image. Everything
else — including the reachable case — is a daytime queue, because at 03:00 nobody walks into
another team's office. That reading is an application of the clearability test and does not have
to be shared by every installation, which is exactly why it lives in a rule.

### What it makes possible, with ADR 0011

For a `reachable` image, the candidate check already separates the two lives of the same
finding, and today both land in the same bucket:

```promql
# A build exists and is not running here. Their part is done; raise the tag.
(kiebitzr_image_upgrade_candidate > 0)
* on (image_digest) group_right () kiebitzr_image_info{build_access=~"own|reachable"}

# Nobody has built it yet. This is the list to walk over with, in the morning.
(kiebitzr_image_upgrade_candidate == 0)
* on (image_digest) group_right () kiebitzr_image_info{build_access="reachable"}
```

The second query is the whole point of the proposal: it is a work list that exists in every
such cluster today and that nothing currently shows.

## Consequences

- **No new series.** The value is a function of the repository, which is already part of
  `image`, so it splits nothing that `kiebitzr_image_info` did not already split. No registry
  requests, no SBOMs.
- **A new maintenance surface that the service cannot validate.** A classification that has gone
  stale — a team dissolved, a component handed over — cannot be detected here. The only defence
  is that the classification is *queryable*: it is a label, so "which images claim to be
  reachable" is one query, and `unknown` names what has never been looked at. A wrong
  `reachable` costs a wrong dashboard bucket rather than an unclearable page, because this axis
  does not page.
- **The runbook's "your move / not your move" split gets re-cut.** For an `own` image the
  distinction largely dissolves: whether the finding sits in a deb or in a vendored library, the
  remedy is a rebuild this team can trigger. `package_type` keeps its meaning for `none`, where
  the question is whether a newer tag is likely to carry the fix.
- **`package` and `location` (ADR 0012) earn their keep here.** They are execution labels: which
  package in the Dockerfile, which file in the image. That is only actionable where the build is
  reachable, which is also the honest statement of how much they are worth to an installation
  that builds none of its images.
- **One more label on `kiebitzr_image_info`.** Queries matching a subset of labels are
  unaffected; a query pinning the full label set breaks. Same consequence as ADR 0008 and 0010,
  and by now a standing one.

### A digest under two references

The same image can be pulled from a vendor and from an internal mirror, and `kiebitzr_image_info`
then carries two series for one digest with two different classifications. This needs no
decision in the code: the label is a function of the reference, and each series carries its own
correct value.

Only an aggregating query has to choose, and the runbook says which way: **the more generous
classification wins**, because the question being asked is whether an action exists at all. One
reachable route to a rebuild is enough, however the image also arrives.

## Open questions

- **Whether a declaration should expire.** `.vulnguard.yaml` makes an accepted vulnerability
  carry a review date for exactly this reason. The same could apply here, at the cost of a
  recurring chore that nothing enforces. Undecided; `unknown` covers only images nobody has
  classified, not classifications that have quietly gone wrong.
- **Whether `own` and `reachable` need different treatment beyond the queries above**, or whether
  the repository name in the work list is enough context for a human to know which door to knock
  on.
- **Whether the axis should also cover deployment control** — who decides which tag this cluster
  runs, as opposed to who builds it. For the operator here both are the same person; in an
  organisation with a platform team and application teams they are not.
