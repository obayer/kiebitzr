---
id: kbz:req:00001
title: The Decisions This Service Has to Serve
date: 2026-11-12
status: active
tags:
  - conventions
  - metrics
  - vulnerability-scanning
related:
  - id: kbz:adr:00001
    reason: The design that follows from these decisions, and the constraints it accepted
  - id: kbz:runbook:00001
    reason: Where each served decision is turned into a query
  - id: kbz:adr:00011
    reason: A proposal this document is the test for, and which it currently fails
  - id: kbz:adr:00012
    reason: Serves decisions 2, 3 and 4 — the filters' silence counted, and findings named by source package and file
  - id: kbz:adr:00013
    reason: Proposes decision 8, and is where the sharpening that a request is not a clearance is applied
---

# The Decisions This Service Has to Serve

## Vision

> Somebody who runs a cluster because it should carry services — not because it is their job —
> spends **minutes a week** on vulnerabilities rather than hours, and still does not watch the
> platform rot or lose a service to a hole that was already known.

The audience in order: the single operator of a small cluster; then somebody who already runs a
scanner and is drowning in its output; then small development teams on a managed cluster, where
an operator-and-CRD deployment is not just complexity but a line on an invoice.

## Mission

> Kiebitzr reports the known vulnerabilities of the images a cluster **actually runs**, as
> Prometheus metrics, arranged so that **one person** can decide what to act on. One read-only
> permission, and a footprint that goes unnoticed on a small node.
>
> It **reports and does not act**: no remediation, no restarts, no CRDs, no admission control.
> What to do is decided and done by a person.

That last paragraph is not modesty, it is what makes the footprint possible. A tool that
remediates needs the right to change workloads, and a tool that annotates needs the right to
replace a running pod's image — which is the right that makes installing it a risk rather than
a decision. Giving those up is what buys the single permission.

## The principle that decides design questions

> **Silence you can believe.** When Kiebitzr says nothing, there is nothing to do — and that may
> be assumed without checking.

The vision says why somebody installs this. The principle settles arguments. Everything that
looks over-careful in this repository follows from it: `kiebitzr_image_pending` is a series
rather than an absence, there is no alert on severity alone because it saturates,
`kiebitzr_build_info` exists because a binary predating a metric publishes nothing for it, and
an unexplained failure gets no series rather than a plausible-looking wrong one.

A scanner whose silence means nothing produces exactly two states, and the persona above ends
in one of them: panic, or numbness. Neither is a service.

### The test for anything that may page

> **An alarm must be clearable by whoever it wakes.** A condition no action of theirs ends is
> not an alarm, it is a state — and a state belongs on a dashboard.

Duration is not the test; **clearability** is. An alarm may burn for three days if the person
woken could have ended it and chose not to. It must not burn at all if no action of theirs ends
it, because such an alarm gets silenced, and a silenced alarm protects nothing.

Applied to findings, the test sorts them without judgement:

| Condition | Does the recipient's action end it? | |
|---|---|---|
| exploited, and a deployable fix exists | yes — raise the pin | **alarm** |
| exploited, no fix published anywhere | no — a mitigation does not change the finding | **state** |
| exploited, fix exists only as a package version | no — it cannot be reached | **state** |

#### A request is not a clearance

The test says "an action of theirs". It has to be said what that excludes, because the obvious
reading is too generous and would let almost anything page.

A finding in an image built by a team one can walk over to in the morning *looks* clearable:
there is something to do, and doing it leads to a fix. It is still a **state**. What the
recipient can do is make a request; whether the condition ends depends on another party's
decision and calendar. Asking is not ending.

Duration is still not the test — the three-day alarm above stands. The line runs between
**ending a condition** and **starting a process whose completion somebody else controls**.
Everything on the far side of that line belongs on a dashboard, in daylight, however real the
action is. ADR 0013 is where this is applied: it classifies images by who can get a build of
them, and deliberately does not make the reachable class page.

The consequence was uncomfortable and it held for most of this project's life: **until
deployability can be verified, this service may page about its own health and about nothing
else.** A finding-based page cannot meet the test on `fix_state="fixed"` alone, because that
names a fixed version in an advisory and not an image carrying it. Decision 7 below was
therefore never an efficiency improvement; it was the precondition for any finding ever paging.

**It has since been met, and exactly one finding alert exists.** Where the candidate check runs,
"exploited, fixable, and an image measured to clear it" is ended by the recipient raising a tag,
so it is an alarm — `KiebitzrExploitedAndDeployable`, with the tag in the label. The test was
not relaxed to get there; the missing measurement was built (ADR 0011).

## Why this document exists

It exists because a feature was designed, costed and half-built before anybody asked how
often the problem it solves occurs. Two increments of code and an ADR went into answering
"is a fix deployable" with no measurement of how often that question blocks anyone.

That was not a failure of care. It was a missing document: there was nothing in the repository
stating what this service is *for* in a form a proposal could be tested against. The README
says what it does and what it is not; the ADRs say why it is built that way. Neither says which
decisions an operator makes, nor which of them are already served.

## The operator's actual loop

Once a day or once a week, somebody looks at the metrics and makes **one of three choices**:
act now, act later, or do nothing. Everything this service publishes is only worth publishing
insofar as it makes one of those choices better.

## The decisions, and whether they are served

| # | The decision | Served? | Evidence |
|---|---|---|---|
| 1 | **Is what I am looking at valid?** Is the scan fresh, did it complete, which build answers | **yes** | `kiebitzr_last_success_timestamp_seconds`, `_db_built_`, `kiebitzr_build_info`. The last one was added after a diagnosis that took a day because the deployed binary predated a metric (ADR 0010) |
| 2 | **Is anything unexamined?** Not "clean" — unlooked-at | **yes** | `kiebitzr_image_failed` with the stage, `kiebitzr_image_pending`, and the absence of `kiebitzr_image_risk_score` as its own signal. Since ADR 0012 this covers the silence the service produces on purpose as well: `kiebitzr_vulnerability_suppressed` counts what each filter removed, so a too-broad ignore rule is a number and not a quiet screen |
| 3 | **Must I act tonight?** | **yes** | `known_exploited` and the risk score. On the pilot cluster: 16 of 50 images, where severity alone said 41 of 50. `location` (ADR 0012) names the file, so a toolchain finding points at a binary instead of at a version string — measured: the `stdlib` findings nobody could place all sat in one statically linked helper binary, in three images |
| 4 | **Is this mine to fix, or a publisher's?** | **yes** | `package_type`. Measured: 46 % of fixable High and Critical findings are application dependencies, where no tag bump helps. `source_package` (ADR 0012) puts the count in the unit of the fix: one advisory against openssl, not one per binary package built from it. Measured on the cluster: 3,635 findings to read became 1,223 things to fix |
| 5 | **Where is the affected image running?** | **yes** | `kiebitzr_image_info`, joined on `image_digest`, at workload-and-container granularity |
| 6 | **What do I pin instead?** | **no** | — |
| 7b | **Is something drifting behind without anything telling me?** The stuck-automation case | **partly** | one half is now a query: a tag running at two digests is a node that never re-pulled, in the runbook's triage section and on the dashboard. The other half — a tag that has moved on in the registry — still needs reading the versions in `kiebitzr_image_info` by hand, which is how it was found. Nothing pages either way. See the operational findings below |
| 7 | **Does a fix exist in any image at all, or has the publisher not shipped it?** | **yes, where it is switched on** | ADR 0011, in force: `kiebitzr_image_upgrade_candidate` names the tag and how many findings it clears, `0` is a measured negative, and `kiebitzr_image_upgrade_unknown` says when nobody could look. Off by default, because it costs registry requests and SBOMs. By the clearability test above, this was **the precondition for any finding ever paging** — and it is now met wherever the check runs. Whether to use it that way is the open product question below |
| 8 | **Can anybody here get a build of this image at all?** Not "is the finding mine to fix" — "does a person exist who decides what goes into this image, and do I reach them" | **no** | Nothing distinguishes an image built by one's own team from one built by a project nobody here can reach. The right-hand half of decision 4 is therefore one undifferentiated bucket, and it hides a work list: the images where no newer build exists *because nobody has built one yet*. ADR 0013 proposes it |

Decisions 1 to 5 are served and in production, 7 is served wherever it is switched on, 7b only
by inspection, and 6 and 8 are not served at all.

**That consequence has been taken.** The paragraph above said this service may page about its
own health and nothing else *until deployability can be verified*. It can be verified now, so
the first finding alert in this project's life is in the metrics runbook:
`KiebitzrExploitedAndDeployable` — exploited in the wild, a fix available, and a candidate image
measured to clear it, with the tag to deploy in the label.

It is one rule and deliberately narrow. It fires on a measurement rather than on an advisory, it
cannot fire at all where the candidate check is switched off, and an `unknown` answer does not
fire it. Everything else about findings stays on the dashboard. The clearability test has not
been relaxed — the precondition it named was simply met.

How often either *blocks* anyone is still unmeasured, and for decision 6 that is the open
question. For decision 7 it stopped mattering: the clearability test does not care how often an
unclearable page fires, because one occurrence is enough to teach its recipient to silence it.

## What a proposal has to show

A change that adds or extends what the service can do names:

1. **Which decision above it serves**, or the new decision it adds to the table.
2. **Evidence that the decision is currently unserved or served badly** — a measurement, a
   failed query, a diagnosis that cost time. Not a plausible story.
3. **What it costs**, in the units this service is sized in: registry requests per run, SBOMs
   per run, series per image.
4. **How it will be known to have worked** — the number that should move.

ADR 0011 was held by requirement 2 and then released by it. Held first, because nobody had
counted how often decision 7 blocks anyone; released, because the clearability test supplies
the evidence in a stronger form — frequency is irrelevant to a page that cannot be cleared.

Both halves are the test working. It stopped a feature from being built on a guess, and then
let it through on a reason that holds. What it did not do is decide that the feature should be
built: that turns on whether this service should page about findings at all, which is a product
question and is recorded nowhere yet.

## What operating it has actually turned up

Kept because this is where the table above is supposed to come from — the betting record of
this document. An entry here beats any amount of reasoning about what an operator might want.

**2026-11-12 — a stuck automatic updater, found on the first day of real data.** An automatic
updater on the pilot cluster had been sitting on a 12.x line while 13.x was published, and
several findings were very likely fixed in the newer line. It showed in the metrics as three
versions of the same component running side by side, visible in the `image` label of
`kiebitzr_image_info`, which is also how it was noticed.

Two things follow, and the second is the more useful.

It is the first evidence for decision 7's neighbourhood, and in the *stronger* direction: not
"no fix exists" but **"a fix exists and nobody noticed"**. That is what ADR 0011's candidate
check finds without anybody looking, which is its argument rather than the one I had been
making.

And it is a decision the vision did not contain. The failure imagined there was an operator
with no time; the failure observed was **automation that does not report that it has stopped**.
Those are different, and the second one is probably common — an updater that fails quietly
looks exactly like an updater with nothing to do. It is now 7b in the table.

**2026-11-13 — the two new labels, measured on the cluster rather than argued about.** First
real data for ADR 0012, and it moved in both directions.

`source_package` was sold as roughly halving the count an operator has to read. It cut it by
**two thirds**: 3,635 distinct `(cve, package)` pairs against 1,223 of `(cve, source_package)`,
over about 11,100 findings. The estimate was conservative because the pilot's breakdown only
showed curl and openssl twice each; a whole cluster has that pattern everywhere.

`location` cost less than it was feared to, and the second estimate was wrong in the same
direction as the first. The design argument allowed for an image with several binaries on one
toolchain multiplying its series fivefold, and that shape exists — one image carries four Go
binaries on two toolchains. But the per-image factor is not the price: the images with the
highest factors are small, so across the cluster the label cost **344 series of 11,099, 3.2 %**.

And it answered the question it was built for. The analysis that produced the item could see
thirty-odd `stdlib` findings and only guess which binary carried them. The answer was one
statically linked helper binary under `/usr/local/bin`, in three separate images, which is what
the guess had said — the difference being that it is now a label and not a hunch.

The lesson for the next proposal is not "the estimates were wrong". It is that **both estimates
were wrong in the direction of the thing being more worth doing than it looked**, and that the
cheapest way to find that out was to ship it and run one query.

**2026-11-13 — half the fleet has a telephone, and the metrics do not know it.** Going through
the images of one cluster by hand, they fell into two groups that nothing here distinguishes.
For some, the only remedy is a different image from a project nobody here can reach. For others
— built by the operator's own team, or by a team two doors down — a rebuild is an available
action even when no newer image exists yet, because the action is *causing* one to exist.

Three things follow.

It is a decision the table did not contain, now 8. `package_type` answers "is this finding mine
to fix"; this asks "is this *image* one anybody here can get a build of", which is a property of
the image and not of the finding.

It cannot be detected, only declared, and the example that settles that is small: two
repositories in one namespace of one registry, one built by the operator's own team and one by
another team. Same publisher, same CI, same signing identity. Nothing in or around the image
tells them apart; only the question of which humans decide does.

And it sharpens the clearability test rather than stretching it. The morning walk to another
team is real work with a real outcome, and it is still not a page — what the recipient can do
is ask, and asking is not ending. The paragraph *A request is not a clearance* above was written
for this, and it is the reason the proposed classification deliberately does not page.

**What this service will not do about 7b**, so the boundary is stated rather than discovered
later: drift that carries no security difference stays invisible here. The candidate check
surfaces a newer build only when that build *clears a finding*. A component three minor
versions behind with no CVE between them is an update-tracking question, and this is a
vulnerability exporter — see the mission.

## The measurements that are open

Neither can be answered by reading code or asking a registry. Both need the service operated.

- **How often decision 7 actually blocks.** Of the images with an exploited, fixable finding,
  how many have no deployable fix anywhere? The cheapest measurement is the work itself: clear
  the current list by hand and count where you hit a wall. This no longer decides whether ADR
  0011 is built — the clearability test settled that — but it does say how much the dashboard
  currently misleads, and therefore how urgent the work is. One data point so far, and it fell
  the other way: a fix existed and had been missed.
- **Whether the alert set causes fatigue.** All but one rule is about the scanner's own health
  and each is designed to be silent for weeks. Only time tells; a month of operation is the
  measurement. If even these fire often enough to be ignored, the problem is not the thresholds
  but that this service is not yet trustworthy enough to page at all. The exception —
  `KiebitzrExploitedAndDeployable` — is the one to watch hardest, because it is the first rule
  here that wakes somebody about a finding, and the whole clearability argument is a prediction
  that it will be cleared rather than silenced.

## Non-goals

In the README under *Where this fits, and where it doesn't*, and not repeated here. The short
form: one read-only permission, cheap at any cluster size, operable by one person — and nothing
that needs a second permission to deliver.
