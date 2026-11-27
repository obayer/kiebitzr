---
id: kbz:runbook:00001
title: Reading the Metrics
date: 2026-11-05
status: active
tags:
  - metrics
  - prometheus
  - vulnerability-scanning
related:
  - id: kbz:adr:00001
    reason: Decided this metric set and the cardinality it is built around
  - id: kbz:adr:00008
    reason: Added the exploitation evidence the urgency half of the triage section rests on
  - id: kbz:adr:00010
    reason: Added package_type and the reasoning behind the triage section and the alert set
  - id: kbz:adr:00011
    reason: Proposes answering the third meaning of "a patch exists", which this document records as unanswered
  - id: kbz:runbook:00002
    reason: What the service needs to run before there is anything to read
  - id: kbz:req:00001
    reason: The decisions each triage query serves, and the clearability test the alert set applies
  - id: kbz:adr:00012
    reason: Added the suppression metric, source_package and location, and the cardinality the last of them costs
---

# Reading the Metrics

Everything Kiebitzr has to say is on `/metrics`. This is how to ask it questions: which
container is affected by a finding, what is worth acting on, and whether the scanner is still
telling the truth.

## What is exported

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `kiebitzr_vulnerability` | gauge, always `1` | `image_digest`, `cve`, `severity`, `package`, `source_package`, `package_type`, `installed`, `location`, `fixed_in`, `fix_state`, `known_exploited` | one known vulnerability in one running image digest |
| `kiebitzr_vulnerability_suppressed` | gauge | `image_digest`, `reason` | how many findings of that digest a configured filter removed in the last run. **No series means nothing was removed** |
| `kiebitzr_image_info` | gauge, always `1` | `image_digest`, `image`, `namespace`, `owner_kind`, `owner_name`, `container`, `build_access` | one container running one digest — this is where "where" lives |
| `kiebitzr_image_risk_score` | gauge | `image_digest` | the highest risk score among that digest's findings, 0 to 100 |
| `kiebitzr_image_failed` | gauge, always `1` | `image_digest`, `reason` | one digest the last run could not analyse, and the stage it failed at |
| `kiebitzr_image_pending` | gauge, always `1` | `image_digest` | one digest the last run had not catalogued yet when it published |
| `kiebitzr_images` | gauge | `state` | digests the last run catalogued, took from the cache, failed on, or did not reach |
| `kiebitzr_catalogue_queue_depth` | gauge | — | cataloguing work outstanding right now; only exists with a worker pool (`-catalogue-locally=false`) |
| `kiebitzr_last_success_timestamp_seconds` | gauge | — | when a run last completed; `0` means never |
| `kiebitzr_db_built_timestamp_seconds` | gauge | — | when the vulnerability database in use was built |
| `kiebitzr_run_duration_seconds` | gauge | — | how long the last completed run took |
| `kiebitzr_scan_errors_total` | counter | `reason` | errors by cause; every reason exists from the start, at `0` |
| `kiebitzr_build_info` | gauge, always `1` | `version`, `commit`, `grype_db_max_age` | which binary is answering — served by matchers and workers alike. `grype_db_max_age` is the oldest database the build's Grype accepts, and so the ceiling `-db-max-age` plus `-interval` has to stay under; `none` on a worker, which holds no database. It is here because the limit is Grype's: an image update can lower it and refuse a configuration that started yesterday, and this is where that is visible before somebody restarts the pod |
| `kiebitzr_image_upgrade_candidate` | gauge | `image_digest`, `tag` | how many of a digest's in-scope findings the best candidate image clears. **`0` is an answer**, not an absence |
| `kiebitzr_image_upgrade_unknown` | gauge, always `1` | `image_digest`, `reason` | the deployability question could not be answered. **Unknown is not "no fix"** |

Workers (`-role worker`) export a different, much smaller set — `kiebitzr_worker_images_total`
by `outcome` and `kiebitzr_build_info`, plus the Go and process collectors. `kiebitzr_build_info`
is on both roles on purpose: a pool where one pod lags a rollout behind the others is otherwise
invisible. They deliberately do **not** serve any of the other metrics above: a worker publishing `kiebitzr_last_success_timestamp_seconds` as `0` would read
exactly like a matcher that has never completed a run, and `KiebitzrNotScanning` would fire
once per worker. Scrape them if you want worker throughput; the state of the scan is on the
matcher.

The Go runtime and process collectors are registered as well, so `process_resident_memory_bytes`
and the `go_memstats_*` family are available for the resource questions.

### Label values you can rely on

- `severity` — `Critical`, `High`, `Medium`, `Low`, `Negligible`, or `Unknown` when the source
  states none. **Capitalised**, because that is what the vulnerability record says. The
  `-min-severity` flag takes the lowercase name; the label does not.
- `fix_state` — `fixed`, `not-fixed`, `wont-fix`, `unknown`. Read it as "a fixed *version*
  exists", not as "you can fix this" — see the triage section below.
- `tag` on `kiebitzr_image_upgrade_candidate` — the candidate that cleared the most, so you
  know where to go. **Empty** means no candidate existed because the running image is already
  the newest build, which is why the series is still there at `0`.
- `reason` on `kiebitzr_image_upgrade_unknown` — `no_tags`, `unorderable_builds`,
  `platform_missing`, `unreachable`, `not_catalogued`. Only `unorderable_builds` needs
  explaining: reproducible builds set the image's creation time to a fixed value on purpose, so
  the builds of that repository cannot be put in order and no negative is earned there.
- `source_package` — the package the affected one was built from: `openssl` for both `libssl3`
  and `libcrypto3`, `curl` for both `curl` and `libcurl`. **A package that is its own source
  carries its own name**, never an empty value, so grouping by it is correct for every finding
  and not only for the distribution ones. `package` stays beside it: the source package is what
  you fix, the binary package is what is installed.
- `location` — the path of the affected artefact inside the image. For a distribution package
  it is the package database (`/lib/apk/db/installed`, `/var/lib/dpkg/status`) and says nothing
  beyond "this image has a package manager"; for a binary or a language package it **names the
  file**, which is what turns thirty findings against `package="stdlib"` into a list of
  binaries. `unknown` where Syft recorded no path. The first path only where a package record
  has several.
- `package_type` — the ecosystem Syft catalogued the package from: `apk`, `deb`, `rpm`,
  `go-module`, `python`, `npm`, `java-archive` and so on, plus `unknown` where Syft states
  none. It is Syft's own type string, passed through and not interpreted; grouping it into
  "a newer image fixes this" and "only a rebuild fixes this" happens in the query, below.
- `known_exploited` — `true` when the vulnerability appears in a known-exploited catalogue.
  This is the one label worth building an alert on before any other: `severity="Critical"`
  narrows to what is bad in theory, `known_exploited="true"` to what is being used.
- `fixed_in` — all fixed versions, comma-separated and sorted, or empty.
- `state` — `scanned` (catalogued in this run), `cached` (SBOM was already there), `failed`,
  `pending` (not catalogued yet when the run published).
- `reason` on `kiebitzr_vulnerability_suppressed` — `ignore_rule`, `min_severity`,
  `only_fixed`, the filter that removed the findings. They are **disjoint**: a finding is
  counted under the first filter that removed it, in that order, so the three can be summed
  without double-counting. A filter that removed nothing from a digest has no series there.
- `reason` on `kiebitzr_image_failed` — the same values as on `kiebitzr_scan_errors_total`.
  The counter says how many failed at a stage, this says which digest did. Neither carries
  the registry's own message: that is in the `image failed` log line, beside the digest.
- `outcome` on `kiebitzr_worker_images_total` — `catalogued` or `failed`, per worker.
- `build_access` — whether anybody here can get a *build* of that image: `own` (a team inside
  your own responsibility boundary triggers it), `reachable` (somebody outside it does, and you
  can ask), `none` (nobody), `unknown` (nobody has classified it). Declared in
  `-build-access-file`; **with no file every image is `unknown`**, which is "nobody has looked"
  and not "nothing can be done". Do not confuse it with `owner_kind` / `owner_name`, which are
  the Kubernetes controller of the pod.
- `owner_kind` / `owner_name` — the workload, approximated from the pod's controller
  reference. A ReplicaSet's hash suffix is stripped, so a Deployment appears as
  `Deployment/<name>`. A pod without a controller appears as `Pod/<pod name>`.

## Before the first scrape: `honorLabels`

One setting decides whether anything below works, and getting it wrong is silent.

`kiebitzr_image_info` carries its own `namespace` and `container` — the *pod's*, which is the
entire point of the metric. A Kubernetes service discovery attaches labels of the same names
describing the Kiebitzr pod itself, and on a collision Prometheus renames ours:

```yaml
# ServiceMonitor, or the equivalent in a scrape config
honorLabels: true
```

Without it, `namespace` is Kiebitzr's own on every series and the workload's namespace moves to
`exported_namespace`. Every namespace filter and every grouping in this document then reads the
wrong label and quietly returns one value for the whole cluster. `KiebitzrLabelsRenamedByScrape`
below alerts on it, the dashboard has a tile for it, and this is the query:

```promql
count(kiebitzr_image_info{exported_namespace!=""}) > 0
```

## The one join you need

`kiebitzr_vulnerability` carries no namespace, no pod and no container on purpose: a finding
belongs to an image, not to the places that image happens to run. `kiebitzr_image_info` holds
that side, and `image_digest` joins the two.

**Which container is affected by a finding** — take the digest out of the finding and look it
up. One query, always correct:

```promql
kiebitzr_image_info{image_digest="sha256:<hex>"}
```

You get one series per container running that digest, with its namespace, workload, container
name and the tag the pod asked for.

`kiebitzr_image_info` carries **no pod name**, only the workload the pod's controller reference
points at. Replicas of one Deployment therefore produce one identical label set and collapse in
the deduplication, so the join below lands on workload-and-container granularity rather than on
replica count — which is what makes its output a work list instead of noise. On the pilot
cluster that was 75 series for 50 digests.

**Actionable findings per container**, for a dashboard or an alert. Aggregate first: a digest
can run in several places, and a plain join would fail with `duplicate series for the match
group`.

```promql
count by (image_digest) (
  kiebitzr_vulnerability{fix_state="fixed", severity=~"High|Critical"}
)
* on (image_digest) group_right () kiebitzr_image_info
```

One series per container, valued with the number of fixable high findings in its image. That is
the mechanism; for the three queries actually worth putting on a dashboard — and why this one is
still too coarse to act on — see *From a digest to a work list* below.

**Every finding of one workload** — the other direction, so collapse the info side instead:

```promql
kiebitzr_vulnerability
* on (image_digest) group_left ()
  max by (image_digest) (
    kiebitzr_image_info{namespace="<namespace>", owner_name="<workload>"}
  )
```

## Triage: must I patch tonight, and can I patch it at all?

Those are two separate questions, and **severity answers neither**. Start here before building
any dashboard or alert.

### Why a severity rollup per image is worthless

It saturates. An image with a full distribution userland carries a few hundred packages, and at
the Critical base rate per package the probability of "at least one Critical" goes to 1. On the
pilot cluster, 41 of 50 digests had one. That is the expected baseline for a fleet of
well-maintained official images, not a finding — and the indicator gets *worse* as images grow,
because every added package can only push it further towards always-true.

So do not build on this, however natural it looks:

```promql
# Don't. True of almost every image that exists, and it reads as "the cluster is on fire".
count by (image_digest) (kiebitzr_vulnerability{severity="Critical"}) > 0
```

An alert that always fires and an alert that never fires are equally useless. The two
dimensions below are the ones that discriminate.

### Must I patch tonight — urgency

Urgency is `known_exploited`, not severity: `severity="Critical"` is what is bad in theory,
`known_exploited="true"` is what is being used against people right now (ADR 0008).

```promql
# The patch-tonight set: exploited in the wild and a fix exists.
count by (image_digest) (
  kiebitzr_vulnerability{known_exploited="true", fix_state="fixed"})
```

**An empty result here is ambiguous, and the ambiguity matters more than the result.** It means
one of three things, and they are operationally opposite: nothing in the cluster is
known-exploited, or the database serves no threat records — in which case
`known_exploited="false"` means "unknown" — or **the running version does not publish the label
at all**, which is what it turned out to be the first time this was asked (see ADR 0010). Rule
that out first, because it is one query:

```promql
# Which binary is answering. One series per distinct build in the deployment.
kiebitzr_build_info

# Belt and braces on an older build that has no build_info either: no series at all, rather
# than a count of zero, means this binary predates the label.
count(kiebitzr_vulnerability{known_exploited="false"})
```

Then tell the remaining two apart with the risk score, which comes from the same metadata:

```promql
count(kiebitzr_image_risk_score)    # no series at all → no threat data, not a clean cluster
topk(10, kiebitzr_image_risk_score) # values with spread → the metadata is arriving
```

`kiebitzr_image_risk_score` only gets a series for a digest where some finding scores above
zero, so its complete absence is the signal. `KiebitzrThreatDataMissing` below alerts on it.

#### Is there even a patch? Three different questions

`fix_state="fixed"` is in the query above for a reason: **waking somebody for a vulnerability
nobody can fix achieves nothing.** But "a patch exists" means three things at decreasing levels
of certainty, and only the first is something this service knows for sure.

1. **A fixed version is named.** `fix_state="fixed"`, and `fixed_in` says which version — every
   fixed version the sources name, comma-separated. This is a fact out of the advisory, and it
   is the one the alert gates on.
2. **A patched image of this lineage probably exists.** True for `apk`, `deb`, `rpm` and the
   other distribution types: the base image's maintainer tracks the same advisories, so a newer
   tag usually carries the version from `fixed_in`. Probably, not certainly — the vendor may not
   have rebuilt yet.
3. **A deployable image exists, for the platform these nodes run.** **Kiebitzr cannot answer
   this, and the gap is worth knowing about.** It reads advisory data; nothing here resolves a
   tag, asks whether a newer image carries your `os/arch`, or checks what that image actually
   contains. For an application dependency — `go-module`, `npm`, `python` — a named fixed
   version routinely exists in a registry while no published image has picked it up yet. And a
   newer image that exists only for `linux/amd64` is no fix for an `arm64` node.

So read `fixed_in` together with `package_type`: the first says what to patch to, the second how
likely it is that something exists to patch *with*. Neither is a promise. Confirming it is a
manual step today — look at the tags of the image in question, or ask its publisher. ADR 0011
proposes closing the gap by cataloguing one candidate image per repository, switched on with
`-upgrade-candidates`; what that costs and what its unknown states mean is in *Checking whether
a fix is deployable* in the running runbook. Until it is in force, stage 3 stays a manual step.

```promql
# What to patch to, finding by finding. No namespace, because a finding belongs to an image —
# join the digest against kiebitzr_image_info for the where.
kiebitzr_vulnerability{known_exploited="true", fix_state="fixed"}
```

**And the mirror image, which is worth seeing and not worth paging on:**

```promql
# Exploited in the wild, and no fixed version exists at all.
count by (image_digest) (kiebitzr_vulnerability{
  known_exploited="true", fix_state=~"wont-fix|not-fixed|unknown"})
```

There is deliberately **no alert on this**. There is nothing to patch to, so the only moves are
compensating ones — a network policy, dropping a feature or a sidecar, retiring the workload —
and none of them belongs to whoever is on call at 03:00. It belongs on the dashboard, where
somebody decides about it in daylight.

### Can I patch it at all — whether the fix can reach you

`fix_state="fixed"` means a fixed *version of the package* exists. It does **not** mean the fix
can reach your container: nothing is patched inside a running container, and the only remedy is
a different image. The real question is whether a different image is likely to carry the fix,
and that is what `package_type` separates:

- **Distribution packages** — `apk`, `deb`, `rpm`, `alpm`, `portage`, `nix`. The base image's
  maintainer tracks the distribution's advisories, so a newer tag of the same lineage usually
  carries the fix. **Your move: bump the tag.**
- **Everything else** — `go-module`, `npm`, `python`, `gem`, `java-archive`, `rust-crate`, … —
  is compiled or bundled into the application. It moves only when whoever publishes the image
  bumps a dependency and rebuilds. **Not your move, unless you publish that image.** `binary`
  and `unknown` belong here too: a binary found without package metadata.

That last qualifier is doing more work than it looks, and `build_access` is what makes it
answerable — see *Is there anybody to ask?* below. For an image your own team builds the
distinction largely dissolves: deb or vendored library, the remedy is a rebuild you can trigger.
It is for `build_access="none"` that `package_type` decides the outcome, because there the only
lever is somebody else's next release.

```promql
# What bumping the image tag would actually fix.
count by (image_digest) (kiebitzr_vulnerability{
  severity=~"High|Critical", fix_state="fixed",
  package_type=~"apk|deb|rpm|alpm|portage|nix"})

# What only a rebuild by the publisher can fix. Chase the vendor, or your own CI.
count by (image_digest) (kiebitzr_vulnerability{
  severity=~"High|Critical", fix_state="fixed",
  package_type!~"apk|deb|rpm|alpm|portage|nix"})
```

On the pilot cluster those two were roughly equal: of 357 fixable Critical findings, about half
were distribution packages — curl, openssl, zlib, a handful of source packages replicated
across 41 images — and about half were Go, with `stdlib` alone at 76 and `golang.org/x/crypto`
at 56. **Half of what the metrics called "fixed" was not actionable by the cluster operator at
all**, and without this label nothing distinguished the two.

### Am I running what the tag says — digest drift between nodes

Before asking whether a newer image exists, ask whether you are already entitled to one you are
not running. `imagePullPolicy: IfNotPresent` means a node that already has an image for a tag
never pulls it again, so a tag that has moved reaches the nodes that happened to pull after it
moved and nobody else. Two workloads then run **the same tag at different digests**, and the
metrics say so:

```promql
# One tag, several digests, so somebody is behind.
count by (image) (count by (image, image_digest) (kiebitzr_image_info)) > 1
```

This was found on the pilot cluster, and the stale digest carried **141 findings more** than the
current one, including a High in openssl that was already fixed. Nothing needed to be upgraded:
a re-pull of the *same tag* would have cleared them. It is the cheapest patch there is — no new
version, no vendor, no maintenance window — and no other metric announces it.

Which of the digests is behind is not in the metrics; there is no build time here. The finding
count is the signal, and it is a suspicion rather than a proof:

```promql
count by (image_digest) (kiebitzr_vulnerability)
* on (image_digest) group_right () kiebitzr_image_info{image="<repo>:<tag>"}
```

One series per container with its digest and finding count. The higher one is where to look
first; confirm against the registry, which is what the tag resolves to today.

**A rollout in flight has the same shape**, because old and new pods briefly run different
digests under one tag. That clears itself by the next run, which is also the distinction worth
making: drift is the case that **persists across runs**. For the same reason this is a dashboard
table — *Same tag, different digests* in the dashboard's drift row — and not a pager rule: the
condition is clearable by whoever sees it (delete the pod, set `imagePullPolicy: Always`, or pin
digests), but a rule on it would page during every normal rollout of a mutable tag.

The mirror of this query — one digest appearing under several names — is in *From a digest to a
work list* below, and it answers a different question: not who is behind, but which tags point
at the same thing.

Serves decision 7b in `kbz:req:00001`, the case of automation that has stopped without saying
so. And the first reading of this case was wrong in a way worth keeping: the drift was taken for
the registry's, as though the published tag had moved on past the cluster. The registry was
never involved. Both digests *were* that tag at some point, and one node simply kept the older
one — which is why no query against a registry would have found it, and why this one does.

### Is there anything to deploy?

Only with `-upgrade-candidates` switched on; without it neither metric has a series, which is
the honest shape for a check nobody asked for.

```promql
# Images where a candidate clears at least one in-scope finding, with the tag to go to.
kiebitzr_image_upgrade_candidate > 0

# The same, with the containers attached — this is the list to act on. The parentheses are
# not optional: * binds tighter than >, so without them this reads as "> (0 * ...)".
(kiebitzr_image_upgrade_candidate > 0)
* on (image_digest) group_right () kiebitzr_image_info

# Checked, and nothing out there clears it: the publisher has not shipped a fix.
kiebitzr_image_upgrade_candidate == 0

# Could not be answered. NOT the same as the line above.
kiebitzr_image_upgrade_unknown
```

The middle two lines are the distinction the whole check exists for. `== 0` is a measurement:
candidates were catalogued and matched, and the finding survives all of them. The `unknown`
metric is the opposite — nobody looked, or could not — and treating it as a negative is how a
page gets suppressed.

### Is there anybody to ask?

`package_type` says whether a *finding* needs a rebuild. It does not say whether anybody here
can get one. Those are different questions, and the second one splits the "not your move"
bucket into a dead end and a work list (ADR 0013):

```promql
# The classification itself, as a picture of the fleet.
count by (build_access) (kiebitzr_image_info)
```

**The morning queue.** A reachable image where the candidate check found nothing newer: nobody
has built it yet, and asking is the action. This list exists in most clusters and nothing
showed it before:

```promql
(kiebitzr_image_upgrade_candidate == 0)
* on (image_digest) group_right () kiebitzr_image_info{build_access=~"own|reachable"}
```

**And its opposite, which is yours to clear today.** A build exists and is simply not running
here — their part is done:

```promql
(kiebitzr_image_upgrade_candidate > 0)
* on (image_digest) group_right () kiebitzr_image_info
```

Both need `-upgrade-candidates` switched on; without it neither has a series, and the question
"has anybody built a fix" has no answer at all.

**The backlog of the classification itself**, because this axis is declared and is therefore
worth exactly what its upkeep is:

```promql
count(kiebitzr_image_info{build_access="unknown"})
count by (image, namespace, owner_name) (kiebitzr_image_info{build_access="unknown"})
```

An installation with no `-build-access-file` sits at 100 % unknown, which is honest and costs
nothing: the label is there, it says nobody has looked, and nothing else about the metrics
changes. What it cannot catch is a classification that was right and has quietly gone stale —
a team dissolved, a component handed over. Only a review does that.

**When one digest runs under two references** — a vendor's and an internal mirror's — there is
one series per reference, each with its own classification. Aggregate with the **more generous**
one: the question is whether an action exists at all, and one reachable route to a rebuild is
enough.

```promql
# "Is there any way to get a build of this digest?" — own > reachable > none > unknown.
max by (image_digest) (
  (kiebitzr_image_info{build_access="own"} * 3)
  or (kiebitzr_image_info{build_access="reachable"} * 2)
  or (kiebitzr_image_info{build_access="none"} * 1)
  or (kiebitzr_image_info{build_access="unknown"} * 0))
```

**There is no alert on any of this**, and that is the rule rather than an omission. A finding in
an image another team builds looks clearable and is not: what the person woken can do is *ask*,
and asking is not ending — `kbz:req:00001`, *A request is not a clearance*. The list belongs in
daylight, next to the coffee.

### The funnel

Run it top to bottom. Each line should cut the previous one down substantially; if one does
not, that is where your reporting is mis-scoped.

```promql
count(count by (image_digest) (kiebitzr_image_info))                      # images watched
count(count by (image_digest) (kiebitzr_vulnerability{severity="Critical"}))        # ~all of them
count(count by (image_digest) (
  kiebitzr_vulnerability{severity="Critical", fix_state="fixed"}))                  # a fix exists
count(count by (image_digest) (kiebitzr_vulnerability{
  severity="Critical", fix_state="fixed",
  package_type=~"apk|deb|rpm|alpm|portage|nix"}))                                   # a tag bump fixes it
count(count by (image_digest) (
  kiebitzr_vulnerability{known_exploited="true", fix_state="fixed"}))               # tonight
```

And where the work actually sits, which is never spread evenly — on the pilot cluster ten
digests carried 73 % of all fixable Critical findings and three carried 35 %:

```promql
topk(10, count by (image_digest) (
  kiebitzr_vulnerability{severity=~"High|Critical", fix_state="fixed"}))

# Root causes rather than findings: a handful of source packages explains most of the count.
topk(15, count by (source_package, package_type) (
  kiebitzr_vulnerability{severity=~"High|Critical", fix_state="fixed"}))
```

**Group that one by `source_package`, not by `package`.** One advisory against one source
package appears once per binary package built from it — `curl` and `libcurl`, `libssl3` and
`libcrypto3` from openssl — so grouping by `package` roughly doubles what you actually have to
fix. A cluster-side analysis of one image hit the same wall harder: 135 advisories across nine
binary packages, about 1,200 series for what is one upgrade. The difference is worth seeing
once:

```promql
count(count by (cve, package) (kiebitzr_vulnerability))         # findings as they are reported
count(count by (cve, source_package) (kiebitzr_vulnerability))  # things to fix
```

One artefact survives this and `source_package` does not help with it: Syft catalogues compiled
Python bytecode under several names (`pyc`, `python3-pyc`, `python3-pycache-pyc0`), which
triple-counts one thing. They are genuinely different package records rather than one source
package, so an ignore rule is still the right answer — and it is now a rule whose effect is
counted, in `kiebitzr_vulnerability_suppressed`.

### From a digest to a work list

Everything above answers in digests, and nobody patches a digest. These are the same three
questions with the containers attached — the queries to put on a dashboard.

The pattern is always the same: **condense the finding side to one value per digest, then fan
out onto the info side.** The `count by (image_digest)` is not cosmetic. Without it the join
fails with `duplicate series for the match group` the moment one digest runs in two places,
which is the normal case.

**Patch tonight.** One series per container, valued with the number of exploited-and-fixable
findings in its image:

```promql
count by (image_digest) (
  kiebitzr_vulnerability{known_exploited="true", fix_state="fixed"}
) * on (image_digest) group_right () kiebitzr_image_info
```

**Your move — what bumping the image tag clears:**

```promql
count by (image_digest) (kiebitzr_vulnerability{
  severity=~"High|Critical", fix_state="fixed",
  package_type=~"apk|deb|rpm|alpm|portage|nix"}
) * on (image_digest) group_right () kiebitzr_image_info
```

**Not your move — what waits on whoever publishes the image.** The same query with `!~` instead
of `=~`. Keep it as a separate list: it ends in a ticket with a vendor, not in your maintenance
window, and mixing the two is how the actionable half gets ignored.

```promql
count by (image_digest) (kiebitzr_vulnerability{
  severity=~"High|Critical", fix_state="fixed",
  package_type!~"apk|deb|rpm|alpm|portage|nix"}
) * on (image_digest) group_right () kiebitzr_image_info
```

In Grafana these are instant queries in a table panel with *Labels to fields*; the label set is
already the work list.

**Collapsed to workloads**, where the container name does not matter:

```promql
max by (namespace, owner_kind, owner_name, image) (
  count by (image_digest) (kiebitzr_vulnerability{
    severity=~"High|Critical", fix_state="fixed",
    package_type=~"apk|deb|rpm|alpm|portage|nix"})
  * on (image_digest) group_right () kiebitzr_image_info
)
```

`max` and not `sum`: where two containers of one workload share a digest, `sum` counts the same
image twice. Where they run *different* digests, `max` reports the worst of them — if you want
the total across those, make the set unique by `image_digest` first.

One thing to expect in all of these: a digest running under two tags appears twice, with
different `image` values. That is the data being honest rather than a broken query — see the
note at the end of this document — and this finds them:

```promql
count by (image_digest) (count by (image_digest, image) (kiebitzr_image_info)) > 1
```

Do not confuse it with its mirror in *Am I running what the tag says* above. Grouping by
`image_digest` finds one thing under several names, which is a naming observation. Grouping by
`image` finds one name over several things, which is somebody running a stale digest.

**And the counter-question, which matters as much as the lists.** Which containers have no
findings at all:

```promql
kiebitzr_image_info unless on (image_digest) count by (image_digest) (kiebitzr_vulnerability)
```

Check every result against `kiebitzr_image_failed` and `kiebitzr_image_pending`. What appears
there is **unexamined, not clean**, and nothing in the finding metrics distinguishes the two on
its own.

### A dashboard built from these

`dashboards/kiebitzr.json` is an importable Grafana dashboard of everything in this section, in
the order this section argues for: whether the display is valid at all, then urgency, then what
you can act on, then whose move it is and whether anybody can be asked for a build, then what
waits on a vendor, then the blind spots, then drift — where the tag-at-two-digests table sits
beside the trends. It asks for the Prometheus
datasource on import and carries no installation-specific values.

Two things in it are deliberate rather than decorative. Severity is drawn as **one hue from
light to dark** over four buckets, because it is an ordered scale — a set of unrelated colours
would claim the levels are equals, and Medium and below are not a work list. And there is **no
headline count of findings**, because an inventory total reads as a verdict: the whole reason
this section exists is that `11060` and "41 of 50 images are Critical" say almost nothing about
whether anyone has to do something tonight.

## Recipes

Severity distribution across the cluster:

```promql
sum by (severity) (kiebitzr_vulnerability)
```

The ten images worth updating first:

```promql
topk(10, count by (image_digest) (kiebitzr_vulnerability{fix_state="fixed"}))
```

What nobody can fix yet — useful to know, not to act on:

```promql
count by (severity) (kiebitzr_vulnerability{fix_state=~"wont-fix|not-fixed"})
```

How many distinct images and containers are being watched:

```promql
count(count by (image_digest) (kiebitzr_image_info))
count(kiebitzr_image_info)
```

New findings since yesterday, per image:

```promql
count by (image_digest) (kiebitzr_vulnerability)
  - count by (image_digest) (kiebitzr_vulnerability offset 24h)
```

## Is the scanner still telling the truth?

A failed run never terminates the process and never clears the result: the previous findings
keep being served. That is deliberate, and it means **stale data looks exactly like fresh
data** unless you watch the freshness metrics.

Age of the last completed run, in seconds:

```promql
time() - kiebitzr_last_success_timestamp_seconds
```

Before the first successful run this is enormous, because the metric is `0` — which is the
intended behaviour: "never finished a run" has to be alertable, not silent.

Age of the vulnerability database:

```promql
time() - kiebitzr_db_built_timestamp_seconds
```

This is the database actually matched against, not the newest one published, so it is also how
a deliberately skipped update shows up where `-db-max-age` is set. Expect it to range up to
`db-max-age` plus `-interval` there, and read any threshold on it against that sum rather than
against a day. The hard ceiling is the build's own, published on the `grype_db_max_age` label of
`kiebitzr_build_info`: past it Grype refuses the database and the run fails.

### Pending is not failed, and it is not clean either

A digest is **pending** when cataloguing ran out of its budget before reaching it. Nothing is
known to be wrong with that image — nobody has looked at it yet — so it increments no error
counter and does not move `kiebitzr_images{state="failed"}`. It gets its own series precisely
because the alternative is worse: a digest with no SBOM and no series would be
indistinguishable from an image with no findings, i.e. it would read as clean.

```promql
kiebitzr_images{state="pending"}
count(kiebitzr_image_pending)
```

Pending on a **first run** against a large cluster is expected. Cataloguing is bounded by
`-catalogue-timeout` (three quarters of `-run-timeout` unless set), so a cold start publishes
what it managed and names the rest; the SBOMs it did write stay in the cache, so each run
starts further along and the number falls. What matters is that it *falls*:

```promql
# Still pending after a day of runs — the budget is too small, or the pool is too small.
kiebitzr_images{state="pending"} > 0
```

Pending in a **steady state** is a problem, and it has three usual causes: the catalogue budget
is too short for the churn, the worker pool is too small (check
`kiebitzr_catalogue_queue_depth`), or workers cannot reach their registries at all — in which
case `kiebitzr_image_failed{reason="unreachable_image"}` will be moving too.

With a worker pool, the depth is what says whether more workers would help:

```promql
# Outstanding cataloguing work. Stays high through a run → add workers.
kiebitzr_catalogue_queue_depth

# What the pool is actually getting through.
sum(rate(kiebitzr_worker_images_total{outcome="catalogued"}[1h]))
```

Scale the pool on this and not on worker CPU: a worker spends its time waiting on a registry,
so its CPU says nothing about whether another worker would help.

### What am I not being shown?

Failures and pending digests are the accidents. The filters are the deliberate silence: every
finding `-min-severity`, `-only-fixed` and `-ignore-file` remove leaves no series behind, and a
screen with nothing on it is exactly what a rule that is too broad produces.
`kiebitzr_vulnerability_suppressed` is that silence written down.

```promql
# What the filters removed in the last run, per filter. The number to watch.
sum by (reason) (kiebitzr_vulnerability_suppressed)

# Where it is concentrated. An ignore rule written for one package and matching everything
# shows up as a tall, flat line here instead of as a quiet dashboard.
topk(10, sum by (image_digest) (kiebitzr_vulnerability_suppressed))

# The share of findings that never reached the metrics. Above about a half, the inventory is
# being filtered rather than narrowed, and `-min-severity` is probably doing more than intended.
sum(kiebitzr_vulnerability_suppressed)
  / (sum(kiebitzr_vulnerability_suppressed) + count(kiebitzr_vulnerability))
```

The counts are in **series, not matches** — deduplicated exactly as the published findings
are — so that last ratio is in one unit and means what it reads as.

**No series is an answer here, and a narrow one.** It says the last run removed nothing, which
also covers the common case of no filter being configured at all. Which filters are set is in
the start-up log, not in this metric; a binary too old to publish the metric is ruled out by
`kiebitzr_build_info`, as everywhere else.

Watch the **jump** rather than the level. A steady `min_severity` count is the configuration
working; the same number tripling overnight is new findings being hidden, and that is the one
movement this metric exists to make visible:

```promql
sum(kiebitzr_vulnerability_suppressed) - sum(kiebitzr_vulnerability_suppressed offset 24h)
```

There is deliberately **no alert on this**. Nobody can clear a suppression count at 03:00 —
the only moves are editing an ignore rule or raising a threshold, in daylight, with the
dashboard in front of them. It is a tile, and `-ignore-file` should not be configured without
it on the dashboard.

### What each error reason means

| `reason` | Cause | What to do |
|---|---|---|
| `list_pods` | the pod listing failed | RBAC (`list` on pods, cluster-wide), API server reachability |
| `unresolved_image_id` | a container reports an imageID that cannot be turned into a pullable reference | usually a container that has not pulled yet; persistent counts mean a runtime that reports no repository, and those images are a blind spot |
| `unreachable_image` | the image could not be reached at all, before anything was read from it | three causes, in order of likelihood: a **missing registry credential** for a private image, a wrong `-platform` for your nodes, or an image that only exists in a node's local store and was never pushed. They cannot be told apart in the metric — the `image failed` log line carries the registry's own message, which names the reason exactly |
| `catalogue` | the image was reached but cataloguing it failed | usually a problem in the image's package metadata; the digest is reported in the log line `image failed`. With a worker pool this reason also covers a digest no worker ever answered for — handed out `-work-attempts` times and never returned, which is what an image that kills whatever catalogues it looks like. The log line says which of the two it was |
| `match` | matching an SBOM against the database failed | a damaged cached SBOM; deleting the cache entry forces a re-catalogue |
| `database` | the database could not be opened or updated | network to the database host, or a database too old to be trusted — the run fails rather than reporting against stale data |
| `cache_write` | the cache could not be pruned | a full or read-only volume; costs disk, not correctness |

A per-run count of failed images is in `kiebitzr_images{state="failed"}`, and every one of
them has a `image failed` line in the log with its digest and the reason.

## Alerts worth having

One rule decides what belongs here: **an alarm must be clearable by whoever it wakes.** A
condition no action of theirs ends is a state, and a state belongs on a dashboard. Duration is
not the test — an alarm may burn for three days if the person woken could have ended it and
chose not to; it must not burn at all if nothing they do ends it. Such an alarm gets silenced,
and a silenced alarm protects nothing (`kbz:req:00001`).

For a long time that rule meant **every alert here was about the scanner's own health and none
about a finding**, because `fix_state="fixed"` says a fixed version is *named in an advisory* —
not that an image exists carrying it. A page on that can burn for weeks while the person woken
has no move.

**One finding alert now passes the test, and only one.** The candidate check measures whether an
image exists that this cluster could deploy and that clears the finding (ADR 0011). Where it is
switched on, "exploited, fixable, and something to deploy" is ended by an action of the
recipient: raise the tag. That is the alarm `KiebitzrExploitedAndDeployable` below, and the
`tag` label is the move.

Everything about it is gated on the measurement rather than on the advisory. Without
`-upgrade-candidates` the metric has no series, so the rule cannot fire — no verification, no
page, which is the right failure direction. A digest whose candidate question came back
`unknown` does not fire either: nobody looked, and that is not a negative.

Match the thresholds to your `-interval`; these assume the default daily run.

```yaml
groups:
  - name: kiebitzr
    rules:
      # The one finding alert that passes the clearability test, and it does so only because
      # the candidate was catalogued and matched: there is an image to deploy, and `tag` names
      # it. `and on (image_digest)` is not redundant — with -upgrade-scope=fixable a candidate
      # may clear High findings nobody is exploiting, which is not a reason to wake anybody.
      - alert: KiebitzrExploitedAndDeployable
        expr: |
          (kiebitzr_image_upgrade_candidate > 0)
          and on (image_digest) (
            count by (image_digest) (
              kiebitzr_vulnerability{known_exploited="true", fix_state="fixed"}) > 0)
        for: 1h
        annotations:
          summary: Exploited in the wild, and an image exists that clears it — deploy {{ $labels.tag }}
          description: >-
            Join {{ $labels.image_digest }} against kiebitzr_image_info for the workloads
            running it. The value is how many in-scope findings that tag clears.

      - alert: KiebitzrNotScanning
        expr: time() - kiebitzr_last_success_timestamp_seconds > 36 * 3600
        for: 30m
        annotations:
          summary: No completed scan for a day and a half — the findings being served are stale

      # 48h assumes -db-max-age is off. With it set, raise this above db-max-age plus
      # -interval, or the rule fires on behaviour somebody configured — and an alarm nobody
      # can clear is a state, which belongs on the dashboard instead.
      - alert: KiebitzrDatabaseStale
        expr: time() - kiebitzr_db_built_timestamp_seconds > 48 * 3600
        for: 1h
        annotations:
          summary: The vulnerability database is older than two days

      - alert: KiebitzrImagesUnreachable
        expr: increase(kiebitzr_scan_errors_total{reason="unreachable_image"}[26h]) > 0
        annotations:
          summary: Images cannot be pulled — part of the cluster is unscanned; the log line names the registry's reason

      - alert: KiebitzrImagesFailing
        expr: kiebitzr_images{state="failed"} > 0
        for: 2h
        annotations:
          summary: Some running images were not scanned in the last run

      # Pending is expected on a cold start and has to fall away. Still pending after two
      # days of runs means the catalogue budget or the worker pool is too small — not that
      # anything is wrong with those images.
      - alert: KiebitzrCataloguingNotKeepingUp
        expr: kiebitzr_images{state="pending"} > 0
        for: 48h
        annotations:
          summary: Images have been waiting to be catalogued for two days — raise -catalogue-timeout or add workers

      # Not a finding alert: it says the exploitation dimension is blind, which is a
      # configuration or database problem and therefore something you can clear.
      - alert: KiebitzrThreatDataMissing
        expr: absent(kiebitzr_image_risk_score) and (kiebitzr_last_success_timestamp_seconds > 0)
        for: 2h
        annotations:
          summary: No risk score on any image — the threat data is missing and known_exploited reads false everywhere

      # Also not a finding alert: our own labels are being renamed by the scrape, so every
      # namespace filter and grouping is reading the exporter's namespace instead of the
      # workload's. One line in the ServiceMonitor clears it.
      - alert: KiebitzrLabelsRenamedByScrape
        expr: count(kiebitzr_image_info{exported_namespace!=""}) > 0
        for: 30m
        annotations:
          summary: Set honorLabels on the scrape — kiebitzr_image_info's own namespace and container are being renamed
```

### What was removed, and why

Two rules that shipped here before the clearability test existed have been withdrawn. They are
not wrong as *questions*; they are wrong as pages.

**`KiebitzrExploitedAndFixable`** was described here as "the only page-worthy finding alert". It
was not: `fix_state="fixed"` cannot promise a deployable image, so it could stay lit for weeks
through no fault of the person woken. It stays withdrawn in that form, and remains the headline
tile of the dashboard, where a condition that persists belongs.

Its replacement is `KiebitzrExploitedAndDeployable` above, and the difference is the whole
argument of ADR 0011 in one line: it fires on a **measurement that an image exists**, not on an
advisory naming a version. The same question, gated on something the recipient can act on.

**`KiebitzrImageBehindOnDistroPatches`** was a backlog with a threshold. A backlog does not
clear in an evening, so by the test it was never an alarm. It is a dashboard table, sorted
descending, which is what a backlog wants to be.

There is likewise **no alert on `severity="Critical"` alone**, and never was: it fired on 41 of
50 images on the pilot cluster — permanently red, hiding everything that matters. Severity is a
filter for a query, not a trigger.

`KiebitzrNotScanning` and `KiebitzrDatabaseStale` remain the two that matter most: without them,
a scanner that stopped working looks like a cluster with no new vulnerabilities.

## Cardinality and scrape cost

One series per vulnerability per image digest, never per pod or container. In a pilot, roughly
fifty running digests produced about eleven thousand `kiebitzr_vulnerability` series and about
seventy-five `kiebitzr_image_info` series — a scrape payload in the low single-digit megabytes.

`package_type` and `source_package` add no series to that: both are determined by the package
they describe, so they split nothing that `package` did not already split. They are the cheap
kind of label — a new way to group what is already published.

**`location` is not of that kind, and it is the one label here that is not free.** Where one
image contains several artefacts carrying the same package at the same version — several Go
binaries built with one toolchain, the same vendored library in two places — those findings used
to arrive as one series and now arrive as one per path. Images whose findings are distribution
packages are unaffected, because every apk or dpkg package has one location, the package
database.

**Measured on a cluster of about 11,100 findings: 344 extra series, 3.2 %.** The per-image
factor reaches 2.5 at worst and 2.0 for a handful, and those happen to be small images, so the
scrape barely notices. Worth checking once after upgrading to a build that has the label, not
worth worrying about:

```promql
# What it cost the whole cluster: with the label, and what the same findings would have been
# without it. The difference is the price.
count(kiebitzr_vulnerability)
count(count by (image_digest, cve, package, installed) (kiebitzr_vulnerability))

# And where it is concentrated, per image.
topk(10, count by (image_digest) (kiebitzr_vulnerability)
  / count by (image_digest) (count by (image_digest, cve, package, installed) (
      kiebitzr_vulnerability)))
```

A ratio of 1 means the label changed nothing for that image. Well above it means the image
carries many binaries built the same way — which is also the image where "which binary is it"
was unanswerable before.

That number is a whole-cluster inventory, not a work list. Narrowing happens at the service,
not in the query, because what is not exported costs nothing to store:

- `-min-severity high` drops everything below a severity.
- `-only-fixed` keeps only what has a fix, which is what can be acted on today.
- `-ignore-file` applies ignore rules per CVE, package or fix state.
- `-exclude-namespaces` drops whole namespaces before anything is scanned.

The first three are counted: `kiebitzr_vulnerability_suppressed` says how many findings each
removed, per digest — see *What am I not being shown?* above. It costs one series per digest
and filter, and only where something was actually removed.

**An excluded namespace is not "clean", it is unexamined**, and it is the one narrowing that is
*not* counted. Nothing in the metrics distinguishes the two: no series appear for it, and no
error is counted. The exclusions are logged once at start-up under `exclude_namespaces`, and
the number of pods they skipped is in the run's debug log — that is the only trace. A namespace
is dropped before any image of it is catalogued, so there is nothing to count by digest, which
is exactly why `-min-severity` or an ignore rule is the better instrument: they narrow what is
reported, keep the inventory honest, and say how much they hid.

## Things that surprise people

- **A Go standard library finding cannot be patched inside the container.** `package="stdlib"`
  with `installed="go<version>"` means a binary in that image was compiled with a vulnerable
  Go toolchain. The only fix is a rebuild of the image by whoever publishes it — and it is
  still reported as `fix_state="fixed"`, because a fixed Go version exists. Every Go program
  in the cluster produces this class of finding, which is why the image of this service is
  rebuilt weekly. `package_type="go-module"` is how you select the whole class rather than
  this one package, and `location` says **which binary** was built with that toolchain —
  without it, thirty findings against one version string name no file at all:

  ```promql
  # The binaries built with a vulnerable toolchain, per image.
  count by (image_digest, location, installed) (
    kiebitzr_vulnerability{package="stdlib", severity=~"High|Critical"})
  ```
- **The same digest in two namespaces appears twice** in `kiebitzr_image_info`, once per
  container. Joins have to aggregate one side, see above.
- **One digest can have several names.** `image` is the reference the pod asked for, so a digest
  reached as `repo:1.4.0` by one workload and as `repo:latest` by another gets a series per
  spelling — as does a digest some pods pin as `repo@sha256:…`. Grouping by `image` therefore
  shows it twice. That is worth seeing rather than aggregating away: it is how you notice a
  mutable tag that has drifted behind a pinned one. The digest is the identity; the name is
  decoration.
- **One tag can mean several digests, inside one cluster.** The other direction, and the more
  consequential one: with `imagePullPolicy: IfNotPresent` a node that already holds an image for
  a tag never pulls it again, so one tag runs at two digests and one of them is behind on
  patches. See *Am I running what the tag says* in the triage section — on the pilot cluster the
  stale digest carried 141 findings more.
- **Findings only move when a run completes.** The result is swapped in as a whole, so a run
  that fails or is cut short changes nothing at all — not even partially.
- **The first run is the slow one.** It catalogues every image and downloads the database;
  `-run-timeout` bounds it and is deliberately much larger than `-interval`. The SBOM cache is
  digest-addressed, so even a run that is cut short leaves its work behind for the next one.
