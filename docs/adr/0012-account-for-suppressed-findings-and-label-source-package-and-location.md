---
id: kbz:adr:00012
title: Account for What the Filters Remove, and Name the Source Package and the File
date: 2026-11-12
status: accepted
tags:
  - metrics
  - prometheus
  - vulnerability-scanning
  - sbom
related:
  - id: kbz:adr:00001
    reason: Adds one metric and two labels under the cardinality rule that ADR defines, and keeps the filters runtime configuration
  - id: kbz:adr:00008
    reason: Extends the same metric and follows its rule that a judgement of ours is not a label
  - id: kbz:adr:00010
    reason: Its closing consequence names the double counting source_package removes, and its unknown-value rule is reused here
  - id: kbz:req:00001
    reason: The decisions these three changes serve, and the leading principle the suppression metric is a direct application of
  - id: kbz:runbook:00001
    reason: Where each of the three is turned into a query, with the cost of the location label
---

# Account for What the Filters Remove, and Name the Source Package and the File

## Status

`accepted`. In force: `kiebitzr_vulnerability_suppressed` exists, and `kiebitzr_vulnerability`
carries `source_package` and `location`.

## Context

Three gaps, found by operating the service rather than by reading it. They are decided together
because they are one kind of change — the finding metrics telling the truth about themselves —
and because two of them are a label apiece, which is not a document each.

### The filters remove findings and nothing says how many

`-min-severity`, `-only-fixed` and `-ignore-file` exist since ADR 0001, which chose to narrow at
the service rather than in the query: what is not exported costs nothing to store. What was
never decided is what happens to the removed findings. Today they simply are not there.

That is the exact shape of absence this project refuses everywhere else. `kiebitzr_image_pending`
is a series rather than a gap, an unexplained failure gets no plausible-looking series,
`kiebitzr_build_info` exists so that "nothing to report" and "a binary that cannot report"
can be told apart. The filters were the one place left where the service goes quiet on purpose
and says nothing about it — and the quiet grows with the configuration: an ignore rule written
for one noisy package and matching half the cluster reads exactly like a clean cluster.

It is **decision 2** in `kbz:req:00001` — *is anything unexamined?* — and it was served for
accidents (failed, pending) and unserved for intent.

This had to be settled before anybody is encouraged to configure the filters, which the
deployment documentation was about to do: a report had already asked why the ADR filters were
"not implemented", when in fact they were implemented and simply not configured.

### One advisory against one source package is counted once per binary package

ADR 0010 closes with this as a known artefact: `curl` and `libcurl`, `libssl3` and `libcrypto3`
from openssl are counted separately for the same advisory, "so the finding count roughly
doubles what you have to fix". It was left open there because collapsing findings onto source
packages "would be a second inventory".

A cluster-side analysis has since made the number harder to live with: one image produced about
1,200 series from 135 advisories across nine binary packages — one upgrade, read as more than a
thousand things. The pilot cluster's own package breakdown shows the same at smaller scale, with
curl and openssl each appearing twice in the top ten.

It is **decision 4** — *is this mine to fix* — answered in a unit that inflates the work.

### A finding names a package, and sometimes that names no file

A cluster-side analysis found 3 Critical and about 30 High findings against
`package="stdlib", installed="go1.24.6"` in one image and **could not determine which binary
carried them**. The probable answer was a statically linked helper binary under
`/usr/local/bin`, and it stayed probable: nothing in the metrics names a path, so the only ways
on were to pull the image apart by hand or to guess.

`package_type="go-module"` (ADR 0010) says such a finding is the publisher's to fix. It does
not say what to tell the publisher. That is **decisions 3 and 4** stopping one step short of an
action.

## Options considered

### For the suppressed findings

**A counter, `kiebitzr_vulnerability_suppressed_total`.** Attractive because the natural alert
is "a jump", and `increase()` is what counters are for. Rejected: a run publishes a snapshot,
and the rest of the result metrics are gauges swapped in as a whole (ADR 0001). A counter would
have to survive between runs, which makes a restart look like a drop to zero, and it would
accumulate across runs so the current state — *how much is hidden right now* — could only be
reconstructed by differencing. A gauge answers that directly, and a jump is still visible with
`offset`.

**One global series per reason, without the digest.** Cheapest, and enough for "is the
configuration hiding a lot". Rejected: it cannot say *where*, so a rule that removes everything
from one image looks the same as one that removes a little from each. The join to
`kiebitzr_image_info` is the whole shape of this metric set, and giving that up to save two
hundred series is the wrong trade at the size this service is built for.

**Count the findings but keep publishing them at a lower value.** Rejected quickly: it defeats
the purpose of the filters, which exist to keep the scrape small.

**A gauge per digest and reason, only where something was removed.** Chosen.

### For the source package

**Collapse findings onto source packages**, publishing one series per advisory and source
package instead of per binary package. This is what ADR 0010 looked at and called a second
inventory, and it is still that: Grype matches per package record, so collapsing means deciding
that two matches are one finding and dropping the version actually installed. A query cannot
undo it.

**Replace `package` with `source_package`.** Rejected: `package` is what is installed and what
an ignore rule matches on; the source package is what is fixed. Removing either one answers one
question by making another unanswerable.

**Add `source_package` beside `package`.** Chosen. The grouping then lives in the query, which
is the same reasoning ADR 0010 used for not deriving an `os` / `app` label.

### For the location

**Publish every location as a comma-separated list**, like `fixed_in`. Rejected: `fixed_in` is a
list of alternatives, where "any of these versions" is one fact. Several locations on one
package record are several paths that led to one record, and a label that sometimes holds a list
is a label every query has to parse.

**Leave it out and tell people to look in the image.** This is the status quo, and it is what
the analysis above actually did. Rejected because it costs a person an hour per finding and
because the answer is already in the SBOM that was catalogued anyway.

**The first location, from Syft's own ordering.** Chosen.

## Decision

### `kiebitzr_vulnerability_suppressed{image_digest, reason}`

A gauge, valued with the number of findings one filter removed from one image digest in the
last run. `reason` is `ignore_rule`, `min_severity` or `only_fixed`.

The reasons are **disjoint and ordered**: the filters apply in that order, and a finding is
counted under the first one that removed it. Summing them therefore gives the total removed,
with nothing counted twice.

The counts are in **series, not matches** — deduplicated by the same label set the exporter
deduplicates published findings on. Two matches that would have collapsed into one series are
one suppressed finding. Without that the number could not be read against
`count(kiebitzr_vulnerability)`, which is the comparison it exists for.

**A filter that removed nothing from a digest gets no series.** There is nothing hidden to
account for, and a zero per digest and reason would be three series per image bought for no
answer. Which filters are configured at all is in the start-up log, where the configuration
belongs; that a binary might predate the metric is ruled out by `kiebitzr_build_info`, as
everywhere else.

The ignore-rule count is Grype's own set of ignored matches, which this service was discarding.
Only the rules this service hands to Grype can appear there — matcher-side suppressions stay
out, because `IncludeMatcherSuppressions` is not set — so the number is attributable to the
configuration and not to Grype's internals.

Candidate images (ADR 0011) are matched through the same policy and therefore suppress findings
too. Those counts are **dropped**: nobody runs a candidate, and a suppression series for one
would name a digest that appears in no other metric, where it would read as a running image
whose findings are being hidden.

### `source_package`

`kiebitzr_vulnerability` carries the package the affected one was built from — `openssl` for
`libssl3` and `libcrypto3`, `curl` for `libcurl`. Grype derives it while matching, from a dpkg
`Source` field, an rpm's source RPM or an apk's origin package, so this reads a value that is
already there.

`package` stays. The source package is what you fix; the binary package is what is installed and
what an ignore rule matches.

**A package that is its own source carries its own name.** The sources state an origin only
sometimes — dpkg omits the field when it equals the package name, and Grype drops rpm's in the
same case — so an empty value would mean "same as the package" for a deb and "no idea" for a Go
module. One label value cannot carry both. With the fallback,
`count by (cve, source_package)` is correct for every finding rather than only for the
distribution ones. This is ADR 0010's unknown-value rule applied to a case where there is a
better answer than `unknown`.

It costs **no series**: the source package is determined by the package it describes.

### `location`

`kiebitzr_vulnerability` carries the path of the artefact inside the image —
`Package.Locations[0].RealPath` as Syft recorded it, in Syft's own stable ordering so the label
does not move between runs for an unchanged image. `unknown` where no path was recorded, for
ADR 0010's reason: an empty label value cannot be told from an absent one.

For a distribution package this is the package database and says nothing. That is accepted
rather than special-cased: a rule like "omit it for apk, deb and rpm" is our judgement compiled
into the metric, and the honest value is the one Syft recorded.

**This label does cost series, and that is the part worth stating plainly.** Where one image
contains several artefacts carrying the same package at the same version — five Go binaries
built with one toolchain, one vendored library in two places — those findings arrived as one
series and now arrive as one per path. The split is the answer the label exists to give, and
the images that pay for it are exactly the ones where the question could not be answered. Images
whose findings are distribution packages are unaffected: every apk or dpkg package has the one
location.

## Consequences

- The filters become safe to recommend. `-ignore-file` can be put in front of an operator
  with a number beside it, which is what the documentation needed before it could encourage
  narrowing at the service.
- `kiebitzr_vulnerability` gained labels for the third and fourth time. Queries matching on a
  subset of labels are unaffected; queries pinning the full label set break. ADR 0010 already
  called the second occurrence a hint that the full label set is not a stable thing to pin —
  this is the third, and the runbook now says so where the label list is.
- The scrape grows for images with several similarly-built binaries, and only for those. The
  runbook carries the query that measures it per image, because this is the first label in this
  service that trades cardinality for an answer rather than being free.
- `Session.Match` returns what the policy removed alongside the findings. The suppression count
  has to be produced where the suppression happens, and nothing downstream can reconstruct it —
  the same argument ADR 0008 made for the exploitation evidence it found being thrown away.
- `topk` by `package` in the runbook and the dashboard becomes `topk` by `source_package`. The
  Python bytecode artefact (`pyc`, `python3-pyc`, `python3-pycache-pyc0`) survives it: those are
  genuinely separate package records, not one source package, so an ignore rule is still the
  answer — and now a counted one.
- Nothing here pages. A suppression count is not clearable at 03:00 by the person it would wake,
  and neither is a backlog that a label made easier to read. All three are dashboard material,
  which `kbz:req:00001` is explicit about.

## Amendment: measured on a real image

Written with the mechanism read out of Grype's and Syft's source and tested against
hand-written matches. The integration test now runs it against a real registry, a real SBOM and
the real database, and the numbers are in, measured on 2026-11-13 against a
distribution-based image with one Go binary in it:

| | |
|---|---|
| findings | 326 |
| of those, naming another source package | **83** |
| examples | `libcrypto3` from openssl, `libcurl` from curl, `busybox-binsh` from busybox, `git-init-template` from git |
| distinct locations | **2** — the apk database, and `/usr/local/bin/trivy` |
| an ignore rule naming one CVE | removed it, and `kiebitzr_vulnerability_suppressed{reason="ignore_rule"}` counted it |

Three things are settled by that. `source_package` does what the item claimed — a quarter of
the findings of that image are counted under a name nobody fixes. `location` separates the
distribution packages from the binary exactly as described, and the dpkg-database case really
is the uninteresting majority. And the suppression count is not a reading of our own code: it
comes back from Grype's own ignored-matches list through a real match.

What that measurement did **not** settle is the cardinality `location` costs, because the image
carried one binary. A cluster run on the same day did, and it is the number this ADR was most
exposed on:

| | |
|---|---|
| series with `location` | 11,099 |
| series the same findings would have been without it | 10,755 |
| **what the label cost the whole cluster** | **344 series, +3.2 %** |
| the worst single image | **2.5×** |
| four images | ≥ 2.0× |
| everything else in the top ten | ≤ 1.16× |

**The fear was overstated, twice.** The reasoning above allowed for five Go binaries on one
toolchain turning thirty series into a hundred and fifty, and that shape does occur — one image
carries four Go binaries on two toolchains, three of them sharing `go1.26.3`, where one series
became three. But the per-image multiplier is not the price: the images with the highest factor
are small ones, so across the cluster the label cost **344 series out of eleven thousand**. The
multiplier is real, bounded, concentrated in a handful of images, and nearly invisible in the
scrape.

Which means the warning in the runbook should be read as "this is the one label that is not
free", not as "watch out for it". Three per cent bought the answer to "which binary" for every
image in the fleet.

The same run settled the other half of the claim. `source_package` was predicted to roughly
halve the count an operator reads; it cut it by two thirds — 3,635 pairs of `(cve, package)`
against 1,223 of `(cve, source_package)` across about 11,100 findings. And `location` answered
the question that produced this ADR: the thirty-odd `stdlib` findings whose carrier could only
be guessed at all sat in one helper binary under `/usr/local/bin`, in three images, exactly as
the guess had it and now without the guessing.

## Open questions

- **What a healthy suppressed share looks like.** The runbook suggests that above about half,
  the inventory is being filtered rather than narrowed. That number is reasoning, not
  measurement, and a month of operating a configured installation is what would replace it.
- **Whether `source_package` should also be what the candidate check compares on** (ADR 0011).
  It compares per `cve`, `package` and `package_type` today, so a candidate that renames a
  binary package while keeping the source looks like a finding that survived. No instance of
  that has been observed; it is recorded here so the next person does not have to rediscover it.
- **How much `location` actually costs**, per image and across a cluster. The mechanism is
  understood and the query is written; the number needs a running installation.
