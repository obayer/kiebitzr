---
id: kbz:runbook:00002
title: Running Kiebitzr
date: 2026-11-06
status: active
tags:
  - kubernetes
  - rbac
  - caching
  - sbom
related:
  - id: kbz:adr:00001
    reason: The design whose operational requirements this records
  - id: kbz:runbook:00001
    reason: What to do with the metrics once it runs
  - id: kbz:adr:00007
    reason: The configuration surface these values are set through
  - id: kbz:adr:00011
    reason: Decided the deployability check this records the operation of
  - id: kbz:adr:00013
    reason: Decided the build access classification this records the configuration of
---

# Running Kiebitzr

What the service needs from a cluster, and the figures to size it with. The manifests
themselves belong to the repository that deploys Kiebitzr — names, namespaces and storage
classes are installation decisions (ADR 0001). What is written here is the requirement.

## What it needs

**Kubernetes.** One permission, cluster-wide:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
```

`watch` may be granted alongside `list` and is harmless, but the service only lists. No
Secrets, no writes, no other resource kind — anything beyond this is a mistake or a different
version.

**One matcher.** The inventory comes from the API server, not from the local kubelet, so this
is a single cluster-wide deployment and not a DaemonSet. Which node it runs on only matters
for its own resource use. It needs its volume back after a restart, so a StatefulSet with a
`volumeClaimTemplate` is the right shape: the identity and the cache stay together, and the
single-attach guarantee is what stops two processes sharing one cache directory.

**Workers, optionally — and never just one.** Cataloguing can move out of the matcher into a
*pool* of stateless pods (ADR 0009). Below one or two hundred image digests there is no reason
to: the default, `-catalogue-locally=true`, is one pod doing everything and is the whole of this
runbook unless stated otherwise. A single worker is the one shape to avoid, because it adds a
pod and a network hop without adding any throughput — see *How many workers* below, which also
covers the one case where it is nevertheless the right answer. *Scaling cataloguing out* says
when the switch is due and what the second shape needs.

Note that the threshold is the number of **distinct image digests**, not the number of nodes.
Cataloguing happens once per digest, ever, so a thousand nodes running the same twenty images
cost no more than twenty nodes running them.

**Network.** The API server, the registries of the images that run in the cluster, and
`grype.anchore.io` for the vulnerability database. Nothing else, and nothing inbound except
the scrape of `/metrics`.

**Registry credentials**, if any image is private — see below. The service reads no Secret
through the API; it reads a file the kubelet placed in its own filesystem, as any pod does.

### Registry credentials

This is the first thing that goes wrong, and the error is unambiguous:

```
image failed  digest=sha256:…  err=catalogue: resolve ghcr.io/…@sha256:… for linux/arm64:
  oci-registry: failed to get image descriptor from registry:
  GET https://ghcr.io/token?scope=…: UNAUTHORIZED: authentication required
```

**An `imagePullSecret` does not help.** The kubelet uses those to pull a pod's own image; they
are never visible inside the pod. Kiebitzr pulls images itself and needs its own copy of the
credentials, as a file:

1. Mount a Secret holding a Docker config into the pod.
2. **Project the key to the file name `config.json`.** A Secret of type
   `kubernetes.io/dockerconfigjson` stores its content under the key `.dockerconfigjson`,
   and that is not the name the credential lookup expects:

   ```yaml
   volumes:
     - name: registry-credentials
       secret:
         secretName: <your pull secret>
         items:
           - key: .dockerconfigjson
             path: config.json
   ```

3. Set **`DOCKER_CONFIG` to the mount directory**, not to the file — the lookup appends
   `config.json` itself.

Credential helpers (`credsStore`, `credHelpers`) work only if the helper binary is in the
image, and it is not: the release image is a distroless binary. Use plain `auths` entries, for
example a token with read access to the packages.

The same applies to a local run outside the cluster: `docker login ghcr.io` once, so the
credentials land in `~/.docker/config.json`.

## Sizing

Measured on a cluster with 50 running image digests, 75 containers and about 11,400 findings.

### Storage — the one that needs attention

| Item | Size |
|---|---|
| Vulnerability database, active | **3.2 GB** |
| Same again, during an update | **+3.2 GB** |
| Downloaded archive, during an update | a few hundred MB |
| SBOM per image | ~2 MB (108 MB for 50 images) |

Grype unpacks a new database into a temporary directory **inside the cache directory** and
only then activates it, so an update transiently needs room for both. A volume sized for the
active database alone will fail an update at some point, and a failed update means a failed
run: the findings stop moving and only the freshness metrics say so.

**Give it 10 GB**, on block storage. An SD card would survive the ~3.2 GB written on each
database update by the numbers, but it is the wrong place for a daily multi-gigabyte rewrite;
a USB SSD on an ARM board is both faster and the right wear profile.

The cache is rebuildable. Losing it costs one slow run — every image is catalogued again — and
never any data. What "losing it" means in Kubernetes is worth being precise about, because an
`emptyDir` survives a **container** restart but not a **pod** replacement: a crash or a
liveness kill comes back warm, while a `rollout restart`, a new image tag, an eviction or a
node reboot starts from nothing and pays the full cold run plus the 3.2 GB download. Since
every deployment of a new tag replaces the pod, an `emptyDir` means every deployment pays it.

### The temporary directory is a second volume

Cataloguing unpacks an image's layers through Stereoscope's temp-dir generator, which is
rooted in the **operating system's temporary directory** — not in the cache directory. So a
new image needs transient room under `/tmp` and nothing there needs to survive anything.

Keep it ephemeral, and keep it **off `medium: Memory`**: the uncompressed layers of the image
being catalogued would otherwise sit in the node's RAM, next to the heap below and, if the
cache is memory-backed too, next to the database. An eviction caused by that takes down more
than this pod. An `emptyDir` on node disk with a `sizeLimit` is the right shape, and the
limit follows the **largest single image**, not their sum — only one image is catalogued at a
time (`parallelism = 1`, internal/catalog).

`$TMPDIR` steers it, so the unpacking can be moved into the cache volume with one
environment variable. Don't: during a database update that volume already needs 3.2 GB twice
over, and a large extraction on top is how an update runs out of room — the failure this
section exists to prevent.

### Memory

The live heap peaks around **274 MB** while an image is catalogued. Left alone, the Go heap
grows well past that before collecting: 1.16 GB of arena was observed.

Set **`GOMEMLIMIT`** (for example `1GiB`) and a container memory limit above it (`1.5Gi`).
That way the garbage collector does the regulating — it works harder as the limit approaches —
instead of the OOM killer ending the process. A memory limit without `GOMEMLIMIT` gives the
runtime no reason to stay below it.

### CPU

A run is one core, by design: cataloguing is deliberately not parallel, because parallelism
multiplies peak memory. Requests of `200m` are plenty for the daily steady state.

**Be careful with a hard CPU limit.** CFS throttling stretches the one long operation this
service has — the cold start, which catalogues every running image — from tens of minutes into
hours. Either leave the limit off or set it to a whole core or two.

### Time

| Phase | Measured / estimated |
|---|---|
| Warm run, 50 digests, everything cached | 44 s on a fast x86/arm64 machine; a few minutes on a Cortex-A72 |
| Cold start, 50 digests | minutes on a fast machine; 20–35 minutes estimated on a Cortex-A72 |
| Database download and unpack | once a day, a few minutes on a small board |

`-interval` defaults to 24 h because the database is published daily; scanning more often
re-reads every SBOM and re-runs every match to reach the same findings. `-run-timeout`
defaults to 2 h and is deliberately not tied to the interval: a cold start must be allowed to
finish, because a run cut short **while matching** publishes nothing at all.

Cataloguing has its own, shorter budget. `-catalogue-timeout` defaults to three quarters of
`-run-timeout` — 90 minutes of the two-hour default — and the remainder is what matching and
publishing get. That split is what keeps a cold start useful: when the budget runs out, the
digests that were catalogued are published with their findings and the rest are reported as
`kiebitzr_images{state="pending"}` and `kiebitzr_image_pending`, instead of the whole run
publishing nothing. Set it explicitly if you shorten `-run-timeout`; a value at or above the
run timeout is refused at start-up, because it would leave matching no room and silently
restore the old behaviour.

### How long a cold start takes, and when that stops working

The figures above are 50 digests. Cataloguing is serial and costs 24–42 s per digest on a
Cortex-A72, which scales badly in exactly one direction:

| Digests | Cold start, one pod | Fits in 90 min of catalogue budget? |
|---|---|---|
| 50 | 20–35 min | yes |
| 200 | 1.5–2.5 h | no — two runs |
| 1000 | 6.7–11.7 h | no — five or more runs |

Nothing breaks: each run catalogues what it can, keeps those SBOMs and publishes what it has.
But at a 24-hour interval, a thousand digests mean about five days before the picture is
complete. That is the point at which the worker pool is worth deploying.

## Configuration

`kiebitzr -h` lists every flag of the running build, and **every one of them is also an
environment variable**: uppercase, hyphens to underscores, prefixed `KIEBITZR_`. So
`-upgrade-candidates` is `KIEBITZR_UPGRADE_CANDIDATES` and `-min-severity` is
`KIEBITZR_MIN_SEVERITY`. There is no second list to look up — the name is derived from the
flag (ADR 0007), which is why this table names flags only.

The ones a deployment usually sets:

| Flag | Default | Purpose |
|---|---|---|
| `-listen` | `:8080` | address serving `/healthz` and `/metrics` |
| `-platform` | `linux/arm64` | the manifest a multi-arch index is resolved to |
| `-cache-dir` | `/var/cache/kiebitzr` | cached SBOMs and the vulnerability database |
| `-interval` | `24h` | time between the start of two runs; the vulnerability database is published daily, so scanning more often repeats the same work |
| `-run-timeout` | `2h` | how long a single run may take; deliberately not the interval, because a cold start catalogues every image |
| `-catalogue-timeout` | ¾ of `-run-timeout` | how long cataloguing may take within a run; what it does not reach is published as pending rather than withheld |
| `-exclude-namespaces` | — | comma-separated namespaces to ignore completely. **The one narrowing that leaves no trace** — see the metrics runbook |
| `-min-severity` | — | drop findings below a severity; what it drops is counted in `kiebitzr_vulnerability_suppressed` |
| `-only-fixed` | `false` | report only findings that have a fix, counted the same way |
| `-ignore-file` | — | YAML file of Grype ignore rules under an `ignore:` key, counted the same way |
| `-build-access-file` | — | YAML file classifying repositories by whether anybody here can get a build of them, under a `build-access:` key; without it every image is `unknown`. See *Declaring which images somebody here can get a build of* below |
| `-upgrade-candidates` | `0` (off) | how many candidate images per repository to check, to find out whether a deployable image exists that clears a finding. Costs a tag listing per repository and one SBOM per candidate |
| `-upgrade-scope` | `exploited` | which findings get that check: `exploited` (the only ones that could page) or `fixable` (≈3× the work) |
| `-role` | `matcher` | `worker` runs the cataloguing half and nothing else — see *Scaling cataloguing out* |

A malformed value is a **start-up error**, not a silently kept default (ADR 0007). That is
deliberate and it is also the thing to expect when a pod stops coming up after a ConfigMap
change: the reason is in the log, on the first line.

### What the pod thinks its settings are

Every start logs **every setting with the value in effect**, on one line, so "did my ConfigMap
land" is answered without a shell in the pod:

```bash
kubectl logs deploy/kiebitzr | head -2
```

```json
{"level":"INFO","msg":"starting","version":"v2026.1109.2","commit":"f783826…"}
{"level":"INFO","msg":"settings","role":"matcher","listen":":8080","platform":"linux/arm64",
 "cache_dir":"/var/cache/kiebitzr","interval":"24h0m0s","run_timeout":"2h0m0s",
 "catalogue_timeout":"1h30m0s","catalogue_locally":true,"exclude_namespaces":"",
 "min_severity":"","only_fixed":false,"build_access_file":"","upgrade_candidates":0, …}
```

Three things about that line are worth knowing:

- **Values are reported as resolved, not as given.** `catalogue_timeout` above is `1h30m0s`
  although no flag set it — it is three quarters of `-run-timeout`. Comparing the ConfigMap
  against the log means comparing intent against effect, which is the comparison you want.
- **Every role logs every setting**, including the ones it ignores. A worker reports
  `interval` even though it runs no loop: a value that arrived and does nothing is exactly the
  mistake this line exists to show.
- **A credential in `-matcher-url` is redacted**, so a URL with a username in it does not end
  up in a log index.

Read it together with the warning below about unknown `KIEBITZR_*` variables: the settings line
says what the process believes, and that warning says what it was handed and could not use.

### Setting values from a ConfigMap

Because the variable names are derived from the flags (above), the values can come from a
ConfigMap instead of `args:` without anything here declaring them. Write them as an env file:

```bash
# kiebitzr.env — one line per flag, same transformation every time
KIEBITZR_INTERVAL=24h
KIEBITZR_MIN_SEVERITY=high
KIEBITZR_UPGRADE_CANDIDATES=3
KIEBITZR_BUILD_ACCESS_FILE=/etc/kiebitzr/build-access.yaml
```

Bind it with `envFrom`, and generate it rather than writing the ConfigMap by hand:

```yaml
configMapGenerator:
  - name: kiebitzr
    envs: [kiebitzr.env]
```

The generated name carries a content hash, which is what makes a changed value roll the
Deployment. A hand-written ConfigMap keeps its name, and running pods keep the old values
until something restarts them — that is the failure to watch for when a change appears to do
nothing. The second thing to check in that case is the start-up log: the `settings` line says
which values the process is actually using, and a `KIEBITZR_*` variable that matches no flag is
named in a warning beside it, which is what a misspelled key looks like.

An argument in `args:` overrides the environment, deliberately. If a value refuses to change,
look for it in the pod spec before suspecting the ConfigMap.

The variable names are **derived rather than declared**, so a new flag gets its variable
automatically and this document cannot drift out of date about which ones exist. And the binary
reads no `.env` file: that file belongs to the repository that deploys Kiebitzr, as input to the
`configMapGenerator` above, whose name hash is what rolls the Deployment.

### Platform

`-platform` must match the architecture of the nodes, not of the machine the binary runs on:
it selects which manifest of a multi-arch image index is catalogued. The default is
`linux/arm64`. Getting this wrong fails every image with
`kiebitzr_scan_errors_total{reason="unreachable_image"}`.

## Declaring which images somebody here can get a build of

Optional, and it costs nothing at runtime: no requests, no SBOMs, no series. `-build-access-file`
points at a YAML file that classifies repositories, and the result is the `build_access` label on
`kiebitzr_image_info` (ADR 0013).

It exists because the metric set otherwise treats two very different situations alike: an image
from a project nobody here can reach, where the only remedy is a newer tag, and an image built
by your own team or by one you can ask, where a rebuild is an available action even when no
newer image exists. The second case is invisible without this, and it is a work list.

```yaml
build-access:
  # The team's own repositories: a build can be triggered without asking anybody outside.
  - repository: registry.example/org/platform/*
    access: own
  # One repository of its own, with nothing below it: named exactly. Written with a `/*` this
  # rule would be accepted and would match nothing — see below.
  - repository: registry.example/org/app
    access: own
  # Another team in the same organisation — a build needs their decision, and you can ask.
  - repository: registry.example/org/billing/*
    access: reachable
  # A mirrored upstream image that happens to sit in the same namespace.
  - repository: registry.example/org/platform/mirrored-upstream
    access: none
```

Five things about the file. Four of them are a start-up error when broken, because a wrong
classification is invisible in the metrics — nothing else can check it. The first is not, and
that is why it comes first:

- **`/*` means *below* this path, and that excludes the path itself.** `registry.example/org/*`
  matches `registry.example/org/app` and does **not** match `registry.example/org` — which is
  what stops a rule for a team's namespace from also claiming a repository that happens to carry
  the team's name. The consequence is for repositories published without sub-paths, which is the
  usual shape (`ko --bare` and most CI produce `registry.example/org/app:1.4.0` with nothing
  below it): name those exactly, without the suffix. `registry.example/org/app/*` is a **valid
  file that classifies nothing** — it is accepted, matches no image, and leaves everything
  `unknown`, which is indistinguishable from having mounted no file at all. Nothing can report
  this for you; the `unknown` count below is what catches it. One rule per namespace covers both
  shapes at once and is the form to reach for.
- **The most specific rule wins**, counted in path segments. A namespace-wide rule is a default
  that a single repository overrides, which is the normal shape: one rule per team, exceptions
  per repository. Two rules of equal specificity are rejected rather than resolved by order.
- **Patterns are fully qualified and match whole segments.** `registry.example/org/*` matches
  everything below it; `registry.example/org/plat*` is refused, because it would also match
  `platform-mirror`. A pattern without a registry is refused too — writing `library/nginx` and
  meaning Docker Hub is a guess, and the message says to write `index.docker.io/library/nginx`.
- **Matching is against the normalised reference**, so one rule for `index.docker.io/library/*`
  catches a pod that says `nginx:1.2` as well as one that says the long form.
- **`unknown` cannot be declared.** It is what no rule matching means.

**With no file at all, every image is `unknown`** — and that is a stated classification, not a
gap. It is also the thing to watch, because this axis is only worth its upkeep:

```promql
count(kiebitzr_image_info{build_access="unknown"})
```

An image pulled into the cluster next month appears there, which is the reminder that somebody
has to sort it. What this cannot notice is a classification that has gone stale — a team
dissolved, a component handed over. Review the file when workloads change hands; nothing else
will.

The queries this is for — the morning queue and the list you can clear yourself — are in
*Is there anybody to ask?* in the metrics runbook. None of them pages: what the recipient can do
is ask, and asking is not ending.

## Checking whether a fix is deployable

Off by default. `-upgrade-candidates` turns it on, and the value is how many candidate images
per repository to check.

It is **in force**: a run selects candidates, catalogues and matches them, and publishes
`kiebitzr_image_upgrade_candidate` and `kiebitzr_image_upgrade_unknown`. Off by default because
it costs registry requests and SBOMs, not because it is unfinished — the figures are under
*What it costs* below. What remains open is the fallback for repositories whose builds cannot be
ordered (ADR 0011's open questions, `TODO.md` T11); that case is reported as
`unknown` rather than guessed at.

### Why it exists

A finding says `fix_state="fixed"` when a fixed *package version* is named in an advisory. That
is not a fix you can deploy: nothing is patched inside a running container, so the only remedy
is a different image — and the advisory says nothing about whether one exists.

This is also the reason **no finding may page**. An alarm has to be clearable by whoever it
wakes, and a finding whose fix exists only as a version number is not clearable at 03:00. Until
deployability is verified, urgency lives on the dashboard.

### What it does, on one image

Say a pod runs `registry.example/app:1.4.0`, and its findings include:

| | |
|---|---|
| `package` | `libcurl` |
| `installed` | `8.5.0-r0` |
| `fixed_in` | `8.7.1-r0` |
| `known_exploited` | `true` |

With `-upgrade-candidates=3`, each run additionally:

1. **lists the tags** of `registry.example/app` — one registry request
2. **reads when each was built**, from the image config of the manifest for your `-platform`.
   Small JSON, no layers
3. **keeps those built after the image you run**, newest first, and takes the first three
4. **catalogues and matches each**, unless the SBOM cache already has it
5. **counts how many of `1.4.0`'s in-scope findings each one clears**

Build time, not tag name, decides the order. Tag strings are arbitrary — SemVer beside CalVer
beside `3.1-alpine` — and every ordering over them is a heuristic that eventually picks wrong.
`created` is a number.

Three candidates rather than one, because the newest *build* is not reliably the newest
*content*: a publisher maintaining two release lines can ship a backport after the next minor,
and a repository with a `nightly` tag has its newest build be something nobody would deploy.
Looking at the next few costs one SBOM each and removes both.

### Turning it on

```yaml
# The usual choice.
- -upgrade-candidates=3

# Only the newest build. Cheapest, and misses a recent backport.
- -upgrade-candidates=1

# Off. The default; the flag can be omitted entirely.
- -upgrade-candidates=0
```

`-upgrade-scope` decides which findings get checked, and it is the cost lever:

| | |
|---|---|
| `exploited` (default) | known-exploited findings with a fix. The only ones that could ever page |
| `fixable` | every High and Critical with a fix. Roughly three times the work, for findings nobody acts on tonight |

As with every flag, `KIEBITZR_UPGRADE_CANDIDATES` and `KIEBITZR_UPGRADE_SCOPE` do the same from
a ConfigMap (ADR 0007).

### A positive is a promise, a negative is only as good as the search

One candidate that clears the finding is enough, and it is definitive: there is an image to
deploy, and the tag is in the label so you know which.

A negative says **"none of the candidates checked clears it"** — with the tags named. It does
not say no fix exists anywhere. If you see that `nightly` and two release candidates were
checked, you know what the statement is worth.

### Unknown is not "no fix"

Five situations produce no answer rather than a negative one, and each gets its own reason:

| reason | What happened |
|---|---|
| `no_tags` | the registry would not list the repository's tags, or there are none |
| `unorderable_builds` | the builds cannot be put in time order — see below |
| `platform_missing` | no candidate carries a manifest for your `-platform`; an amd64-only image is no fix for an arm64 node |
| `unreachable` | the registry refused or could not be reached, usually a credential or a rate limit |
| `not_catalogued` | the run ran out of budget before a candidate had an SBOM |

**Nothing newer existing is not in that list.** If every build is older than the one you run,
that is an answer: you are on the newest, and there is nothing to deploy. It is reported as a
candidate count of zero, and the series exists at zero rather than being absent.

### The case where this gives up: reproducible builds

Reproducible builds set the image's creation time to a **fixed** value on purpose, so that the
same source produces byte-identical output. ko, Bazel and Nix all do it, writing the Unix epoch.
This project's own image is built by ko with nothing overriding it, so it is almost certainly
affected.

For such a repository every build carries the same timestamp, and "newer than what runs" has no
meaning. That is reported as `unorderable_builds` and **never as a negative**, because a
negative suppresses a page. The honest reading is "these builds cannot be ordered, look
yourself".

Measured on five repositories a real cluster runs — a GitOps controller, a backup operator, an
application image and two scanners — all five carry usable timestamps, so the exception is real
but not the common case. The
ways out are recorded in ADR 0011 as open questions rather than built; the one with the best
cost-to-value ratio is reading `buildFinishedOn` out of a BuildKit provenance attestation, and
the probe in `internal/upgrade` is what measures how often that would help.

### What it costs

From the cold-start figures above: **24–42 s and ~2 MB per image** on a Cortex-A72.

| | SBOMs per run | Cataloguing | Cache |
|---|---|---|---|
| `-upgrade-candidates=3`, scope `exploited` | 48 | **19–34 min** | 96 MB |
| the same with scope `fixable` | 123 | 49–86 min | 246 MB |

So the default shape costs about **one extra cold start**, once — and then only when a candidate
moves, because the SBOM cache is digest-addressed and candidate digests are kept rather than
pruned. Allow for it in `-catalogue-timeout`, or expect `not_catalogued`.

Registry requests are not the constraint: one tag listing per repository plus a config fetch per
tag, all small JSON. Against a rate-limited registry — Docker Hub above all — that still argues
for leaving `-interval` at its daily default.

**Candidates never go ahead of a running image.** A cluster that cannot keep up with its own
images keeps its primary metrics and reports `not_catalogued` for the rest.

### What it does not tell you

Whether the candidate is a sane upgrade. The newest build may be several major versions ahead,
may change the entrypoint, may drop a feature you use. The report says which tag clears the
finding and how many it clears; the decision to go there is yours, and the tag is what lets you
judge it.

## Scaling cataloguing out

Which shape an installation wants, before any of the detail:

| Cluster | Pods | What to set |
|---|---|---|
| Up to roughly 200 image digests | **one matcher** | nothing — this is the default |
| Beyond that | one matcher **+ a pool of workers** | matcher: `-catalogue-locally=false -work-listen :8081`<br>workers: `-role worker -matcher-url http://<matcher service>:8081` |

One matcher is a complete installation: it takes the inventory, catalogues, matches and serves
the metrics, and it is the only pod with a volume, a vulnerability database and any Kubernetes
permission at all. The threshold is the number of **distinct image digests**, not of nodes — a
thousand nodes running the same twenty images need nothing from this.

The same binary and the same image run both roles; `-role` decides which (ADR 0009). Deploying
a pool is three changes to the matcher and one new Deployment.

**The matcher** stops cataloguing and starts handing the work out:

```
-catalogue-locally=false
-work-listen :8081
```

Both together or neither — each alone is refused at start-up, because a matcher that
catalogues itself never fills the queue and workers would poll an empty one forever, while a
matcher that does neither would catalogue nothing at all.

`-work-listen` is a second port on purpose. `/metrics` stays on `-listen` for Prometheus; the
work API is internal and takes POSTs, so the two want different NetworkPolicies. Expose the
work port through a Service the workers can reach, and nothing else.

**The workers** are an ordinary Deployment, scaled by replica count:

```
-role worker
-matcher-url http://<matcher service>:8081
-platform linux/arm64     # must match the matcher's
```

What a worker needs, and what it does not:

| | Worker |
|---|---|
| Kubernetes permissions | **none** — no ServiceAccount token needs mounting |
| Persistent volume | none |
| Vulnerability database | none, so no 3.2 GB and no daily download |
| Registry credentials | **yes** — the same `DOCKER_CONFIG` mount as above |
| Temporary space | yes, sized by the largest single image, as for the matcher |
| Memory | the 274 MB peak and `GOMEMLIMIT` advice move here, per worker |

This is also where the credentials end up separated: after the split the matcher reads pods
and holds no Docker config, while a worker pulls images and cannot reach the API server at
all. No component holds both.

`-platform` must be the same on both. A worker resolves the index itself, so a mismatch fails
every image with `unreachable_image` — and it fails on the *worker*, while the metric appears
on the matcher.

### How many workers

**Not one.** This is the first thing to get right, because "one of each" is the natural reading
of a matcher-and-workers design and it is the one shape that makes things worse. A single
worker catalogues exactly as serially as the matcher would have done itself — `parallelism = 1`
is per process, so nothing is gained — while every SBOM now crosses the network and a second
pod has to be run and watched. Zero workers or four to eight; one is strictly worse than zero.

Size the pool from the queue, not from CPU: a worker spends its time waiting on a registry, so
its own CPU says nothing about whether another worker would help.

```promql
kiebitzr_catalogue_queue_depth
```

Sixteen workers bring the 1000-digest cold start from 6.7–11.7 h to roughly 25–45 min. In a
steady state the queue is empty for most of the day, so a fixed four to eight replicas is a
reasonable default and an autoscaler on the depth is only worth it if your image estate churns
hard. Whether to use one is an installation decision and not in this repository.

**The one exception**, and it is about memory rather than throughput: cataloguing peaks at
274 MB of live heap with over a gigabyte of arena (see *Memory* above), and that peak moves
into the worker. A single worker on a roomy node therefore buys a matcher that can be sized
small and stays predictable — worth it when the matcher sits on a board where that peak is the
difference between fitting and being evicted. It is not faster; it is calmer. If that is the
reason, say so in the deployment, because the replica count otherwise looks like a mistake.

### Losing the matcher

The matcher is a single point of failure for **freshness**, not for data. Its findings keep
being served while it is down, `kiebitzr_last_success_timestamp_seconds` stops moving, and a
StatefulSet brings it back with the same volume in minutes — against a freshness budget of a
day, that is not a problem worth engineering around.

Losing the **volume** is the real case, and the pool is the answer to it: the cache is
rebuildable by design, and with workers it is rebuildable in parallel. The disaster recovery
for a lost cache is one cold start, which is under an hour with a pool rather than several days
without one.

### Two timings to leave alone unless you have a reason

`-work-deadline` (10 min) is how long a handed-out digest may stay out before it is offered to
someone else. It has to exceed the time cataloguing one image takes, or healthy work is handed
out twice; raise it if your largest images take longer than that on your nodes.

`-work-attempts` (3) bounds how often a digest is handed out when **no answer** comes back at
all — a worker that was evicted, OOM-killed or lost the network. A worker that does answer has
answered: a reported failure is final and is never retried. After the last attempt the digest
becomes `kiebitzr_image_failed{reason="catalogue"}`, and the log line says it was attempts
rather than the image's contents.

## What a first start looks like

1. The database is downloaded — several hundred megabytes, once.
2. Every running digest is catalogued. This is the slow part, and it is bounded by
   `-run-timeout`, not by the interval.
3. The result is published as a whole, `kiebitzr_last_success_timestamp_seconds` moves, and
   `kiebitzr_images{state="scanned"}` equals the number of digests it got through.
4. Every later run finds its SBOMs in the cache: `state="cached"` instead of `"scanned"`.

If cataloguing runs out of its budget, the run still publishes: the digests it managed appear
with their findings, and the rest are named by `kiebitzr_image_pending`. The SBOMs already
written stay in the cache, so the next run starts further along and the pending count falls. A
cold start that needs more than one run is slow, not broken — and it is no longer silent.

A run cut short while **matching** is the other case, and that one publishes nothing: an SBOM
that exists but was not matched would appear as an image with no findings, which reads as
clean. There is no metric for that, so the run fails and the previous result keeps being
served.

See [`reading-the-metrics.md`](reading-the-metrics.md) for what the numbers mean afterwards,
which errors say what, and the alerts that make a stopped scanner visible.

## Images that cannot be scanned

The service pulls from a registry. An image that exists only in a node's local container
store — built there and never pushed — cannot be catalogued, and shows up as
`kiebitzr_scan_errors_total{reason="unreachable_image"}` with a failed count. This is a
consequence of the access model, not a defect: reaching into a node's store would need the
container runtime socket, which ADR 0001 rules out. Push such images to a registry, even a
local one, or accept them as a blind spot — but know which it is.
