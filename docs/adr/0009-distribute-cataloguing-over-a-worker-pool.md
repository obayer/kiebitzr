---
id: kbz:adr:00009
title: Distribute Cataloguing over a Worker Pool, Keep One Matcher
date: 2026-11-10
status: accepted
tags:
  - architecture
  - scalability
  - kubernetes
  - rbac
  - caching
  - sbom
related:
  - id: kbz:adr:00001
    reason: Distributes the pipeline that ADR decides, under its access model and cardinality rule
  - id: kbz:runbook:00002
    reason: The measured figures this extrapolates from, and the deployment shape it changes
  - id: kbz:runbook:00001
    reason: The queries and alerts that have to change when a second pod exists
  - id: kbz:adr:00007
    reason: The configuration surface the new flags follow
---

# Distribute Cataloguing over a Worker Pool, Keep One Matcher

## Status

`accepted`, and implemented: `internal/workq` is the queue, `internal/dispatch` the work API
and the worker, `runner.Cataloguing` the stage with `runner.Serial` and `dispatch.Pool` as its
two implementations, and `-role` selects which process a binary is. `-catalogue-locally`
defaults to `true`, so an installation that deploys no workers is unchanged.

What has been exercised and what has not, precisely: the queue semantics, the client-to-handler
round trip, the rejections at the network boundary and the pending accounting are covered by
tests; the two roles as two processes against a real cluster are not. The figures in the
*Context* below are extrapolations from the 50-digest measurement in
[`running-kiebitzr.md`](../runbooks/running-kiebitzr.md), not measurements of a pool.

## Context

Kiebitzr runs as a single pod. Every run lists the cluster's pods, catalogues each new image
digest and matches every cached SBOM, one after another, in one process. On the cluster the
figures in [`running-kiebitzr.md`](../runbooks/running-kiebitzr.md) come from — 50 digests,
75 containers, 11 400 findings — that is the right shape. On a cluster with a thousand nodes
it is not.

### The work does not scale with nodes

This has to be said first, because it decides what to fix. Two costs exist in a run, and only
one of them follows the node count:

**Listing pods** is the one that does, and it is already handled. `inventory.Collect` pages
with `Limit: 500` and lets the API server drop everything that is not running via a field
selector; each page is projected and dropped. Thirty thousand pods are sixty list calls and a
peak of five hundred pods, once per interval.

**Cataloguing and matching** follow the number of *distinct digests*, which is a property of
the image estate, not of the fleet. A homogeneous thousand-node cluster can carry fewer
digests than a twenty-node development cluster. The serial loop in `Runner.scan` is where the
time goes, and `catalog.parallelism` is deliberately one because parallel cataloguing
multiplies the 274 MB peak.

Extrapolating the measured 24–42 s per digest for a cold catalogue on a Cortex-A72:

| | 50 digests (measured) | 1000 digests (extrapolated) |
|---|---|---|
| Cold start | 20–35 min | **6.7–11.7 h** |
| Warm run | a few minutes | ~70 min |
| Cache volume | ~3.3 GB | 2 GB SBOMs + 6.4 GB database = **8.4 GB** |

The failure this produces is specific. `-run-timeout` defaults to two hours, and a run that
is cut short publishes nothing at all — deliberately, so a partial result never reads as a
complete one (ADR 0001). A cold start of 1000 digests therefore publishes nothing, repeatedly,
while the cache fills a run at a time: roughly **five days before the first result appears**.
The service is not broken; it is useless for that week.

### The second wall

At 228 findings per digest — the measured ratio — a thousand digests are about 228 000
`kiebitzr_vulnerability` series from one target, and a scrape body in the tens of megabytes.
Distribution does not create this problem and does not solve it; `-min-severity` and
`-only-fixed` do, which is why ADR 0001 made them runtime configuration. It is recorded here
so that nobody reads a scaling ADR and concludes the metric side was considered and found
fine.

### Options considered

**A DaemonSet.** The reflex when one pod carries everything, and wrong here for four reasons.
Cataloguing pulls from the registry through `image.OciRegistrySource`, never from the node's
container store — ADR 0001 rules out the runtime socket — so a per-node split buys no
locality. A digest running on five hundred nodes would be pulled and catalogued five hundred
times. Each pod would need the 3.2 GB vulnerability database, so a thousand nodes mean 3.2 TB
and a thousand downloads a day. And every node would publish the same digest-keyed series,
which double-counts in every dashboard. Per-node placement only makes sense for a service
that reads its local kubelet, and this one reads the API server.

**Shard the whole pipeline by digest.** Several replicas, each taking the full inventory and
handling the digests whose hash falls to it. The metric side works out well — the digest is
the join key of the whole metric set, so every series stays owned by exactly one replica —
and the cache stays single-process per shard. It was rejected on storage: every shard needs
its own copy of the database, so N shards cost N × 3.2 GB, doubled during an update, plus N
downloads a day. The multiplier exists only because the *whole* pipeline is sharded, and the
decision below removes it instead of paying it.

**Leader election over homogeneous pods.** Every pod able to be either role, a lease electing
the matcher. Rejected on four counts. A new leader holds no cache and no database, so the
failover produces a pod that must download 3.2 GB and re-catalogue everything — fast
election, cold winner; the design only becomes coherent if both the database *and* the SBOM
cache are on shared storage, which trades the problem for an RWX dependency. The freshness
budget is a day (`-interval` 24 h, the stale alert at 36 h), so an RTO measured in seconds
buys nothing a StatefulSet reschedule does not already provide. Two leaders that briefly
disagree would have `Prune` delete each other's live entries and would publish every
digest-keyed series twice, which the per-process `dedupBy` guard cannot see — whereas an RWO
volume fences for free, because Kubernetes enforces single-attach. And each failover moves
228 000 series between `instance` values, breaking `rate`, `increase` and the `offset 24h`
query in [`reading-the-metrics.md`](../runbooks/reading-the-metrics.md). The lease right
itself (`get`, `create`, `update` on `coordination.k8s.io/leases`) is small and namespaced —
the objection is not the right, it is that it purchases nothing this service needs.

**Pod annotations as the channel between pods.** Rejected for the reason that disqualified
sbom-operator in ADR 0001: it needs `update` or `patch` on pods, and that is the right to
replace a running pod's image. We would be granting ourselves the very permission whose
absence is this project's argument. Two practical objections follow anyway — annotations are
capped at 256 KB against a 2 MB SBOM, so they could carry a marker at most, and thirty
thousand pod writes would go through etcd. The state here is digest-addressed and
rebuildable; it belongs on a disk, not in the cluster's consensus store.

**NATS with JetStream.** Rejected, and the reason is not size but direction. The queue is
*derived state*: it is recomputed every run from the inventory minus the cache, so a work
item that survives a restart is stale — the pod may be gone and the digest no longer running,
and a replayed item catalogues something `prune` then deletes. Durability is the feature we
would be paying for and the one we must not have. Beyond that: `go.mod` already lists 359
modules and every reachable vulnerability in that tree has to be defended in `.vulnguard.yaml`
with a reason and a review date (ADR 0005), so a broker's dependency tree is a recurring
obligation; JetStream's default message limit is 1 MB against a 2 MB SBOM, which would force
chunking or its object store — a second storage system beside the volume we already have; and
workers would need bus credentials to a stream that *is* the cluster's image inventory, which
ADR 0001 declines to hand to anything. The throughput is one item per eighty-six seconds.

**Grype behind an RPC facade.** Taking "one pod owns the database" literally. The seam is
clean — `vulnerability.Provider` is an interface — but `FindMatchesContext` queries the
provider repeatedly per package with version-constraint logic, so this would be tens of
thousands of round trips per image, and we would own a Grype-coupled network protocol that
breaks on every upstream release. The insulation it promises already exists in-process as
`runner.Opener` and `vulndb.Session`.

**Share the vulnerability database now.** Grype v6 is a single SQLite file, and the read path
opens it with `immutable=1`, `mode=ro` and `cache=shared` — locking is disabled entirely,
which is precisely the mode in which a SQLite file tolerates many readers across processes and
across a network filesystem. `LoadVulnerabilityDB` with `update=false` touches neither network
nor disk, and the curator creates no directories on the read path, so a read-only mount works.
This is a real option and it is deferred, not rejected: the decision below leaves exactly one
database in the cluster, so there is nothing to share yet. It becomes the right answer when
matching itself has to scale, and the shape is recorded under *Consequences* so that the next
person does not have to rediscover it.

## Decision

**Split the pipeline by stage, not by digest.** Cataloguing needs no vulnerability database at
all: it pulls an image and runs Syft. Only matching needs the 3.2 GB. So the expensive,
parallel, database-free stage moves to a pool, and the database stays in one place.

| | Matcher | Worker |
|---|---|---|
| Kind | StatefulSet, one replica, PVC | Deployment, N replicas, no volume |
| Vulnerability database | yes | — |
| SBOM cache | yes | — |
| Kubernetes access | `list` on pods | **none** |
| Registry credentials | — | yes |

Matching runs at roughly 1–4 s per digest, so a single matcher covers a thousand digests in
17 to 70 minutes. One is enough, and one is all the storage.

**Workers pull work; nothing pushes to them.** The matcher serves a work API and the workers
poll it:

```
GET  /work             → {digest, ref} or 204 (long-poll, ~30 s)
POST /sbom/<digest>    ← the SBOM, streamed into cache.Create → Commit
POST /failure/<digest> ← {reason, message}
```

Pull is what keeps the access model intact. A push model would need to discover worker pods,
which means more Kubernetes rights or a message bus; pulling needs neither, the workers need
no inbound Service, and scaling the pool is a replica count and nothing else.

The work API listens on its own address (`-work-listen`), not on `-listen`. A POST surface
does not belong on the endpoint Prometheus scrapes, and the two have to be separable by
network policy.

**The queue lives in the matcher's memory.** It is rebuilt every run from
`snapshot.Digests()` minus what the cache already holds, so there is nothing to persist. A
handed-out item carries a deadline and goes back into the queue when no result arrives; an
attempt counter bounds a digest that always fails, which then becomes
`kiebitzr_image_failed{reason="catalogue"}` — the metric ADR 0008 already created for exactly
this. Roughly a hundred lines against the standard library, with the clock injected the way
`Runner.now` already is.

**The stage and the registry's own words cross the boundary explicitly.** Today
`catalogueReason` distinguishes `unreachable_image` from `catalogue` by matching the error
structurally on `ResolveFailed()`. Over HTTP that type is gone, so the worker reports the
reason as one of the existing `metrics.Reason*` constants and sends the underlying message
with it, which the matcher logs beside the digest. Without that field, the property
[`reading-the-metrics.md`](../runbooks/reading-the-metrics.md) relies on — that the log line
carries the registry's own explanation, because the metric cannot tell three causes apart —
would break silently.

**The digest validation in `cache.path` is now a network boundary.** It already rejects
anything that is not `<algorithm>:<lowercase hex>`, which is what stops a hostile imageID from
escaping the cache directory. From now on it also stops a compromised worker from posting an
SBOM to an arbitrary path. Same check, wider threat model; it must not be removed as
redundant.

**Availability is answered by rebuild speed, not by a standby.** The matcher is a single point
of failure for *freshness*, not for data: the cache is rebuildable by design, the previous
result keeps being served, and `kiebitzr_last_success_timestamp_seconds` makes the gap
alertable. A StatefulSet brings the pod back with the same identity and the same volume in
minutes, against a freshness budget of a day. The real exposure is losing the volume, and the
worker pool is what answers it — a cold start that takes 6.7–11.7 h in one process takes
roughly 25–45 minutes across sixteen workers. The disaster case goes from days to under an
hour, without a lease, a shared filesystem or a line of consensus code.

**The single-pod deployment stays.** One binary, one image, and `-catalogue-locally` (default
`true`) decides whether the matcher catalogues in-process. With no workers deployed, the
service is exactly the design ADR 0001 describes; deploying workers turns the pool into an
optimisation rather than a dependency. Explicit, not inferred from whether a worker polled
recently — every value is a flag (ADR 0007).

**A run ends when the queue drains or `-run-timeout` expires.** What did not come back is
published as `kiebitzr_image_pending{image_digest}`, in the shape `kiebitzr_image_failed`
already uses. This keeps the invariant ADR 0001 set — a digest without findings is never
silently reported as clean — while letting each run publish what it has instead of publishing
nothing for a week.

## How this differs from the tools ADR 0001 evaluated

With a pool of pods cataloguing images, this now looks like Trivy Operator from a distance,
and the difference has to be stated rather than implied. **None of this makes Kiebitzr
better.** It is built for a narrower use case — cluster-wide scanning that stays cheap at
scale, needs one read-only permission, and can be operated by one person — and the
differences below are what that use case costs and buys, not a scorecard.

**Trivy Operator** does considerably more than this service will ever do: misconfiguration,
exposed secrets, compliance reports, RBAC assessment, SBOM generation, with reports as CRDs
that other tooling consumes. Where it differs structurally is the unit of work and who creates
the compute. It runs a scan Job per workload, so the same digest is analysed once for every
workload that runs it, and it creates those Jobs itself — which means it must hold the right
to create workloads, that is, to run arbitrary pods. Here the unit of work is the digest,
deduplicated cluster-wide (`Snapshot.Refs` is "one entry per digest, however many pods run
it"), so an image on five hundred nodes is one work item; and the compute is deployed by the
operator once, never created by the scanner, so `list pods` remains the only permission. The
memory profile follows from the same difference: the cluster-wide peak here is N × a limit an
operator chose, not a function of how many workloads happen to roll at the same time. If what
you want is per-workload reports and a broad scanner suite, Trivy Operator is the better
tool and this is not an argument against it.

**sbom-operator** solves a different problem: it generates SBOMs and delivers them to
backends — Git, Dependency-Track, OCI registries — so the SBOM lifecycle is the product.
Kiebitzr keeps SBOMs as a private cache and publishes findings as metrics; neither replaces
the other. The one place the two are genuinely comparable is the permission model, and ADR
0001 rejected it there for cluster-wide `secrets get` and `pods update`. This decision widens
that gap rather than narrowing it: after the split, the worker holds registry credentials and
cannot reach the API server at all, while the matcher reaches the API server and holds no
credentials. No component holds both. It is worth recording that pod annotations were
considered here as the channel between matcher and workers, and rejected for the same reason
that disqualified sbom-operator — the mechanism is convenient, and the right it requires is
not one a detection tool should hold.

**vulnerability-operator** was accepted on RBAC in ADR 0001 and rejected on behaviour: metrics
reset each run, a fatal error ends the process, one series per container, no freshness metric.
Distribution reinforces each of those choices rather than relaxing them. The atomic swap
stays, `kiebitzr_image_pending` makes an incomplete run say so instead of lying or falling
silent, and per-digest cardinality matters more at a thousand digests, not less — per
container, 228 000 series would be a multiple of that.

The honest cost: "one pod, one binary, nothing to coordinate" was an implicit advantage over
all three, and this decision gives part of it up. What it keeps is that the same artefact
covers both ends — with no workers deployed, a single-node installation on small hardware is
the old design, and the same image scales to a thousand nodes. None of the three can collapse
to a single process that way.

## Consequences

- **The storage multiplier never appears.** One database and one SBOM cache in the cluster,
  on one volume: 6.4 GB for the database during an update plus about 2 GB of SBOMs at a
  thousand digests. Sharding the whole pipeline would have cost that per shard.
- **RBAC is unchanged.** `list` on pods, cluster-wide, nothing else — no leases, no CRDs, no
  annotations, no Jobs. The workers hold no Kubernetes credential at all.
- **A new internal protocol exists**, and with it a failure mode the single-pod design did not
  have: workers that cannot reach the matcher do no work, and the queue drains to nothing.
  It is bounded — `-catalogue-locally` restores the old behaviour, and the pending metric
  makes the shortfall visible — but it is new surface that has to be tested.
- **Worker count is sized by queue depth**, not CPU: a worker is network-bound on the registry
  pull, so a CPU-driven autoscaler reacts too late. `kiebitzr_catalogue_queue_depth` is the
  signal to expose; whether a deployment uses it for an autoscaler or sets a fixed count is an
  installation decision and stays out of this repository (ADR 0001).
- **The pool is worth having at several workers or none, never at one.** `parallelism = 1` is
  per process, so a single worker catalogues exactly as serially as the matcher would have, and
  pays a network hop per SBOM plus a second pod for it. This follows from splitting by stage
  rather than by digest — the gain is parallelism, not relocation — and it is worth stating
  because "one of each" is the natural reading of a matcher-and-workers design. The exception
  is memory rather than throughput: the 274 MB peak moves into the worker, so one worker on a
  roomy node buys a matcher that can be sized small and stays predictable.
- **The metrics are unchanged in shape.** Everything digest-keyed is still published by one
  process, so the join in [`reading-the-metrics.md`](../runbooks/reading-the-metrics.md) and
  every recipe built on it keep working untouched. This is a direct consequence of splitting
  by stage rather than by digest, and it is the main reason the metric side survived the
  redesign without amendment.
- **Scaling the matcher is the next decision, not this one.** When one matcher stops being
  enough, the database is sharable — Grype opens it `mode=ro&immutable=1` — and the shape to
  reach for is the database as an OCI artefact mounted read-only, so the container runtime's
  content store deduplicates it per node rather than per pod, with no RWX storage class and no
  cluster writes. `Curator.Import` takes a locally supplied archive, which is the entry point
  for that; pointing `v6dist.Config.LatestURL` at an in-cluster mirror solves only the download
  multiplier, not the disk. Doing it in that order matters: each step has to earn its place
  before the next one makes sense.

## Amendment: the peak is larger and parallelism is not why it is serial

Two figures above come from [ADR 0001](0001-scan-running-images-with-read-only-pod-access.md)'s
original pilot observation and have since been measured properly; its amendment carries the
numbers and the method. What changes here:

- "`catalog.parallelism` is deliberately one because parallel cataloguing multiplies the
  274 MB peak" — the premise is wrong. Raising Syft's parallelism from 1 to 4 against a
  559 MiB image cost 8 % more heap, not 4×, and returned no wall time at all. The constant
  stays at one because raising it buys nothing, which leaves the scaling argument intact:
  cataloguing is still serial per process, so the digest count still drives the time.
- "the 274 MB peak moves into the worker" — the direction holds, the size does not. The
  peak is 812 MiB of live heap on that 559 MiB image, so what moves into the worker is
  larger than this ADR assumed, and the case for one worker on a roomy node is stronger
  rather than weaker.

## Amendment: the work API stays unauthenticated, and the network stays the boundary

Left open here and carried as P3 in `TODO.md`: whether workers should authenticate to the
matcher with a shared secret. **They should not.** The decision, with its reasons, so that
the next reader does not reopen it:

- **The precondition is already the incident.** Reaching the work port means being able to
  run or take over a pod in the cluster. An attacker who can do that has better targets than
  a vulnerability exporter — starting with the workloads it reports on.
- **There is nothing to take.** The service holds no data, writes nothing to the cluster and
  reads only pods. The whole prize is a dashboard showing wrong numbers.
- **A secret adds more failure than it removes.** It would be this project's first long-lived
  credential, and therefore its first rotation — a procedure that can break the pool. A
  worker pool desynchronised during a rotation is likelier than the attack the secret
  prevents, and against the attacker who can read Secrets in the namespace it does nothing at
  all, because every worker holds the same one.
- **`SECURITY.md` already said so**, listing a deliberately exposed work API under what is
  not a vulnerability. This records the reasoning that sentence rests on.

What the decision owes in return is that the control it relies on must be deployable without
inventing it. `running-kiebitzr.md` now ships both policies and asks for a namespace of its
own, and it says which of the three routes is the one that matters: `GET /work` and
`POST /failure` move metrics somebody can see, while a forged `POST /sbom` is the single
silent failure this service has.

Revisit if the work API ever gains a route that writes outside the cache, or if a deployment
appears where the matcher and its workers cannot be isolated by network policy at all.
