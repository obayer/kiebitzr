<p align="center"><img src="assets/banner.svg" height="128" alt="Kiebitzr"></p>

*Kiebitz* (German): the northern lapwing, *Vanellus vanellus* — the bird above, and the root of
*kiebitzen*, to watch over someone's shoulder without interfering.

Kiebitzr watches the container images that are actually running in a Kubernetes cluster and
exports their known vulnerabilities as Prometheus metrics. It only reads pods — no Secrets,
no writes, no CRDs — and analyses each image digest once.

> Somebody who runs a cluster because it should carry services — not because it is their job —
> spends **minutes a week** on vulnerabilities rather than hours, and still does not watch the
> platform rot or lose a service to a hole that was already known.

That is the vision, and everything here is measured against it. It follows one principle:
**silence you can believe.** When Kiebitzr says nothing, there is nothing to do, and you may
assume that without checking. The mission and what follows from both are in
[`docs/req/`](docs/req/0001-the-decisions-this-service-has-to-serve.md).

> Status: early. The design is recorded in [`docs/adr`](docs/adr). The scanning pipeline runs
> and has been measured on a cluster — the figures are in
> [`running-kiebitzr.md`](docs/runbooks/running-kiebitzr.md) — but it has not been operated
> over time yet. The worker pool (ADR 0009) is implemented and covered by tests; it has not
> been run against a real cluster.

## What you get

**Triage, not a list of findings.** A whole-cluster inventory is easy and nearly useless: on
the pilot cluster, 41 of 50 running images carried at least one `Critical`. That number
saturates — any image with a full distribution userland has one — so Kiebitzr publishes the
dimensions that actually discriminate, and the metrics runbook builds its queries on them
rather than on severity. Each row is a question somebody asks on a Monday morning:

| Question | What answers it |
|---|---|
| **Must I patch tonight?** | `known_exploited` — in a known-exploited catalogue, not merely bad in theory — and `kiebitzr_image_risk_score`, Grype's own 0–100 from EPSS and severity |
| **Can I patch it at all?** | `package_type` — an `apk`/`deb`/`rpm` finding is usually cleared by a newer image tag; a `go-module` or `npm` one moves only when the publisher rebuilds, however much `fix_state` says a fix exists |
| **What exactly am I fixing, and where is it?** | `source_package`, so one advisory against openssl counts once instead of once per binary package built from it, and `location`, the path inside the image — which turns thirty findings against `package="stdlib"` into the binaries that carry them |
| **Is there anybody to ask for a build?** | `build_access` on the image — `own`, `reachable`, `none` or `unknown`. Declared, because nothing in an image says who decides what goes into it; see below |
| **Am I running what the tag says?** | one tag at two digests in `kiebitzr_image_info`. With `imagePullPolicy: IfNotPresent` a node that already holds the image never re-pulls it, so it sits on a stale digest — on the pilot cluster 141 findings more, cleared by re-pulling the same tag |

On that same cluster the first two together turned 41 affected images into **five actions**, and
showed that 46 % of the "fixable" findings were not fixable by the cluster's operator at all.
The third cut the count an operator reads from 3,635 to 1,223 — the same work, named in the unit
it is actually done in.

**The images you can get a build of, and the ones you cannot.** The fourth row is the newest
and the least obvious, so plainly: a cluster's images fall into two groups that most scanners
report identically. For an image from a project nobody here can reach, the only remedy
is a newer tag — if the publisher has shipped one. For an image built by your own team, or by a
team you can walk over to, a rebuild is an available action *even when no newer image exists
yet*, because the action is causing one to exist. Kiebitzr can only know which is which if you
say so, in a file of repository patterns:

```yaml
build-access:
  - repository: registry.example/org/platform/*   # my team builds these
    access: own
  - repository: registry.example/org/billing/*    # another team does, and I can ask
    access: reachable
```

Everything unclassified is `unknown` — "nobody has looked", not "nothing can be done" — so an
installation that declares nothing loses nothing it had before, and the count of unknowns is
the one honest measure of whether the file is being kept up. Together with the deployability
check this turns the old "nothing can be done" bucket into a dead end and a **work list**: the
images where no newer build exists *because nobody has built one yet*. None of it pages: what
the person woken could do is ask, and asking is not ending.

**Absence is never silence.** The failure this design is built against is a metric that reads
as good news when nobody looked. Every way that can happen has its own series: an image that
could not be analysed (`kiebitzr_image_failed`, with the stage), one the run had no time for
(`kiebitzr_image_pending`), a vulnerability database serving no exploitation data (no
`kiebitzr_image_risk_score` at all), and which build is answering
(`kiebitzr_build_info`) — because a binary that predates a metric publishes nothing for it,
which looks exactly like a cluster with nothing to report.

That includes the silence this service produces **on purpose**: `-min-severity`, `-only-fixed`
and an ignore rule all make findings disappear, and `kiebitzr_vulnerability_suppressed` counts
how many, per image and per filter. An ignore rule written for one noisy package and matching
half the cluster is a number that jumps, not a dashboard that goes quiet.

**What is actually running, analysed once.** Digests come from pod status, so what is reported
is what the kubelet has, not what a registry or a manifest in Git says. An image on five
hundred nodes is catalogued once and cached under its digest.

**One permission.** `list` on pods, cluster-wide. No Secrets, no CRDs, no writes, no Jobs — see
*Where this fits* below for why that constraint is the starting point rather than a feature.

**A dashboard, in the order that matters.** [`dashboards/kiebitzr.json`](dashboards) is
importable and asks for a datasource; its first row answers whether anything below it is valid
at all, before a single finding is shown.

**Manifests to start from.** [`deploy/`](deploy) is a Kustomize base and a commented example
overlay: the StatefulSet, the one permission, the cache volume, and the two files an
installation supplies. A template to copy rather than something to depend on — the manifests an
installation runs belong to the repository that deploys it.

**It scales by moving one step.** Cataloguing is the expensive part and the only part that
leaves the process; everything else stays in one pod.

## How it works

Every run, by default once a day:

1. List the running pods and collect the image digests they report.
2. For each new digest, resolve the multi-arch index to the configured platform, generate an
   SBOM with [Syft](https://github.com/anchore/syft) and cache it under the digest.
3. Match every cached SBOM against the [Grype](https://github.com/anchore/grype) database,
   updating it first unless `-db-max-age` says the one on disk is still young enough — an
   update rewrites several gigabytes, which on a small node costs more than the download does.
4. Swap the whole result into the `/metrics` endpoint atomically, and drop the SBOMs of
   digests that are no longer running.

A run that fails changes nothing: the previous result keeps being served, the error is
counted by reason, and `kiebitzr_last_success_timestamp_seconds` stops moving — which is what
an alert watches. A run that only runs out of time for step 2 still publishes: the images it
catalogued appear with their findings, and the rest are named as pending rather than passed off
as having nothing.

Step 2 is the expensive one, and it is the only one that can move out of the process. Up to
roughly 200 distinct image digests, one pod is the whole installation and the default. Beyond
that, cataloguing goes to a pool of stateless workers that ask the matcher for an image, pull
it, and hand the SBOM back — one binary, one image, `-role worker`. Everything else stays in
the single pod that holds the cache, the vulnerability database and the metrics. The threshold
is the number of distinct digests, not of nodes: a thousand nodes running the same twenty
images need nothing from this.

**What it needs from a cluster:** one RBAC rule (`list` on pods, cluster-wide), a cache volume,
and registry credentials for private images — read from the Docker config file the kubelet
mounts, never from a Secret this service reads itself. The sizes, the memory and CPU advice and
the one scrape setting that decides whether any query works are in the runbooks below.

## Where this fits, and where it doesn't

There are good tools in this space already, and Kiebitzr is not an attempt to beat them. It
comes from a different starting point: **one read-only permission, cheap at any cluster size,
and operable by one person.** Everything below follows from those three, and each of them
costs something another tool spends differently.

**It does one thing.** Running images, their known vulnerabilities, as metrics.
No misconfiguration checks, no secret scanning, no compliance reports, no admission control,
no web interface. [Trivy Operator](https://github.com/aquasecurity/trivy-operator) does all
of that, with a community behind it and per-workload reports as CRDs. If that is the shape
you want, use it — this is the smaller thing on purpose.

**One permission, and nothing creates anything.** `list` on pods, cluster-wide. Kiebitzr
reads no Secrets, writes no annotations, defines no CRDs and starts no Jobs. That last part
is a real constraint rather than a boast: a tool that runs a scan Job per workload needs the
right to create workloads, which is the right to run arbitrary pods, and a tool that marks
pods with annotations needs `update` on pods, which is the right to replace a running pod's
image. Both are reasonable trades for what those tools deliver. We decided not to make them
(ADR 0001), and that decision constrains every later one — including how the load gets
distributed (ADR 0009).

**The unit of work is the image digest, not the workload.** An image running on five hundred
nodes is analysed once, ever, and its SBOM is cached under the digest. This is why the steady
state is cheap and why a large cluster costs little more than a small one with the same image
estate — and it is also why a finding names a digest instead of a pod. Where that digest runs
is a second metric you join against, which keeps cardinality following images rather than
replica counts.

**It stays honest when it fails.** A failed run never ends the process and never clears the
result: the previous findings keep being served, the error is counted by reason, and the
freshness timestamp stops moving. Stale data looks exactly like fresh data unless something
watches that timestamp, so the alerts in the metrics runbook are not optional extras — they
are how you find out the scanner stopped.

**It is not an SBOM platform.** The SBOMs are a private cache and are not published anywhere.
If you need SBOMs delivered to Dependency-Track, a Git repository or a registry, that is what
[sbom-operator](https://github.com/ckotzbauer/sbom-operator) is for, and it is a different
product rather than a competing one.

What this costs: no history (Prometheus holds it, not us), no per-pod findings, no scanning of
anything that is not a container image, and images that exist only in a node's local store
are a blind spot by construction — reaching into it would need the container runtime socket.
ADR 0001 lists the alternatives that were weighed and why each was set aside.

## Documentation

This file answers "does this fit what I need". Everything technical has its own document:

| | |
|---|---|
| [**Running it**](docs/runbooks/running-kiebitzr.md) | the RBAC rule, volumes, memory and CPU, every flag, configuration from a ConfigMap, declaring who can get a build of an image, the deployability check, and scaling cataloguing out |
| [**Reading the metrics**](docs/runbooks/reading-the-metrics.md) | the one scrape setting to get right first, every metric and label value, the triage queries, what each error reason means, and the alerts worth having |
| [**What it has to serve**](docs/req/0001-the-decisions-this-service-has-to-serve.md) | the vision, the mission, the decisions an operator makes and whether each is served today — with the evidence, and with what operating it has turned up |
| [**Decisions**](docs/adr) | the ADRs: what was chosen, what was rejected and why. Start at ADR 0001 |
| [**Dashboard**](dashboards) | `kiebitzr.json`, importable, asks for a datasource |
| [**TODO.md**](TODO.md) | what is open, what needs evidence first, and what was rejected with the reason |
| [**CONTRIBUTING.md**](CONTRIBUTING.md) | tasks, build configurations, the agent sandbox, the secret gates, releases |
| [**SECURITY.md**](SECURITY.md) | how to report a vulnerability in Kiebitzr itself, and which surfaces are in scope |

## License

[Apache-2.0](LICENSE), and read [`NOTICE`](NOTICE) with it: this is a single-maintainer project
distributed **without warranty of any kind**. Kiebitzr reports what a vulnerability database
says about the images a cluster runs — that is not a guarantee that an image is clean, and
neither is silence from it. What the metrics do and do not claim is in
[`reading-the-metrics.md`](docs/runbooks/reading-the-metrics.md); the known gaps are in
[`TODO.md`](TODO.md).
