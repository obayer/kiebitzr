---
id: kbz:adr:00001
title: Scan Running Images with Read-Only Pod Access, Syft and Grype as Libraries
date: 2026-11-05
status: accepted
tags:
  - architecture
  - security
  - rbac
  - sbom
  - vulnerability-scanning
  - caching
  - metrics
  - prometheus
related:
  - id: kbz:adr:00008
    reason: Extends the metric set decided here, with exploitation evidence and per-image failures
  - id: kbz:adr:00009
    reason: Distributes the pipeline decided here across pods, keeping this access model and cardinality rule
  - id: kbz:adr:00002
    reason: How the image that runs this design is built, signed and published
  - id: kbz:runbook:00001
    reason: How the metric set decided here is read and alerted on
  - id: kbz:runbook:00002
    reason: The measured resource requirements this design turned out to have
  - id: kbz:adr:00004
    reason: Narrows the Kubernetes access decided here to the in-cluster path in release builds
  - id: kbz:adr:00005
    reason: How the dependency surface of the embedded scanners is governed
---

# Scan Running Images with Read-Only Pod Access, Syft and Grype as Libraries

## Status

`accepted`. The pipeline is implemented and has run against a cluster: `internal/inventory`,
`internal/catalog`, `internal/cache`, `internal/vulndb`, `internal/runner` and
`internal/metrics` are this decision in code, and the figures the pilot was to produce are
recorded in [`running-kiebitzr.md`](../runbooks/running-kiebitzr.md). The two questions this
left open are answered below.

ADR 0009 distributes the cataloguing stage over several pods. It changes neither the access
model nor the cardinality rule decided here, and the single-pod shape described below remains
a supported deployment.

## Context

A cluster's automated image updates say nothing about whether the version that runs *right
now* carries a known, fixable vulnerability. The answer must come from the cluster itself
(any externally maintained image list drifts), must not hand the inventory or the findings
to a third party, and must fit small ARM64 nodes.

Existing tools were evaluated and rejected:

- **Trivy Operator** — one scan Job per workload, the same digest is pulled and analysed
  repeatedly, spiky memory, results as CRDs that still need an exporter.
- **sbom-operator** — cluster-wide `secrets get` (for pull secrets) and `pods update` (for a
  marker annotation). `pods update` allows replacing a running pod's image, i.e. code
  execution anywhere, granted to a detection tool; the chart cannot drop it.
- **vulnerability-operator** — acceptable RBAC, but metrics are reset each run (a daily gap),
  errors are fatal, one series per container, no freshness metric, and a single maintainer.
- **Scanning in CI against an image list**, cloud nodes, edge workers, full SIEM suites —
  drift, third-party custody of findings, or far beyond the resource budget.

## Decision

A single Go service, Kiebitzr, built on `client-go`, Syft and Grype **as libraries**, and
`prometheus/client_golang`.

### Inventory

- The only Kubernetes permission is **`list` and `watch` on `pods`**, cluster-wide. No
  Secrets, no writes, no CRDs, no other resources.
- Running digests come from `status.containerStatuses[].imageID` and
  `status.initContainerStatuses[].imageID`. containerd reports the digest of the
  **multi-arch index**, so the service resolves the index to the manifest of a configured
  platform (default `linux/arm64`) before cataloguing. The platform is configuration, not
  derived from nodes (no `get nodes`).
- The owner is the direct `ownerReference` (`kind/name`); a ReplicaSet's hash suffix is
  stripped to approximate the Deployment. No `get` on workload resources.
- *Residual risk:* `list pods` returns full pod specs including literal `env` values. This is
  the price of a cluster-sourced inventory and far smaller than `secrets get`.

### Digest-addressed cache

- SBOMs are stored as `sboms/sha256_<digest>.json` under a cache directory, next to the
  Grype database. A digest with an SBOM is never re-catalogued; SBOMs of digests no longer
  running are deleted.
- No state is written to the cluster (no annotations, no CRDs). The cache is rebuildable;
  losing it costs one slow run, never data.

### Registry access

Credentials are read from a Docker config file (`DOCKER_CONFIG`) mounted by the kubelet. The
service itself needs no access to Secrets.

### Metrics

Low cardinality: one series per vulnerability per **image digest**, never per pod or
container.

| Metric | Labels |
|---|---|
| `kiebitzr_vulnerability` | `image_digest`, `cve`, `severity`, `package`, `installed`, `fixed_in`, `fix_state` |
| `kiebitzr_image_info` | `image_digest`, `image`, `namespace`, `owner_kind`, `owner_name`, `container` |
| `kiebitzr_last_success_timestamp_seconds` | — |
| `kiebitzr_db_built_timestamp_seconds` | — |
| `kiebitzr_run_duration_seconds` | — |
| `kiebitzr_scan_errors_total` | `reason` |
| `kiebitzr_images` | `state` (`scanned`, `cached`, `failed`) |

- Results are **swapped atomically** after a run; there is no reset gap.
- A failed run **never terminates the process**: it increments the error counter, leaves
  `last_success` untouched and keeps serving the previous result.
- Severity threshold, "only with fix" and ignore rules are runtime configuration supplied by
  the deployment, not compiled in.

### Later modules (out of scope for v1, designed for)

- Host/node SBOMs as a second subject type; inventory and cache must not assume that only
  images exist.
- A dedicated matcher for distribution kernels whose version scheme (epoch plus vendor
  suffix) general matchers misjudge.

## Consequences

- Least privilege: read-only pods, nothing else; no admission policy needed to neutralise a
  shipped right.
- Steady state is cheap: cataloguing runs once per new digest, a regular run is a diff plus
  a database check.
- Freshness is observable: a stopped scanner or a stale database is an alertable condition,
  not silence.
- We own the code: maintenance, Syft/Grype API changes and dependency updates are ours.
- Gaps: anything outside container images (host packages) until the later modules exist.

## Questions this left open, and their answers

The questions are kept verbatim; the answers are what the first cluster produced.

**Peak memory of in-process cataloguing on the largest images (pilot measurement).** The live
heap peaks around 274 MB while an image is catalogued, and the Go heap grows well past that
before collecting — 1.16 GB of arena was observed. The answer is therefore not a container
limit alone: `GOMEMLIMIT` has to be set (for example 1 GiB) with the container limit above it,
so the garbage collector regulates instead of the OOM killer. `catalog.parallelism` stays at
one, because parallel cataloguing multiplies this peak. Figures and the reasoning are in
[`running-kiebitzr.md`](../runbooks/running-kiebitzr.md).

**Image visibility (private or public).** Private images work, and the mechanism is the one
assumed here — a Docker config file in the pod's own filesystem, no Secret read through the
API. What the design did not anticipate is how easily it is mistaken for an
`imagePullSecret`: those are the kubelet's and are never visible inside the pod. The Secret
has to be mounted, its key projected to the file name `config.json`, and `DOCKER_CONFIG`
pointed at the directory. Credential helpers do not work in a distroless image, because the
helper binary is not in it. This is the single most common deployment failure and is
documented as such in [`running-kiebitzr.md`](../runbooks/running-kiebitzr.md).

What the pilot added that was not asked: an image that exists only in a node's local
container store can never be catalogued, because this design pulls from a registry and
refuses the container runtime socket. It surfaces as
`kiebitzr_scan_errors_total{reason="unreachable_image"}` and is a consequence of the access
model, not a defect.
