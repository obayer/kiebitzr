# Deploying Kiebitzr

A **template** for a Kiebitzr installation, as Kustomize manifests, for a cluster where nobody
is a full-time Kubernetes administrator. It is built with `kubectl` and needs no other tool.

It is a template and not the installation itself. The manifests an installation actually runs
belong to the repository that deploys it, because that is where names, namespaces and storage
classes are decided ([ADR 0001](../docs/adr/0001-scan-running-images-with-read-only-pod-access.md));
what is here is a working starting point for them, and the requirements it satisfies are
written out in [`running-kiebitzr.md`](../docs/runbooks/running-kiebitzr.md). So this directory
gets copied, and nothing here expects to stay connected to the copy.

| Path | What it is |
|---|---|
| `base/` | the shape the service needs: a StatefulSet of one pod, one permission, two volumes, one port — and no Service, because nothing looks this pod up. Not meant to be edited |
| `examples/single-pod/` | an example installation on top of it — the file to copy. Namespace, storage, platform, settings, credentials |

The split is the point. Everything in `base/` follows from how the service works and is the
same everywhere; everything in `examples/single-pod/` is a decision about *your* cluster. Copy
both, keeping the layout, and then only ever edit the second — that way a later version of the
base can be dropped in without re-reading your own values out of it.

## What you need

- **A cluster**, and `kubectl` with access to it. One permission is granted, cluster-wide:
  `list` on `pods`. Nothing else, and nothing is created, updated or deleted by this service.
- **10 GB of storage**, on block storage rather than an SD card. This is the one figure worth
  reading the reasoning for before choosing a value, in
  [`running-kiebitzr.md`](../docs/runbooks/running-kiebitzr.md#storage--the-one-that-needs-attention).
- **The node architecture**, as `linux/arm64` or `linux/amd64`. It must match the nodes.
- **Registry credentials**, only if images in the cluster come from a private registry.
- Outbound network to the API server, to the registries of the running images, and to
  `grype.anchore.io`. Nothing inbound but the scrape of `/metrics`.

## Installing it

**1. See what it would create.** Nothing here touches a cluster:

```
kubectl kustomize deploy/examples/single-pod
```

**2. Copy this whole directory** somewhere of your own — your own repository if the cluster is
managed in Git, a directory otherwise. Copying `base/` along with the example keeps the
example's `resources: ../../base` pointing at something, and keeps the copy independent of this
repository.

**3. Edit four things**, all of them in the copy:

| Where | What |
|---|---|
| `kiebitzr.env` | `KIEBITZR_PLATFORM`, to match your nodes |
| `kustomization.yaml` | the storage class in the first patch, and the namespace if you want another one (it is named twice there, on purpose) |
| `build-access.yaml` | your repository patterns, replacing the examples |
| `kustomization.yaml` | the image tag comes from `base/kustomization.yaml`; override `images:` in your copy to pin a different release or a digest |

Everything else has a working default. The settings you can change are the flags in
[`running-kiebitzr.md`](../docs/runbooks/running-kiebitzr.md#configuration) — every one of them
is also a `KIEBITZR_*` variable and belongs in `kiebitzr.env`.

**4. Apply it:**

```
kubectl apply -k <your copy>
```

**5. Check that it is running what you think it is.** The start-up log prints every setting
with the value in effect, which answers "did my ConfigMap land" without a shell in the pod:

```
kubectl -n kiebitzr logs statefulset/kiebitzr | head -2
```

A misspelled `KIEBITZR_*` key is named in a warning beside that line. A malformed *value* is a
start-up error, so a pod that never comes up has its reason in the first log line.

**6. Wait for the first run.** It is the slow one — every running image is catalogued and the
vulnerability database is downloaded. Twenty to thirty-five minutes for fifty images on a small
ARM board; minutes on a fast machine. Nothing is published before it completes:

```
kubectl -n kiebitzr port-forward statefulset/kiebitzr 8080:8080
curl -s localhost:8080/metrics | grep kiebitzr_last_success_timestamp_seconds
```

A non-zero value there means a run finished and the findings are real. What to do with them is
[`reading-the-metrics.md`](../docs/runbooks/reading-the-metrics.md), and
[`dashboards/kiebitzr.json`](../dashboards) imports into Grafana.

**7. Scrape it for good.** With the Prometheus Operator, uncomment `podmonitor.yaml` in your
copy's `kustomization.yaml`; with plain Prometheus, add a `kubernetes_sd_configs` job with
`role: pod`. Either way `honorLabels` / `honor_labels: true` is not optional — the reasoning is
at the top of `podmonitor.yaml`, and it is the one mistake here that produces wrong numbers
instead of no numbers.

## If the pod does not come up

Three failures account for nearly all of it:

- **`UNAUTHORIZED: authentication required`** in the log, against a private registry. An
  `imagePullSecret` does not help — the kubelet uses those to pull this pod's own image, and
  they are never visible inside it. Create the Secret the way the comment at the bottom of the
  example's `kustomization.yaml` shows; the projection to the file name `config.json` and
  `DOCKER_CONFIG` are already wired in the base.
- **Every image fails with `unreachable_image`.** `KIEBITZR_PLATFORM` does not match the
  nodes.
- **`Pending`, with no volume.** No default storage class, or the class named in the patch does
  not exist. `kubectl -n kiebitzr describe pvc` says which.

One more, and it is the one thing in the base nobody has yet run against a real cluster:
`readOnlyRootFilesystem: true`. The release image is a distroless binary with two writable
mounts — the cache volume and `/tmp` — so it should need nothing else. If a first start fails
on a read-only file system, the log names the path and the fix is that one line in
`base/statefulset.yaml`.

## What is deliberately not here

- **A worker pool.** Cataloguing can be moved into a pool of stateless pods, and below roughly
  200 distinct image digests there is no reason to: one pod is the whole installation. The
  shape, the two NetworkPolicies it needs and the reason a *single* worker is worse than none
  are in
  [`running-kiebitzr.md`](../docs/runbooks/running-kiebitzr.md#scaling-cataloguing-out).
- **Alert rules.** The rules worth having are in
  [`reading-the-metrics.md`](../docs/runbooks/reading-the-metrics.md#alerts-worth-having),
  including why exactly one of them is about a finding. They are not duplicated here, because a
  second copy of a rule is a copy that drifts.
- **A Helm chart.** The manifests are what this project ships; a chart would be a second
  configuration surface over the flags, with its own versioning and release. If `helm install`
  is what your cluster is managed with, say so in an issue — that is the evidence it would take.
