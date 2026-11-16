---
id: kbz:adr:00004
title: Compile the Kubeconfig Path Out of Release Builds
date: 2026-11-06
status: accepted
tags:
  - architecture
  - security
  - kubernetes
  - tooling
related:
  - id: kbz:adr:00001
    reason: Narrows how the Kubernetes access decided there is reached
  - id: kbz:adr:00002
    reason: The release build this applies to is the one that pipeline publishes
  - id: kbz:adr:00007
    reason: Why KIEBITZR_KUBECONFIG is reported as having no effect in a release build
---

# Compile the Kubeconfig Path Out of Release Builds

## Status

`accepted`. In force: the release build has no `-kubeconfig` flag and does not link the
kubeconfig loader.

## Context

In a cluster the service reaches the API server through its own service account: the token and
CA the kubelet mounts, plus the `KUBERNETES_SERVICE_*` environment. That is all it ever needs
there.

Outside a cluster it needs a kubeconfig, and that is worth having — a run against a real
cluster from a workstation needs no image, no deployment and no RBAC change, which makes it
the cheapest way to see the whole pipeline work.

But the kubeconfig path is not a small thing to carry. `clientcmd` reads a file from a path
somebody chooses, honours `$KUBECONFIG`, merges contexts, and supports exec credential
plugins — a mechanism whose entire purpose is to run an external program to obtain a
credential. None of that has a reason to exist in a process whose only job in production is to
read pods with a mounted token.

### Options considered

- **Always include it.** Simplest, and what most controllers do. Rejected: it ships the
  surface described above into every deployment for a convenience only developers use.
- **Keep the flag, refuse it at runtime in production** (an environment variable, or a check).
  Rejected: the code is still linked, and a flag that exists but is refused invites someone to
  find the switch that re-enables it.
- **A second command** (`cmd/kiebitzr-dev`). Rejected: two binaries, two entry points, and the
  development one would drift from the one that ships.
- **A build tag.** Chosen.

## Decision

- A `dev` build tag selects how the API server is reached. Without it — the release build —
  `internal/kube/config_cluster.go` is compiled: in-cluster configuration only, and the
  kubeconfig loader is not part of the binary. With it, `config_dev.go` adds the usual
  kubeconfig discovery.
- The `-kubeconfig` flag is **not registered** in a release build, so passing it is
  `flag provided but not defined` rather than a setting that quietly does nothing.
- A kubeconfig that reaches the release path anyway is **refused, not ignored**: silently
  falling back would turn a deployment mistake into a service watching the wrong cluster.
- `mise run build` uses `-tags dev`; `mise run build:release` and the image build do not.
- Every gate runs over both configurations: `vet` three times (release, `dev`, `integration`),
  `lint` twice, the tests once per configuration. A path that is not built by default cannot
  rot unnoticed.

## Consequences

- The production binary has one way in, and it is the one the cluster grants.
- Development keeps its shortcut, and the shortcut is the same binary with one tag.
- Two configurations have to keep compiling, which is why the gates cover both. That roughly
  doubles the lint and test time of `check`.
- *Measured, so nobody expects more than it gives:* the release build is 5 packages and
  0.16 MB smaller (101.43 against 101.59 MB, both stripped). `clientcmd/api` and the exec
  credential plugin remain, because `client-go/rest` imports them regardless. What is gone is
  the loader — the arbitrary file path, `$KUBECONFIG`, context merging. The gain is removed
  behaviour, not bytes.

## Open questions

- Whether the `dev` build should also drop its in-cluster preference and only ever use a
  kubeconfig. It would make the two configurations fully disjoint, at the cost of a binary that
  cannot be dropped into a cluster to reproduce something.
