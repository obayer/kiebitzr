---
id: kbz:adr:00007
title: Configure from Flags and the Environment, with Flags Winning
date: 2026-11-09
status: accepted
tags:
  - architecture
  - conventions
  - kubernetes
  - tooling
related:
  - id: kbz:adr:00004
    reason: Why a release build reports KIEBITZR_KUBECONFIG as having no effect
  - id: kbz:adr:00006
    reason: Records that a version in this scheme cannot warn about a renamed interface
---

# Configure from Flags and the Environment, with Flags Winning

## Status

`accepted`. In force: every flag can also be given as `KIEBITZR_<FLAG>`, and the command line
wins.

## Context

Until now every value a deployment may need to change was a flag and nothing else. That is
configurable in Kubernetes — `args:` in the pod spec takes them — but it cannot be driven from
a ConfigMap, which is where cluster configuration normally lives.

The request was a `.env` file. The binary should not read one. Kubernetes has no concept of
such a file; what exists is a ConfigMap, and a `.env` file is an *input* to it on the
deploying side:

```yaml
configMapGenerator:
  - name: kiebitzr
    envs: [kiebitzr.env]
```

Kustomize appends a content hash to the generated name and rewrites the reference, so changing
a value rolls the Deployment. A ConfigMap written by hand and bound with `envFrom` does not do
that: the name stays the same and running pods keep the old values until someone restarts
them. Had the binary parsed the file itself, the deployment would additionally need a volume,
the process a parser and a reload story — and the rollout property would still be missing.

So the interface to build is environment variables; the `.env` file belongs to the repository
that deploys Kiebitzr, like every other installation decision (ADR 0001).

### Options considered

**A table mapping variables to flags.** Rejected: a second list of names, which drifts the
first time a flag is added and nobody remembers the table.

**A configuration library.** Rejected. The value is small — the mapping is mechanical — and
the cost is a dependency in a tree that is already 2100 packages deep (ADR 0001), plus a
second validation path beside the one the flags already have.

**Environment only, dropping the flags.** Rejected: an ad-hoc run would then have no way to
override a value without editing the environment, and `-h` is the only documentation of the
configuration surface there is.

## Decision

Environment variables are derived from the flags, not declared: `-min-severity` is
`KIEBITZR_MIN_SEVERITY`, by uppercasing and replacing hyphens. A new flag gets its variable
without a second edit, and the two cannot disagree.

Precedence is **command line > environment > default**. A value passed explicitly is never
overridden by a ConfigMap, because a debugging run has to be reasoned about from its arguments.

Each value is applied through the flag's own `Value.Set`, so `KIEBITZR_INTERVAL` is parsed and
validated exactly like `-interval`, and a malformed value is a start-up error rather than a
silently kept default.

`KIEBITZR_TEST_*` is carved out of the namespace: the integration tests already use
`KIEBITZR_TEST_IMAGE` and `KIEBITZR_TEST_PLATFORM`, and neither is a flag.

Unknown `KIEBITZR_*` variables are reported once at start-up, as a warning that names them.
`envFrom` puts every key of a ConfigMap into the environment, so a misspelled key would
otherwise change nothing and say nothing, and "the value I set has no effect" is a long search.

## Consequences

- The variable names are now an interface. A renamed flag renames its variable, and ADR 0006
  records that the version number carries no signal for that — such a change belongs in the
  release notes.
- A release build reports `KIEBITZR_KUBECONFIG` as unknown, which is correct rather than
  unfortunate: the flag is not registered without the `dev` tag (ADR 0004), so the variable
  genuinely has no effect, and saying so is better than ignoring it.
- None of these values is a secret, so a ConfigMap is the right carrier and no Secret handling
  is needed. If a future value ever is one, it needs its own decision — `envFrom` over a
  Secret would put it in the environment of the process and in `kubectl describe pod` output.
- The flags remain the documentation of the surface. `kiebitzr -h` lists them, and the
  variable for each is mechanical from its name.
