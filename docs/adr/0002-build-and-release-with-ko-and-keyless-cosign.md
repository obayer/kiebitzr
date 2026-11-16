---
id: kbz:adr:00002
title: Build and Release with ko, Keyless Cosign and a Weekly Rebuild
date: 2026-11-05
status: accepted
tags:
  - ci
  - release
  - signing
  - supply-chain
  - tooling
related:
  - id: kbz:adr:00001
    reason: The service whose image this pipeline produces
  - id: kbz:adr:00003
    reason: Defines the format and lint gates this pipeline runs
  - id: kbz:adr:00004
    reason: What the release build this pipeline produces deliberately leaves out
  - id: kbz:adr:00005
    reason: The rule the vulnerability gate of this pipeline follows
  - id: kbz:adr:00006
    reason: Decides the shape of the tag that triggers this pipeline
---

# Build and Release with ko, Keyless Cosign and a Weekly Rebuild

## Status

`accepted`. In force and exercised: `.ko.yaml` builds both platforms from the distroless
static base, `release.yaml` builds with `--sbom=spdx` and signs the pushed digest with
keyless cosign, and the weekly rebuild runs on a Monday cron. Releases have been cut under
this pipeline, and `mise run verify` checks a published image's certificate identity and OIDC
issuer against this repository's workflow.

Two refinements the implementation added, neither of which changes the decision:

- CI runs on pushes to `main` and on every pull request, not on every push to every branch —
  a superseded pull-request run is also cancelled, because runner minutes on a private
  repository are finite.
- `ldflags` is **one** list entry, not three. Repeated `-ldflags` occurrences do not
  accumulate; the last one wins and the earlier ones are discarded, which is why a released
  image once reported version `dev` while carrying the right commit. The measurement and the
  reasoning are in `.ko.yaml` beside the setting.

The consequence marked *unverified* below — build-provenance attestations on a private
repository's free plan — is still unverified, and still does not affect signing.

## Context

The service is a static Go binary. It needs a small, reproducible, multi-arch image with an
SBOM, a verifiable signature and timely pickup of Go standard-library fixes. The code has a
single home: one private GitHub repository. There is no mirror elsewhere.

## Decision

- **ko** builds the image: no Dockerfile, `CGO_ENABLED=0`, cross-compiled for `linux/arm64`
  and `linux/amd64` on hosted amd64 runners, distroless static base running as non-root,
  SBOM generated at build time. Configuration in `.ko.yaml`.
- Images go to `ghcr.io` under the repository owner, tagged with the semver tag and the
  commit SHA. Consumers pin by digest.
- **cosign keyless** signs every pushed image with the workflow's OIDC identity. Signing
  happens **only in CI**, never locally (a local keyless signature would publish the
  signer's e-mail to the public transparency log). The CI identity itself — repository and
  workflow path — is public in that log as well; accepted.
- CI on every push and pull request: `gofumpt`, `go vet`, `golangci-lint`, tests with the race
  detector, `govulncheck`, `betterleaks`.
- **Weekly scheduled rebuild** of the latest release tag, so standard-library and base-image
  fixes reach the image without a code change.
- **Actions are pinned to a commit**, with the version they carried in a trailing comment. A
  tag is a moving reference its owner can repoint, and the release job holds `packages: write`
  and `id-token: write` — the one place where a repointed tag would run beside the signing key.
- **Renovate** keeps Go modules, those action digests and the mise tool versions current — the
  last of these is why it rather than Dependabot, which has no mise manager and would leave the
  gates themselves unversioned. It runs as the hosted app, so no write-scoped token is stored
  in this repository. Updates are batched to one weekly window and three open pull requests,
  because every one of them costs a full `check` run and a maintainer who reads it; a
  vulnerability alert is exempt from that window. **Not yet installed on the repository**, so
  nothing updates anything today and the digests above were pinned by hand — `TODO.md` P4.
- Commits use the GitHub no-reply address; no personal e-mail appears in history.

## Consequences

- No Dockerfile to maintain; the image contains the binary, CA certificates and nothing else.
- Signatures are verifiable with
  `cosign verify --certificate-identity-regexp '^https://github.com/<owner>/kiebitzr/' --certificate-oidc-issuer https://token.actions.githubusercontent.com`.
- The repository name becomes publicly visible through the transparency log even while the
  repository is private.
- *Unverified:* GitHub build-provenance attestations may not be available for private
  repositories on the free plan; cosign signing does not depend on them.
