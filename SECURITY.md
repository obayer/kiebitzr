# Security policy

## Reporting a vulnerability

Report it privately through GitHub: **[Security → Report a
vulnerability](https://github.com/obayer/kiebitzr/security/advisories/new)**. That opens a
private advisory only the maintainer can read.

Please do not open a public issue for a vulnerability, and please do not send it by e-mail —
the advisory route is the only one that is actually monitored for this, and it keeps the report
out of a public history while it is being fixed.

What helps, in order: the version or image digest, what an attacker needs to reach the problem
(network position, cluster rights), and the smallest sequence that shows it. A pull request is
welcome but never necessary.

**Expect a slow answer.** This is a single-maintainer project worked on in spare time. A first
response may take a week or two, and there is no commitment beyond best effort — if you need a
guaranteed timeline, this is the wrong dependency to take.

## What is in scope

Kiebitzr reads a Kubernetes API and container registries and publishes Prometheus metrics. The
interesting surfaces are therefore:

- **The work API** (`-work-listen`, ADR 0009). It serves work to workers and accepts the SBOMs
  they produce, and it is **unauthenticated by design**: it is meant to be reachable only from
  the worker pods, via a network policy. Reaching it means you can starve the queue or submit a
  forged SBOM, which makes findings disappear — that is the documented consequence of exposing
  it, not a vulnerability in itself. A way to escape the cache directory, to make the matcher
  write outside it, or to reach it *through* `-listen`, is one.
- **The metrics endpoint** (`-listen`). It must expose no label value that is not derived from
  the cluster inventory and the vulnerability database, and no credential: a registry
  credential in a flag or an image reference must never reach a metric, a log line or an error
  message.
- **Privilege.** The service needs `list` on pods and nothing else (ADR 0001). Any path that
  needs, uses or would enable more than read access to the cluster is a security bug, even
  where it works.
- **Dependencies.** A reachable vulnerability in a dependency, where `mise run vuln` is green
  because of an entry in `.vulnguard.yaml`, is worth reporting if you think the acceptance
  reasoning is wrong.

## What is not in scope

- **A finding Kiebitzr misses, or reports wrongly.** That is a bug, sometimes a serious one —
  open an issue. It is not a vulnerability in this service, and the known gaps are in
  `TODO.md`.
- **Vulnerabilities in the images Kiebitzr reports on.** Those belong to their publishers.
- **An unauthenticated work API or metrics endpoint that was deliberately exposed.** See above:
  the deployment decides the network, and `docs/runbooks/running-kiebitzr.md` says what each
  port is for.

## Supported versions

The latest release, and only it. Releases are rebuilt weekly so base-image and Go standard
library fixes land without a code change (ADR 0002); there are no backports to older tags.

## Verifying what you run

Release images are signed keyless with cosign, so a build that did not come from this
repository's release workflow can be told apart:

```bash
cosign verify ghcr.io/obayer/kiebitzr:<tag> \
  --certificate-identity-regexp '^https://github.com/obayer/kiebitzr/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
