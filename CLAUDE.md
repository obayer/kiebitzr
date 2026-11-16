# Kiebitzr — Claude Code Instructions

Kiebitzr watches the container images running in a Kubernetes cluster and reports their
known vulnerabilities as Prometheus metrics. It reads, never changes.

## Hard rules

- **No local information in this repository**: no hostnames, IPs, cluster or namespace
  names of a real installation, local paths, usernames, e-mail addresses or tokens. Use
  neutral placeholders. Personal settings stay in git-ignored local files.
- **Read-only towards the cluster.** Any change that would need more Kubernetes rights than
  reading pods needs an ADR first.
- **Go only** — no shell scripts for product logic or tooling.
- **Silence you can believe.** The leading principle, in `docs/req/`: when the service says
  nothing, there is nothing to do, and that may be assumed without checking. It settles design
  arguments — a state that cannot be acted on still gets its own series rather than looking like
  a clean result, and an indicator that would fire on almost everything is not shipped at all.
- **An alarm must be clearable by whoever it wakes.** A condition that no action of the
  recipient ends is a state, and a state belongs on a dashboard, never in a pager rule.
  Duration is not the test — clearability is, and a request is not a clearance: starting a
  process somebody else completes does not end a condition. A finding may page only where
  deployability was **measured** — `fix_state="fixed"` names a version in an advisory, not an
  image somebody can roll out, so exactly one rule qualifies and it gates on the candidate
  check (ADR 0011). Anything else about findings is a dashboard.
- **A proposal names the decision it serves and the evidence that it is unserved.** The
  decisions this service exists for are listed in `docs/req/`, with whether each is already
  served and by what. A change that extends what the service can do states which one it is
  for, shows a measurement or a diagnosis rather than a plausible story, gives its cost in
  registry requests, SBOMs and series per image, and names the number that should move.
  Designing before that is how a feature gets half-built for a problem nobody has counted.
- **Every capability appears in the README's overview; its detail does not.** `README.md`
  answers one question — *does this fit what I need* — and holds only *What you get*, *How it
  works* and *Where this fits*. Flags, metrics, sizing and operation live in the runbooks,
  development and releasing in `CONTRIBUTING.md`, and the README links to them. So a change that
  adds or changes what the service can do writes **both** in the same commit: a line in the
  overview, and the detail where that kind of detail lives. A capability nobody can find from
  the README does not exist; a flag table in the README is a copy that will drift. Both
  directions matter — a feature the README calls unfinished when it is wired in does not get
  used either.
- **Conventional Commits.** Signing and releasing happen in CI only.
- **No package registries for vendored tools** — vendored code is updated by hand.

## Where to look

- **Tooling:** everything runs through mise — `mise tasks ls`, then `mise run <task>`. Task
  descriptions say what each task answers; do not hand-roll pipelines a task already covers.
- **Design decisions:** the ADRs in `docs/` are the source of truth. Query them via the docs
  tasks before asking why something is built a certain way, and check status and incoming
  links before relying on one. Do not list ADRs, tasks or file paths here — they drift.
- **Documentation format:** `docs/CONVENTIONS.md`. Create documents with the `/new-doc`
  skill.
