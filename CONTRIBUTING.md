# Contributing to Kiebitzr

How to work on this repository: the tasks, the two build configurations, the agent sandbox and
what it deliberately cannot reach, how CI is read from inside it, the secret gates, and how a
release is cut.

What the service *is* and whether it fits you is in [`README.md`](README.md); how to run and
read it is in [`docs/runbooks/`](docs/runbooks). Design decisions are ADRs in
[`docs/adr/`](docs/adr) — a change that alters what the service can do needs one, and
[`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) says how documents are written. Commits are
Conventional Commits; signing and releasing happen in CI only.

Vulnerabilities in Kiebitzr itself go through [`SECURITY.md`](SECURITY.md), not through an
issue.

## License and sign-off

The project is [Apache-2.0](LICENSE), and a contribution is accepted under the same license.
Every commit needs a **Developer Certificate of Origin** sign-off, which is one line:

```
Signed-off-by: Your Name <your@address>
```

`git commit -s` adds it from your git identity. What you are certifying is the Developer
Certificate of Origin 1.1, which is in [`DCO`](DCO) verbatim and published at
[developercertificate.org](https://developercertificate.org): in short, that you wrote the
change or have the right to submit it under this license — and, in its clause (d), that the
record of the contribution including the address you sign with is public and kept
indefinitely.

That last clause is not a formality in a git history, which cannot forget. Use an address you
are content to publish forever; the [GitHub noreply
address](https://docs.github.com/en/account-and-profile/how-tos/setting-up-and-managing-your-personal-account-on-github/managing-email-preferences/setting-your-commit-email-address)
is the usual answer, and it is what the identity gate below expects, so the sign-off and the
commit agree.

**Every commit** means the maintainer's too. A rule with an exception for whoever wrote it is
not a rule, and a history where the sign-off is sometimes there and sometimes not cannot be
checked by anybody later.

The DCO is deliberately not a CLA. Nobody signing off hands over any right: the contributor
keeps the copyright, the contribution arrives under the same Apache-2.0 the project ships
under, and this project therefore cannot be relicensed later without asking everybody who
contributed. That is a constraint accepted on purpose, not an oversight.

That matters more than it used to, and this is the only place it is stated: **a contribution
written with an AI assistant is welcome**, and this repository is largely written that way
itself. The sign-off does not ask how the code was produced; it asks you to take
responsibility that you may license it. If a tool reproduced somebody else's code and you
cannot say that, it cannot go in — the sign-off is the point at which that question has to have
an answer rather than a plausible assumption.

## Tasks and tooling

Tools and tasks come from [mise](https://mise.jdx.dev):

```bash
mise run setup             # tools, docs tooling and the pre-commit hook
mise run check             # what CI runs
mise run precommit         # what the hook runs: staged secret scan and commit identity
mise run test:integration  # the real registry and the real vulnerability database
mise tasks ls              # everything else
```

`check` never touches the network except for `govulncheck`; the integration tests pull an
image and download the vulnerability database, so they are a separate task.

Formatting is **gofumpt** plus fixed import groups, applied through `golangci-lint fmt` so
that formatting and linting can never disagree about a file. `.golangci.yaml` documents both
what is enabled and what is deliberately not — the second list is the more useful one.

## Build configurations

| Build | How | Kubeconfig |
|---|---|---|
| release (what CI publishes) | no build tag | not available: no flag, and the kubeconfig loader is not linked in |
| development | `-tags dev`, which `mise run build` uses | `-kubeconfig` points the binary at a cluster from outside it |

The release build reaches the API server through the pod's service account and has no other
way in. `check` tests and vets both configurations, so the path that is not built by default
cannot rot.

Personal settings go into `mise.local.toml`, which is git-ignored.

## The agent sandbox

Work on this repository is done with an agent, and `mise run claude` is how it starts. The
sandbox it starts *in* is optional and deliberately not described here, because a sandbox
profile describes one machine: which paths a session may write, where its credentials are kept,
which hosts it may reach. Publishing that would hand anybody who later got code execution in
such a session a finished map, and it would go stale the moment the machine changed.

What the repository does define is the rule, and it is asymmetric:

| State | What `mise run claude` does |
|---|---|
| no sandbox installed ([nono](https://nono.sh) not on the PATH) | runs the agent directly, and says so |
| sandbox installed, `KBZ_SANDBOX_PROFILE` unset or unreadable | **refuses to start** |

An installed sandbox that is silently not used is the failure worth preventing; running without
one, knowingly, is a choice. The variable points at a profile outside the repository and
belongs in `mise.local.toml`, which is git-ignored — as does the `nono` version itself, so that
a clone of this repository installs no sandbox it has no profile for.

Three properties are worth reproducing in any profile used here, independent of the tool:

- **The session cannot read the login keychain or any other credential store.** An agent that
  can read every secret on the machine is a worse risk than the one it is being protected from.
  Claude Code then authenticates from `$CLAUDE_CONFIG_DIR/.credentials.json`, which it falls
  back to when a keychain write is rejected — `mise run claude-auth` is what creates it, from
  inside the sandbox, because that is where the file has to end up.
- **The tool directory is read-only to the session.** This is what stops a session rewriting
  the gates that check its own work (`go`, `golangci-lint`, `betterleaks`). The cost is that
  installing a tool becomes a host step.
- **The network is an allowlist**, and it needs the registries, the Go module proxy and
  `grype.anchore.io` — the integration tests and `mise run dev` reach all three. The ports
  `8080–8082` have to be bindable *and* connectable for the work API and a local worker.

## Reading CI

A failing CI run is read with `gh`, so nobody has to paste log excerpts into an agent session:

```bash
mise run ci:runs                   # which run, and whether a second one cancelled it
mise run ci:why -- <run-id>        # every job and step with its conclusion
mise run ci:annotations -- <run-id> # what a dying runner still managed to report
```

These are plain `gh` calls and work with or without a sandbox. Where one is used, `gh` should be
a *mediated* command — the credential injected outside the session, restricted to this
repository's Actions read endpoints — so that no token ever enters an agent transcript. `gh` is
declared in `[tools]` rather than on the task for exactly that reason: a task-scoped tool
directory is prepended ahead of the mediating shim and bypasses it.

The tasks read the jobs API rather than `gh run view --log`, because the log endpoint redirects
to a blob host a restricted session typically may not reach.

That is also why the CI job emits annotations. A runner that runs out of memory is not
failed but force-terminated: the step shows up as `cancelled`, every later step is skipped
even with `if: always()`, and nothing it would have recorded exists. Annotations go to the
API as they are printed and survive it, so `ci:annotations` can still name the gate that was
running and the headroom at the time. They live under `check-runs` rather than `/actions/`,
which is the one extra pair of `GET` paths in the endpoint policy.

A token in a remote URL or in `~/.gitconfig` remains the worst case regardless of any of
this: it is printed by ordinary commands like `git remote -v`, which puts it in logs and agent
transcripts.

## What must not reach a commit

This repository is public, so three kinds of mistake are permanent rather than correctable: a
credential, an identity, and anything naming a real installation. Each has a gate.

### Credentials

Three gates, all running betterleaks against `.betterleaks.toml`:

| Gate | When | Scope |
|---|---|---|
| `secrets` | `mise run check` | working tree, before anything is staged |
| `secrets:staged` | pre-commit hook, via `mise run precommit` | what the next commit would add |
| `secrets:history` | `mise run check` and CI | every commit — a credential committed and deleted again stays in the history and only this finds it |

The hook is local and bypassable with `git commit --no-verify`; CI runs `secrets:history` on
the full history, so a bypass still fails the pull request. The git-ignored paths that exist to
hold personal tokens, profiles and notes are skipped by the `[[allowlists]]` entries in the
config, so `mise.local.toml` never trips a scan — `betterleaks dir` walks the filesystem and
does not honour `.gitignore`, which is why they have to be named there as well.

### The commit identity

`mise run identity` (`tools/identityguard`) checks the author *and* committer address git would
use against the addresses already in this repository's history, and the pre-commit hook runs it
before the secret scan. An address that is new here stops the commit until it is confirmed:

```bash
IDENTITYGUARD_ALLOW_NEW=1 git commit …   # yes, that address is right and new — e.g. a first contribution
git config user.email '<address>'        # no: set the one you publish under, per repository
```

The reason it exists rather than relying on `git config`: a repository-local `user.email` lives
in `.git/config`, which is not versioned and is not inherited by a fresh clone, a new worktree
or a checkout on another machine. The first commit made there carries the global identity
instead — into a public history, where it cannot be taken back, and where a private address
gets harvested and an employer address attributes a personal project to an organisation that
has nothing to do with it. Rotating an address afterwards is no remedy, because the commit
stays.

It compares against the history rather than against a list of permitted addresses on purpose.
A list in a published repository would either refuse every contribution but the maintainer's or
become a register of other people's e-mail addresses, and nobody should have to send a pull
request against a policy file to be allowed to commit. For the same reason the check is **not**
part of `mise run check` and does not run in CI: a first contribution is new by definition, and
a gate that fails every newcomer gets removed rather than heeded. What CI cannot repair — a
published address — a commit hook can prevent.

### Anything naming a real installation

No hostnames, addresses, cluster, namespace or workload names, no local paths, no usernames.
That is a hard rule rather than a preference, and it extends to what a measurement *implies*:
the documents here cite the numbers an installation produced — "41 of 50 images carried at
least one `Critical`" — and not the software, versions or platform that produced them. Those
belong in `notes/`, which is git-ignored, so that the evidence stays checkable without
publishing an inventory of somebody's cluster.

Reports from a real installation (`feedback*.md`) are git-ignored for the same reason; their
findings reach `TODO.md` in neutral form.

Every secret gate passes `--config .betterleaks.toml` explicitly. betterleaks ignores a config
found in the scanned directory unless `--unsafe-auto-load-config` is given, which is the safer
default — but it means a gate that forgets the flag runs on the built-in rules with no
allowlist and reports the local token files it is supposed to skip. Keep the flag when you
add a gate.

A credential that did reach a push is compromised — rotate it; removing the commit is not
enough.

## Releases

Release images are published to `ghcr.io/obayer/kiebitzr` for `linux/arm64` and
`linux/amd64`, built with [ko](https://ko.build) and signed keyless with cosign.

A release is cut by pushing a tag, and that is the only local step there is:

```bash
mise run release -- v2026.1109.0   # tags and pushes; CI builds, pushes and signs
mise run verify  -- v2026.1109.0   # checks that the published image carries that signature
```

Versions are CalVer, `vYYYY.MMDD.N` (ADR 0006).

Nothing builds or signs a release locally on purpose: a keyless signature made on a
workstation would publish the signer's e-mail to the public transparency log, so it happens in
CI only. `mise run release` also refuses to tag a commit that is not on `origin/main`, because
the release workflow triggers on the tag and does not run the gates itself.

### Testing a local build in a cluster

To try a build before it is released, without a registry in between:

```bash
mise run image:tarball                                            # writes bin/ and prints the import
sudo ctr -n k8s.io images import bin/kiebitzr-linux-arm64.tar     # on the node; k3s: sudo k3s ctr images import …
```

The image carries the ghcr reference and `git describe` as its tag, so only the tag in the
Deployment changes — and that Deployment needs `imagePullPolicy: IfNotPresent` and no `latest`
tag, or the kubelet goes looking for the image in a registry that does not have it. Plain
containerd needs `ctr -n k8s.io`, because that is the namespace the kubelet reads.

This is for testing only. An imported image has no signature and nothing ties it to a commit
in this repository beyond the tag it was given; what stays in the cluster should come from a
release.

`mise run verify` is the same check a consumer would run:

```bash
cosign verify ghcr.io/obayer/kiebitzr:<tag> \
  --certificate-identity-regexp '^https://github.com/obayer/kiebitzr/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
