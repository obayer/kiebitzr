---
id: kbz:meta:00001
title: Documentation Conventions
date: 2026-11-05
status: active
tags:
  - conventions
  - documentation
---

# Documentation Conventions

Reference for all Markdown documents in `docs/`.

## Frontmatter

Every document starts with a YAML frontmatter block. Fields are lowercase, dates are ISO 8601.

```yaml
---
id: kbz:<category>:<nnnnn>     # mandatory, unique
title: <Human-readable title>  # mandatory
date: <YYYY-MM-DD>             # mandatory, creation date
status: <see below>
tags: [tag-one, tag-two]       # from the local taxonomy, see below
related:
  - id: kbz:adr:00001
    reason: <why this document relates>
---
```

Tags come from a controlled vocabulary rather than being invented per document, and a new
topic adds its canonical tag in the same change. The vocabulary and the ID configuration live
in the authoring tool's own configuration (`.claude/`), which is git-ignored because it
configures an editing setup rather than the service — so the tags already in use in
`docs/` are the authoritative list here, and `mise run docs:tag -- <tag>` enumerates them.

## ID namespace

`kbz:<category>:<nnnnn>` — `kbz` is the project namespace, the number is zero-padded to five
digits and sequential within the category.

| Category | Used for | File pattern |
|---|---|---|
| `adr` | Architectural Decision Records | `docs/adr/<NNNN>-<slug>.md` |
| `req` | What the service has to answer, and the evidence that it does. The test a proposal is held to | `docs/req/<NNNN>-<slug>.md` |
| `runbook` | Operational procedures | `docs/runbooks/<slug>.md` |
| `review` | Security reviews, audits | `docs/review/<NNNN>-<slug>.md` |
| `meta` | Documents about documentation (this file) | `docs/<NAME>.md` |

Slugs are lowercase and hyphen-separated.

## Status values

| Value | Meaning |
|---|---|
| `draft` | Work in progress |
| `proposed` | ADR written, not yet decided |
| `accepted` | ADR decided and in effect |
| `active` | Current, authoritative (runbooks, meta) |
| `open` / `resolved` | Reviews with / without unresolved findings |
| `superseded` | Replaced; set `superseded_by: kbz:adr:<nnnnn>` |
| `deprecated` | No longer relevant, kept for history |

## Content rules

- English only.
- **No installation-specific information**: no hostnames, IPs, cluster or namespace names of
  a real deployment, no local paths, users or e-mail addresses. Use neutral placeholders.
  Installation decisions belong in the repository that deploys Kiebitzr.
- An ADR records context, options considered (with the reason each was rejected), the
  decision and its consequences. Later refinements are added as amendment sections or a
  superseding ADR, never by silently rewriting the decision.

## Tooling

| Tool | Purpose |
|---|---|
| `/new-doc` skill | Create a document with the next free ID and validated links |
| `mise run docs:*` | Query the knowledge graph (ADR list, tags, refs, search) |
| `frontmatter-lint --session` | Runs as a Stop hook; validates changed docs |

The tools are vendored in `tools/claude-frontmatter/`; run `npm install` once.
