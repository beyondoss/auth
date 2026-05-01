# Wiki Schema

This file is the source of truth for wiki conventions. Agents must read it
before writing pages. Humans may edit it (rarely) to evolve conventions.

## Three Layers

- **Raw sources** are immutable. Code, ADRs, ingested RFCs, Discord/Slack
  threads, PR descriptions, coding-agent plan files, package `ARCHITECTURE.md`.
  The wiki reads them; it never rewrites them.
- **The wiki** is LLM-synthesized markdown under `.wiki/`. Owned by the agent,
  mediated by the `wiki` binary.
- **The schema** is this file.

## Page Kinds

| Kind         | Directory       | What it captures                                              |
| ------------ | --------------- | ------------------------------------------------------------- |
| entity       | `entities/`     | First-class noun in the system (Box, Volume, Tenant, Account) |
| concept      | `concepts/`     | Pattern/technique used (ReBAC, Typestate FSM, S3-FIFO, CoW)   |
| decision     | `decisions/`    | ADR — why we did X over Y                                     |
| surface      | `surfaces/`     | Public interface — API endpoints, CLI commands, NATS subjects |
| architecture | `architecture/` | Synthesis layer linking to package-level `ARCHITECTURE.md`    |
| source       | `sources/`      | Summary of an ingested raw source (RFC, thread, plan)         |
| change       | `changes/`      | One per shipped feature; links source → entities → code       |

The directory is enforced by lint. A page with `kind: entity` must live under
`entities/`.

## Frontmatter (required)

```yaml
kind: entity
title: Box
summary: Single-sentence description used in the TOC.
sources:
  - boxes/box-manager/src/vm/mod.rs
  - .wiki/sources/2026-04-volume-tiers.md
links:
  - .wiki/entities/volume.md
last_verified_sha: a1b2c3d
last_verified_at: 2026-04-30
---
```

| Field             | Required for             | Purpose                                           |
| ----------------- | ------------------------ | ------------------------------------------------- |
| kind              | all                      | Page kind; must match parent directory            |
| title             | all                      | Display title and search anchor                   |
| summary           | all                      | One-line description; appears in `index.md`       |
| sources           | all except source        | Provenance (lint blocks if empty)                 |
| links             | optional                 | Cross-references; binary mirrors as bidirectional |
| last_verified_sha | optional but recommended | Git SHA at last verification — drives lint        |
| last_verified_at  | optional but recommended | Date of last verification                         |
| source_uri        | source pages only        | Original URI of ingested source                   |
| source_hash       | source pages only        | BLAKE3 hash of raw archive snapshot               |
| ingested_at       | source pages only        | When the source was ingested                      |

## Three Operations

### Ingest

Drop a raw source via `wiki ingest <path>` or `wiki_inbox(...)`. Then invoke
`wiki:ingest`: read source, find affected entities, write/update pages, append
to log.

### Query

Read `index.md` first (TOC). Use `wiki_query` for keyword search,
`wiki_outline(path)` for cheap orientation, `wiki_read(path, section?)` for
content. Search the wiki — not raw sources.

### Lint

`wiki lint` reports orphan pages, broken links, stale verifications, missing
provenance, kind/directory mismatches. Use `wiki:lint` to interpret semantic
issues (contradictions, missing concept pages).

## Provenance

Every page must cite at least one raw source. This is enforced. No "vibes"
entries. Source pages cite the upstream URI via `source_uri`.

## Links

Use standard markdown links to other wiki pages: `[Box](.wiki/entities/box.md)`.
Anchors to specific sections: `[Box lifecycle](.wiki/entities/box.md#lifecycle)`.
The binary mirrors links bidirectionally — no orphans by accident.
