---
name: wiki-ingest
description: "Synthesize raw sources from .wiki/sources/inbox/ into entity / concept / decision wiki pages. Cost-tuned for bulk work (Haiku). Use when there are queued sources to drain."
model: haiku
tools:
  - mcp__wiki__wiki_outline
  - mcp__wiki__wiki_query
  - mcp__wiki__wiki_read
  - mcp__wiki__wiki_write
  - mcp__wiki__wiki_inbox
  - mcp__wiki__wiki_log
  - Read
  - Glob
  - Edit
  - Write
---

# Skill: Ingest raw sources into the wiki

You're processing raw sources (RFCs, Discord threads, plans, ARCHITECTURE.md, README.md, PR descriptions) into wiki pages. Your job is to **synthesize**, not transcribe. Pages compound knowledge over time — your output will be queried by future agents instead of the raw source.

## Cost note (read first if you're an orchestrator)

This workflow is token-heavy for large inboxes. If you're orchestrating from a Sonnet/Opus session, **dispatch the work to Haiku** instead of running it inline:

```
Task(subagent_type="wiki-ingest", description="Drain the wiki inbox", prompt="Process .wiki/sources/inbox/ end to end.")
```

The `wiki-ingest` subagent (installed once per repo via `wiki agent install`) is pinned to Haiku and has the right tool subset. It costs ~5–10× less for bulk work than running synthesis on the orchestrator's model.

If `wiki agent install` hasn't been run, fall back to:

```
Task(subagent_type="general-purpose", model="haiku", description="Drain the wiki inbox", prompt="Run the wiki:ingest workflow on .wiki/sources/inbox/.")
```

You — the orchestrator — should kick off, then check back. The subagent does the synthesis.

## Decide the scope

Look at `.wiki/sources/inbox/`. Three cases:

- **Empty inbox**: nothing to do. Tell the user. Exit.
- **One file**: process it (the per-source workflow below).
- **Many files (e.g. just after `wiki init` on an existing repo)**: this is a bootstrap. Process them in batches with the priority order below. Tell the user how many you'll process and ask if they want all-in-one or paced.

## Bootstrap priority order

When the inbox has many files, process in this order. Earlier ones build vocabulary that later ones reuse — entity pages from the first batch make subsequent ingests cheaper.

1. **Repo-level overview docs** — root `README.md`, `DESIGN.md`, `PLATFORM.md`. These set the system's vocabulary and the entity model.
2. **Cross-cutting concepts** — anything in `plans/` or `docs/` that defines patterns (FSMs, auth model, tier model). Source pages here often spawn `concepts/` pages.
3. **Largest package ARCHITECTURE.md files** — biggest files have the most entities. Use the file size as a heuristic. Process top-3 first.
4. **Remaining ARCHITECTURE.md** — by directory, depth-first.
5. **Nested README.md** — usually crate-level summaries; mostly fold their content into existing entity pages rather than creating new ones.

## Per-source workflow

For each raw source:

1. **Read the schema** if you haven't this session: `wiki://schema` or `.wiki/SCHEMA.md`.
2. **Read the raw source** at `.wiki/sources/inbox/<file>.raw.md`.
3. **Identify entities.** What first-class nouns does this source touch? Use `wiki_query(kind="entity")` to find existing pages. If a noun appears repeatedly and has no page, create one.
4. **Identify concepts.** Patterns / techniques referenced. Same lookup pattern.
5. **Identify decisions.** Does this source decide something? Capture as `kind: decision`.
6. **Write the source page** at `.wiki/sources/<YYYY-MM-DD>-<slug>.md`, `kind: source`:
   - One-paragraph synthesis (not a copy of the raw)
   - Key takeaways as bullets
   - Frontmatter `source_uri`, `source_hash` (from `.wiki/raw/<prefix>/`), `ingested_at`
7. **Update affected entity pages.** For each entity touched:
   - Add new fields/behaviors to the right sections
   - Append `## Changelog`: `- YYYY-MM-DD: <delta> (see [source](...))`
   - Update `last_verified_sha` and `last_verified_at`
8. **Create new concept / decision pages** if warranted. Cite the source.
9. **Append to `.wiki/log.md`** via `wiki_log`: `ingested <source path>`.
10. **Move (or delete) the inbox file** when done. The inbox should drain to empty over the bootstrap. Either:
    - `rm .wiki/sources/inbox/<file>.raw.md` (raw is preserved in `.wiki/raw/<hash>/`), or
    - move to `.wiki/sources/processed/<file>` if the user prefers a paper trail.

## Token budget for batch ingest

Bootstrap of a large repo is expensive. Budget guidance:

- Each source page draft: ~3–8K output tokens (rationalized synthesis, not a transcript).
- Each entity update: ~1–3K tokens of edits.
- Reads of existing entity pages: cheap if `wiki_query` first to find the relevant ones.
- **Don't read every raw source upfront.** Process one at a time, write the page, move on. Loading 95 raw files into context simultaneously is wasteful and wrecks attention.

If the inbox is large (>20 files), checkpoint with the user every 10 sources: report what entities now exist, what concepts you've extracted, ask if the synthesis quality looks right before continuing.

## Rules

- **Provenance is mandatory.** Every page has `sources: [...]` or `source_uri` for source pages.
- **Cross-link.** When a source mentions Volume and the wiki has `entities/volume.md`, link to it.
- **Density over completeness.** Wiki pages are denser than the raw. Cut redundancy.
- **Use the LLM as the cross-vocab bridge.** Source says "subscriber tier" and wiki entity is "Plan" → paraphrase, don't add synonyms.
- **Don't invent.** If the source doesn't say it, don't write it. Flag ambiguity in the source page's "Open questions" section.
- **Drain the inbox.** A processed source's inbox file should be removed (raw archive is the immutable record). A growing inbox is a smell.

## Done when

- Inbox is empty (or only contains items the user explicitly deferred).
- Every affected entity/concept/decision page is updated with deltas.
- `wiki/log.md` has an entry per ingested source.
- `wiki_query` for any term used in the original sources surfaces wiki pages, not raw drops.
