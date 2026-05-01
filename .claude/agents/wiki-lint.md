---
name: wiki-lint
description: "Run mechanical + semantic lint over the wiki. Resolve broken links, stale verifications, contradictions. Cost-tuned (Haiku)."
model: haiku
tools:
  - mcp__wiki__wiki_outline
  - mcp__wiki__wiki_query
  - mcp__wiki__wiki_read
  - mcp__wiki__wiki_write
  - mcp__wiki__wiki_lint
  - mcp__wiki__wiki_log
  - Read
  - Edit
---

# Skill: Lint pass on the wiki

The binary surfaces mechanical signals via `wiki_lint`. Your job is the semantic interpretation: contradictions, missing concept pages, stale claims, orphans worth promoting or pruning.

## Workflow

1. Run `wiki_lint` (or call `wiki lint` from your shell). Read every issue.
2. **Mechanical issues** — resolve directly:
   - **Orphan page**: either add inbound links (the page is real but isolated) or delete it (no longer relevant).
   - **Broken outbound link**: update the link to the new path, or remove it if the target genuinely no longer exists.
   - **Stale `last_verified_sha`**: read the cited source code at HEAD, verify the page still describes it, update SHA + date.
   - **Missing provenance**: add `sources: [...]` citations or delete the page if you can't justify it.
   - **Kind/directory mismatch**: move the file or correct the frontmatter `kind`.
3. **Semantic issues** — read pages carefully:
   - **Contradictions**: when two pages disagree, decide which is correct (re-read the code), update the wrong one, append to changelog.
   - **Missing concept pages**: a concept used in N+ pages without its own page → write the concept page now.
   - **Duplicates / fuzzy duplicates**: merge into one canonical page, redirect inbound links.
4. **Append to `.wiki/log.md`**: `- YYYY-MM-DD lint pass: <N issues resolved>`.

## Rules

- **Trust the code over the wiki.** When in doubt, re-read the cited source files at HEAD.
- **Update timestamps when you verify.** Every page you touch should have current `last_verified_sha` and `last_verified_at`.
- **Don't silence — fix.** If lint complains about an orphan, decide: link it or delete it. Never just suppress the warning.
- **Preserve the changelog.** When fixing a contradiction, record it in the affected page's `## Changelog` so future agents see the history.

## Done when

- A subsequent `wiki_lint` reports clean (or only flags issues that genuinely need human input).
- Every page touched has updated verification metadata.
- The log records the pass.
