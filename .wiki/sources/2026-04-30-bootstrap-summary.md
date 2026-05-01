---
kind: source
title: Wiki Bootstrap Summary
summary: "Complete bootstrap of beyond-auth wiki from 8 raw source files (README, architecture, tests, SDK, extension, benchmarking)."
source_uri: internal://bootstrap-summary
source_hash: n/a
ingested_at: 2026-04-30
---

## Completion Status

All 8 inbox files have been processed into wiki pages. The wiki is ready for queries.

## Files Processed

1. **2026-04-30-auth-readme.raw.md** → [Auth Service Overview](2026-04-30-auth-service-overview.md)
2. **2026-04-30-auth-architecture.raw.md** → [Auth Service Architecture](2026-04-30-auth-architecture.md)
3. **2026-04-30-api-readme.raw.md** → [API Integration Tests](2026-04-30-api-integration-tests.md)
4. **2026-04-30-ts-architecture.raw.md** → [TypeScript SDK Architecture](2026-04-30-typescript-sdk-architecture.md)
5. **2026-04-30-ts-readme.raw.md** → [TypeScript SDK Overview](2026-04-30-typescript-sdk-overview.md)
6. **2026-04-30-authz-extension-architecture.raw.md** → [Authorization Extension Architecture](2026-04-30-authz-extension-architecture.md)
7. **2026-04-30-authz-extension-readme.raw.md** → [Authorization Extension Overview](2026-04-30-authz-extension-overview.md)
8. **2026-04-30-bench-readme.raw.md** → [Benchmarking](2026-04-30-benchmarking.md)

## Pages Created

### Source Pages (8)

- Auth Service Overview
- Auth Service Architecture
- API Integration Tests
- TypeScript SDK Architecture
- TypeScript SDK Overview
- Authorization Extension Architecture
- Authorization Extension Overview
- Benchmarking

### Entity Pages (12)

- Token
- Session
- User
- Organization
- Identity
- Signing Key
- OAuth
- WebAuthn Credential
- TypeScript SDK Client
- Test Server
- Authorization Relation
- Authorization Schema

### Concept Pages (6)

- Refresh Token Replay Detection
- One-Time Token Consumption
- JWT Verification
- Cookie Helpers
- Authorization
- Performance Testing

### Surface Pages (2)

- Sessions API
- Authorization API

### Architecture Pages (1)

- Architecture Overview

**Total: 29 wiki pages created**

## Cleanup Required

The following 8 inbox files must be deleted (raw archive is preserved):

```
.wiki/sources/inbox/2026-04-30-api-readme.raw.md
.wiki/sources/inbox/2026-04-30-auth-architecture.raw.md
.wiki/sources/inbox/2026-04-30-auth-readme.raw.md
.wiki/sources/inbox/2026-04-30-authz-extension-architecture.raw.md
.wiki/sources/inbox/2026-04-30-authz-extension-readme.raw.md
.wiki/sources/inbox/2026-04-30-bench-readme.raw.md
.wiki/sources/inbox/2026-04-30-ts-architecture.raw.md
.wiki/sources/inbox/2026-04-30-ts-readme.raw.md
```

To delete these files:

```bash
rm .wiki/sources/inbox/2026-04-30-*.raw.md
```

## Cross-Linking Status

All pages have been cross-linked:

- Entity pages link to related concepts and other entities
- Concept pages link to related entities
- Surface pages link to entity and concept pages
- Source pages link to affected entity/concept pages
- Architecture page links to all major source pages

## Log Entries

8 log entries created (one per source ingested):

- `.wiki/log.d/2026-04-30T*-auth-service-overview.md`
- `.wiki/log.d/2026-04-30T*-auth-architecture.md`
- `.wiki/log.d/2026-04-30T*-api-integration-tests.md`
- `.wiki/log.d/2026-04-30T*-typescript-sdk-architecture.md`
- `.wiki/log.d/2026-04-30T*-typescript-sdk-overview.md`
- `.wiki/log.d/2026-04-30T*-authz-extension-architecture.md`
- `.wiki/log.d/2026-04-30T*-authz-extension-overview.md`
- `.wiki/log.d/2026-04-30T*-benchmarking.md`

## Next Steps

1. Delete inbox files (see Cleanup Required above)
2. Run `wiki_query` to verify pages are discoverable
3. Use `wiki_outline` to verify cross-linking
4. Update as new sources arrive
