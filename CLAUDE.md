## Service Model

**This is a private, internal service.** Each deployment runs inside a single customer's private network, serving exactly one project's users. It is not a public SaaS, not a shared multi-org platform, and not exposed to the open internet without the operator's own infrastructure in front of it.

**Consequences — do not add to this service:**

- Rate limiting, IP blocking, DDoS mitigation — the operator's load balancer, firewall, or edge proxy handles this. We see trusted traffic only.
- Abuse detection, fraud scoring, CAPTCHA — not our layer.
- Account lockout after N failed attempts — the network boundary and Argon2's cost parameter are the defenses. If an attacker is making requests, the operator's infrastructure should be stopping them, not us.
- Any feature whose entire justification is "what if a bad actor hammers this endpoint" — wrong layer.

When a feature is tempting because "this is what Auth0/Clerk does," stop and ask: do they need it because they're a _public multi-org service_ taking traffic from the whole internet? If yes, we probably don't need it.

## Architecture

**Keep docs in sync**: When changing code that affects documented behavior (data flows, state machines, APIs, config), update the ARCHITECTURE.md in the same commit. Stale docs are worse than no docs.

## Database

**All sqlx queries must be type-safe.** Use `sqlx::query_as!`, `sqlx::query!`, and related macros — never `sqlx::query` with manual `.try_get()` calls or untyped row access. The compile-time checked macros are the guarantee that query results match Rust types; bypassing them removes that guarantee.

## Local Development

We use mise for running development tasks.

Search tasks:

```sh
mise tasks | grep "search"
```

Run them from anywhere:

```sh
mise run test
```

To run the TypeScript SDK tests locally:

```sh
mise run extension:build:linux:arm64   # build the .so for the testcontainer (linux/arm64)
mise run test:integration:ts             # builds the debug binary, then runs the tests
```

`test:ts` depends on `build`, so the binary is always up to date. The extension build is separate because it spins up Docker and takes minutes — run it once, re-run only when extension code changes.

## System Design

**IMPORTANT**: We seek the minimum effective abstraction. Elegant simplicity. Composable parts that "just work".

**Performance is a feature, not an optimization pass.**

- Do less work. The fastest code is code that doesn't run.
- Minimize allocations. Reuse where it matters.
- Parallelize only when the work itself is the bottleneck—not as a first instinct.
- Measure before you optimize, but design with performance in mind from the start.

## API Design: REST, Not RPC

This API is **resource-oriented REST**. If you're adding an endpoint, think nouns and HTTP semantics — not verbs and function calls.

**Resources are nouns. HTTP methods are the verbs.**

| Intent             | Correct                               | Wrong                        |
| ------------------ | ------------------------------------- | ---------------------------- |
| Create a session   | `POST /v1/sessions`                   | `POST /v1/createSession`     |
| Get a token        | `GET /v1/tokens/{id}`                 | `GET /v1/getToken?id=…`      |
| Revoke a key       | `DELETE /v1/keys/{id}`                | `POST /v1/revokeKey`         |
| Rotate credentials | `POST /v1/credentials/{id}/rotations` | `POST /v1/rotateCredentials` |

**HTTP methods map to intent:**

- `GET` — read, safe, idempotent, cacheable
- `POST` — create a new resource or trigger a subordinate action
- `PUT` — full replacement, idempotent
- `PATCH` — partial update, idempotent
- `DELETE` — removal, idempotent

**Status codes carry meaning — use them:**

- `200 OK` — successful read or update
- `201 Created` — resource created; include `Location` header
- `204 No Content` — successful delete or action with no body
- `400 Bad Request` — client sent invalid input
- `401 Unauthorized` — authentication required or failed
- `403 Forbidden` — authenticated but not allowed
- `404 Not Found` — resource doesn't exist
- `409 Conflict` — state conflict (e.g. already exists)
- `422 Unprocessable Entity` — valid JSON, invalid semantics
- `500 Internal Server Error` — our fault

**URL conventions:**

- Lowercase, hyphen-separated path segments: `/v1/signing-keys`
- Collections are plural nouns: `/v1/sessions`, `/v1/keys`
- Sub-resources nest under their parent: `/v1/sessions/{id}/tokens`
- Version prefix on all application routes: `/v1/…`
- System routes (`/healthz`, `/metrics`, `/openapi.json`) are unversioned

**What REST is not:**

- No verbs in paths (`/create`, `/get`, `/delete`, `/do`)
- No action tunneling through `POST` with a `action=…` body field
- No ignoring HTTP method semantics (e.g. mutations via `GET`)
- No generic `/rpc` or `/api` catch-all endpoints

If an action doesn't map cleanly to a resource + method, model it as a sub-resource (e.g. `POST /v1/sessions/{id}/revocations` to revoke a session). When genuinely stuck, ask: what _thing_ is being created or changed?

## Operations & State

All operations that modify state—infrastructure (GlideFS, VXLAN, iptables, TAP devices) and application—**must be idempotent and atomic**.

**Idempotent**: Running an operation multiple times produces the same result as running it once.

- Check before create; don't error if it exists
- Check before destroy; don't error if it's gone
- Safe to retry after network failures or crashes

**Atomic (or safe)**: An operation either fully succeeds, fully fails, or leaves the system in a valid intermediate state that subsequent retries can recover from.

- Multi-step operations should use transactions or compensating actions
- If you can't make it atomic, make the intermediate states safe to observe

These properties are critical for crash recovery, distributed coordination, and reasoning about system behavior.

## Performance Improvement

Apply the **Theory of Constraints**: a system's throughput is limited by its single tightest bottleneck. Optimizing anything else is waste.

1. **Identify** the constraint. Profile. Trace. Measure. Don't guess — find the one thing that actually bounds throughput or latency right now.
2. **Exploit** the constraint. Squeeze maximum performance from the bottleneck with minimal change — better batching, fewer allocations, smarter scheduling. No redesigns yet.
3. **Subordinate** everything else. Non-bottleneck components should serve the constraint, not outrun it. Over-optimizing a fast path that feeds into a slow one is wasted effort.
4. **Elevate** the constraint. If exploiting isn't enough, invest in removing it — redesign, parallelize, change the algorithm, add capacity.
5. **Repeat.** The bottleneck has shifted. Go back to step 1.

The corollary: if you can't name the current constraint, you aren't ready to optimize.

<!-- wiki-managed:start (managed by `wiki claude install`; edits inside this block will be overwritten) -->

## Wiki

This repo uses [agent-wiki](.wiki/SCHEMA.md): `.wiki/` holds synthesized entity, concept, decision, and source pages cross-linked into a queryable knowledge graph.

**Read the wiki before grepping the codebase or reading ARCHITECTURE.md.** Pages are pre-synthesized — searching them is faster and ~5–10× cheaper than re-deriving from raw files.

Wiki tools — pick based on what you need:

- `wiki_query "<term>"` — first move for any specific question. BM25++ over wiki pages, repo docs, and code symbols; returns ranked hits with paths, scores, and inline snippets.
- `wiki_answer "<question>"` — returns top-ranked pages with query-relevant passage extracts in one round-trip. Best when you expect the answer exists and want it immediately.
- `wiki_read "path/to/page.md"` (optionally `section: "..."` or `paths: [...]`) — full page, one section, or multiple pages in one call.
- `wiki_search_code "<query>"` — search exported symbols, signatures, and doc comments when you need to locate a declaration or understand an API.

When shipping a feature: invoke the `wiki:reconcile_change` prompt to close the source → code loop. When auditing the wiki itself: `Task(subagent_type="wiki-lint", ...)`.

<!-- wiki-managed:end -->
