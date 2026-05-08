# TypeScript SDK Architecture

Takes a Beyond Auth service URL and credentials, and produces typed HTTP clients, token verifiers, Zanzibar-style permission checks, and Next.js middleware/helpers — all as thin wrappers over the auth service's REST API.

## Data Flow

### Session token verification (opaque tokens)

```
Incoming request
  │
  ├── getSessionToken(request)
  │     checks __Host-session cookie, then __Secure-session, then Authorization: Bearer
  │
  └── verifier.verify(token)
        │
        GET /v1/sessions/current  ─► 401 → return null
        Authorization: Bearer <token>  ─► 5xx/4xx → throw AuthError
                                       ─► 200 → return SessionContext
```

### JWT verification

```
verifier.verify(token)
  │
  ├── [cache hit] verify signature locally → return JwtClaims
  │
  ├── [cache miss / first call]
  │     fetch JWKS from jwksUri, cache for 1 hour
  │     └── verify signature → return JwtClaims
  │
  ├── [unknown kid]
  │     refresh JWKS once (30s cooldown), retry
  │     └── still fails → throw JwtVerificationError(retryable=false)
  │
  └── [network error / JWKSTimeout]
        throw JwtVerificationError(retryable=true)
```

### Authorization check (ReBAC)

```
authz.check(resourceType, permission, resourceId, subject)
  │
  GET /v1/authz/decisions
    ?resource_type=&permission=&resource_id=&user=<subject>
  │
  ├── { allowed: true }  → resolve void
  ├── { allowed: false } → throw AuthzError("unauthorized")
  └── error body         → throw AuthzError or AuthError by code

authz.checkSession(token, resourceType, permission, resourceId)
  │
  GET /v1/authz/decisions
    Authorization: Bearer <token>
    ?resource_type=&permission=&resource_id=
    (subject resolved from session server-side — one DB round-trip)
```

### Next.js middleware

```
request arrives
  │
  matchesPublicPath(pathname, publicPaths)?
  ├── yes → NextResponse.next()
  └── no
        │
        getSessionToken(request)
        ├── null → redirect(redirectTo)
        └── token
              │
              verifier.verify(token)
              ├── ok → NextResponse.next()
              ├── AuthError(status >= 500) → re-throw
              └── any other error → redirect(redirectTo)
```

### RSC session helpers

```
getSession(cookieStore) / getMe(cookieStore)
  │
  memoized per-request via React.cache() (falls back to identity if React unavailable)
  │
  getTokenFromCookieStore → checks __Host-session, then __Secure-session
  │
  verifier.verify(token)
  ├── null → return null
  └── SessionContext
        │
        getMe only: GET /v1/users/me  Authorization: Bearer <token>
        └── return MeResponse | null
```

## Concepts & Terminology

| Term             | What It Controls                                                                         | NOT                                                                                       |
| ---------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `SessionContext` | The record returned when an opaque session token is valid                                | A decoded JWT — it's a DB record fetched on every call                                    |
| `JwtClaims`      | Cryptographically verified payload; `sub` is guaranteed present                          | Valid session state — a JWT can be valid but the session revoked                          |
| `Relation`       | An edge in the authorization graph: `objectType:objectId#relation@subjectId`             | A permission — relations are roles; permissions are derived from roles via schema         |
| Subject set      | A `Relation` with `subjectType` + `subjectRelation` — expands transitively at check time | A group stored in the SDK — expansion happens in the auth service                         |
| `adminSecret`    | Bearer token that authorizes admin operations on the authz client                        | A user token — it never comes from a session                                              |
| `__Host-session` | Session cookie without a domain — pinned to the exact origin                             | Interchangeable with `__Secure-session` — prefix is determined by whether `domain` is set |

## Core Mechanisms

### HTTP client (`createAdminClient` / `createAuthClient`)

Both clients wrap `openapi-fetch` with the OpenAPI `paths` type parameter. Every path, method, request body, query parameter, and response shape is inferred from `types.ts` (generated from the OpenAPI spec).

`createAdminClient` takes a `secret` at construction time and bakes `Authorization: Bearer <secret>` into every request. It exposes namespaced semantic methods for admin operations (`users.*`, `config.*`, `oauthProviders.*`, `authz.*`) — consistent with the rest of the Beyond SDK family.

`createAuthClient` takes a session `token` at construction time and bakes `Authorization: Bearer <token>` into every request. It exposes namespaced semantic methods for user-scoped operations (`identities.*`, `orgs.*`, `orgs.members.*`, `orgs.invitations.*`, `me.*`, `emails.*`, `sessions.*`, `keys.*`, `passkeys.*`, `totp.*`).

The generic `OrgRole` type parameter (`createAuthClient<{ OrgRole: 'admin' | 'member' }>`) constrains the `role` field on invitation bodies at compile time. It is a phantom type — nothing happens at runtime.

### JWT verifier (`createJwtVerifier`)

Stateful — holds JWKS in memory. Create once at startup and reuse.

`jose`'s `createRemoteJWKSet` handles caching (1-hour TTL, 30-second cooldown on refresh) and unknown-`kid` retry automatically. The SDK adds:

- Mandatory `sub` claim check (throws if missing)
- `retryable` classification on errors: `JWKSTimeout` or any non-`JOSEError` (network failure) is retryable; everything else (bad signature, wrong issuer, expired) is not

### Session verifier (`createSessionVerifier`)

Stateless — no in-memory state. Every `verify()` call makes `GET /v1/sessions/current`. Returns `null` on 401; throws `AuthError` on anything else non-2xx. In Next.js RSCs, wrap with `React.cache()` (done automatically by `createServerHelpers`) to avoid redundant requests within one render tree.

### Authz client (`createAuthzClient`)

Stateless — schema is compiled and cached server-side.

`check` passes the subject as a `user` query param with no auth header. `checkSession` passes the session token as `Authorization: Bearer` with no `user` param; the service resolves the subject from the session in a single CTE — one DB round-trip instead of two.

Batch writes use `PATCH /v1/authz/relations` with a `{ writes, deletes }` body. `createRelations` sends writes with an empty deletes array; `deleteRelations` does the reverse. Both short-circuit on empty input.

Error dispatch (`parseError`): if the error code is one of the four authz-specific codes it throws `AuthzError`; everything else becomes `AuthError`.

### Cookie helpers (`sessionCookieAttrs` / `clearCookieAttrs` / `getSessionToken`)

Framework-agnostic — returns plain objects. Callers apply them to their cookie API.

Cookie name is determined by whether `domain` is set: without domain → `__Host-session` (pins to exact origin); with domain → `__Secure-session` (allows subdomains). The attributes `HttpOnly`, `Secure`, `SameSite=lax`, `Path=/` are hardcoded — callers cannot weaken them.

`getSessionToken` parses the `cookie` header manually (no library dependency) to avoid taking a cookie-parsing dependency. Prefers `__Host-session`, falls back to `__Secure-session`, then `Authorization: Bearer`.

## Trust Boundaries

**What the SDK verifies locally:**

- JWT signature (via JWKS + `jose`)
- JWT `iss`, `aud` (if configured), `exp`, `nbf` (with clock skew tolerance)
- Presence of `sub` claim

**What passes to the auth service unchecked:**

- Opaque session token values (auth service validates against DB)
- All subject IDs, resource IDs, and relation tuples passed to authz operations
- The `Authorization: Bearer` header forwarded by `checkSession` and `lookup`

**What the middleware does NOT check:**

- Token structure or type — passes any non-null string to `verifier.verify()`
- Whether the user is authorized for the specific route — only authenticated vs. not

**Why this boundary exists:**
The auth service is the authoritative store for sessions, permissions, and schema. Local JWT verification is an optimization (no HTTP round-trip on cache hit). Everything else requires the service, so the SDK delegates rather than duplicating server-side logic.

## Package Structure

| File                     | What It Does                                                                                                 |
| ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `src/index.ts`           | Re-exports the entire public API                                                                             |
| `src/client.ts`          | `createAdminClient` (bare typed fetch client) and `createAuthClient` (authed client with namespaced helpers) |
| `src/session.ts`         | `createSessionVerifier` — stateless opaque token verifier via `GET /v1/sessions/current`                     |
| `src/jwt.ts`             | `createJwtVerifier` — stateful JWKS-backed JWT verifier                                                      |
| `src/authz.ts`           | `createAuthzClient` — Zanzibar check/expand/trace/lookup/write/schema operations                             |
| `src/errors.ts`          | `AuthError`, `AuthzError`, `JwtVerificationError`                                                            |
| `src/server/cookie.ts`   | `sessionCookieAttrs`, `clearCookieAttrs`, `getSessionToken` — framework-agnostic cookie helpers              |
| `src/next/middleware.ts` | `createAuthMiddleware` — Next.js route protection with public path matching                                  |
| `src/next/server.ts`     | `createServerHelpers` (RSC `getSession`/`getMe`), `setSessionCookie`, `clearSessionCookie`                   |
| `src/next/index.ts`      | Re-exports the Next.js subpackage public API                                                                 |
| `src/react/index.ts`     | Placeholder — reserved for future client-side state management                                               |
| `src/types.ts`           | Auto-generated OpenAPI types (4000+ lines) — do not edit                                                     |

## Configuration

### `createAdminClient`

| Option   | Effect                                                         |
| -------- | -------------------------------------------------------------- |
| `url`    | Base URL of the auth service; trailing slash stripped          |
| `secret` | Prepended as `Authorization: Bearer <secret>` on every request |

### `createAuthClient`

| Option              | Effect                                                                               |
| ------------------- | ------------------------------------------------------------------------------------ |
| `baseUrl`           | Base URL of the auth service                                                         |
| `token`             | Prepended as `Authorization: Bearer <token>` on every request                        |
| `Config["OrgRole"]` | Generic type parameter — constrains `role` on invitation bodies at compile time only |

### `createSessionVerifier`

| Option    | Effect                                   |
| --------- | ---------------------------------------- |
| `baseUrl` | Where to send `GET /v1/sessions/current` |

### `createJwtVerifier`

| Option             | Default | Effect                                                  |
| ------------------ | ------- | ------------------------------------------------------- |
| `jwksUri`          | —       | Fetched on first `verify()` call; cached for 1 hour     |
| `issuer`           | —       | Rejects tokens where `iss` doesn't match                |
| `audience`         | unset   | When set, rejects tokens without a matching `aud` claim |
| `clockSkewSeconds` | `30`    | Tolerance applied to `exp` and `nbf` validation         |

### `createAuthzClient`

| Option        | Effect                                                                                  |
| ------------- | --------------------------------------------------------------------------------------- |
| `baseUrl`     | Base URL of the auth service                                                            |
| `adminSecret` | Sent as `Authorization: Bearer` on all admin operations (writes, expand, trace, schema) |

### `createAuthMiddleware`

| Option        | Default    | Effect                                                                                                   |
| ------------- | ---------- | -------------------------------------------------------------------------------------------------------- |
| `redirectTo`  | `'/login'` | Where unauthenticated requests are redirected                                                            |
| `publicPaths` | `[]`       | Paths that bypass auth. Supports exact match (`'/login'`) and trailing wildcard (`'/api/public/*'`) only |

## Failure Modes

| Failure                                      | What Actually Happens                                                       | Recovery                                                    |
| -------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Auth service returns 401 on session verify   | `verify()` returns `null` — not an exception                                | Caller redirects to login                                   |
| Auth service returns 5xx on session verify   | Throws `AuthError(status >= 500)`                                           | Middleware re-throws; RSC helpers surface as uncaught error |
| JWKS fetch timeout                           | Throws `JwtVerificationError(retryable=true)`                               | Caller retries with backoff                                 |
| JWT bad signature / expired / wrong issuer   | Throws `JwtVerificationError(retryable=false)`                              | Do not retry; reject token                                  |
| Unknown JWT `kid`                            | JWKS refreshed once (if cooldown elapsed), retried                          | If still unknown, `JwtVerificationError(retryable=false)`   |
| `authz.check` denied                         | Throws `AuthzError("unauthorized")`                                         | Caller returns 403                                          |
| Schema not uploaded                          | Throws `AuthzError("authz_not_enabled")`                                    | Upload schema via `putSchema`                               |
| Unknown resource type / permission in check  | Throws `AuthzError("authz_unknown_resource" \| "authz_unknown_permission")` | Fix schema or caller argument                               |
| `deleteRelation` on nonexistent tuple        | Throws `AuthError(status=404)`                                              | Treat as already-deleted if idempotency is needed           |
| React not available in `createServerHelpers` | `require("react")` throws; `withCache` falls back to identity function      | Functions work correctly; no per-request deduplication      |

## Build

Two entry points compiled to ESM only via `tsdown`:

- `dist/index.mjs` + `.d.mts` — core package (`@beyond.dev/auth`)
- `dist/next/index.mjs` + `.d.mts` — Next.js subpackage (`@beyond.dev/auth/next`)

`next/server` is dynamically imported inside `createAuthMiddleware` at call time rather than statically, so the `next` peer dependency is not bundled into the core package.

TypeScript is configured with `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, and `erasableSyntaxOnly` (no `enum` or `namespace` — only syntax that type-strips cleanly).

## Tests

Tests require a live auth service and Postgres. `vitest.config.ts` points `globalSetup` at `src/__tests__/global-setup.ts`, which:

1. Starts a Postgres 18 testcontainer with the `authz_extension.so` C extension mounted
2. Finds a free port and spawns the `beyond-auth` binary
3. Polls `/healthz` until healthy (60s timeout)
4. Enables JWT issuance via `PATCH /v1/admin/config`
5. Injects `BEYOND_AUTH_URL` and `BEYOND_AUTH_ADMIN_SECRET` into the test environment

`src/__tests__/harness.ts` exposes `signup`, `login`, typed client factories, and `uniqueEmail()` (UUID-based) for test isolation.
