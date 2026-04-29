# Auth Service Architecture

Takes an HTTP request with a bearer token or credentials, validates or creates auth state in PostgreSQL, and returns a structured response containing the authenticated user, org, session, and (optionally) a signed JWT. Each deployment serves exactly one project's users inside a private network.

## Data Flow

### Session Login (Password)

```
POST /v1/sessions
        │
        ▼
  [middleware]
  extract bearer     (none required for login)
        │
        ▼
  routes/sessions.rs
  parse LoginRequest
        │
        ├─── email/password ──────────────────────────────────────┐
        │                                                         ▼
        │                                              identities table lookup
        │                                              argon2id.verify(pw, hash)
        │                                                         │
        │                                              ┌──── TOTP enrolled? ──┐
        │                                              │                      │
        │                                              │ no                   │ yes
        │                                              ▼                      ▼
        │                                        create session          create step-up
        │                                        + token row             one-time token
        │                                              │                      │
        │                                              ▼                      ▼
        │                                        AuthResponse           StepUpResponse
        │                                        201 Created            200 OK
        │
        ├─── magic_link ──► consume one_time_tokens row (DELETE…RETURNING)
        │                   create session + token ──► AuthResponse 201
        │
        ├─── refresh_token ► verify family, detect replay, rotate ──► TokenResponse 200
        │
        └─── oauth callback ► exchange code, fetch profile, upsert identity ──► AuthResponse 201
```

### Every Authenticated Request

```
Request
  │
  ▼
SetRequestIdLayer      adds X-Request-ID (UUIDv4)
TraceLayer             structured span per request
TimeoutLayer           30-second hard deadline
CatchPanicLayer        converts panics to 500
  │
  ▼
middleware::auth (require_auth)
  parse "Bearer <prefix>_<uuid>_<secret_b64url>"
  SHA-256(secret_bytes) ──► bundled CTE query
  ┌───────────────────────────────────────────────────────────────┐
  │  WITH valid_token AS (                                        │
  │    SELECT id FROM auth.tokens                                 │
  │    WHERE id = $1 AND secret = digest($2,'sha256')             │
  │      AND expires_at > now()                                   │
  │  ), update_attempt AS (                                       │
  │    UPDATE auth.tokens SET last_used_at = now()                │
  │    WHERE id IN (SELECT id FROM valid_token)                   │
  │      AND (last_used_at IS NULL                                │
  │           OR last_used_at < now() - '1 minute'::interval)     │
  │  )                                                            │
  │  SELECT u.*, o.*, e.*, s.id AS session_id, t.id AS token_id   │
  │  FROM auth.sessions s                                         │
  │  JOIN auth.tokens t ON t.id = s.token_id                      │
  │  JOIN auth.users u  ON u.id = s.user_id                       │
  │  JOIN auth.orgs  o  ON o.id = u.primary_org_id                │
  │  JOIN auth.emails e ON e.id = u.primary_email_id              │
  │  WHERE s.token_id IN (SELECT id FROM valid_token)             │
  └───────────────────────────────────────────────────────────────┘
  ──► AuthContext injected into request extensions
  │
  ▼
Route handler
  │
  ▼
Response (JSON)
```

**Error paths:**

```
Token absent        ──► 401 Unauthorized
Token invalid/expired──► 401 Unauthorized
Token valid, wrong role (admin endpoint) ──► 403 Forbidden
DB unavailable      ──► 503 (pool timeout) or 500
Handler panic       ──► 500 (caught by CatchPanicLayer)
```

### JWT Issuance (opt-in)

```
POST /v1/tokens { grant_type: "access_token" }
  │
  ▼
require_auth (session must be valid)
  │
  ▼
load active signing_key row ──► AES-256-GCM decrypt with KEK ──► Ed25519 keypair
  │
  ▼
build claims: sub, iss, aud, iat, nbf, exp, jti [+ extra_claims]
sign: base64url(header).base64url(claims) ──Ed25519──► signature
  │
  ▼
200 OK { access_token: "<jwt>", expires_in, token_type: "Bearer" }
```

### Authorization Check

```
GET /v1/authz/decisions?object=doc:1&permission=write&subject=user:42
  │
  ▼
require_auth
  │
  ▼
authz::cache lookup (LRU, 100k entries, 30 min TTL, version-tagged)
  │
  ├── cache hit ──► allow/deny immediately
  │
  └── cache miss
        │
        ▼
      authz::schema::compile(schema, resource_type, permission)
      ──► Vec<AuthzCheckCall>
            │
            ├── SingleHop:  SELECT auth.authz_check(subject, relations[], obj_type, obj_id)
            │                       (PostgreSQL extension: indexed EXISTS + BFS for subject-sets)
            │
            └── MultiHop:  SELECT auth.authz_check_path_batch(subjects[], relations[][], ...)
                                   (PostgreSQL extension: BFS across resource hierarchy)
        │
        ▼
      result cached ──► allow/deny
```

## Concepts & Terminology

| Term               | What It Controls                                                                                                               | NOT                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| **Token**          | A credential row in `auth.tokens`; identified by UUID, validated by SHA-256(secret)                                            | Not a JWT — the opaque bearer is what creates/revokes sessions          |
| **Session**        | A join between a token and a user; carries IP, user-agent, created/used timestamps                                             | Not a cookie or server-side state blob                                  |
| **AuthContext**    | The struct injected by middleware after validation; contains user, email, org, session_id                                      | Not a permission decision — it proves identity only                     |
| **Signing Key**    | An Ed25519 keypair stored encrypted in `auth.signing_keys`; used for JWT issuance                                              | Not used to sign session tokens (those are opaque)                      |
| **KEK**            | The AES-256-GCM key-encryption-key from env; wraps signing key material at rest                                                | Not a user-facing concept; never stored in the DB                       |
| **Identity**       | A row in `auth.identities` binding (provider, subject) to a user; holds the argon2 hash for passwords                          | Not the same as a session; one user can have multiple identities        |
| **One-time Token** | Rows in `auth.one_time_tokens` consumed atomically via DELETE…RETURNING; used for magic links, password reset, email verify    | Not a session token — cannot be reused                                  |
| **Authz Relation** | A tuple (object_id, object_type, relation, subject_id) written to `auth.authz_relations`; the raw data the BFS walks           | Not a role assignment in the RBAC sense — it's a graph edge             |
| **Authz Schema**   | A JSON document declaring resource types, roles, and permission→role mappings; compiled to `Vec<AuthzCheckCall>` at query time | Not enforced by the DB — enforced by the extension's BFS                |
| **Step-up Token**  | A short-lived (5 min) `impersonate`-prefixed one-time token returned after password verification when TOTP is enrolled         | Not a session; must be exchanged with a TOTP code for an actual session |
| **Refresh Token**  | A `rt_`-prefixed long-lived token in `auth.refresh_tokens`; rotated on use; family-based replay detection                      | Not the same as a session token — only the SDK uses these               |
| **Personal Org**   | An org created 1:1 with the user on signup; always present, never deletable                                                    | Not a team org — team orgs have members and invitations                 |

## Core Mechanisms

### Token Format and Validation

Every credential follows the same wire format:

```
<prefix>_<uuid7-hex>_<secret-base64url-no-padding>
```

`secret` is 32 random bytes from `OsRng`. The database stores `SHA-256(secret_bytes)` as bytea — the plaintext never persists. Validation is a single indexed lookup on `(id, secret)` with a `WHERE expires_at > now()` guard.

UUID v7 provides monotonic ordering, so the BRIN index on `expires_at` and the B-tree primary key stay efficient as rows age.

| Prefix        | Lifetime               | Table                   | Notes                          |
| ------------- | ---------------------- | ----------------------- | ------------------------------ |
| `session`     | 30 days (configurable) | tokens + sessions       | Main auth credential           |
| `rt`          | 30 days (configurable) | tokens + refresh_tokens | SDK long-lived; rotates on use |
| `key`         | ∞ (manual revoke)      | tokens + keys           | Named API keys                 |
| `ml`          | 15 min                 | one_time_tokens         | Magic link                     |
| `pwr`         | 60 min                 | one_time_tokens         | Password reset                 |
| `ev`          | 24 h                   | one_time_tokens         | Email verification             |
| `ec`          | 24 h                   | one_time_tokens         | Email change                   |
| `inv`         | 7 days                 | org_invitations         | Invitation link                |
| `impersonate` | 5 min                  | one_time_tokens         | MFA step-up (internal only)    |

### Session Validation: One Round-Trip

`src/sessions.rs` validates and touches a session in a single bundled CTE. The `UPDATE` is skipped if `last_used_at` is less than 1 minute old, avoiding write amplification under load. The CTE returns the full `AuthContext` — user, primary email, primary org — so no second query is needed.

### Password Hashing

Argon2id with OWASP 2024 parameters: `m=19456` (19 MiB), `t=2`, `p=1`, 32-byte output. The PHC string is stored in `identities.secret` as bytea. `src/passwords.rs` also checks against a compiled common-password list baked into the binary at build time.

### Signing Key Lifecycle

At startup (`src/signing_keys.rs`):

1. Try to load the active key from `auth.signing_keys`.
2. If none exists, generate a new Ed25519 keypair and insert with `ON CONFLICT DO NOTHING` — concurrent starters converge to the same key.
3. Decrypt with KEK using AES-256-GCM; AAD is the key ID (prevents ciphertext swapping).
4. If decryption fails, retry with `SIGNING_KEY_ENCRYPTION_KEY_OLD` values; on success, re-encrypt and update the row (zero-downtime KEK rotation).

Old keys are kept in `auth.signing_keys` with `status='inactive'` and served at `/v1/jwks.json` until all JWTs they signed expire.

### Refresh Token Rotation and Replay Detection

`src/refresh_tokens.rs` assigns each refresh token to a `family_id`. On rotation, the old token is consumed and a new one is issued in the same family. If a token that has already been rotated is presented again, the entire family is revoked — any token in the family from that point forward is invalid. This detects theft where both the attacker and the legitimate client attempt to use the same token.

### Authorization: Schema → Calls → Extension

`src/authz/schema.rs` compiles a resource's permission into a `Vec<AuthzCheckCall>`:

- **`SingleHop`** — one `auth.authz_check()` call; handles direct role grants and subject-set membership.
- **`MultiHop`** — one `auth.authz_check_path_batch()` call; traverses resource hierarchies (e.g., document inside folder).

`src/authz/cache.rs` wraps results in an LRU keyed by `(subject, resource_type, resource_id, permission, schema_version)`. Writes to `auth.authz_relations` increment a version counter; stale cache entries miss on the version tag and fall through to the extension.

The PostgreSQL extension (`authz_extension/`) runs BFS inside the database process: one indexed EXISTS for direct grants, additional passes for subject-set chains. See `authz_extension/ARCHITECTURE.md` for the extension's own internals.

## State Machines

### User Account

```
(new) ──signup──► active ──admin_delete──► deleted
                    │
                    └──► email unverified (initial)
                               │
                         verify token ──► email verified
```

### MFA Step-Up (TOTP)

```
POST /v1/sessions (password OK, TOTP enrolled)
  │
  ▼
step_up_token issued (5 min TTL)
  │
  ├── POST /v1/sessions { step_up_token, totp_code }
  │     │
  │     ├── code valid ──► session created ──► AuthResponse 201
  │     └── code invalid ──► 401
  │
  └── token expires ──► 401 TokenExpired
```

### Session

```
created ──► active (last_used_at updated on each request, debounced 1 min)
               │
               ├── expires_at reached ──► invalid (token GC deletes async)
               ├── DELETE /v1/sessions/{id} ──► deleted immediately
               └── idle_timeout exceeded ──► invalid (checked at validation time)
```

### Signing Key

```
generating ──insert ON CONFLICT DO NOTHING──► active
                                                 │
                                          admin initiates rotation
                                                 │
                                                 ▼
                                             inactive  (served in JWKS until old JWTs expire)
```

### OAuth Flow

```
GET /v1/oauth/{provider}?redirect_uri=...&code_challenge=...
  │
  ▼
PKCE verifier stored in state token (signed HS256, 10 min TTL)
  │
  ▼
redirect to provider ──► user authenticates
  │
  ▼
GET /v1/oauth/{provider}/callback?code=...&state=...
  │
  ├── state valid, PKCE matches ──► exchange code ──► fetch profile
  │                                                         │
  │                                          ┌── identity exists? ──┐
  │                                          │ yes                  │ no
  │                                          ▼                      ▼
  │                                    link to user            create user
  │                                          │                 + identity
  │                                          └──────┬──────────┘
  │                                                 ▼
  │                                          create session
  │                                          HTML response (postMessage to opener)
  │
  └── state invalid / PKCE mismatch ──► 400
```

## Why It Behaves This Way

### Why sessions are opaque tokens, not JWTs

Session validation requires a DB lookup regardless — we need `last_used_at`, idle timeout, and revocation. Since the DB is always consulted, there is no latency benefit to a self-contained JWT. Opaque tokens give us instant revocation (DELETE the row) without a blocklist. JWTs are offered as a separate, opt-in `POST /v1/tokens` endpoint for callers that need stateless edge verification.

### Why tokens are SHA-256 hashed, not stored plaintext

The secret is only needed to validate a presented token. Storing the hash means a read of the `auth.tokens` table reveals no usable credentials — an attacker with DB read access cannot impersonate any session. SHA-256 is appropriate here (not Argon2) because tokens are already 32 random bytes; there is no dictionary-attack surface.

### Why session validation uses a single bundled CTE

The CTE combines the token lookup, the `last_used_at` update, and the full user/org/email join into one round-trip. Separating them would require two serial queries on every authenticated request, doubling latency at the most common hot path.

### Why `last_used_at` is debounced to 1 minute

Every request in a session would otherwise cause a write. At even modest traffic, this becomes the dominant write load on the `auth.tokens` table. A 1-minute debounce cuts writes by ~60× while keeping session freshness accurate enough for idle-timeout enforcement.

### Why the authz extension runs inside PostgreSQL

Authorization checks need to walk the relation graph, which lives in `auth.authz_relations`. Moving that traversal into the database eliminates the round-trips that a service-side BFS would require (one query per hop). The extension's BFS is single-process, ACID-consistent with the relation writes, and eliminates serialization overhead.

### Why refresh tokens use family-based replay detection instead of per-token revocation

Per-token revocation only catches the attacker if the legitimate client rotates first. Family revocation catches theft regardless of order: if any token in a family is used after it has been rotated, every token in that family becomes invalid. This closes the window where a stolen token is used before the victim rotates.

### Why one-time tokens use DELETE…RETURNING instead of a status flag

`DELETE…RETURNING` is an atomic consume: if two concurrent requests present the same token, exactly one DELETE succeeds and returns a row; the other returns empty and is rejected. A status flag approach would require a `SELECT` then `UPDATE`, introducing a race window without an explicit lock.

## Trust Boundaries

**What the service verifies:**

- Bearer token format, UUID lookup, SHA-256(secret) match, `expires_at > now()`
- Argon2id password hash match
- Ed25519 JWT signature on inbound JWTs (not issued by us — only on `/v1/sessions` magic-link flow)
- OAuth state token HMAC (HS256) and PKCE code verifier
- WebAuthn credential signature and challenge binding
- TOTP code window (±1 step, 30-second intervals)
- Admin secret on `/v1/admin/*` endpoints

**What passes through unchecked:**

- Any traffic before it reaches the process (TLS termination, DDoS mitigation, rate limiting — operator's responsibility)
- The content of `extra_claims` in JWT issuance requests (passed through verbatim into the signed token)
- User-supplied `redirect_uri` beyond the configured `OAUTH_ALLOWED_REDIRECT_ORIGINS` allowlist (if the env var is unset, all origins are accepted)
- Authorization decisions for application resources — authz checks are opt-in via the `/v1/authz/*` endpoints; nothing enforces them on other routes

**Why these boundaries are where they are:**

This service is deployed inside a private network behind the operator's own proxy. The operator's infrastructure is the right place for IP filtering, rate limiting, and TLS. We trust all traffic that reaches our port.

## Configuration

**Process environment:**

| Variable                         | Default                  | What It Controls                                                                                 |
| -------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------ |
| `DATABASE_URL`                   | —                        | Postgres connection string; `search_path` is set to `auth, public`                               |
| `ADDRESS`                        | `0.0.0.0:8080`           | HTTP bind address                                                                                |
| `SIGNING_KEY_ENCRYPTION_KEY`     | —                        | Base64url-encoded 32-byte AES-256-GCM KEK; wraps Ed25519 private keys at rest                    |
| `SIGNING_KEY_ENCRYPTION_KEY_OLD` | (empty)                  | Comma-separated old KEKs; decryption fallback during rotation, triggers re-encryption on success |
| `ADMIN_SECRET`                   | —                        | Bearer token that gates `/v1/admin/*` routes                                                     |
| `WEBAUTHN_RP_ID`                 | —                        | Relying party domain (e.g., `example.com`); must match the origin                                |
| `WEBAUTHN_RP_ORIGIN`             | —                        | Relying party origin (e.g., `https://example.com`)                                               |
| `PUBLIC_URL`                     | derived from Host header | Base URL prepended to OAuth callback paths                                                       |
| `OAUTH_ALLOWED_REDIRECT_ORIGINS` | (all allowed)            | Comma-separated allowlist; empty = accept any origin                                             |
| `LOG_LEVEL`                      | `info`                   | Tracing filter: `debug`, `info`, `warn`, `error`                                                 |
| `OTLP_ENABLED`                   | `false`                  | Enables OpenTelemetry OTLP export                                                                |
| `OTLP_ENDPOINT`                  | `http://localhost:4317`  | OTLP collector gRPC endpoint                                                                     |
| `AUTHZ_CACHE_SIZE`               | `100_000`                | Max entries in the in-process authz LRU cache                                                    |
| `AUTHZ_CACHE_TTL_SECS`           | `1800`                   | Per-entry TTL before a cache miss re-queries the extension                                       |

**Runtime configuration (stored in `auth.app_config`, writable via `PATCH /v1/admin/config`):**

| Setting                        | Default      | What It Controls                                                                            |
| ------------------------------ | ------------ | ------------------------------------------------------------------------------------------- |
| `session_ttl_seconds`          | 30 days      | Hard expiry on session tokens                                                               |
| `session_idle_timeout_seconds` | null         | If set, sessions expire after this many seconds of inactivity                               |
| `access_token_ttl_seconds`     | 900 (15 min) | JWT `exp` claim                                                                             |
| `refresh_token_ttl_seconds`    | 30 days      | Refresh token hard expiry                                                                   |
| `jwt_enabled`                  | false        | Gates `POST /v1/tokens`; returns 403 if false                                               |
| `issuer_url`                   | null         | JWT `iss` claim                                                                             |
| `jwt_audience`                 | null         | JWT `aud` claim                                                                             |
| `oauth_email_link`             | false        | When true, OAuth login with a known email links the identity instead of creating a new user |

## Failure Modes

| Failure                               | What Actually Happens                                                                                 | Recovery                                                                     |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Postgres unavailable at startup       | Process exits with error; no server starts                                                            | Restart after DB recovers; migrations re-run idempotently                    |
| Postgres unavailable at runtime       | Pool exhausted; requests fail with 503 after pool timeout                                             | Automatic reconnect when DB recovers                                         |
| KEK missing or wrong                  | Startup fails: cannot decrypt signing key                                                             | Set correct `SIGNING_KEY_ENCRYPTION_KEY`; use `_OLD` for rotation            |
| Concurrent signup with same email     | One INSERT succeeds; the other gets a 409 Conflict (unique constraint on `auth.emails`)               | Client retries login                                                         |
| Concurrent one-time token consume     | One `DELETE…RETURNING` returns a row; the other returns empty and gets 401                            | Legitimate client re-requests a new token                                    |
| Refresh token replay (theft scenario) | Family is revoked; all tokens in the family become invalid immediately                                | User must re-authenticate                                                    |
| Token GC crash                        | Expired rows stay in the DB until GC restarts; validation still rejects them via `expires_at > now()` | GC task restarts on next process start                                       |
| Authz extension unavailable           | All `authz_check` calls fail; authz endpoints return 500                                              | Re-install extension; no data loss (relations are in `auth.authz_relations`) |
| Authz cache stale                     | Version counter mismatch causes cache miss; query falls through to extension                          | Automatic; no operator action needed                                         |
| WebAuthn RP origin mismatch           | Credential verification fails; passkey authentication returns 401                                     | Fix `WEBAUTHN_RP_ORIGIN` env var and restart                                 |
