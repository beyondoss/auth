# beyond-auth

Authenticate users, issue tokens, and manage sessions — deployed inside your network, owned by you.

Each project gets its own deployment, its own signing keys, and its own `auth` schema within the project's existing Postgres database. No shared user namespace. Forking a project's database volume forks its auth state automatically — users, sessions, signing keys, all of it.

## What it does

- **Sessions** — opaque bearer tokens validated in one SQL query; JWT exchange opt-in for stateless edge verification
- **Auth methods** — password, magic links, TOTP (2FA with recovery codes), passkeys (WebAuthn/FIDO2), OAuth (GitHub, Google, Apple, Microsoft, generic OIDC)
- **Multi-email** — users can attach and verify multiple email addresses
- **API keys** — server-to-server authentication with `key_` tokens
- **Organizations** — create orgs, manage members and roles, send and accept invitations
- **Authorization** — opt-in Zanzibar-style relation engine; define schemas, write relation tuples, check permissions in one query
- **Stateless** — no in-process state; scale to zero and restart cleanly against the existing DB

## Running

The service runs migrations automatically on startup. To migrate only:

```sh
beyond-auth migrate --database-url "postgres://..."
```

### From source

```sh
mise run build:release
./target/release/beyond-auth serve \
  --database-url "postgres://user:pass@host:5432/dbname" \
  --signing-key-encryption-key "$(openssl rand -base64 32)" \
  --admin-secret "$(openssl rand -hex 32)" \
  --webauthn-rp-id "example.com" \
  --webauthn-rp-origin "https://example.com"
```

## Configuration

| Flag / Env                                                            | Default                 | Description                                                                  |
| --------------------------------------------------------------------- | ----------------------- | ---------------------------------------------------------------------------- |
| `--database-url` / `DATABASE_URL`                                     | —                       | Postgres connection string. The service operates within the `auth` schema.   |
| `--address` / `ADDRESS`                                               | `0.0.0.0:8080`          | Bind address                                                                 |
| `--signing-key-encryption-key` / `SIGNING_KEY_ENCRYPTION_KEY`         | —                       | Base64url-encoded 32-byte AES-256-GCM key for signing key encryption at rest |
| `--signing-key-encryption-key-old` / `SIGNING_KEY_ENCRYPTION_KEY_OLD` | —                       | Comma-separated old KEK values for zero-downtime key rotation                |
| `--admin-secret` / `ADMIN_SECRET`                                     | —                       | Bearer token required for admin endpoints                                    |
| `--webauthn-rp-id` / `WEBAUTHN_RP_ID`                                 | —                       | WebAuthn relying party ID (e.g. `example.com`)                               |
| `--webauthn-rp-origin` / `WEBAUTHN_RP_ORIGIN`                         | —                       | WebAuthn origin (e.g. `https://example.com`)                                 |
| `--public-url` / `PUBLIC_URL`                                         | —                       | Public base URL for OAuth callbacks                                          |
| `--oauth-allowed-redirect-origins` / `OAUTH_ALLOWED_REDIRECT_ORIGINS` | —                       | Comma-separated origins allowed as OAuth redirect targets                    |
| `--authz-cache-size` / `AUTHZ_CACHE_SIZE`                             | `100000`                | Max cached authz check entries                                               |
| `--authz-cache-ttl-secs` / `AUTHZ_CACHE_TTL_SECS`                     | `1800`                  | Authz cache TTL in seconds                                                   |
| `--log-level` / `LOG_LEVEL`                                           | `info`                  | Log verbosity                                                                |
| `--otlp-enabled` / `OTLP_ENABLED`                                     | `false`                 | Enable OpenTelemetry export                                                  |
| `--otlp-endpoint` / `OTLP_ENDPOINT`                                   | `http://localhost:4317` | OTLP collector endpoint                                                      |

Set `ENVIRONMENT=development` for human-readable logs.

### Generating the encryption key

```sh
openssl rand -base64 32
```

This key protects signing key material at rest in Postgres. Keep it out of the database. Loss of this key requires key rotation; compromise of the DB alone is not sufficient to forge JWTs.

### Database setup

The service connects to an existing Postgres database and operates entirely within the `auth` schema. It does not touch other schemas. Run it against your app's existing database, or a dedicated one — either works.

The `auth` schema is part of the public contract. Migrations are additive-only; no column is ever removed or renamed in a way that breaks existing data.

## Token shapes

| Token               | Format                  | Used for                    | Revoke          |
| ------------------- | ----------------------- | --------------------------- | --------------- |
| Session             | `session_{id}_{secret}` | End-user sessions           | Delete row      |
| Refresh             | `rt_{id}_{secret}`      | Long-lived SDK credential   | Soft-delete row |
| API key             | `key_{id}_{secret}`     | Server-to-server            | Soft-delete row |
| Magic link          | `ml_{id}_{secret}`      | Passwordless login          | Expiry          |
| Password reset      | `pwr_{id}_{secret}`     | Password recovery           | Expiry          |
| Email verification  | `ev_{id}_{secret}`      | Email confirmation          | Expiry          |
| Invitation          | `inv_{id}_{secret}`     | Org invitations             | Expiry          |
| JWT (EdDSA, opt-in) | Standard JWT            | Stateless edge verification | Key rotation    |

Wire format: `{prefix}_{uuid_v7_hex}_{32_random_bytes_b64url}`. The DB stores only `SHA-256(secret)` — the raw secret is never persisted.

## OAuth providers

Configure providers via the admin API (`PUT /v1/admin/oauth-providers`): GitHub, Google, Apple, Microsoft, and generic OpenID Connect. Provider credentials are encrypted at rest.

## JWT verification

Projects that opt in to JWT mode publish their public keys at `/v1/jwks.json`. Tokens are signed with Ed25519 (`EdDSA`). Verify against the JWKS:

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

const JWKS = createRemoteJWKSet(
  new URL("https://auth.yourproject.beyond.dev/v1/jwks.json"),
);

const { payload } = await jwtVerify(token, JWKS);
```

JWKS responses are cache-controlled (`public, max-age=3600`). Key rotation is additive — old keys remain in the set until all valid tokens issued under them have expired.

## Authorization (opt-in)

The authz engine is off unless you define a schema. No rows in `authz_relations`, no CPU cost.

Define resource types, roles, and permissions as JSON:

```json
{
  "version": 1,
  "resources": [
    {
      "name": "document",
      "roles": ["owner", "viewer"],
      "permissions": {
        "edit": ["owner"],
        "view": ["owner", "viewer"]
      }
    }
  ]
}
```

Check a single permission (defaults to the current session user):

```
GET /v1/authz/decisions?resource_type=document&resource_id=123&permission=edit
GET /v1/authz/decisions?resource_type=document&resource_id=123&permission=edit&user=456
```

Batch-check multiple permissions in one request:

```sh
POST /v1/authz/checks
{
  "checks": [
    { "resource_type": "document", "resource_id": "123", "permission": "edit" },
    { "resource_type": "document", "resource_id": "123", "permission": "view", "user": "789" }
  ]
}
```

Other authz endpoints: `POST/DELETE/PATCH /v1/authz/relations` (write tuples), `GET/PUT /v1/authz/schema`, `GET /v1/authz/subjects`, `GET /v1/authz/objects`, `GET /v1/authz/traces` (decision audit).

## TypeScript SDK

```sh
npm install @beyond.dev/auth
```

```ts
import { createAuthzClient, createSessionVerifier } from "@beyond.dev/auth";

// Verify an opaque session token
const verifier = createSessionVerifier({
  baseUrl: "https://auth.yourproject.beyond.dev",
});
const session = await verifier.verify(bearerToken); // null if invalid/expired

// Check a permission
const authz = createAuthzClient({
  baseUrl: "https://auth.yourproject.beyond.dev",
  adminSecret: process.env.AUTH_ADMIN_SECRET!,
});
const allowed = await authz.check({
  resource: "document",
  id: "123",
  permission: "edit",
  subject: session?.userId,
});
```

Next.js integration ships in `@beyond.dev/auth/next`: middleware, RSC helpers, and cookie utilities.

## Development

```sh
mise run format   # format all source files
```

Integration tests use [testcontainers](https://github.com/testcontainers/testcontainers-rs) and spin up a real Postgres instance.

## Self-hosting and portability

To move off Beyond (or any managed host) to your own infrastructure:

1. Export your database: `pg_dump --schema=auth -f auth.sql "$DATABASE_URL"`
2. Stand up `beyond-auth` anywhere that can reach a Postgres instance.
3. `pg_restore` the auth schema into your target database.
4. Set `DATABASE_URL`, `SIGNING_KEY_ENCRYPTION_KEY`, `ADMIN_SECRET`, and WebAuthn config, then start the service.

Existing sessions and JWTs remain valid. The same binary, the same schema, the same keys.

## License

AGPLv3. Self-host for any purpose, including commercial use. If you offer this software as a service, you must release your modifications under AGPLv3.
