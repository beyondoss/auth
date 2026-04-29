# beyond-auth

Per-project authentication and authorization service for apps running on [Beyond](https://beyond.dev). AGPLv3. Self-hostable.

Each project gets its own deployment, its own signing keys, and its own `auth` schema within the project's existing app database. No shared user namespace. No shared blast radius. Forking a project's database volume forks its auth state automatically — users, sessions, signing keys, all of it.

## How it works

**Sessions are opaque by default.** Validate, update `last_used_at`, extract subject, and optionally check permissions — one SQL query, one round-trip. JWT exchange is opt-in, for projects that need stateless verification at the edge.

**Auth state lives in your database.** The service is stateless. Every request consults the `auth` schema in the project's app database (Postgres). Scale to zero; a fresh instance can serve traffic against the existing DB immediately.

**Take it with you.** `pg_dump --schema=auth` your project DB, restore it somewhere else, point the service at it. Existing sessions and JWTs remain valid — you have the signing keys.

## Token shapes

| Token                                   | Used for                                    | Revoke          |
| --------------------------------------- | ------------------------------------------- | --------------- |
| `session_{id}_{secret}`                 | End-user sessions (default)                 | Delete row      |
| `refresh_{id}_{secret}`                 | Long-lived SDK credential                   | Soft-delete row |
| `pk_{id}_{secret}` / `sk_{id}_{secret}` | Server-to-server API keys                   | Soft-delete row |
| Signed stateless                        | Magic links, password reset, 2FA ceremonies | Expiry          |
| JWT (EdDSA, opt-in)                     | Stateless edge verification                 | Key rotation    |

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
  --signing-key-encryption-key "$(openssl rand -base64 32)"
```

## Configuration

| Flag / Env                                                    | Default                 | Description                                                                  |
| ------------------------------------------------------------- | ----------------------- | ---------------------------------------------------------------------------- |
| `--database-url` / `DATABASE_URL`                             | —                       | Postgres connection string. The service operates within the `auth` schema.   |
| `--address` / `ADDRESS`                                       | `0.0.0.0:8080`          | Bind address                                                                 |
| `--signing-key-encryption-key` / `SIGNING_KEY_ENCRYPTION_KEY` | —                       | Base64url-encoded 32-byte AES-256-GCM key for signing key encryption at rest |
| `--log-level` / `LOG_LEVEL`                                   | `info`                  | Log verbosity                                                                |
| `--otlp-enabled` / `OTLP_ENABLED`                             | `false`                 | Enable OpenTelemetry export                                                  |
| `--otlp-endpoint` / `OTLP_ENDPOINT`                           | `http://localhost:4317` | OTLP collector endpoint                                                      |

Set `ENVIRONMENT=development` for human-readable logs.

### Generating the encryption key

```sh
openssl rand -base64 32
```

This key protects signing key material at rest in Postgres. Keep it out of the database. Loss of this key requires key rotation; compromise of the DB alone is not sufficient to forge JWTs.

### Database setup

The service connects to an existing Postgres database and operates entirely within the `auth` schema. It does not touch other schemas. Run it against your app's existing database, or a dedicated one — either works.

The `auth` schema is part of the public contract. Migrations are additive-only; no column is ever removed or renamed in a way that breaks existing data.

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

The authz engine is off unless you define a schema. No `relation_tuple` rows, no CPU cost.

Define object types, roles, and permissions as JSON:

```json
{
  "types": {
    "document": {
      "relations": {
        "owner": { "subject": "user" },
        "viewer": { "subject": "user" }
      },
      "permissions": {
        "edit": { "union": ["owner"] },
        "view": { "union": ["owner", "viewer"] }
      }
    }
  }
}
```

Check a permission:

```sh
POST /v1/authz/check
{
  "object": "document:123",
  "permission": "edit",
  "subject": "user:456"
}
```

## Development

```sh
mise run format   # format all source files
```

Integration tests use [testcontainers](https://github.com/testcontainers/testcontainers-rs) and spin up a real Postgres instance.

## Self-hosting and portability

To move off Beyond (or any managed host) to your own infrastructure:

1. Export your database: `pg_dump --schema=auth -f auth.sql "$DATABASE_URL"`
2. Export your signing keys via the Beyond control plane or directly from `auth.signing_key`.
3. Stand up `beyond-auth` anywhere that can reach a Postgres instance.
4. `pg_restore` the auth schema into your target database.
5. Set `DATABASE_URL` and `SIGNING_KEY_ENCRYPTION_KEY`, start the service.

Existing sessions and JWTs remain valid. The same binary, the same schema, the same keys.

## License

AGPLv3. Self-host for any purpose, including commercial use. If you offer this software as a service, you must release your modifications under AGPLv3.
