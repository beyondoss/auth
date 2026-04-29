# @beyond.dev/auth

Verify sessions, validate JWTs, and enforce authorization — from TypeScript.

## Install

```sh
npm install @beyond.dev/auth
```

## Quick Start

```ts
import { createSessionVerifier } from "@beyond.dev/auth";

const verifier = createSessionVerifier({ baseUrl: "http://auth:8080" });

const session = await verifier.verify(token);
if (!session) {
  // token invalid or expired
}
// session.userId, session.metadata, ...
```

## What It Does

- **Session verification** — validate opaque session tokens against the auth service
- **JWT verification** — verify access tokens with automatic JWKS caching and `kid`-based refresh
- **Authorization** — Zanzibar-style relation checks, permission lookups, and auditing
- **HTTP client** — fully typed REST client for managing sessions, keys, and users directly
- **Next.js** — middleware for route protection, RSC helpers, and cookie utilities

## Session Verification

```ts
import { createSessionVerifier, getSessionToken } from "@beyond.dev/auth";

const verifier = createSessionVerifier({ baseUrl: "http://auth:8080" });

// From a request
const token = getSessionToken(request); // checks Authorization header and cookies
const session = await verifier.verify(token ?? "");
```

`verify()` returns `SessionContext | null`. Null means invalid, expired, or revoked.

## JWT Verification

```ts
import { createJwtVerifier } from "@beyond.dev/auth";

const jwtVerifier = createJwtVerifier({
  jwksUri: "https://auth.example.com/v1/jwks.json",
  issuer: "https://auth.example.com",
  audience: "your-app", // optional
  clockSkewSeconds: 30, // optional, default: 30
});

const claims = await jwtVerifier.verify(accessToken);
// claims.sub, claims.exp, ...
```

JWKS keys cache for one hour. Unknown `kid` values trigger an immediate refresh.

## Authorization

```ts
import { createAuthzClient, defineSchema } from "@beyond.dev/auth";

const authz = createAuthzClient({
  baseUrl: "http://auth:8080",
  adminSecret: process.env.AUTH_ADMIN_SECRET!,
  schema: defineSchema({
    version: 1,
    resources: [{
      name: "document",
      roles: ["owner", "editor", "viewer"],
      permissions: {
        delete: ["owner"],
        write: ["owner", "editor"],
        read: ["owner", "editor", "viewer"],
      },
      roleHierarchy: [["owner", "editor"], ["editor", "viewer"]],
    }],
  }),
});

// Check a permission — throws AuthzError if denied
await authz.check({
  resource: "document",
  id: documentId,
  permission: "write",
  subject: userId,
});

// Check against a session token in one round-trip
await authz.checkSession({
  token,
  resource: "document",
  id: documentId,
  permission: "write",
});

// Who has access?
const subjects = await authz.expand({
  resource: "document",
  id: documentId,
  relation: "editor",
});

// What can this user access?
const docs = await authz.lookup({
  token,
  resource: "document",
  permission: "read",
  limit: 50,
});

// Why was access allowed or denied?
const trace = await authz.trace({
  resource: "document",
  id: documentId,
  permission: "write",
  subject: userId,
});
```

`defineSchema` enables strict typing — resource types, permission names, and relation names are all checked at compile time. Literal types are inferred automatically; no `as const` needed.

Alternatively, import a JSON schema file for the same strict typing automatically:

```ts
import schema from "./authz-schema.json"; // TypeScript infers literals from JSON imports

const authz = createAuthzClient({ baseUrl, adminSecret, schema });
```

**Manage relations:**

```ts
await authz.createRelation({
  resource: "document",
  id: documentId,
  relation: "editor",
  subject: userId,
});

await authz.deleteRelation({
  resource: "document",
  id: documentId,
  relation: "editor",
  subject: userId,
});
```

**Schema:**

```ts
await authz.putSchema({
  version: 1,
  resources: [{
    name: "document",
    roles: ["owner", "editor", "viewer"],
    permissions: {
      delete: ["owner"],
      write: ["owner", "editor"],
      read: ["owner", "editor", "viewer"],
    },
    role_hierarchy: [
      { superior: "owner", inferior: "editor" },
      { superior: "editor", inferior: "viewer" },
    ],
  }],
});
```

## HTTP Client

```ts
import { createAdminClient, createAuthClient } from "@beyond.dev/auth";

// Admin operations (uses admin secret)
const admin = createAdminClient({ baseUrl: "http://auth:8080" });

// User-scoped operations (uses session token)
const client = createAuthClient({
  baseUrl: "http://auth:8080",
  token: sessionToken,
});
```

Both are fully typed wrappers over the auth service REST API.

## Next.js

```ts
// middleware.ts
import { createSessionVerifier } from "@beyond.dev/auth";
import { createAuthMiddleware } from "@beyond.dev/auth/next";

const verifier = createSessionVerifier({ baseUrl: "http://auth:8080" });

export const middleware = createAuthMiddleware(verifier, {
  publicPaths: ["/login", "/api/public/*"],
  redirectTo: "/login",
});
```

```ts
// app/page.tsx (RSC)
import { createServerHelpers } from "@beyond.dev/auth/next";
import { cookies } from "next/headers";

const { getSession, getMe } = createServerHelpers(verifier, adminClient);

export default async function Page() {
  const me = await getMe(await cookies());
  // me.id, me.email, ...
}
```

**Cookies:**

```ts
import { clearCookieAttrs, sessionCookieAttrs } from "@beyond.dev/auth/next";

// After login
response.cookies.set(sessionCookieAttrs(token, { maxAge: 86400 }));

// After logout
response.cookies.set(clearCookieAttrs());
```

## Errors

| Class                  | When                                              |
| ---------------------- | ------------------------------------------------- |
| `AuthServiceError`     | Auth service returned an error response           |
| `AuthzError`           | Authorization check denied or authz service error |
| `JwtVerificationError` | JWT invalid, expired, or JWKS fetch failed        |

`JwtVerificationError` includes a `retryable` boolean — JWKS network failures are retryable; signature failures are not.
