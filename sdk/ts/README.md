# @beyond.dev/auth

Authenticate users, verify sessions, and enforce authorization — from TypeScript.

## Install

```sh
npm install @beyond.dev/auth
```

## Quick Start

```ts
import {
  createAuthFlowClient,
  createSessionVerifier,
  getSessionToken,
} from "@beyond.dev/auth";
import { sessionCookieAttrs } from "@beyond.dev/auth";

const flows = createAuthFlowClient({ baseUrl: "http://auth:8080" });
const verifier = createSessionVerifier({ baseUrl: "http://auth:8080" });

// Sign in
const result = await flows.signIn({ grantType: "password", email, password });
// result.session.token — store in a cookie, return to the client

// On subsequent requests
const token = getSessionToken(request); // checks cookies and Authorization header
const session = await verifier.verify(token ?? "");
if (!session) {
  // token invalid, expired, or revoked
}
// session.userId, session.metadata, ...
```

## What It Does

- **Auth flows** — sign up, sign in, passkeys, magic links, password reset, MFA, sign out
- **Session verification** — validate opaque session tokens against the auth service
- **JWT verification** — verify access tokens with automatic JWKS caching and `kid`-based refresh
- **Authorization** — Zanzibar-style relation checks, permission lookups, and auditing
- **HTTP client** — fully typed REST client for managing sessions, keys, and users directly
- **Next.js** — middleware for route protection, RSC helpers, and cookie utilities

## Auth Flows

`createAuthFlowClient` handles everything related to getting users in and out of your application. Create it once at startup and reuse it across requests.

```ts
import { createAuthFlowClient } from "@beyond.dev/auth";

const flows = createAuthFlowClient({ baseUrl: "http://auth:8080" });
```

**Sign up:**

```ts
const { session } = await flows.signUp({ email, password });
// session.token — store in a cookie
```

**Sign in with password:**

```ts
const result = await flows.signIn({ grantType: "password", email, password });

if ("stepUpToken" in result) {
  // User has TOTP enrolled — redirect to /verify-totp and pass result.stepUpToken
} else {
  // result.session.token
}
```

**Complete a TOTP challenge:**

```ts
const { session } = await flows.completeTotpStepUp(stepUpToken, totpCode);
// or, with a recovery code:
const { session } = await flows.completeTotpRecovery(stepUpToken, recoveryCode);
```

**Magic link:**

```ts
// Step 1: send the link
await flows.requestMagicLink(email);

// Step 2: when the user clicks the link and lands with ?token=…
const { session } = await flows.signIn({ grantType: "magic_link", token });
```

**Password reset:**

```ts
// Step 1: send the reset link
await flows.requestPasswordReset(email);

// Step 2: when the user submits the reset form
const { session } = await flows.signIn({
  grantType: "password_reset",
  token,
  newPassword,
});
```

**Passkeys:**

```ts
// Step 1: get WebAuthn options
const { options, stateToken } = await flows.beginPasskeyAuth();

// Step 2: get credential from the browser (navigator.credentials.get)
const { session } = await flows.finishPasskeyAuth(stateToken, credential);
```

**Sign out:**

```ts
await flows.signOut(sessionToken);
// clear the session cookie on the response
```

**Sign out all sessions:**

```ts
await flows.signOutAll(sessionToken); // revokes all sessions including current
await flows.signOutAll(sessionToken, { excludeCurrent: true }); // keep current session
```

**Issue a JWT from a session:**

```ts
const { token } = await flows.issueToken(sessionToken, { audience: "my-api" });
```

## Session Verification

```ts
import { createSessionVerifier, getSessionToken } from "@beyond.dev/auth";

const verifier = createSessionVerifier({ baseUrl: "http://auth:8080" });

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

**Session verifier vs JWT verifier:**

|                          | Session verifier            | JWT verifier                                       |
| ------------------------ | --------------------------- | -------------------------------------------------- |
| Round-trip per request   | Yes                         | No (cache hit)                                     |
| Detects revocation       | Yes                         | No — JWT valid until expiry                        |
| Requires auth service up | Always                      | Only on cache miss                                 |
| Use when                 | Default; revocation matters | High request volume; short-lived tokens acceptable |

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
      roleInheritance: { owner: ["editor"], editor: ["viewer"] },
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
    role_inheritance: { owner: ["editor"], editor: ["viewer"] },
  }],
});
```

## HTTP Client

```ts
import { createAdminClient, createAuthClient } from "@beyond.dev/auth";

// Admin operations — create once at startup with your admin secret
const admin = createAdminClient({
  url: "http://auth:8080",
  secret: process.env.AUTH_ADMIN_SECRET!,
});

const { data: user } = await admin.users.getByEmail("alice@example.com");
const { data: config } = await admin.config.get();
const { data: session } = await admin.users.impersonate(userId);

// User-scoped operations — create per request with the user's session token
const client = createAuthClient({
  url: "http://auth:8080",
  token: sessionToken,
});

const { data: orgs } = await client.orgs.list();
const { data: me } = await client.me.get();
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

const { getSession, getMe } = createServerHelpers(verifier, "http://auth:8080");

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
| `AuthError`            | Auth service returned an error response           |
| `AuthzError`           | Authorization check denied or authz service error |
| `JwtVerificationError` | JWT invalid, expired, or JWKS fetch failed        |

`JwtVerificationError` includes a `retryable` boolean — JWKS network failures are retryable; signature failures are not.
