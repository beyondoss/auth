# @beyond.dev/auth

Authenticate users, verify sessions, and enforce permission checks — from TypeScript.

## Install

```sh
npm install @beyond.dev/auth
```

## Quickstart

`BEYOND_AUTH_URL` (and optionally `BEYOND_AUTH_ADMIN_SECRET`) read from environment. Import the lazy `auth` handle and go:

```ts
import { auth } from "@beyond.dev/auth";
import { authn } from "@beyond.dev/auth/express";

app.use("/protected", authn(auth));
app.get("/protected/me", (req, res) => res.json({ user: req.auth }));
```

That's it — three lines after imports. The `auth` handle is the unified surface: it covers token verification, permission checks, sign-in flows, and admin operations.

```ts
// Sign in
const result = await auth.flow.signIn({
  grantType: "password",
  email,
  password,
});

// Verify a session token
const { data: session } = await auth.verify(token);

// Check a permission (returns the bundled session context too — see "Why it's fast" below)
const { data } = await auth.checkSession({
  token,
  resource: "document",
  id: documentId,
  permission: "edit",
});
```

## Why it's fast

Routes guarded by `authz` are **one HTTP call to the auth service** — not two. The service validates the session and checks the permission in a single bundled SQL query, then returns the resolved session context alongside the allow/deny decision. The framework adapters use that to populate `req.auth` (or `c.var.auth` / `request.auth`) directly, so you don't need to stack `authn` first.

```ts
import { auth } from "@beyond.dev/auth";
import { authz } from "@beyond.dev/auth/express";

// authz alone — validates session + checks permission + populates req.auth
app.delete(
  "/docs/:id",
  authz(auth, (req) => ({
    resource: "document",
    id: req.params.id as string,
    permission: "delete",
  })),
  (req, res) => {
    res.json({ deletedBy: req.auth!.tokenId });
  },
);
```

Stacking `authn + authz` still works; it just costs one wasted HTTP call.

## Customization

`createAuth(opts?)` returns the same shape as the lazy `auth` import. Use it when you need to override defaults — `url` is **never** in customization examples because the env var is the source of truth:

```ts
import { createAuth } from "@beyond.dev/auth";

const auth = createAuth({
  adminSecret: process.env.BEYOND_AUTH_ADMIN_SECRET, // unlocks .admin and .authz
  schema: documentSchema, // typed ReBAC
  fetch: instrumentedFetch, // tracing
  timeout: 30_000,
  retries: 3,
});
```

The handle exposes `auth.url`, `auth.verify`, `auth.checkSession`, `auth.flow`, `auth.admin`, `auth.authz`. `auth.verify` and `auth.checkSession` authenticate with the user's session token and work without `adminSecret` — that's why the `authn` / `authz` middleware in the framework adapters works on a bare `createAuth({ url })`. `auth.admin` and `auth.authz` (the full ReBAC client — `createRelation`, `expand`, `trace`, `putSchema`, …) are admin-only and throw a named error on first access if `adminSecret` is missing.

## Framework adapters

### Express

```ts
import { auth } from "@beyond.dev/auth";
import { authn, authz, proxy } from "@beyond.dev/auth/express";

// Browser → auth service proxy (cookie ↔ Bearer translation, blocks /v1/admin)
app.use("/api/auth", proxy(auth));

// Protected routes — req.auth populated for the handler
app.use("/protected", authn(auth));
app.get("/protected/me", (req, res) => res.json({ user: req.auth }));

// Permission-gated routes — single HTTP call, populates req.auth
app.delete(
  "/docs/:id",
  authz(auth, (req) => ({
    resource: "document",
    id: req.params.id as string,
    permission: "delete",
  })),
  handler,
);
```

### Hono

```ts
import { auth } from "@beyond.dev/auth";
import { authn, authz, proxy } from "@beyond.dev/auth/hono";

type Env = { Variables: { auth: SessionContext } };
const app = new Hono<Env>();

app.all("/api/auth/*", proxy(auth));
app.use("/protected/*", authn(auth));

app.delete(
  "/docs/:id",
  authz(auth, (c) => ({
    resource: "document",
    id: c.req.param("id")!,
    permission: "delete",
  })),
  (c) => c.json({ deletedBy: c.var.auth.tokenId }),
);
```

### Fastify

`authn` and `proxy` are plugin constants (`fastify.register(plugin, opts)`). `authz` is a `preHandler` hook — the canonical Fastify pattern, matching `@fastify/auth` and `@fastify/jwt`.

```ts
import { auth } from "@beyond.dev/auth";
import { authn, authz, proxy } from "@beyond.dev/auth/fastify";

await app.register(authn, { auth, publicPaths: ["/health"] });
await app.register(proxy, { auth, prefix: "/api/auth" });

// Per-route guard:
app.get(
  "/docs/:id",
  {
    preHandler: authz(auth, (req) => ({
      resource: "document",
      id: (req.params as { id: string }).id,
      permission: "read",
    })),
  },
  async (request) => ({ user: request.auth }),
);

// Or scoped over a route group (when many routes share one check):
await app.register(
  async (instance) => {
    instance.addHook("preHandler", authz(auth, getCheck));
    instance.get("/:id", handler);
    instance.delete("/:id", handler);
  },
  { prefix: "/docs" },
);
```

### Next.js

```ts
// middleware.ts
import { auth } from "@beyond.dev/auth";
import { withAuth } from "@beyond.dev/auth/next";

export default withAuth(auth, { publicPaths: ["/login", "/api/public/*"] });
export const config = { matcher: ["/((?!_next/static|favicon.ico).*)"] };
```

```ts
// lib/auth.server.ts
import { auth } from "@beyond.dev/auth";
import { serverAuth } from "@beyond.dev/auth/next";

export const { getSession, getMe, requireSession, requirePermission, proxy } =
  serverAuth(auth);
```

```ts
// app/api/auth/[...path]/route.ts
export const { GET, POST, PUT, PATCH, DELETE } = proxy;
```

```tsx
// app/docs/[id]/page.tsx
import { requirePermission } from "@/lib/auth.server";
import { cookies } from "next/headers";

export default async function Page({ params }: { params: { id: string } }) {
  // Single bundled call: validates session + checks permission, redirects on either failure.
  const session = await requirePermission(await cookies(), {
    resource: "document",
    id: params.id,
    permission: "edit",
  });
  return <Editor sessionId={session.id} />;
}
```

## Auth flows

`auth.flow` covers everything related to getting users in and out of your app.

```ts
// Sign up
const { session } = await auth.flow.signUp({ email, password });

// Sign in
const result = await auth.flow.signIn({
  grantType: "password",
  email,
  password,
});
if ("stepUpToken" in result) {
  // TOTP enrolled — redirect to /verify-totp with result.stepUpToken
} else {
  // result.session.token
}

// Complete TOTP step-up
const { session } = await auth.flow.completeTotpStepUp(stepUpToken, code);
const { session } = await auth.flow.completeTotpRecovery(
  stepUpToken,
  recoveryCode,
);

// Magic link
await auth.flow.requestMagicLink(email);
const { session } = await auth.flow.signIn({ grantType: "magic_link", token });

// Password reset
await auth.flow.requestPasswordReset(email);
const { session } = await auth.flow.signIn({
  grantType: "password_reset",
  token,
  newPassword,
});

// Passkeys
const { options, stateToken } = await auth.flow.beginPasskeyAuth();
// ... navigator.credentials.get(...)
const { session } = await auth.flow.finishPasskeyAuth(stateToken, credential);

// Sign out
await auth.flow.signOut(sessionToken);
await auth.flow.signOutAll(sessionToken); // revokes everything
await auth.flow.signOutAll(sessionToken, { excludeCurrent: true });

// Issue a JWT from a session
const { token } = await auth.flow.issueToken(sessionToken, {
  audience: "my-api",
});
```

## Authorization

`auth.authz` exposes the full ReBAC surface — checks, lookups, traces, schema management. Requires `BEYOND_AUTH_ADMIN_SECRET`.

```ts
// Single check (with explicit subject)
await auth.authz.check({
  resource: "document",
  id: documentId,
  permission: "write",
  subject: userId,
});

// Bundled session check + permission gate (the framework adapters use this)
const { data } = await auth.authz.checkSession({
  token,
  resource: "document",
  id: documentId,
  permission: "write",
});
// data.allowed: boolean
// data.session: SessionContext | null  (bundled — no separate /v1/sessions/current call)

// Who has access?
await auth.authz.expand({
  resource: "document",
  id: documentId,
  relation: "editor",
});

// What can this user access?
await auth.authz.lookup({
  token,
  resource: "document",
  permission: "read",
  limit: 50,
});

// Why was access allowed/denied?
await auth.authz.trace({
  resource: "document",
  id: documentId,
  permission: "write",
  subject: userId,
});

// Manage tuples
await auth.authz.createRelation({
  resource: "document",
  id: documentId,
  relation: "editor",
  subject: userId,
});
await auth.authz.deleteRelation({/* ... */});

// Schema management
await auth.authz.putSchema({ version: 1, resources: [/* ... */] });
```

### Typed schema

Pass `schema` to `createAuth` to get strict typing on every authz call. Resource names, permissions, and relations are all checked at compile time. No `as const` needed:

```ts
import { createAuth, defineSchema } from "@beyond.dev/auth";

const auth = createAuth({
  schema: defineSchema({
    version: 1,
    resources: [
      {
        name: "document",
        roles: ["owner", "editor", "viewer"],
        permissions: {
          delete: ["owner"],
          write: ["owner", "editor"],
          read: ["owner", "editor", "viewer"],
        },
        roleInheritance: { owner: ["editor"], editor: ["viewer"] },
      },
    ],
  }),
});

// ✅
await auth.authz.check({
  resource: "document",
  id,
  permission: "write",
  subject: userId,
});

// ❌ TypeScript: 'unknown_resource' is not assignable
await auth.authz.check({ resource: "unknown_resource" /* ... */ });

// ❌ TypeScript: 'admin' is not a permission of 'document'
await auth.authz.check({
  resource: "document",
  id,
  permission: "admin",
  subject: userId,
});
```

JSON schema imports work the same way — TypeScript infers literals from `import schema from "./schema.json"`.

## JWT verification

For services that prefer stateless tokens — verify access tokens locally with JWKS caching:

```ts
import { createJwtVerifier } from "@beyond.dev/auth";

const jwt = createJwtVerifier({
  jwksUri: "https://auth.example.com/v1/jwks.json",
  issuer: "https://auth.example.com",
  audience: "your-app",
  clockSkewSeconds: 30,
});

const claims = await jwt.verify(accessToken);
```

JWKS keys cache for one hour; unknown `kid` triggers an immediate refresh.

|                          | `auth.verify`               | `createJwtVerifier`                |
| ------------------------ | --------------------------- | ---------------------------------- |
| Round-trip per request   | Yes                         | No (cache hit)                     |
| Detects revocation       | Yes                         | No — JWT valid until `exp`         |
| Requires auth service up | Always                      | Only on cache miss                 |
| Use when                 | Default; revocation matters | High volume; short-lived tokens OK |

## Cookies

```ts
import {
  clearSessionCookie,
  sessionCookieAttrs,
  setSessionCookie,
} from "@beyond.dev/auth/next";

// After login
setSessionCookie(response, token, { maxAge: 86_400 });

// After logout
clearSessionCookie(response);
```

For server frameworks other than Next.js, use the lower-level helpers from `@beyond.dev/auth/server`:

```ts
import { clearCookieAttrs, sessionCookieAttrs } from "@beyond.dev/auth/server";

response.cookies.set(sessionCookieAttrs(token, { maxAge: 86_400 }));
response.cookies.set(clearCookieAttrs());
```

## Errors

| Class                  | When                                              |
| ---------------------- | ------------------------------------------------- |
| `AuthError`            | Auth service returned an error response           |
| `AuthzError`           | Authorization check denied or authz service error |
| `JwtVerificationError` | JWT invalid, expired, or JWKS fetch failed        |

`JwtVerificationError.retryable` — `true` for JWKS network failures, `false` for signature failures.

## Browser / per-user client

`createAuthClient` returns a per-user, hierarchical client for app code that talks to the auth service on behalf of a specific user (orgs, identities, sessions, keys, profile, emails, TOTP, passkeys):

```ts
import { createAuthClient } from "@beyond.dev/auth";

const client = createAuthClient<"admin" | "billing" | "member">({
  url: "http://auth:8080",
  token: sessionToken,
});

const { data: me } = await client.me.get();
const { data: orgs } = await client.orgs.list();
await client.orgs.invitations.create(orgId, {
  email: "x@y.com",
  role: "admin",
});
```

The optional generic constrains org invitation `role` fields to your app's role union.

For React apps, the `@beyond.dev/auth/react` entry point exposes the same surface as hooks. See `createBrowserAuth`.
