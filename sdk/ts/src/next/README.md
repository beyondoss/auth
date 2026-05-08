# `@beyond.dev/auth/next`

Protect routes, read the current user, and proxy the auth service — all from Next.js server code.

## Quick Start

```ts
// lib/auth.server.ts
import { createSessionVerifier } from "@beyond.dev/auth";
import { createServerHelpers } from "@beyond.dev/auth/next";

const AUTH_URL = process.env.AUTH_URL!;
const verifier = createSessionVerifier({ baseUrl: AUTH_URL });

export const { getSession, getMe, proxy } = createServerHelpers(verifier, {
  authServiceUrl: AUTH_URL,
});
```

```ts
// app/api/auth/[...path]/route.ts
export const { GET, POST, DELETE, PUT, PATCH } = proxy;
```

```ts
// middleware.ts
import { createSessionVerifier } from "@beyond.dev/auth";
import { createAuthMiddleware } from "@beyond.dev/auth/next";

const verifier = createSessionVerifier({ baseUrl: process.env.AUTH_URL! });

export default createAuthMiddleware(verifier, {
  publicPaths: ["/login", "/api/auth/*"],
});
```

## What's included

- [`createServerHelpers`](#createserverhelpers) — `getSession`, `getMe`, and proxy route handlers
- [`createAuthMiddleware`](#createauthmiddleware) — protect routes; redirect unauthenticated requests
- [`setSessionCookie`](#setsessioncookie--clearsessioncookie) — set the session cookie on a `NextResponse`
- [`clearSessionCookie`](#setsessioncookie--clearsessioncookie) — clear the session cookie on a `NextResponse`

---

## `createServerHelpers`

```ts
createServerHelpers(verifier, url): { getSession, getMe }
createServerHelpers(verifier, opts): { getSession, getMe, proxy }
```

Returns per-request session and profile helpers, memoized via React `cache()` so each is called at most once per server request regardless of how many components use it.

```ts
interface ServerHelpersOptions {
  authServiceUrl: string; // Required to enable the proxy handlers
  domain?: string; // Cookie domain for cross-subdomain auth
  maxAge?: number; // Cookie max-age in seconds (matches your session TTL)
}
```

### `getSession`

```ts
getSession(cookieStore: CookieStore): Promise<SessionContext | null>
```

Verifies the session token from cookies. Returns the session record or `null` if unauthenticated.

```ts
// app/page.tsx
import { getSession } from "@/lib/auth.server";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export default async function Page() {
  const session = await getSession(await cookies());
  if (!session) redirect("/login");
  return <div>User ID: {session.userId}</div>;
}
```

### `getMe`

```ts
getMe(cookieStore: CookieStore): Promise<MeResponse | null>
```

Verifies the token and fetches the full user profile from `GET /v1/users/me`. Returns `null` if unauthenticated.

```ts
// app/layout.tsx
import { AuthProvider } from "@/lib/auth.client";
import { getMe } from "@/lib/auth.server";
import { cookies } from "next/headers";

export default async function RootLayout({ children }) {
  const initialUser = await getMe(await cookies());
  return (
    <html>
      <body>
        <AuthProvider initialUser={initialUser}>{children}</AuthProvider>
      </body>
    </html>
  );
}
```

`MeResponse` shape:

```ts
interface MeResponse {
  user: {
    id: string;
    name: string;
    imageUrl?: string;
    metadata: unknown;
    createdAt: string;
    primaryOrgId: string;
  };
  email: { id: string; email: string; verifiedAt?: string };
  org: { id: string; name: string; slug: string; imageUrl?: string };
}
```

### `proxy`

```ts
proxy: {
  GET, POST, PUT, PATCH, DELETE;
}
```

Catch-all Next.js route handlers. Mount at `app/api/auth/[...path]/route.ts` to bridge the browser to the private auth service.

```ts
// app/api/auth/[...path]/route.ts
export const { GET, POST, DELETE, PUT, PATCH } = proxy;
```

**What the proxy does:**

- Blocks all `/v1/admin/**` requests with `403 Forbidden` — admin routes are never browser-accessible.
- On `POST /v1/sessions` (sign-in): sets the httpOnly session cookie and strips the raw token from the response body.
- On `DELETE /v1/sessions/current` (sign-out): clears the session cookie.
- Forwards all other requests transparently.

**Cookie behavior:**

Without `domain`: uses `__Host-session` (most secure; tied to the exact host, no subdomain sharing).

With `domain`: uses `__Secure-session` (allows sharing the cookie across subdomains like `app.example.com` and `api.example.com`).

---

## `createAuthMiddleware`

```ts
createAuthMiddleware(verifier, opts?): NextMiddleware
```

Returns a Next.js middleware function that protects routes. Unauthenticated requests are redirected; tokens are read from the session cookie, with `Authorization: Bearer` as fallback.

`createAuthMiddleware` accepts any verifier with a `verify(token)` method. Two are available:

| Verifier                | How it works                                                              | Use when                                                   |
| ----------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `createSessionVerifier` | Round-trip to the auth service on every request; detects revoked sessions | Default choice; revocation matters                         |
| `createJwtVerifier`     | Validates locally with cached JWKS; no network call                       | High-volume edge routes where revocation lag is acceptable |

```ts
// Stateless JWT verification — no round-trip, safe for the edge
import { createJwtVerifier } from "@beyond.dev/auth";

const verifier = createJwtVerifier({
  jwksUri: `${process.env.AUTH_URL}/v1/jwks`,
  issuer: process.env.AUTH_URL!,
});

export default createAuthMiddleware(verifier, {
  publicPaths: ["/login", "/api/auth/*"],
});
```

```ts
interface AuthMiddlewareOptions {
  redirectTo?: string; // Redirect destination for unauthenticated requests. Default: '/login'
  publicPaths?: string[]; // Paths that bypass the auth check
}
```

Public paths support exact matches and trailing wildcards:

```ts
export default createAuthMiddleware(verifier, {
  redirectTo: "/login",
  publicPaths: [
    "/login",
    "/signup",
    "/api/auth/*", // Matches /api/auth/anything
  ],
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
```

---

## `setSessionCookie` / `clearSessionCookie`

Use these when you're handling auth outside the proxy — for example, in a custom sign-in route handler.

```ts
setSessionCookie(response: NextResponse, token: string, opts?: CookieOptions): void
clearSessionCookie(response: NextResponse, opts?: Pick<CookieOptions, 'domain'>): void
```

```ts
interface CookieOptions {
  domain?: string; // Set to share the cookie across subdomains
  maxAge?: number; // Cookie lifetime in seconds
}
```

```ts
// app/api/custom-signin/route.ts
import { clearSessionCookie, setSessionCookie } from "@beyond.dev/auth/next";
import { NextResponse } from "next/server";

export async function POST(req: Request) {
  const { token } = await getTokenFromAuthService(req);
  const response = NextResponse.redirect("/dashboard");
  setSessionCookie(response, token);
  return response;
}

export async function DELETE() {
  const response = NextResponse.redirect("/login");
  clearSessionCookie(response);
  return response;
}
```

Pass the same `domain` to both `setSessionCookie` and `clearSessionCookie` — the clear must match the set to guarantee deletion.

---

## Issuing JWTs for downstream services

If a downstream service expects a JWT rather than an opaque session token, issue one server-side using `issueToken`. JWTs are Ed25519-signed and can carry custom claims.

```ts
import { createAuthFlowClient } from "@beyond.dev/auth";
import { getSessionToken } from "@beyond.dev/auth";
import { cookies } from "next/headers";

const flows = createAuthFlowClient({ baseUrl: process.env.AUTH_URL! });

// In a route handler or server action
export async function GET(req: Request) {
  const token = getSessionToken(req);
  if (!token) return new Response(null, { status: 401 });

  const { accessToken } = await flows.issueToken(token, { role: "editor" });
  // Forward accessToken to the downstream service
}
```

`issueToken` returns `{ accessToken, expiresIn }`. The downstream service validates the JWT with `createJwtVerifier`.
