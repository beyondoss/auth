import type { Context, MiddlewareHandler } from "hono";
import type { Auth } from "../auth.js";
import type { CheckSessionArgs, SchemaInput } from "../authz.js";
import { AuthError, AuthzError } from "../errors.js";
import { getSessionToken } from "../server/cookie.js";
import {
  matchesPublicPath,
  type ProxyOptions,
  proxyRequest,
} from "../server/proxy-core.js";
import type { SessionContext } from "../session.js";

export type { ProxyOptions };

export interface AuthnOptions {
  /**
   * Paths that bypass the auth check.
   *
   * Supports two forms only:
   * - Exact match: `'/login'`
   * - Trailing wildcard: `'/api/public/*'` (matches any path that starts with `/api/public/`)
   *
   * Mid-path wildcards and regex patterns are not supported.
   */
  publicPaths?: string[];
  /**
   * Called when the request has no valid session. Return a `Response` to send
   * to the client. Defaults to `{ code: 'unauthorized' }` with status 401.
   */
  onUnauthorized?: (c: Context) => Response | Promise<Response>;
}

/**
 * Hono middleware that protects routes behind session authentication.
 *
 * Tokens are read from the `__Host-session` / `__Secure-session` cookie first,
 * with an `Authorization: Bearer` fallback. Unauthenticated requests receive a
 * 401 JSON response (or your custom `onUnauthorized` handler).
 *
 * The verified session is stored in context variables as `'auth'`. Declare
 * your `Variables` type to get type safety on `c.var.auth`:
 *
 * **If your route also runs an {@link authz} check, prefer `authz` alone — it
 * does both in one call.** Use `authn` for routes that need a session but no
 * specific permission gating.
 *
 * @example
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 * import { authn } from '@beyond.dev/auth/hono'
 *
 * type Env = { Variables: { auth: SessionContext } }
 * const app = new Hono<Env>()
 *
 * app.use('/protected/*', authn(auth))
 * ```
 */
export function authn(auth: Auth, opts?: AuthnOptions): MiddlewareHandler {
  const publicPaths = opts?.publicPaths ?? [];
  const onUnauthorized = opts?.onUnauthorized
    ?? ((c: Context) => c.json({ code: "unauthorized" }, 401));

  return async (c, next) => {
    if (matchesPublicPath(c.req.path, publicPaths)) {
      return next();
    }

    const token = getSessionToken(c.req.raw);
    if (!token) {
      return onUnauthorized(c);
    }

    const result = await auth.verify(token);
    if (result.error) {
      if (result.error instanceof AuthError && result.error.status >= 500) {
        throw result.error;
      }
      return onUnauthorized(c);
    }
    if (!result.data) {
      return onUnauthorized(c);
    }

    c.set("auth" as never, result.data as SessionContext);
    return next();
  };
}

export interface AuthzOptions {
  /**
   * Called when the permission check is denied. Return a `Response` to send
   * to the client. Defaults to `{ code: 'forbidden' }` with status 403.
   */
  onForbidden?: (c: Context) => Response | Promise<Response>;
}

/**
 * Hono middleware that enforces a permission check on a route using
 * Zanzibar-style authorization.
 *
 * **Validates the session AND checks the permission in a single bundled call.**
 * Populates `c.var.auth` with the resolved session context. **You do not need
 * to stack `authn` before `authz` — it's a strict superset.**
 *
 * - 401 when no session token is presented or the token is invalid/expired.
 * - 403 when the session is valid but permission is denied.
 *
 * `getCheck` receives the context and returns the resource, id, and permission
 * to check — allowing dynamic values from route params.
 *
 * @example
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 * import { authz } from '@beyond.dev/auth/hono'
 *
 * type Env = { Variables: { auth: SessionContext } }
 * const app = new Hono<Env>()
 *
 * app.delete('/docs/:id',
 *   authz(auth, (c) => ({
 *     resource: 'document',
 *     id: c.req.param('id')!,
 *     permission: 'delete',
 *   })),
 *   (c) => c.json({ deletedBy: c.var.auth.tokenId }),
 * )
 * ```
 */
export function authz<S extends SchemaInput>(
  auth: Auth<S>,
  getCheck: (c: Context) => Omit<CheckSessionArgs<S>, "token">,
  opts?: AuthzOptions,
): MiddlewareHandler {
  const onForbidden = opts?.onForbidden
    ?? ((c: Context) => c.json({ code: "forbidden" }, 403));

  return async (c, next) => {
    const token = getSessionToken(c.req.raw);
    if (!token) {
      return c.json({ code: "unauthorized" }, 401);
    }

    const check = getCheck(c);
    const result = await auth.checkSession({
      token,
      ...check,
    } as CheckSessionArgs<S>);

    if (result.error) {
      if (
        result.error instanceof AuthzError
        && (result.error.code === "authz_not_enabled"
          || result.error.code === "authz_unknown_resource"
          || result.error.code === "authz_unknown_permission")
      ) {
        throw result.error;
      }
      if (result.error instanceof AuthError) {
        if (result.error.status === 401) {
          return c.json({ code: "unauthorized" }, 401);
        }
        if (result.error.status >= 500) {
          throw result.error;
        }
      }
      return onForbidden(c);
    }

    if (!result.data.allowed) return onForbidden(c);
    // Bundled response carries the resolved session context — populate
    // c.var.auth so handlers don't need a separate authn() in the chain.
    c.set("auth" as never, result.data.session as SessionContext);
    return next();
  };
}

/**
 * Hono middleware that proxies requests to the private auth service.
 *
 * Mount as a catch-all on your auth prefix — the wildcard segment becomes the
 * path forwarded to the auth service:
 *
 * @example
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 * import { proxy } from '@beyond.dev/auth/hono'
 *
 * app.all('/api/auth/*', proxy(auth))
 * ```
 *
 * - Blocks `/v1/admin/**` with 403 — admin routes must never be browser-accessible
 * - Reads the session cookie, forwards it as `Authorization: Bearer`
 * - On sign-in (POST /v1/sessions → 201): sets httpOnly cookie, strips token from body
 * - On sign-out (DELETE /v1/sessions/current or /v1/sessions): clears cookie
 * - All JSON responses are camelCased
 */
export function proxy(auth: Auth, opts?: ProxyOptions): MiddlewareHandler {
  const authServiceUrl = auth.url;
  const cookieOpts = {
    ...(opts?.domain !== undefined ? { domain: opts.domain } : {}),
    ...(opts?.maxAge !== undefined ? { maxAge: opts.maxAge } : {}),
  };

  return async (c) => {
    // Derive the target path by stripping the mount prefix from the URL pathname.
    // c.req.routePath is the matched route pattern (e.g. '/api/auth/*');
    // slicing off the trailing '*' gives the prefix including the final '/'.
    const mountPrefix = c.req.routePath.slice(0, -1); // '/api/auth/'
    const pathname = new URL(c.req.url).pathname;
    const targetPath = pathname.slice(mountPrefix.length - 1) || "/";

    if (targetPath.startsWith("/v1/admin/") || targetPath === "/v1/admin") {
      return c.json(
        {
          code: "forbidden",
          message: "Admin routes are not accessible via the browser proxy.",
        },
        403,
      );
    }

    const token = getSessionToken(c.req.raw);
    const headers = new Headers(c.req.raw.headers);
    headers.delete("cookie");
    headers.delete("host");
    if (token) headers.set("Authorization", `Bearer ${token}`);

    const searchParams = new URL(c.req.url).searchParams;

    // Buffer the body to avoid stream lifecycle issues with Node.js keep-alive
    // connections — forwarding ReadableStream directly can leave the underlying
    // IncomingMessage undrained, corrupting subsequent requests on the same socket.
    const body = c.req.raw.body ? Buffer.from(await c.req.arrayBuffer()) : null;

    return proxyRequest(
      c.req.method,
      targetPath,
      searchParams,
      headers,
      body,
      authServiceUrl,
      cookieOpts,
      c.req.url,
    );
  };
}
