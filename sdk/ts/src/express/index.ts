import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { Auth } from "../auth.js";
import type { CheckSessionArgs, SchemaInput } from "../authz.js";
import { AuthError, AuthzError } from "../errors.js";
import { getSessionTokenFromNodeHeaders } from "../server/cookie.js";
import {
  matchesPublicPath,
  type ProxyOptions,
  proxyRequest,
} from "../server/proxy-core.js";
import type { SessionContext } from "../session.js";

export type { ProxyOptions };

declare global {
  namespace Express {
    interface Request {
      auth: SessionContext | null;
    }
  }
}

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
   * Called when the request has no valid session. Send an error response and
   * return. Defaults to `{ code: 'unauthorized' }` with status 401.
   */
  onUnauthorized?: (req: Request, res: Response, next: NextFunction) => void;
}

/**
 * Express middleware that protects routes behind session authentication.
 *
 * Tokens are read from the `__Host-session` / `__Secure-session` cookie first,
 * with an `Authorization: Bearer` fallback. Unauthenticated requests receive a
 * 401 JSON response (or your custom `onUnauthorized` handler).
 *
 * The verified session is stored on `req.auth`.
 *
 * **If your route also runs an {@link authz} check, prefer `authz` alone — it
 * does both in one call.** Use `authn` for routes that need a session but no
 * specific permission gating.
 *
 * @example
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 * import { authn } from '@beyond.dev/auth/express'
 *
 * app.use('/protected', authn(auth))
 * ```
 */
export function authn(auth: Auth, opts?: AuthnOptions): RequestHandler {
  const publicPaths = opts?.publicPaths ?? [];
  const onUnauthorized = opts?.onUnauthorized
    ?? ((_req: Request, res: Response) => {
      res.status(401).json({ code: "unauthorized" });
    });

  return async (req, res, next) => {
    try {
      if (matchesPublicPath(req.path, publicPaths)) {
        return next();
      }

      const token = getSessionTokenFromNodeHeaders(req.headers);
      if (!token) {
        return onUnauthorized(req, res, next);
      }

      const result = await auth.verify(token);
      if (result.error) {
        if (result.error instanceof AuthError && result.error.status >= 500) {
          return next(result.error);
        }
        return onUnauthorized(req, res, next);
      }
      if (!result.data) {
        return onUnauthorized(req, res, next);
      }

      req.auth = result.data as SessionContext;
      next();
    } catch (err) {
      next(err);
    }
  };
}

export interface AuthzOptions {
  /**
   * Called when the permission check is denied. Send an error response and
   * return. Defaults to `{ code: 'forbidden' }` with status 403.
   */
  onForbidden?: (req: Request, res: Response, next: NextFunction) => void;
}

/**
 * Express middleware that enforces a permission check on a route using
 * Zanzibar-style authorization.
 *
 * **Validates the session AND checks the permission in a single bundled call.**
 * Populates `req.auth` with the resolved session context. **You do not need to
 * stack `authn` before `authz` — it's a strict superset.**
 *
 * - 401 when no session token is presented.
 * - 401 when the session token is invalid/expired (delegates to `onForbidden`
 *   only after a valid session is established and permission is denied).
 * - 403 when the session is valid but permission is denied.
 *
 * `getCheck` receives the request and returns the resource, id, and permission
 * to check — allowing dynamic values from route params.
 *
 * @example
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 * import { authz } from '@beyond.dev/auth/express'
 *
 * app.delete('/docs/:id',
 *   authz(auth, (req) => ({
 *     resource: 'document',
 *     id: req.params.id as string,
 *     permission: 'delete',
 *   })),
 *   (req, res) => {
 *     // req.auth is populated — no separate authn() needed
 *     res.json({ deletedBy: req.auth!.tokenId })
 *   },
 * )
 * ```
 */
export function authz<S extends SchemaInput>(
  auth: Auth<S>,
  getCheck: (req: Request) => Omit<CheckSessionArgs<S>, "token">,
  opts?: AuthzOptions,
): RequestHandler {
  const onForbidden = opts?.onForbidden
    ?? ((_req: Request, res: Response) => {
      res.status(403).json({ code: "forbidden" });
    });

  return async (req, res, next) => {
    try {
      const token = getSessionTokenFromNodeHeaders(req.headers);
      if (!token) {
        res.status(401).json({ code: "unauthorized" });
        return;
      }

      const check = getCheck(req);
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
          return next(result.error);
        }
        if (result.error instanceof AuthError) {
          if (result.error.status === 401) {
            res.status(401).json({ code: "unauthorized" });
            return;
          }
          if (result.error.status >= 500) {
            return next(result.error);
          }
        }
        return onForbidden(req, res, next);
      }

      if (!result.data.allowed) return onForbidden(req, res, next);
      // Bundled response carries the resolved session context — populate
      // req.auth so handlers don't need a separate authn() in the chain.
      req.auth = result.data.session;
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Express middleware that proxies requests to the private auth service.
 *
 * Mount with `app.use('/api/auth', proxy(auth))` — Express strips the
 * mount prefix so `req.path` gives the subpath forwarded to the auth service.
 *
 * **Important**: Mount this proxy *before* `express.json()` on the same path,
 * or use a dedicated sub-router. If `express.json()` runs first, the request
 * body stream will be consumed before the proxy can forward it.
 *
 * @example
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 * import { proxy } from '@beyond.dev/auth/express'
 *
 * // Mount before express.json() on this path
 * app.use('/api/auth', proxy(auth))
 * ```
 *
 * - Blocks `/v1/admin/**` with 403
 * - Reads the session cookie, forwards it as `Authorization: Bearer`
 * - On sign-in (POST /v1/sessions → 201): sets httpOnly cookie, strips token from body
 * - On sign-out (DELETE /v1/sessions/current or /v1/sessions): clears cookie
 * - All JSON responses are camelCased
 */
export function proxy(auth: Auth, opts?: ProxyOptions): RequestHandler {
  const authServiceUrl = auth.url;
  const cookieOpts = {
    ...(opts?.domain !== undefined ? { domain: opts.domain } : {}),
    ...(opts?.maxAge !== undefined ? { maxAge: opts.maxAge } : {}),
  };

  return async (req, res, next) => {
    try {
      // req.path is relative to the mount point (Express strips the prefix)
      const targetPath = req.path;

      if (targetPath.startsWith("/v1/admin/") || targetPath === "/v1/admin") {
        res.status(403).json({
          code: "forbidden",
          message: "Admin routes are not accessible via the browser proxy.",
        });
        return;
      }

      const token = getSessionTokenFromNodeHeaders(req.headers);
      const headers = new Headers(
        Object.entries(req.headers).flatMap(([k, v]) =>
          Array.isArray(v)
            ? v.map((val) => [k, val] as [string, string])
            : v !== undefined
            ? [[k, v] as [string, string]]
            : []
        ),
      );
      headers.delete("cookie");
      headers.delete("host");
      if (token) headers.set("Authorization", `Bearer ${token}`);

      // req.url includes the query string relative to the mount point
      const searchParams = new URLSearchParams(
        req.url.includes("?") ? req.url.slice(req.url.indexOf("?") + 1) : "",
      );

      let bodyBuf: Buffer | null = null;
      if (req.method !== "GET" && req.method !== "HEAD") {
        const chunks: Buffer[] = [];
        for await (const chunk of req) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        bodyBuf = chunks.length > 0 ? Buffer.concat(chunks) : Buffer.alloc(0);
      }

      const upstream = await proxyRequest(
        req.method,
        targetPath,
        searchParams,
        headers,
        bodyBuf as BodyInit | null,
        authServiceUrl,
        cookieOpts,
        `http://proxy${req.url}`,
      );

      res.status(upstream.status);
      upstream.headers.forEach((value, key) => {
        res.setHeader(key, value);
      });
      const buf = Buffer.from(await upstream.arrayBuffer());
      res.send(buf);
    } catch (err) {
      next(err);
    }
  };
}
