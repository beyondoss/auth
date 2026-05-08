import type { NextFunction, Request, RequestHandler, Response } from "express";
import { AuthError } from "../errors.js";
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

export interface AuthMiddlewareOptions {
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
 * @example
 * ```ts
 * import { createAuthMiddleware } from '@beyond.dev/auth/express'
 *
 * const verifier = createSessionVerifier({ url: process.env.AUTH_URL! })
 * app.use('/protected', createAuthMiddleware(verifier))
 * ```
 */
export function createAuthMiddleware(
  verifier: {
    verify(token: string): Promise<{ data: unknown; error: unknown }>;
  },
  opts?: AuthMiddlewareOptions,
): RequestHandler {
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

      const result = await verifier.verify(token);
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

/**
 * Express middleware that proxies requests to the private auth service.
 *
 * Mount with `app.use('/api/auth', createProxy(...))` — Express strips the
 * mount prefix so `req.path` gives the subpath forwarded to the auth service.
 *
 * **Important**: Mount this proxy *before* `express.json()` on the same path,
 * or use a dedicated sub-router. If `express.json()` runs first, the request
 * body stream will be consumed before the proxy can forward it.
 *
 * @example
 * ```ts
 * import { createProxy } from '@beyond.dev/auth/express'
 *
 * // Mount before express.json() on this path
 * app.use('/api/auth', createProxy(process.env.AUTH_SERVICE_URL!))
 * ```
 *
 * - Blocks `/v1/admin/**` with 403
 * - Reads the session cookie, forwards it as `Authorization: Bearer`
 * - On sign-in (POST /v1/sessions → 201): sets httpOnly cookie, strips token from body
 * - On sign-out (DELETE /v1/sessions/current or /v1/sessions): clears cookie
 * - All JSON responses are camelCased
 */
export function createProxy(
  authServiceUrl: string,
  opts?: ProxyOptions,
): RequestHandler {
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

      // Stream req (IncomingMessage / Readable) directly as body.
      // Node 18+ fetch accepts a Readable as BodyInit; duplex: 'half' is required.
      const hasBody = req.method !== "GET" && req.method !== "HEAD";

      const upstream = await proxyRequest(
        req.method,
        targetPath,
        searchParams,
        headers,
        hasBody ? (req as unknown as BodyInit) : null,
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
