import {
  clearCookieAttrs,
  getSessionToken,
  sessionCookieAttrs,
} from "../server/cookie.js";
import type { CookieAttrs, CookieOptions } from "../server/cookie.js";

type RouteContext = { params: Promise<{ path: string[] }> };
type Handler = (req: Request, context: RouteContext) => Promise<Response>;

export interface ProxyOptions {
  /**
   * Cookie domain. Pass when the auth cookie must be visible across subdomains.
   * Omit (default) to use `__Host-session` (most secure).
   */
  domain?: CookieOptions["domain"];
  /**
   * Cookie max-age in seconds. Pass the session TTL from your auth config to
   * make the cookie persistent across browser restarts.
   */
  maxAge?: CookieOptions["maxAge"];
}

/**
 * Creates Next.js catch-all route handlers that transparently proxy requests
 * to the private auth service.
 *
 * - Blocks `/v1/admin/**` — admin routes must never be browser-accessible
 * - Reads the `__Host-session` cookie, forwards it as `Authorization: Bearer`
 * - On sign-in success (POST /v1/sessions → 201): sets the httpOnly cookie and
 *   strips the raw token from the response body
 * - On sign-out (DELETE /v1/sessions/current or /v1/sessions): clears the cookie
 *
 * @example
 * ```ts
 * // app/api/auth/[...path]/route.ts
 * import { proxy } from '@/lib/auth.server'
 * export const { GET, POST, DELETE, PUT, PATCH } = proxy
 * ```
 */
export function createProxy(
  authServiceUrl: string,
  opts?: ProxyOptions,
): Record<"GET" | "POST" | "PUT" | "PATCH" | "DELETE", Handler> {
  const cookieOpts: CookieOptions = {};
  if (opts?.domain !== undefined) cookieOpts.domain = opts.domain;
  if (opts?.maxAge !== undefined) cookieOpts.maxAge = opts.maxAge;

  async function handler(
    req: Request,
    context: RouteContext,
  ): Promise<Response> {
    const segments = (await context.params).path;
    const targetPath = "/" + segments.join("/");

    if (targetPath.startsWith("/v1/admin/") || targetPath === "/v1/admin") {
      return Response.json({
        code: "forbidden",
        message: "Admin routes are not accessible via the browser proxy.",
      }, { status: 403 });
    }

    const token = getSessionToken(req);
    const headers = new Headers(req.headers);
    headers.delete("cookie");
    headers.delete("host");
    if (token) headers.set("Authorization", `Bearer ${token}`);

    const upstream = await fetch(new URL(targetPath, authServiceUrl), {
      method: req.method,
      headers,
      body: req.body,
      // @ts-expect-error: duplex is required for streaming request bodies in Node 18+
      duplex: "half",
    });

    const resHeaders = new Headers(upstream.headers);

    // Sign-in success: set httpOnly cookie, strip raw token from response body
    if (
      req.method === "POST"
      && targetPath === "/v1/sessions"
      && upstream.status === 201
    ) {
      const body = await upstream.json();
      resHeaders.append(
        "Set-Cookie",
        toCookieHeader(
          sessionCookieAttrs(body.session.token, cookieOpts),
        ),
      );
      const stripped = {
        ...body,
        session: {
          id: body.session.id,
          expires_at: body.session.expires_at,
        },
      };
      return new Response(JSON.stringify(stripped), {
        status: 201,
        headers: resHeaders,
      });
    }

    // Sign-out: clear the httpOnly cookie
    if (
      req.method === "DELETE"
      && (targetPath === "/v1/sessions/current"
        || targetPath === "/v1/sessions")
    ) {
      resHeaders.append(
        "Set-Cookie",
        toCookieHeader(clearCookieAttrs(cookieOpts)),
      );
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers: resHeaders,
    });
  }

  return {
    GET: handler,
    POST: handler,
    PUT: handler,
    PATCH: handler,
    DELETE: handler,
  };
}

function toCookieHeader(attrs: CookieAttrs): string {
  const parts: string[] = [`${attrs.name}=${attrs.value}`];
  if (attrs.maxAge !== undefined) parts.push(`Max-Age=${attrs.maxAge}`);
  if (attrs.domain) parts.push(`Domain=${attrs.domain}`);
  parts.push(`Path=${attrs.path}`);
  if (attrs.secure) parts.push("Secure");
  if (attrs.httpOnly) parts.push("HttpOnly");
  if (attrs.sameSite) parts.push(`SameSite=${attrs.sameSite}`);
  return parts.join("; ");
}
