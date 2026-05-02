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

    // OAuth callbacks: set session cookie and redirect browser to the original
    // redirect_url embedded in the state JWT. The auth service has already
    // verified the JWT signature — we just decode the payload to read the URL.
    const isOAuthCallback = (req.method === "GET"
      && /^\/v1\/oauth\/[^/]+\/callback$/.test(targetPath))
      || (req.method === "POST"
        && targetPath === "/v1/oauth/apple/callback");

    if (isOAuthCallback) {
      // Buffer body so we can both read the state param and forward it.
      // For GET callbacks the body is null; for Apple's POST form it's text.
      const bodyText = req.body ? await req.text() : null;

      const stateParam = req.method === "GET"
        ? new URL(req.url).searchParams.get("state")
        : bodyText
        ? new URLSearchParams(bodyText).get("state")
        : null;

      const redirectUrl = extractOAuthRedirectUrl(stateParam, req.url);

      const upstream = await fetch(
        buildUpstreamUrl(targetPath, authServiceUrl, req.url),
        { method: req.method, headers, body: bodyText },
      );

      const dest = new URL(redirectUrl);
      const resHeaders = new Headers();

      if (!upstream.ok) {
        dest.searchParams.set("error", "oauth_failed");
        resHeaders.set("Location", dest.toString());
        return new Response(null, { status: 302, headers: resHeaders });
      }

      const body = await upstream.json() as Record<string, unknown>;

      if (typeof body.token === "string") {
        resHeaders.append(
          "Set-Cookie",
          toCookieHeader(sessionCookieAttrs(body.token, cookieOpts)),
        );
        dest.searchParams.set("success", "1");
      } else if (body.linked) {
        dest.searchParams.set("linked", "1");
      } else if (typeof body.step_up_required === "string") {
        dest.searchParams.set("step_up_required", body.step_up_required);
        if (typeof body.step_up_token === "string") {
          dest.searchParams.set("step_up_token", body.step_up_token);
        }
      } else {
        dest.searchParams.set("error", "oauth_failed");
      }

      resHeaders.set("Location", dest.toString());
      return new Response(null, { status: 302, headers: resHeaders });
    }

    const upstream = await fetch(
      buildUpstreamUrl(targetPath, authServiceUrl, req.url),
      {
        method: req.method,
        headers,
        body: req.body,
        // @ts-expect-error: duplex is required for streaming request bodies in Node 18+
        duplex: "half",
      },
    );

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

function buildUpstreamUrl(
  targetPath: string,
  authServiceUrl: string,
  reqUrl: string,
): URL {
  const url = new URL(targetPath, authServiceUrl);
  for (const [k, v] of new URL(reqUrl).searchParams) {
    url.searchParams.set(k, v);
  }
  return url;
}

// Decode redirect_url from the OAuth state JWT payload without verifying the
// signature — the auth service already verified it before processing the callback.
function extractOAuthRedirectUrl(
  state: string | null,
  requestUrl: string,
): string {
  if (state) {
    try {
      const part = state.split(".")[1] ?? "";
      const payload = JSON.parse(
        atob(part.replace(/-/g, "+").replace(/_/g, "/")),
      ) as Record<string, unknown>;
      const url = payload["redirect_url"];
      if (typeof url === "string" && url.length > 0) {
        // Resolve relative URLs against the request origin
        return new URL(url, requestUrl).toString();
      }
    } catch {
      // Fall through to default
    }
  }
  return new URL("/", requestUrl).toString();
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
