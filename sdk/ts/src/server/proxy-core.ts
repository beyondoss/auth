import { camelize } from "../utils/camelize.js";
import {
  clearCookieAttrs,
  type CookieAttrs,
  type CookieOptions,
  sessionCookieAttrs,
} from "./cookie.js";

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

export function matchesPublicPath(
  pathname: string,
  publicPaths: string[],
): boolean {
  for (const pattern of publicPaths) {
    if (pattern.endsWith("*")) {
      if (pathname.startsWith(pattern.slice(0, -1))) return true;
    } else if (pathname === pattern) {
      return true;
    }
  }
  return false;
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

function buildUpstreamUrl(
  targetPath: string,
  authServiceUrl: string,
  searchParams: URLSearchParams,
): URL {
  const url = new URL(targetPath, authServiceUrl);
  for (const [k, v] of searchParams) {
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
        return new URL(url, requestUrl).toString();
      }
    } catch {
      // Fall through to default
    }
  }
  return new URL("/", requestUrl).toString();
}

/**
 * Core proxy handler. Forwards a request to the auth service, managing
 * session cookies and camelizing all JSON responses.
 *
 * Cohesion contract: every adapter (Next.js, Hono, Fastify, Express) calls
 * this function so cookie management, OAuth handling, and camelCase conversion
 * are identical across all frameworks.
 *
 * @param method - HTTP method
 * @param targetPath - Path on the auth service, e.g. "/v1/sessions"
 * @param searchParams - Query parameters from the incoming request
 * @param headers - Pre-normalized headers: cookie stripped, Authorization injected
 * @param body - Raw request body to forward
 * @param authServiceUrl - Base URL of the private auth service
 * @param cookieOpts - Cookie domain/maxAge options
 * @param requestUrl - Full URL of the original incoming request (for OAuth redirect resolution)
 */
export async function proxyRequest(
  method: string,
  targetPath: string,
  searchParams: URLSearchParams,
  headers: Headers,
  body: BodyInit | null,
  authServiceUrl: string,
  cookieOpts: CookieOptions,
  requestUrl: string,
): Promise<Response> {
  const isOAuthCallback = (method === "GET"
    && /^\/v1\/oauth\/[^/]+\/callback$/.test(targetPath))
    || (method === "POST" && targetPath === "/v1/oauth/apple/callback");

  if (isOAuthCallback) {
    // For Apple's POST form callback the body is text; for GET callbacks it's null.
    const bodyText = body instanceof ReadableStream
      ? await new Response(body).text()
      : typeof body === "string"
      ? body
      : body instanceof Uint8Array || body instanceof ArrayBuffer
      ? new TextDecoder().decode(
        body instanceof ArrayBuffer ? new Uint8Array(body) : body,
      )
      : null;

    const stateParam = method === "GET"
      ? searchParams.get("state")
      : bodyText
      ? new URLSearchParams(bodyText).get("state")
      : null;

    const redirectUrl = extractOAuthRedirectUrl(stateParam, requestUrl);

    const upstream = await fetch(
      buildUpstreamUrl(targetPath, authServiceUrl, searchParams),
      { method, headers, body: bodyText },
    );

    const dest = new URL(redirectUrl);
    const resHeaders = new Headers();

    if (!upstream.ok) {
      dest.searchParams.set("error", "oauth_failed");
      resHeaders.set("Location", dest.toString());
      return new Response(null, { status: 302, headers: resHeaders });
    }

    const upstreamBody = await upstream.json() as Record<string, unknown>;

    if (typeof upstreamBody.token === "string") {
      resHeaders.append(
        "Set-Cookie",
        toCookieHeader(sessionCookieAttrs(upstreamBody.token, cookieOpts)),
      );
      dest.searchParams.set("success", "1");
    } else if (upstreamBody.linked) {
      dest.searchParams.set("linked", "1");
    } else if (typeof upstreamBody.step_up_required === "string") {
      dest.searchParams.set("step_up_required", upstreamBody.step_up_required);
      if (typeof upstreamBody.step_up_token === "string") {
        dest.searchParams.set("step_up_token", upstreamBody.step_up_token);
      }
    } else {
      dest.searchParams.set("error", "oauth_failed");
    }

    resHeaders.set("Location", dest.toString());
    return new Response(null, { status: 302, headers: resHeaders });
  }

  const upstream = await fetch(
    buildUpstreamUrl(targetPath, authServiceUrl, searchParams),
    {
      method,
      headers,
      body,
      // @ts-expect-error: duplex is required for streaming request bodies in Node 18+
      duplex: "half",
    },
  );

  const resHeaders = new Headers(upstream.headers);

  // Sign-in success: set httpOnly cookie, strip raw token from response body
  if (
    method === "POST" && targetPath === "/v1/sessions"
    && upstream.status === 201
  ) {
    const upstreamBody = await upstream.json();
    resHeaders.append(
      "Set-Cookie",
      toCookieHeader(
        sessionCookieAttrs(upstreamBody.session.token, cookieOpts),
      ),
    );
    const stripped = {
      ...upstreamBody,
      session: {
        id: upstreamBody.session.id,
        expires_at: upstreamBody.session.expires_at,
      },
    };
    const responseBody = JSON.stringify(camelize(stripped));
    // Upstream Content-Length is now wrong (token was stripped); let the
    // framework recalculate it from the actual body.
    resHeaders.delete("content-length");
    return new Response(responseBody, {
      status: 201,
      headers: resHeaders,
    });
  }

  // Sign-out: clear the httpOnly cookie
  if (
    method === "DELETE"
    && (targetPath === "/v1/sessions/current" || targetPath === "/v1/sessions")
  ) {
    resHeaders.append(
      "Set-Cookie",
      toCookieHeader(clearCookieAttrs(cookieOpts)),
    );
  }

  const ct = resHeaders.get("content-type");
  if (ct?.includes("application/json") && upstream.status !== 204) {
    const upstreamBody = await upstream.json();
    const responseBody = JSON.stringify(camelize(upstreamBody));
    // Camelization can change key lengths; upstream Content-Length is now wrong.
    resHeaders.delete("content-length");
    return new Response(responseBody, {
      status: upstream.status,
      headers: resHeaders,
    });
  }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: resHeaders,
  });
}
