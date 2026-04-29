/**
 * Server-only cookie helpers for Beyond Auth session tokens.
 *
 * Encodes cookie security best-practices so callers can't opt out:
 * - `HttpOnly`, `Secure`, `SameSite=lax`, `Path=/` on every cookie
 * - `__Host-` prefix when no `domain` is set (HTTPS + exact domain, no Domain attribute)
 * - `__Secure-` prefix when `domain` is set (HTTPS, allows cross-subdomain)
 * - `MaxAge: -1` to clear (correct — not just omitting the attribute)
 */

/** Options for setting a session cookie. */
export interface CookieOptions {
  /**
   * Cookie domain. When omitted the `__Host-` prefix is used, which pins the
   * cookie to the exact origin and is the most secure option. Set this only
   * when you need the cookie to be visible across subdomains.
   */
  domain?: string;
  /**
   * Lifetime in seconds. When omitted the cookie is session-scoped (deleted
   * when the browser closes). Pass the session TTL from your auth config to
   * make the cookie persistent.
   */
  maxAge?: number;
}

/** Fully-resolved cookie attributes ready to pass to any framework. */
export interface CookieAttrs {
  /** Cookie name, including the security prefix. */
  name: string;
  /** Opaque session token value. */
  value: string;
  /** Always `true` — prevents JS access to the session token. */
  httpOnly: true;
  /** Always `true` — cookie is only sent over HTTPS. */
  secure: true;
  /** Always `'lax'` — CSRF-safe while allowing top-level navigations. */
  sameSite: "lax";
  /** Always `'/'` — visible to all routes. */
  path: "/";
  maxAge?: number;
  domain?: string;
}

const HOST_COOKIE = "__Host-session";
const SECURE_COOKIE = "__Secure-session";

function cookieName(domain?: string): string {
  return domain !== undefined ? SECURE_COOKIE : HOST_COOKIE;
}

/**
 * Returns cookie attributes for storing a Beyond Auth session token.
 *
 * Apply the returned attributes to a `Set-Cookie` header or your framework's
 * cookie API. The token is never modified — pass it exactly as received from
 * the auth service.
 *
 * @param token - Opaque session token from the auth service.
 * @param opts - Optional domain and maxAge overrides.
 * @returns Fully-resolved cookie attributes.
 *
 * @example
 * ```ts
 * // Next.js route handler
 * const attrs = sessionCookieAttrs(token, { maxAge: 3600 })
 * response.cookies.set(attrs)
 * ```
 */
export function sessionCookieAttrs(
  token: string,
  opts?: CookieOptions,
): CookieAttrs {
  const attrs: CookieAttrs = {
    name: cookieName(opts?.domain),
    value: token,
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
  };
  if (opts?.maxAge !== undefined) attrs.maxAge = opts.maxAge;
  if (opts?.domain !== undefined) attrs.domain = opts.domain;
  return attrs;
}

/**
 * Returns cookie attributes that instruct the browser to delete the session
 * cookie. Uses `MaxAge: -1`, which is guaranteed to clear it — unlike omitting
 * `MaxAge` or setting `Expires` in the past, which some browsers handle
 * inconsistently.
 *
 * @param opts - Optional domain override (must match the domain used when setting).
 * @returns Cookie attributes that clear the session cookie.
 *
 * @example
 * ```ts
 * // Next.js route handler
 * const attrs = clearCookieAttrs()
 * response.cookies.set(attrs)
 * ```
 */
export function clearCookieAttrs(
  opts?: Pick<CookieOptions, "domain">,
): CookieAttrs {
  const attrs: CookieAttrs = {
    name: cookieName(opts?.domain),
    value: "",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: -1,
  };
  if (opts?.domain !== undefined) attrs.domain = opts.domain;
  return attrs;
}

/**
 * Extracts the Beyond Auth session token from an incoming `Request`.
 *
 * Checks the `__Host-session` cookie first (preferred), then
 * `__Secure-session`, then falls back to the `Authorization: Bearer <token>`
 * header. Returns `null` when no token is present.
 *
 * @param request - The incoming HTTP request (Web API `Request` or compatible).
 * @returns The raw session token string, or `null` if absent.
 *
 * @example
 * ```ts
 * const token = getSessionToken(request)
 * if (!token) return new Response('Unauthorized', { status: 401 })
 * ```
 */
export function getSessionToken(request: Request): string | null {
  const cookieHeader = request.headers.get("cookie");
  if (cookieHeader) {
    let hostValue: string | undefined;
    let secureValue: string | undefined;
    for (const part of cookieHeader.split(";")) {
      const eq = part.indexOf("=");
      if (eq === -1) continue;
      const name = part.slice(0, eq).trim();
      const value = part.slice(eq + 1).trim();
      if (name === HOST_COOKIE && value) hostValue = value;
      else if (name === SECURE_COOKIE && value) secureValue = value;
    }
    if (hostValue) return hostValue;
    if (secureValue) return secureValue;
  }

  const auth = request.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) {
    const token = auth.slice(7).trim();
    if (token) return token;
  }

  return null;
}
