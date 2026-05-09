import type { NextResponse } from "next/server";
import type { Profile } from "../account/me.js";
import {
  clearCookieAttrs,
  type CookieOptions,
  sessionCookieAttrs,
} from "../server/cookie.js";
import type { SessionContext, SessionVerifier } from "../session.js";
import { camelize } from "../utils/camelize.js";
import { createProxy } from "./proxy.js";
import type { ProxyOptions } from "./proxy.js";

export type { Profile };

/**
 * A Next.js-compatible read-only cookie store, compatible with the object
 * returned by `cookies()` from `next/headers`.
 */
export interface CookieStore {
  get(name: string): { value: string } | undefined;
}

type ServerHelpers = {
  /** Returns the current session record, or `null` if unauthenticated. */
  getSession(cookieStore: CookieStore): Promise<SessionContext | null>;
  /** Returns the authenticated user's full profile, or `null` if unauthenticated. */
  getMe(cookieStore: CookieStore): Promise<Profile | null>;
};

type ServerHelpersWithProxy = ServerHelpers & {
  /**
   * Next.js catch-all route handlers. Mount at `app/api/auth/[...path]/route.ts`.
   * Transparently proxies requests to the private auth service, managing the
   * session cookie on sign-in/sign-out and blocking `/v1/admin/**`.
   */
  proxy: ReturnType<typeof createProxy>;
};

export interface ServerHelpersOptions extends ProxyOptions {
  /**
   * The base URL of the auth service — the same URL passed to
   * `createSessionVerifier`. Required to enable the proxy route handlers.
   */
  authServiceUrl: string;
}

/**
 * Creates per-request session and profile helpers for Next.js server
 * components and route handlers. Reads the session cookie from the provided
 * `cookies()` store (from `next/headers`).
 *
 * - `getSession` — verifies the token; returns the session record or `null`.
 * - `getMe` — verifies the token and fetches the full user profile.
 * - `proxy` — catch-all route handlers that bridge the browser to the private
 *   auth service (only returned when `opts` is provided).
 *
 * `getSession` and `getMe` are memoized per-request via React `cache()`.
 *
 * @example
 * ```ts
 * // lib/auth.server.ts
 * import { createSessionVerifier } from '@beyond.dev/auth'
 * import { createServerHelpers } from '@beyond.dev/auth/next'
 *
 * const AUTH_URL = process.env.BEYOND_AUTH_URL!
 * const verifier = createSessionVerifier({ baseUrl: AUTH_URL })
 *
 * // Without proxy:
 * export const { getSession, getMe } = createServerHelpers(verifier, AUTH_URL)
 *
 * // With proxy:
 * export const { getSession, getMe, proxy } = createServerHelpers(verifier, { authServiceUrl: AUTH_URL })
 *
 * // app/api/auth/[...path]/route.ts
 * export const { GET, POST, DELETE, PUT, PATCH } = proxy
 * ```
 */
export function createServerHelpers(
  verifier: SessionVerifier,
  opts: ServerHelpersOptions,
): ServerHelpersWithProxy;
export function createServerHelpers(
  verifier: SessionVerifier,
  url: string,
): ServerHelpers;
export function createServerHelpers(
  verifier: SessionVerifier,
  urlOrOpts: string | ServerHelpersOptions,
): ServerHelpers | ServerHelpersWithProxy {
  const url = (
    typeof urlOrOpts === "string" ? urlOrOpts : urlOrOpts.authServiceUrl
  ).replace(/\/+$/, "");

  function withCache<A extends unknown[], R>(
    fn: (...args: A) => Promise<R>,
  ): (...args: A) => Promise<R> {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { cache } = require("react") as {
        cache: <T extends (...args: never[]) => unknown>(fn: T) => T;
      };
      return cache(fn as (...args: never[]) => unknown) as (
        ...args: A
      ) => Promise<R>;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "MODULE_NOT_FOUND") throw err;
      return fn;
    }
  }

  const getSession = withCache(async (cookieStore: CookieStore) => {
    const token = getTokenFromCookieStore(cookieStore);
    if (!token) return null;
    const result = await verifier.verify(token);
    if (result.error) {
      if (result.error.status >= 500) throw result.error;
      return null;
    }
    return result.data;
  });

  const getMe = withCache(async (cookieStore: CookieStore) => {
    const session = await getSession(cookieStore);
    if (!session) return null;
    const token = getTokenFromCookieStore(cookieStore);
    const res = await fetch(`${url}/v1/users/me`, {
      headers: { Authorization: `Bearer ${token!}` },
    });
    if (!res.ok) return null;
    return camelize(await res.json() as unknown) as Profile;
  });

  if (typeof urlOrOpts === "object") {
    const { authServiceUrl: _, ...proxyOpts } = urlOrOpts;
    return { getSession, getMe, proxy: createProxy(url, proxyOpts) };
  }

  return { getSession, getMe };
}

function getTokenFromCookieStore(store: CookieStore): string | null {
  const hostCookie = store.get("__Host-session");
  if (hostCookie?.value) return hostCookie.value;
  const secureCookie = store.get("__Secure-session");
  if (secureCookie?.value) return secureCookie.value;
  return null;
}

/**
 * Sets the Beyond Auth session cookie on a Next.js `NextResponse`.
 *
 * Uses `__Host-session` by default (most secure). Pass `domain` in `opts` to
 * switch to `__Secure-session` for cross-subdomain cookies.
 *
 * @param response - The `NextResponse` to set the cookie on.
 * @param token - Opaque session token from the auth service.
 * @param opts - Optional domain and maxAge overrides.
 *
 * @example
 * ```ts
 * const response = NextResponse.next()
 * setSessionCookie(response, token, { maxAge: 3600 })
 * return response
 * ```
 */
export function setSessionCookie(
  response: NextResponse,
  token: string,
  opts?: CookieOptions,
): void {
  const attrs = sessionCookieAttrs(token, opts);
  response.cookies.set(attrs);
}

/**
 * Clears the Beyond Auth session cookie on a Next.js `NextResponse`.
 *
 * Sets `MaxAge: -1` to guarantee browser deletion. Pass the same `domain`
 * option that was used when the cookie was set.
 *
 * @param response - The `NextResponse` to clear the cookie on.
 * @param opts - Optional domain override (must match the domain used when setting).
 *
 * @example
 * ```ts
 * const response = NextResponse.redirect('/login')
 * clearSessionCookie(response)
 * return response
 * ```
 */
export function clearSessionCookie(
  response: NextResponse,
  opts?: Pick<CookieOptions, "domain">,
): void {
  const attrs = clearCookieAttrs(opts);
  response.cookies.set(attrs);
}
