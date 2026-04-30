import type { NextResponse } from "next/server";
import type { Client } from "openapi-fetch";
import {
  clearCookieAttrs,
  type CookieOptions,
  sessionCookieAttrs,
} from "../server/cookie.js";
import type { SessionContext, SessionVerifier } from "../session.js";
import type { components, paths } from "../types.js";
import { camelize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";

/**
 * A Next.js-compatible read-only cookie store, compatible with the object
 * returned by `cookies()` from `next/headers`.
 */
export interface CookieStore {
  get(name: string): { value: string } | undefined;
}

/** User profile from `GET /v1/users/me`. */
export type MeResponse = Camelize<components["schemas"]["MeResponse"]>;

/**
 * Creates per-request session and profile helpers for Next.js server
 * components and route handlers. Reads the session cookie from the provided
 * `cookies()` store (from `next/headers`).
 *
 * - `getSession` — verifies the token; returns the session record or `null`.
 *   Makes one request to the auth service.
 * - `getMe` — verifies the token and fetches the full user profile; returns
 *   `MeResponse` or `null`. Makes two requests (session verify + profile).
 *
 * Both are memoized per-request via React `cache()` when React is available.
 *
 * @param verifier - Session verifier from {@link createSessionVerifier}.
 * @param client - Admin client from {@link createAdminClient}.
 * @returns Per-request helpers. Call with the `cookies()` store each time.
 *
 * @example
 * ```ts
 * // lib/auth.ts
 * import { createSessionVerifier, createAdminClient } from '@beyond.dev/auth'
 * import { createServerHelpers } from '@beyond.dev/auth/next'
 *
 * const verifier = createSessionVerifier({ baseUrl: process.env.AUTH_URL! })
 * const client = createAdminClient({ baseUrl: process.env.AUTH_URL! })
 * export const { getSession, getMe } = createServerHelpers(verifier, client)
 *
 * // app/page.tsx (RSC)
 * import { cookies } from 'next/headers'
 * import { getMe } from '@/lib/auth'
 *
 * export default async function Page() {
 *   const me = await getMe(await cookies())
 *   if (!me) redirect('/login')
 * }
 * ```
 */
export function createServerHelpers(
  verifier: SessionVerifier,
  client: Client<paths>,
): {
  /**
   * Returns the current session record, or `null` if unauthenticated.
   *
   * @param cookieStore - The store returned by `cookies()` from `next/headers`.
   */
  getSession(cookieStore: CookieStore): Promise<SessionContext | null>;

  /**
   * Returns the authenticated user's full profile, or `null` if unauthenticated.
   * Verifies the session then fetches `GET /v1/users/me`.
   *
   * @param cookieStore - The store returned by `cookies()` from `next/headers`.
   */
  getMe(cookieStore: CookieStore): Promise<MeResponse | null>;
} {
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
    return verifier.verify(token);
  });

  const getMe = withCache(async (cookieStore: CookieStore) => {
    const session = await getSession(cookieStore);
    if (!session) return null;
    const token = getTokenFromCookieStore(cookieStore);
    const { data } = await client.GET("/v1/users/me", {
      headers: { Authorization: `Bearer ${token!}` },
    });
    return data !== undefined ? camelize(data) : null;
  });

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
