import type { NextResponse } from "next/server";
import type { Profile } from "../account/me.js";
import type { Auth } from "../auth.js";
import type { CheckSessionArgs, SchemaInput } from "../authz.js";
import { AuthzError } from "../errors.js";
import {
  clearCookieAttrs,
  type CookieOptions,
  sessionCookieAttrs,
} from "../server/cookie.js";
import type { SessionContext } from "../session.js";
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

/** Helpers returned by {@link serverAuth}. */
export interface ServerAuthHelpers<S extends SchemaInput = SchemaInput> {
  /** Returns the current session record, or `null` if unauthenticated. */
  getSession(cookieStore: CookieStore): Promise<SessionContext | null>;
  /** Returns the authenticated user's full profile, or `null` if unauthenticated. */
  getMe(cookieStore: CookieStore): Promise<Profile | null>;
  /**
   * Returns the current session, redirecting to `redirectTo` (default: `/login`)
   * if the request is unauthenticated. Never resolves to `null`.
   */
  requireSession(cookieStore: CookieStore): Promise<SessionContext>;
  /**
   * Checks that the session has a given permission, redirecting to
   * `opts.redirectTo` (default: `/403`) on denial. **Validates the session AND
   * checks the permission in a single bundled call** — no `requireSession`
   * needed first.
   *
   * Throws if the underlying `auth` handle was constructed without
   * `adminSecret`. The schema generic `S` constrains `resource` and
   * `permission` literals when a typed `auth` is passed.
   */
  requirePermission(
    cookieStore: CookieStore,
    check: Omit<CheckSessionArgs<S>, "token">,
    opts?: { redirectTo?: string },
  ): Promise<SessionContext>;
  /**
   * Next.js catch-all route handlers. Mount at `app/api/auth/[...path]/route.ts`.
   * Transparently proxies requests to the private auth service, managing the
   * session cookie on sign-in/sign-out and blocking `/v1/admin/**`.
   */
  proxy: ReturnType<typeof createProxy>;
}

export interface ServerAuthOptions extends ProxyOptions {
  /**
   * Path to redirect unauthenticated requests to from `requireSession` and
   * unauthenticated `requirePermission` calls.
   * @defaultValue '/login'
   */
  redirectTo?: string;
}

/**
 * Creates per-request session, permission, and profile helpers for Next.js
 * server components and route handlers. Reads the session cookie from the
 * provided `cookies()` store (from `next/headers`).
 *
 * Returns:
 * - `getSession` — verifies the token; returns the session record or `null`.
 * - `getMe` — verifies the token and fetches the full user profile.
 * - `requireSession` — like `getSession` but redirects to `redirectTo` if unauthenticated.
 * - `requirePermission` — bundled session+authz check; redirects on denial.
 * - `proxy` — catch-all route handlers that bridge the browser to the auth service.
 *
 * `getSession` and `getMe` are memoized per-request via React `cache()`.
 *
 * @example
 * ```ts
 * // lib/auth.server.ts
 * import { auth } from '@beyond.dev/auth'
 * import { serverAuth } from '@beyond.dev/auth/next'
 *
 * export const { getSession, getMe, requireSession, requirePermission, proxy } = serverAuth(auth)
 *
 * // app/api/auth/[...path]/route.ts
 * export const { GET, POST, DELETE, PUT, PATCH } = proxy
 *
 * // app/docs/[id]/page.tsx
 * const session = await requirePermission(await cookies(), {
 *   resource: 'document',
 *   id: params.id,
 *   permission: 'edit',
 * })
 * ```
 */
export function serverAuth<S extends SchemaInput>(
  auth: Auth<S>,
  opts?: ServerAuthOptions,
): ServerAuthHelpers<S> {
  const url = auth.url;
  const redirectTo = opts?.redirectTo ?? "/login";
  const proxyOpts: ProxyOptions = {
    ...(opts?.domain !== undefined ? { domain: opts.domain } : {}),
    ...(opts?.maxAge !== undefined ? { maxAge: opts.maxAge } : {}),
  };

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
    const result = await auth.verify(token);
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
    return camelize((await res.json()) as unknown) as Profile;
  });

  const requireSession = async (
    cookieStore: CookieStore,
  ): Promise<SessionContext> => {
    const session = await getSession(cookieStore);
    if (!session) {
      // Dynamic import keeps next/navigation out of non-Next bundles.
      const { redirect } = await import("next/navigation");
      redirect(redirectTo);
    }
    // redirect() returns never but TypeScript can't narrow through dynamic imports
    return session!;
  };

  const requirePermission = async (
    cookieStore: CookieStore,
    check: Omit<CheckSessionArgs<S>, "token">,
    permOpts?: { redirectTo?: string },
  ): Promise<SessionContext> => {
    const token = getTokenFromCookieStore(cookieStore);
    if (!token) {
      const { redirect } = await import("next/navigation");
      redirect(redirectTo);
    }
    const result = await auth.checkSession({
      token: token!,
      ...check,
    } as CheckSessionArgs<S>);
    if (result.error !== undefined) {
      // Config errors (authz disabled, unknown resource/permission) propagate.
      if (
        result.error instanceof AuthzError
        && (result.error.code === "authz_not_enabled"
          || result.error.code === "authz_unknown_resource"
          || result.error.code === "authz_unknown_permission")
      ) {
        throw result.error;
      }
      const { redirect } = await import("next/navigation");
      redirect(permOpts?.redirectTo ?? "/403");
    }
    const data = result.data!;
    if (!data.allowed) {
      const { redirect } = await import("next/navigation");
      redirect(permOpts?.redirectTo ?? "/403");
    }
    if (!data.session) {
      // The bundled response always populates session for valid tokens; absence
      // here means the request reached `requirePermission` without a Bearer.
      const { redirect } = await import("next/navigation");
      redirect(redirectTo);
    }
    return data.session!;
  };

  return {
    getSession,
    getMe,
    requireSession,
    requirePermission,
    proxy: createProxy(url, proxyOpts),
  };
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
