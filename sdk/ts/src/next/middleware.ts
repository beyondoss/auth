import type {
  NextRequest,
  NextResponse as NextResponseType,
} from "next/server";
import { getSessionToken } from "../server/cookie.js";

/** Options for {@link createAuthMiddleware}. */
export interface AuthMiddlewareOptions {
  /**
   * Path to redirect unauthenticated requests to.
   * @defaultValue '/login'
   */
  redirectTo?: string;
  /**
   * Paths that bypass the auth check. Supports exact strings and simple
   * `*` wildcards, e.g. `'/api/public/*'`.
   */
  publicPaths?: string[];
}

function matchesPublicPath(pathname: string, publicPaths: string[]): boolean {
  for (const pattern of publicPaths) {
    if (pattern.endsWith("*")) {
      if (pathname.startsWith(pattern.slice(0, -1))) return true;
    } else if (pathname === pattern) {
      return true;
    }
  }
  return false;
}

/**
 * Creates a Next.js middleware function that protects routes behind session
 * authentication.
 *
 * Tokens are read from the `__Host-session` / `__Secure-session` cookie first,
 * with an `Authorization: Bearer` fallback. Unauthenticated requests are
 * redirected to `opts.redirectTo` (default: `/login`).
 *
 * @param verifier - A session or JWT verifier with a `verify(token)` method.
 * @param opts - Middleware configuration.
 * @returns A Next.js middleware function compatible with `middleware.ts`.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { createAuthMiddleware } from '@beyond.dev/auth/next'
 * import { verifier } from './lib/auth'
 *
 * export const middleware = createAuthMiddleware(verifier, {
 *   publicPaths: ['/login', '/signup', '/api/public/*'],
 * })
 *
 * export const config = { matcher: ['/((?!_next/static|favicon.ico).*)'] }
 * ```
 */
export function createAuthMiddleware(
  verifier: { verify(token: string): Promise<unknown> },
  opts?: AuthMiddlewareOptions,
): (request: NextRequest) => Promise<NextResponseType> {
  const redirectTo = opts?.redirectTo ?? "/login";
  const publicPaths = opts?.publicPaths ?? [];

  return async (request: NextRequest): Promise<NextResponseType> => {
    // Dynamic import keeps next/server out of the core package bundle.
    const { NextResponse } = await import("next/server");

    const { pathname } = request.nextUrl;

    if (matchesPublicPath(pathname, publicPaths)) {
      return NextResponse.next();
    }

    const token = getSessionToken(request);

    if (!token) {
      return NextResponse.redirect(new URL(redirectTo, request.url));
    }

    try {
      await verifier.verify(token);
      return NextResponse.next();
    } catch {
      return NextResponse.redirect(new URL(redirectTo, request.url));
    }
  };
}
