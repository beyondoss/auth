import type {
  NextRequest,
  NextResponse as NextResponseType,
} from "next/server";
import type { Auth } from "../auth.js";
import { AuthError } from "../errors.js";
import { getSessionToken } from "../server/cookie.js";
import { matchesPublicPath } from "../server/proxy-core.js";

/** Options for {@link withAuth}. */
export interface WithAuthOptions {
  /**
   * Path to redirect unauthenticated requests to.
   * @defaultValue '/login'
   */
  redirectTo?: string;
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
}

/**
 * Creates a Next.js middleware function that protects routes behind session
 * authentication.
 *
 * Tokens are read from the `__Host-session` / `__Secure-session` cookie first,
 * with an `Authorization: Bearer` fallback. Unauthenticated requests are
 * redirected to `opts.redirectTo` (default: `/login`).
 *
 * @param auth - Unified server-side auth handle from `createAuth`.
 * @param opts - Middleware configuration.
 * @returns A Next.js middleware function compatible with `middleware.ts`.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { auth } from '@beyond.dev/auth'
 * import { withAuth } from '@beyond.dev/auth/next'
 *
 * export default withAuth(auth, {
 *   publicPaths: ['/login', '/signup', '/api/public/*'],
 * })
 *
 * export const config = { matcher: ['/((?!_next/static|favicon.ico).*)'] }
 * ```
 */
export function withAuth(
  auth: Auth,
  opts?: WithAuthOptions,
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

    const result = await auth.verify(token);
    if (result.error) {
      if (result.error instanceof AuthError && result.error.status >= 500) {
        throw result.error;
      }
      return NextResponse.redirect(new URL(redirectTo, request.url));
    }
    if (!result.data) {
      return NextResponse.redirect(new URL(redirectTo, request.url));
    }
    return NextResponse.next();
  };
}
