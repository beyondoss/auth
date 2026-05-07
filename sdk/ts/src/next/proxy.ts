import { getSessionToken } from "../server/cookie.js";
import { type ProxyOptions, proxyRequest } from "../server/proxy-core.js";

export type { ProxyOptions };

type RouteContext = { params: Promise<{ path: string[] }> };
type Handler = (req: Request, context: RouteContext) => Promise<Response>;

/**
 * Creates Next.js catch-all route handlers that transparently proxy requests
 * to the private auth service.
 *
 * - Blocks `/v1/admin/**` — admin routes must never be browser-accessible
 * - Reads the `__Host-session` cookie, forwards it as `Authorization: Bearer`
 * - On sign-in success (POST /v1/sessions → 201): sets the httpOnly cookie and
 *   strips the raw token from the response body
 * - On sign-out (DELETE /v1/sessions/current or /v1/sessions): clears the cookie
 * - All JSON responses are camelCased for the browser
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
  const cookieOpts = {
    ...(opts?.domain !== undefined ? { domain: opts.domain } : {}),
    ...(opts?.maxAge !== undefined ? { maxAge: opts.maxAge } : {}),
  };

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

    const searchParams = new URL(req.url).searchParams;

    return proxyRequest(
      req.method,
      targetPath,
      searchParams,
      headers,
      req.body,
      authServiceUrl,
      cookieOpts,
      req.url,
    );
  }

  return {
    GET: handler,
    POST: handler,
    PUT: handler,
    PATCH: handler,
    DELETE: handler,
  };
}
