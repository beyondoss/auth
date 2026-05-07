import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import fp from "fastify-plugin";
import { AuthServiceError } from "../errors.js";
import { getSessionTokenFromNodeHeaders } from "../server/cookie.js";
import {
  matchesPublicPath,
  type ProxyOptions,
  proxyRequest,
} from "../server/proxy-core.js";
import type { SessionContext } from "../session.js";

export type { ProxyOptions };

declare module "fastify" {
  interface FastifyRequest {
    auth: SessionContext | null;
  }
}

export interface AuthPluginOptions {
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
  /**
   * Called when the request has no valid session. Send an error reply and
   * return. Defaults to `{ code: 'unauthorized' }` with status 401.
   */
  onUnauthorized?: (
    request: FastifyRequest,
    reply: FastifyReply,
  ) => void | Promise<void>;
}

/**
 * Fastify plugin that protects routes behind session authentication.
 *
 * Wrap with `fp()` is applied internally so `request.auth` is visible across
 * the entire app. Tokens are read from the `__Host-session` / `__Secure-session`
 * cookie first, with an `Authorization: Bearer` fallback.
 *
 * @example
 * ```ts
 * import { createAuthPlugin } from '@beyond.dev/auth/fastify'
 *
 * const verifier = createSessionVerifier({ url: process.env.AUTH_URL! })
 * await app.register(createAuthPlugin(verifier), { prefix: '/protected' })
 * ```
 */
export function createAuthPlugin(
  verifier: {
    verify(token: string): Promise<{ data: unknown; error: unknown }>;
  },
  opts?: AuthPluginOptions,
): FastifyPluginAsync {
  const publicPaths = opts?.publicPaths ?? [];
  const onUnauthorized = opts?.onUnauthorized
    ?? (async (_request: FastifyRequest, reply: FastifyReply) => {
      await reply.code(401).send({ code: "unauthorized" });
    });

  const plugin: FastifyPluginAsync = async (fastify) => {
    fastify.decorateRequest("auth", null);

    fastify.addHook("preHandler", async (request, reply) => {
      if (matchesPublicPath(request.url, publicPaths)) return;

      const token = getSessionTokenFromNodeHeaders(request.headers);
      if (!token) {
        return onUnauthorized(request, reply);
      }

      const result = await verifier.verify(token);
      if (result.error) {
        if (
          result.error instanceof AuthServiceError
          && result.error.status >= 500
        ) {
          throw result.error;
        }
        return onUnauthorized(request, reply);
      }
      if (!result.data) {
        return onUnauthorized(request, reply);
      }

      request.auth = result.data as SessionContext;
    });
  };

  // fp() makes the decorateRequest visible in the parent scope
  return fp(plugin, { name: "@beyond.dev/auth", fastify: ">=4" });
}

/**
 * Fastify plugin that proxies requests to the private auth service.
 *
 * Do NOT wrap in `fastify-plugin` — prefix isolation is required so the
 * content-type parser override is scoped only to these routes:
 *
 * @example
 * ```ts
 * import { createProxyPlugin } from '@beyond.dev/auth/fastify'
 *
 * await app.register(createProxyPlugin(process.env.AUTH_SERVICE_URL!), {
 *   prefix: '/api/auth',
 * })
 * ```
 *
 * - Blocks `/v1/admin/**` with 403
 * - Reads the session cookie, forwards it as `Authorization: Bearer`
 * - On sign-in (POST /v1/sessions → 201): sets httpOnly cookie, strips token from body
 * - On sign-out (DELETE /v1/sessions/current or /v1/sessions): clears cookie
 * - All JSON responses are camelCased
 */
export function createProxyPlugin(
  authServiceUrl: string,
  opts?: ProxyOptions,
): FastifyPluginAsync {
  const cookieOpts = {
    ...(opts?.domain !== undefined ? { domain: opts.domain } : {}),
    ...(opts?.maxAge !== undefined ? { maxAge: opts.maxAge } : {}),
  };

  // NOT wrapped with fp() — prefix isolation must work
  return async (fastify) => {
    // Remove all default content type parsers (including Fastify's built-in
    // JSON parser) for routes in this plugin only. The '*' catch-all below
    // would otherwise not override application/json. This is scoped to this
    // plugin because it is NOT wrapped with fp().
    fastify.removeAllContentTypeParsers();
    fastify.addContentTypeParser(
      "*",
      { parseAs: "buffer" },
      (_req, body, done) => done(null, body),
    );

    fastify.route({
      method: ["GET", "POST", "PUT", "PATCH", "DELETE"],
      url: "/*",
      handler: async (request, reply) => {
        const targetPath = "/" + (request.params as { "*": string })["*"];

        if (targetPath.startsWith("/v1/admin/") || targetPath === "/v1/admin") {
          return reply.code(403).send({
            code: "forbidden",
            message: "Admin routes are not accessible via the browser proxy.",
          });
        }

        const token = getSessionTokenFromNodeHeaders(request.headers);
        const headers = new Headers(
          Object.entries(request.headers).flatMap(([k, v]) =>
            Array.isArray(v)
              ? v.map((val) => [k, val] as [string, string])
              : v !== undefined
              ? [[k, v] as [string, string]]
              : []
          ),
        );
        headers.delete("cookie");
        headers.delete("host");
        if (token) headers.set("Authorization", `Bearer ${token}`);

        const rawUrl = `http://proxy${request.url}`;
        const searchParams = new URL(rawUrl).searchParams;
        const body = request.body instanceof Buffer && request.body.length > 0
          ? request.body
          : null;

        const res = await proxyRequest(
          request.method,
          targetPath,
          searchParams,
          headers,
          body,
          authServiceUrl,
          cookieOpts,
          rawUrl,
        );

        reply.code(res.status);
        res.headers.forEach((value, key) => {
          reply.header(key, value);
        });
        const buf = Buffer.from(await res.arrayBuffer());
        return reply.send(buf);
      },
    });
  };
}
