import type {
  FastifyPluginCallback,
  FastifyReply,
  FastifyRequest,
} from "fastify";
import fp from "fastify-plugin";
import type { Auth } from "../auth.js";
import type { CheckSessionArgs, SchemaInput } from "../authz.js";
import { AuthError, AuthzError } from "../errors.js";
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

export interface AuthnPluginOptions {
  /** Unified server-side auth handle from `createAuth` (or the lazy `auth` singleton). */
  auth: Auth;
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
 * `fp()` is applied internally so `request.auth` is visible across the entire
 * app. Tokens are read from the `__Host-session` / `__Secure-session` cookie
 * first, with an `Authorization: Bearer` fallback.
 *
 * **If your route also runs an {@link authz} check, prefer `authz` alone — it
 * does both in one call.** Use `authn` for routes that need a session but no
 * specific permission gating.
 *
 * @example
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 * import { authn } from '@beyond.dev/auth/fastify'
 *
 * await app.register(authn, { auth, publicPaths: ['/health'] })
 * ```
 */
export const authn: FastifyPluginCallback<AuthnPluginOptions> = fp(
  (fastify, opts: AuthnPluginOptions, done) => {
    const { auth, publicPaths = [], onUnauthorized } = opts;
    const handleUnauthorized = onUnauthorized
      ?? (async (_request: FastifyRequest, reply: FastifyReply) => {
        await reply.code(401).send({ code: "unauthorized" });
      });

    fastify.decorateRequest("auth", null);

    fastify.addHook("preHandler", async (request, reply) => {
      if (matchesPublicPath(request.url, publicPaths)) return;

      const token = getSessionTokenFromNodeHeaders(request.headers);
      if (!token) {
        return handleUnauthorized(request, reply);
      }

      const result = await auth.verify(token);
      if (result.error) {
        if (result.error instanceof AuthError && result.error.status >= 500) {
          throw result.error;
        }
        return handleUnauthorized(request, reply);
      }
      if (!result.data) {
        return handleUnauthorized(request, reply);
      }

      request.auth = result.data as SessionContext;
    });

    done();
  },
  { name: "@beyond.dev/auth", fastify: ">=4" },
);

export interface AuthzPluginOptions {
  /**
   * Called when the permission check is denied. Send an error reply and
   * return. Defaults to `{ code: 'forbidden' }` with status 403.
   */
  onForbidden?: (
    request: FastifyRequest,
    reply: FastifyReply,
  ) => void | Promise<void>;
}

/**
 * Creates a Fastify `preHandler` hook that enforces a permission check using
 * Zanzibar-style authorization.
 *
 * **Validates the session AND checks the permission in a single bundled call.**
 * Populates `request.auth` with the resolved session context. **You do not
 * need to stack `authn` before `authz` — it's a strict superset.**
 *
 * The canonical Fastify pattern (matching `@fastify/auth` / `@fastify/jwt`)
 * is per-route via the route's `preHandler` array. For a route group sharing
 * one check, register the hook inside a scoped plugin.
 *
 * `getCheck` receives the request and returns the resource, id, and permission
 * to check — allowing dynamic values from route params.
 *
 * @example Per-route (canonical Fastify pattern)
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 * import { authz } from '@beyond.dev/auth/fastify'
 *
 * app.get('/docs/:id', {
 *   preHandler: authz(auth, (req) => ({
 *     resource: 'document',
 *     id: (req.params as { id: string }).id,
 *     permission: 'read',
 *   })),
 * }, async (request) => ({ user: request.auth }))
 * ```
 *
 * @example Scoped over a route group
 * ```ts
 * await app.register(async (instance) => {
 *   instance.addHook('preHandler', authz(auth, getCheck))
 *   instance.get('/:id', handler)
 *   instance.delete('/:id', handler)
 * }, { prefix: '/docs' })
 * ```
 */
export function authz<S extends SchemaInput>(
  auth: Auth<S>,
  getCheck: (request: FastifyRequest) => Omit<CheckSessionArgs<S>, "token">,
  opts?: AuthzPluginOptions,
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  const onForbidden = opts?.onForbidden
    ?? (async (_request: FastifyRequest, reply: FastifyReply) => {
      await reply.code(403).send({ code: "forbidden" });
    });

  return async (request, reply) => {
    const token = getSessionTokenFromNodeHeaders(request.headers);
    if (!token) {
      return reply.code(401).send({ code: "unauthorized" });
    }

    const check = getCheck(request);
    const result = await auth.checkSession({
      token,
      ...check,
    } as CheckSessionArgs<S>);

    if (result.error) {
      if (
        result.error instanceof AuthzError
        && (result.error.code === "authz_not_enabled"
          || result.error.code === "authz_unknown_resource"
          || result.error.code === "authz_unknown_permission")
      ) {
        throw result.error;
      }
      if (result.error instanceof AuthError) {
        if (result.error.status === 401) {
          return reply.code(401).send({ code: "unauthorized" });
        }
        if (result.error.status >= 500) {
          throw result.error;
        }
      }
      return onForbidden(request, reply);
    }

    if (!result.data.allowed) return onForbidden(request, reply);
    // Bundled response carries the resolved session context — populate
    // request.auth so handlers don't need a separate authn() in the chain.
    request.auth = result.data.session;
  };
}

export interface ProxyPluginOptions extends ProxyOptions {
  /** Unified server-side auth handle from `createAuth` (or the lazy `auth` singleton). */
  auth: Auth;
}

/**
 * Fastify plugin that proxies requests to the private auth service.
 *
 * NOT wrapped with `fastify-plugin` — prefix isolation is required so the
 * content-type parser override is scoped only to these routes.
 *
 * @example
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 * import { proxy } from '@beyond.dev/auth/fastify'
 *
 * await app.register(proxy, { auth, prefix: '/api/auth' })
 * ```
 *
 * - Blocks `/v1/admin/**` with 403
 * - Reads the session cookie, forwards it as `Authorization: Bearer`
 * - On sign-in (POST /v1/sessions → 201): sets httpOnly cookie, strips token from body
 * - On sign-out (DELETE /v1/sessions/current or /v1/sessions): clears cookie
 * - All JSON responses are camelCased
 */
export const proxy: FastifyPluginCallback<ProxyPluginOptions> = (
  fastify,
  opts,
  done,
) => {
  const authServiceUrl = opts.auth.url;
  const cookieOpts = {
    ...(opts.domain !== undefined ? { domain: opts.domain } : {}),
    ...(opts.maxAge !== undefined ? { maxAge: opts.maxAge } : {}),
  };

  // Body of the original async plugin, run synchronously inside this callback.
  // Content-type parser override + the catch-all route are registered before
  // calling done() so prefix isolation is preserved (no fp() wrapper).
  {
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
  }

  done();
};
