import createFetchClient from "openapi-fetch";
import * as v from "valibot";
import { AuthServiceError } from "./errors.js";
import type { components, paths } from "./types.js";

const ErrorBody = v.object({
  error: v.optional(
    v.object({
      code: v.optional(v.string()),
      message: v.optional(v.string()),
    }),
  ),
});

/** Options for {@link createSessionVerifier}. */
export interface SessionVerifierOptions {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  baseUrl: string;
}

/**
 * The context returned when an opaque session token is verified.
 * Shape is sourced directly from the auth service's `CurrentSessionResponse` schema.
 */
export type SessionContext = components["schemas"]["CurrentSessionResponse"];

/** A verifier that validates Beyond Auth opaque session tokens. */
export interface SessionVerifier {
  /**
   * Verifies an opaque session token against the auth service.
   *
   * Calls `GET /v1/sessions/current` with the token as a Bearer credential.
   * Returns the session context on success, or `null` when the token is
   * absent, invalid, or expired (401).
   *
   * @param token - Raw opaque session token.
   * @returns Session context, or `null` for an invalid/expired token.
   * @throws {AuthServiceError} On unexpected auth service errors (5xx, etc.).
   *
   * @example
   * ```ts
   * const ctx = await verifier.verify(token)
   * if (!ctx) return new Response('Unauthorized', { status: 401 })
   * console.log(ctx.id) // session ID
   * ```
   */
  verify(token: string): Promise<SessionContext | null>;
}

/**
 * Creates a verifier for Beyond Auth opaque session tokens.
 *
 * Each call to `verify` makes a lightweight HTTP request to the auth service.
 * For RSC trees where `verify` might be called multiple times per request,
 * wrap it with React's `cache()` (see `@beyond.dev/auth/next`).
 *
 * @param opts - Verifier configuration.
 * @returns A stateless verifier. Safe to share across requests.
 *
 * @example
 * ```ts
 * const verifier = createSessionVerifier({ baseUrl: 'http://auth:8080' })
 * const ctx = await verifier.verify(token)
 * ```
 */
export function createSessionVerifier(
  opts: SessionVerifierOptions,
): SessionVerifier {
  const client = createFetchClient<paths>({
    baseUrl: opts.baseUrl.replace(/\/+$/, ""),
  });

  return {
    async verify(token: string): Promise<SessionContext | null> {
      const { data, error, response } = await client.GET(
        "/v1/sessions/current",
        { headers: { Authorization: `Bearer ${token}` } },
      );

      if (response.status === 401) return null;

      if (error !== undefined) {
        const parsed = v.safeParse(ErrorBody, error);
        const body = parsed.success ? parsed.output : {};
        throw new AuthServiceError(
          body.error?.code ?? "unknown_error",
          body.error?.message ?? response.statusText,
          response.status,
        );
      }

      if (data === undefined) {
        throw new AuthServiceError(
          "unexpected_response",
          "Auth service returned success with no session data",
          response.status,
        );
      }
      return data;
    },
  };
}
