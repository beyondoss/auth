import {
  createRemoteJWKSet,
  errors as joseErrors,
  type JWTPayload,
  jwtVerify,
  type JWTVerifyOptions,
  type RemoteJWKSetOptions,
} from "jose";
import { JwtVerificationError } from "./errors.js";

export type VerifyResult<T, E extends Error = Error> =
  | { data: T; error: undefined }
  | { data: undefined; error: E };

/** Options for {@link createJwtVerifier}. */
export interface JwtVerifierOptions {
  /** Full URL to the JWKS endpoint, e.g. `https://auth.example.com/v1/jwks.json`. */
  jwksUri: string;
  /** Expected `iss` claim. Tokens with a different issuer are rejected. */
  issuer: string;
  /**
   * Expected `aud` claim. When provided, tokens without a matching audience
   * are rejected. Leave unset if the auth service is not issuing audience-scoped tokens.
   */
  audience?: string;
  /**
   * Tolerated clock skew in seconds for `exp` and `nbf` validation.
   * @defaultValue 30
   */
  clockSkewSeconds?: number;
  /**
   * Number of additional attempts after a transient failure (JWKS network error
   * or timeout). Non-retryable failures (bad signature, expired token, wrong
   * issuer) are never retried. Default: 0 (no retries).
   */
  retryAttempts?: number;
  /**
   * Base delay in milliseconds for exponential backoff between retry attempts.
   * Actual delay for attempt N is `retryDelay * 2^(N-1)`.
   * @defaultValue 100
   */
  retryDelay?: number;
}

/** Verified JWT claims. */
export interface JwtClaims extends JWTPayload {
  /** Subject — the user ID. */
  sub: string;
}

/** A verifier that validates Beyond Auth JWTs against the live JWKS. */
export interface JwtVerifier {
  /**
   * Verifies a JWT access token and returns its claims.
   *
   * Fetches the JWKS from the configured endpoint on first call (and caches
   * it for one hour). On an unknown `kid`, the cache is refreshed once before
   * the token is rejected.
   *
   * @param token - Raw JWT string (without `Bearer ` prefix).
   * @returns `{ data: JwtClaims }` on success; `{ error: JwtVerificationError }` on any failure.
   *
   * @example
   * ```ts
   * const { data, error } = await verifier.verify(accessToken)
   * if (error) return new Response('Unauthorized', { status: 401 })
   * console.log(data.sub) // user ID
   * ```
   */
  verify(token: string): Promise<VerifyResult<JwtClaims, JwtVerificationError>>;
}

/**
 * Creates a JWT verifier backed by the auth service's JWKS endpoint.
 *
 * The verifier caches the key set for one hour. On an unknown `kid` it
 * refreshes the cache once before rejecting the token — this handles key
 * rotation without requiring a restart.
 *
 * @param opts - Verifier configuration.
 * @returns A stateful verifier. Create once and reuse for the lifetime of your server.
 *
 * @example
 * ```ts
 * const verifier = createJwtVerifier({
 *   jwksUri: 'https://auth.example.com/v1/jwks.json',
 *   issuer: 'https://auth.example.com',
 * })
 * const claims = await verifier.verify(token)
 * ```
 */
export function createJwtVerifier(opts: JwtVerifierOptions): JwtVerifier {
  const jwksOptions: RemoteJWKSetOptions = {
    cacheMaxAge: 60 * 60 * 1000, // 1 hour
    cooldownDuration: 30_000,
  };

  const jwks = createRemoteJWKSet(new URL(opts.jwksUri), jwksOptions);

  const verifyOptions: JWTVerifyOptions = {
    issuer: opts.issuer,
    clockTolerance: opts.clockSkewSeconds ?? 30,
  };
  if (opts.audience !== undefined) {
    verifyOptions.audience = opts.audience;
  }

  const maxAttempts = 1 + (opts.retryAttempts ?? 0);
  const retryDelay = opts.retryDelay ?? 100;

  return {
    async verify(
      token: string,
    ): Promise<VerifyResult<JwtClaims, JwtVerificationError>> {
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        if (attempt > 0) {
          await new Promise<void>((res) =>
            setTimeout(res, retryDelay * 2 ** (attempt - 1))
          );
        }
        try {
          const { payload } = await jwtVerify(token, jwks, verifyOptions);
          if (!payload.sub) {
            return {
              data: undefined,
              error: new JwtVerificationError("JWT is missing sub claim"),
            };
          }
          return { data: payload as JwtClaims, error: undefined };
        } catch (err) {
          if (err instanceof JwtVerificationError) {
            if (err.retryable && attempt < maxAttempts - 1) continue;
            return { data: undefined, error: err };
          }
          // JWKSTimeout = explicit JWKS fetch timeout; non-JOSEError = network failure.
          const retryable = err instanceof joseErrors.JWKSTimeout
            || !(err instanceof joseErrors.JOSEError);
          const wrapped = new JwtVerificationError(
            err instanceof Error ? err.message : "JWT verification failed",
            err,
            retryable,
          );
          if (retryable && attempt < maxAttempts - 1) continue;
          return { data: undefined, error: wrapped };
        }
      }
      // unreachable — loop always returns
      return {
        data: undefined,
        error: new JwtVerificationError("JWT verification failed"),
      };
    },
  };
}
