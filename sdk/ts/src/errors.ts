/**
 * Thrown when the auth service returns a non-2xx response.
 *
 * @example
 * ```ts
 * try {
 *   await verifier.verify(token)
 * } catch (err) {
 *   if (err instanceof AuthServiceError) {
 *     console.error(err.code, err.message)
 *   }
 * }
 * ```
 */
export class AuthServiceError extends Error {
  /** Machine-readable error code returned by the auth service. */
  readonly code: string;
  /** HTTP status code of the response. */
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "AuthServiceError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Thrown when JWT verification fails — expired token, bad signature, wrong
 * issuer/audience, or any other validation failure.
 *
 * @example
 * ```ts
 * try {
 *   const claims = await verifier.verify(jwt)
 * } catch (err) {
 *   if (err instanceof JwtVerificationError) {
 *     console.error('invalid token:', err.message)
 *   }
 * }
 * ```
 */
export class JwtVerificationError extends Error {
  /** `true` when the failure is transient (e.g. JWKS fetch timeout) and a retry may succeed. */
  readonly retryable: boolean;

  constructor(message: string, cause?: unknown, retryable = false) {
    super(message, { cause });
    this.name = "JwtVerificationError";
    this.retryable = retryable;
  }
}
