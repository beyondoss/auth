import createFetchClient from "openapi-fetch";
import { env } from "std-env";
import type { paths } from "../types.js";
import { buildFetch } from "../utils/fetch.js";
import { requestMagicLink } from "./magic-link.js";
import { requestPasswordReset } from "./password-reset.js";
import {
  beginPasskeyAuth,
  completeTotpRecovery,
  completeTotpStepUp,
  finishPasskeyAuth,
  signIn,
} from "./sign-in.js";
import { signOut, signOutAll } from "./sign-out.js";
import { signUp } from "./sign-up.js";
import { issueToken } from "./token.js";

export type { MagicLinkResponse } from "./magic-link.js";
export type { PasswordResetResponse } from "./password-reset.js";
export {
  isStepUpResponse,
  type PasskeyAuthChallenge,
  type SignInRequest,
  type StepUpResponse,
} from "./sign-in.js";
export type { AuthResponse } from "./sign-up.js";
export type { TokenResponse } from "./token.js";

/** Options for {@link createAuthFlowClient}. */
export interface AuthFlowClientOptions {
  /**
   * Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically.
   * Defaults to the `BEYOND_AUTH_URL` environment variable when omitted.
   */
  url?: string;
  /** Custom fetch implementation. Defaults to `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
  /** Per-request timeout in milliseconds. */
  timeout?: number;
  /** Number of retries on transient 5xx responses. Defaults to 2. */
  retries?: number;
}

/** @see {@link createAuthFlowClient} */
export interface AuthFlowClient {
  signUp: ReturnType<typeof createAuthFlowClient>["signUp"];
  signIn: ReturnType<typeof createAuthFlowClient>["signIn"];
  beginPasskeyAuth: ReturnType<typeof createAuthFlowClient>["beginPasskeyAuth"];
  completeTotpStepUp: ReturnType<
    typeof createAuthFlowClient
  >["completeTotpStepUp"];
  completeTotpRecovery: ReturnType<
    typeof createAuthFlowClient
  >["completeTotpRecovery"];
  finishPasskeyAuth: ReturnType<
    typeof createAuthFlowClient
  >["finishPasskeyAuth"];
  signOut: ReturnType<typeof createAuthFlowClient>["signOut"];
  signOutAll: ReturnType<typeof createAuthFlowClient>["signOutAll"];
  requestMagicLink: ReturnType<typeof createAuthFlowClient>["requestMagicLink"];
  requestPasswordReset: ReturnType<
    typeof createAuthFlowClient
  >["requestPasswordReset"];
  issueToken: ReturnType<typeof createAuthFlowClient>["issueToken"];
}

/**
 * Creates a typed client for Beyond Auth flow operations.
 *
 * Covers every auth flow a developer needs: sign-up, sign-in (all grant
 * types), sign-out, magic links, password resets, passkey initiation, and
 * JWT issuance.
 *
 * All method inputs and outputs use camelCase keys. The `grantType`
 * discriminant narrows the `signIn` union — TypeScript infers the required
 * fields per variant automatically.
 *
 * Authenticated methods (`signOut`, `signOutAll`, `issueToken`) accept the
 * session token as a parameter rather than at construction time, since
 * server-side each request carries a different user's token.
 *
 * @example
 * ```ts
 * const flows = createAuthFlowClient({ baseUrl: process.env.BEYOND_AUTH_URL! })
 *
 * // Sign up
 * const { session } = await flows.signUp({ email, password })
 *
 * // Sign in — grantType narrows required fields; TOTP-enrolled users get a StepUpResponse
 * const result = await flows.signIn({ grantType: 'password', email, password })
 * if (isStepUpResponse(result)) {
 *   // Complete TOTP step-up with a 6-digit code from the authenticator app
 *   const auth = await flows.completeTotpStepUp(result.stepUpToken, totpCode)
 *   // Or use a recovery code if the user lost their authenticator
 *   const auth = await flows.completeTotpRecovery(result.stepUpToken, recoveryCode)
 * }
 *
 * // Passkey auth — begin returns WebAuthn options to pass to the browser
 * const { options, stateToken } = await flows.beginPasskeyAuth()
 * const credential = await navigator.credentials.get({ publicKey: options })
 * const auth = await flows.finishPasskeyAuth(stateToken, credential)
 *
 * // Magic link round-trip
 * const { token } = await flows.requestMagicLink(email)
 * const auth = await flows.signIn({ grantType: 'magic_link', token })
 *
 * // Sign out
 * await flows.signOut(sessionToken)
 * ```
 */
export function createAuthFlowClient(opts: AuthFlowClientOptions = {}) {
  const url = opts.url ?? env["BEYOND_AUTH_URL"];
  if (!url) {
    throw new Error(
      "BEYOND_AUTH_URL is required (pass `url` or set the BEYOND_AUTH_URL env var)",
    );
  }
  const client = createFetchClient<paths>({
    baseUrl: url.replace(/\/+$/, ""),
    fetch: buildFetch(opts.fetch, opts.retries ?? 2, opts.timeout),
  });

  return {
    signUp: (body: Parameters<typeof signUp>[1]) => signUp(client, body),
    signIn: (body: Parameters<typeof signIn>[1]) => signIn(client, body),
    beginPasskeyAuth: () => beginPasskeyAuth(client),
    completeTotpStepUp: (stepUpToken: string, code: string) =>
      completeTotpStepUp(client, stepUpToken, code),
    completeTotpRecovery: (stepUpToken: string, code: string) =>
      completeTotpRecovery(client, stepUpToken, code),
    finishPasskeyAuth: (
      stateToken: string,
      credential: Record<string, unknown>,
    ) => finishPasskeyAuth(client, stateToken, credential),
    signOut: (token: string) => signOut(client, token),
    signOutAll: (token: string, opts?: Parameters<typeof signOutAll>[2]) =>
      signOutAll(client, token, opts),
    requestMagicLink: (email: string) => requestMagicLink(client, email),
    requestPasswordReset: (email: string) =>
      requestPasswordReset(client, email),
    issueToken: (token: string, claims?: Record<string, unknown>) =>
      issueToken(client, token, claims),
  };
}
