import createFetchClient from "openapi-fetch";
import type { paths } from "../types.js";
import { requestMagicLink } from "./magic-link.js";
import { requestPasswordReset } from "./password-reset.js";
import { beginPasskeyAuth, signIn } from "./sign-in.js";
import { signOut, signOutAll } from "./sign-out.js";
import { signUp } from "./sign-up.js";
import { issueToken } from "./token.js";

export type { MagicLinkResponse } from "./magic-link.js";
export type { PasswordResetResponse } from "./password-reset.js";
export type {
  BeginPasskeyAuthResponse,
  SignInRequest,
  StepUpResponse,
} from "./sign-in.js";
export type { AuthResponse } from "./sign-up.js";
export type { TokenResponse } from "./token.js";

/** Options for {@link createAuthFlowClient}. */
export interface AuthFlowClientOptions {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  baseUrl: string;
}

/** @see {@link createAuthFlowClient} */
export interface AuthFlowClient {
  signUp: ReturnType<typeof createAuthFlowClient>["signUp"];
  signIn: ReturnType<typeof createAuthFlowClient>["signIn"];
  beginPasskeyAuth: ReturnType<typeof createAuthFlowClient>["beginPasskeyAuth"];
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
 * const flows = createAuthFlowClient({ baseUrl: process.env.AUTH_URL! })
 *
 * // Sign up
 * const { session } = await flows.signUp({ email, password })
 *
 * // Sign in — TypeScript narrows required fields by grantType
 * const result = await flows.signIn({ grantType: 'password', email, password })
 * if ('stepUpRequired' in result) {
 *   // TOTP step-up needed — result.stepUpToken is available
 * }
 *
 * // Magic link round-trip
 * const { token } = await flows.requestMagicLink(email)
 * const auth = await flows.signIn({ grantType: 'magic_link', token })
 *
 * // Sign out
 * await flows.signOut(sessionToken)
 * ```
 */
export function createAuthFlowClient(opts: AuthFlowClientOptions) {
  const client = createFetchClient<paths>({
    baseUrl: opts.baseUrl.replace(/\/+$/, ""),
  });

  return {
    signUp: (body: Parameters<typeof signUp>[1]) => signUp(client, body),
    signIn: (body: Parameters<typeof signIn>[1]) => signIn(client, body),
    beginPasskeyAuth: () => beginPasskeyAuth(client),
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
