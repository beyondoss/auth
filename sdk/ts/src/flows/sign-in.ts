import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { snakenize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";
import type { AuthResponse } from "./sign-up.js";

export type SignInRequest = Camelize<components["schemas"]["LoginRequest"]>;
export type StepUpResponse = Camelize<components["schemas"]["StepUpResponse"]>;
export type PasskeyAuthChallenge = Camelize<
  components["schemas"]["BeginResponse"]
>;

export const signIn = (client: Client<paths>, body: SignInRequest) =>
  wrap(client.POST("/v1/sessions", {
    body: snakenize(
      body as Record<string, unknown>,
    ) as components["schemas"]["LoginRequest"],
  }));

export const beginPasskeyAuth = (client: Client<paths>) =>
  wrap(client.POST("/v1/passkey-authentications", {}));

export const completeTotpStepUp = (
  client: Client<paths>,
  stepUpToken: string,
  code: string,
) =>
  wrap(client.POST("/v1/sessions", {
    body: { grant_type: "totp_step_up", step_up_token: stepUpToken, code },
  }));

export const completeTotpRecovery = (
  client: Client<paths>,
  stepUpToken: string,
  code: string,
) =>
  wrap(client.POST("/v1/sessions", {
    body: { grant_type: "totp_recovery", step_up_token: stepUpToken, code },
  }));

export const finishPasskeyAuth = (
  client: Client<paths>,
  stateToken: string,
  credential: Record<string, unknown>,
) =>
  wrap(client.POST("/v1/sessions", {
    body: {
      grant_type: "passkey",
      state_token: stateToken,
      credential,
    } as components["schemas"]["LoginRequest"],
  }));

/**
 * Type guard — returns `true` when `signIn` returned a step-up challenge
 * rather than a completed session.
 *
 * @example
 * ```ts
 * const { data: result } = await flows.signIn({ grantType: 'password', email, password })
 * if (isStepUpResponse(result!)) {
 *   // TOTP required — redirect to /verify-totp with result.stepUpToken
 * } else {
 *   // result.session.token — set cookie and proceed
 * }
 * ```
 */
export function isStepUpResponse(
  result: AuthResponse | StepUpResponse,
): result is StepUpResponse {
  return "stepUpToken" in result;
}
