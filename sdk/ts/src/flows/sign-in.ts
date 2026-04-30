import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize, snakenize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";
import type { AuthResponse } from "./sign-up.js";

export type SignInRequest = Camelize<components["schemas"]["LoginRequest"]>;
export type StepUpResponse = Camelize<components["schemas"]["StepUpResponse"]>;
export type BeginPasskeyAuthResponse = Camelize<
  components["schemas"]["BeginResponse"]
>;

export async function signIn(
  client: Client<paths>,
  body: SignInRequest,
): Promise<AuthResponse | StepUpResponse> {
  const { data, error, response } = await client.POST("/v1/sessions", {
    body: snakenize(
      body as Record<string, unknown>,
    ) as components["schemas"]["LoginRequest"],
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function beginPasskeyAuth(
  client: Client<paths>,
): Promise<BeginPasskeyAuthResponse> {
  const { data, error, response } = await client.POST(
    "/v1/passkey-authentications",
    {},
  );
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function completeTotpStepUp(
  client: Client<paths>,
  stepUpToken: string,
  code: string,
): Promise<AuthResponse> {
  const { data, error, response } = await client.POST("/v1/sessions", {
    body: { grant_type: "totp_step_up", step_up_token: stepUpToken, code },
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!) as AuthResponse;
}

export async function completeTotpRecovery(
  client: Client<paths>,
  stepUpToken: string,
  code: string,
): Promise<AuthResponse> {
  const { data, error, response } = await client.POST("/v1/sessions", {
    body: { grant_type: "totp_recovery", step_up_token: stepUpToken, code },
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!) as AuthResponse;
}

export async function finishPasskeyAuth(
  client: Client<paths>,
  stateToken: string,
  credential: Record<string, unknown>,
): Promise<AuthResponse> {
  const { data, error, response } = await client.POST("/v1/sessions", {
    body: {
      grant_type: "passkey",
      state_token: stateToken,
      credential,
    } as components["schemas"]["LoginRequest"],
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!) as AuthResponse;
}
