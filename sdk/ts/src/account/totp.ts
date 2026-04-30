import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";

export type TotpEnrollmentResponse = Camelize<components["schemas"]["EnrollmentResponse"]>;
export type RecoveryCodesResponse = Camelize<components["schemas"]["RecoveryCodesResponse"]>;

export async function enrollTotp(
  client: Client<paths>,
): Promise<TotpEnrollmentResponse> {
  const { data, error, response } = await client.POST("/v1/totp", {});
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function confirmTotp(
  client: Client<paths>,
  code: string,
): Promise<RecoveryCodesResponse> {
  const { data, error, response } = await client.POST("/v1/totp/confirmations", {
    body: { code },
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function disableTotp(client: Client<paths>): Promise<void> {
  const { error, response } = await client.DELETE("/v1/totp", {});
  if (error !== undefined) throwServiceError(error, response);
}

export async function regenerateTotpRecoveryCodes(
  client: Client<paths>,
  code: string,
): Promise<RecoveryCodesResponse> {
  const { data, error, response } = await client.POST(
    "/v1/totp/recovery-codes",
    { body: { code } },
  );
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}
