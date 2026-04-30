import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize, snakenize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";
import { wrap } from "../utils/wrap.js";

export type PasskeyRecord = Camelize<components["schemas"]["CredentialRecord"]>;
export type RegisteredPasskey = Camelize<components["schemas"]["RegisteredCredential"]>;
export type BeginPasskeyRegistrationResponse = Camelize<components["schemas"]["BeginResponse"]>;
export type FinishPasskeyRegistrationRequest = Camelize<
  components["schemas"]["FinishRegistrationRequest"]
>;

export const listPasskeys = (client: Client<paths>) =>
  wrap(client.GET("/v1/passkeys", {}));

export const beginPasskeyRegistration = (client: Client<paths>) =>
  wrap(client.POST("/v1/passkey-registrations", {}));

export async function finishPasskeyRegistration(
  client: Client<paths>,
  body: FinishPasskeyRegistrationRequest,
): Promise<RegisteredPasskey> {
  const { data, error, response } = await client.POST("/v1/passkeys", {
    body: snakenize(
      body as Record<string, unknown>,
    ) as components["schemas"]["FinishRegistrationRequest"],
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function updatePasskey(
  client: Client<paths>,
  id: string,
  nickname: string,
): Promise<void> {
  const { error, response } = await client.PATCH("/v1/passkeys/{id}", {
    params: { path: { id } },
    body: { nickname },
  });
  if (error !== undefined) throwServiceError(error, response);
}

export async function deletePasskey(
  client: Client<paths>,
  id: string,
): Promise<void> {
  const { error, response } = await client.DELETE("/v1/passkeys/{id}", {
    params: { path: { id } },
  });
  if (error !== undefined) throwServiceError(error, response);
}
