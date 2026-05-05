import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { snakenize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";

export type Passkey = Camelize<components["schemas"]["CredentialRecord"]>;
export type RegisteredPasskey = Camelize<
  components["schemas"]["RegisteredCredential"]
>;
export type PasskeyRegistrationChallenge = Camelize<
  components["schemas"]["BeginResponse"]
>;
export type FinishPasskeyRegistrationRequest = Camelize<
  components["schemas"]["FinishRegistrationRequest"]
>;

export const listPasskeys = (client: Client<paths>) =>
  wrap(client.GET("/v1/passkeys", {}));

export const beginPasskeyRegistration = (client: Client<paths>) =>
  wrap(client.POST("/v1/passkey-registrations", {}));

export const finishPasskeyRegistration = (
  client: Client<paths>,
  body: FinishPasskeyRegistrationRequest,
) =>
  wrap(client.POST("/v1/passkeys", {
    body: snakenize(
      body as Record<string, unknown>,
    ) as components["schemas"]["FinishRegistrationRequest"],
  }));

export const updatePasskey = (
  client: Client<paths>,
  id: string,
  nickname: string,
) =>
  wrap(client.PATCH("/v1/passkeys/{id}", {
    params: { path: { id } },
    body: { nickname },
  }));

export const deletePasskey = (client: Client<paths>, id: string) =>
  wrap(client.DELETE("/v1/passkeys/{id}", { params: { path: { id } } }));
