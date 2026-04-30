import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";
import { wrap } from "../utils/wrap.js";

export type EmailRecord = Camelize<components["schemas"]["EmailRecord"]>;
export type OttTokenResponse = Camelize<
  components["schemas"]["OttTokenResponse"]
>;

export const listEmails = (client: Client<paths>) =>
  wrap(client.GET("/v1/emails", {}));

export async function addEmail(
  client: Client<paths>,
  email: string,
): Promise<OttTokenResponse> {
  const { data, error, response } = await client.POST("/v1/emails", {
    body: { email },
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function deleteEmail(
  client: Client<paths>,
  id: string,
): Promise<void> {
  const { error, response } = await client.DELETE("/v1/emails/{id}", {
    params: { path: { id } },
  });
  if (error !== undefined) throwServiceError(error, response);
}

export async function makeEmailPrimary(
  client: Client<paths>,
  id: string,
): Promise<void> {
  const { error, response } = await client.PUT("/v1/emails/{id}", {
    params: { path: { id } },
  });
  if (error !== undefined) throwServiceError(error, response);
}

export async function createEmailVerification(
  client: Client<paths>,
  id: string,
): Promise<OttTokenResponse> {
  const { data, error, response } = await client.POST(
    "/v1/emails/{id}/verifications",
    { params: { path: { id } } },
  );
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}
