import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize, snakenize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";

export type MeResponse = Camelize<components["schemas"]["MeResponse"]>;
export type UpdateMeRequest = Camelize<components["schemas"]["UpdateMeRequest"]>;

export async function getMe(client: Client<paths>): Promise<MeResponse> {
  const { data, error, response } = await client.GET("/v1/users/me", {});
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function updateMe(
  client: Client<paths>,
  body: UpdateMeRequest,
): Promise<MeResponse> {
  const { data, error, response } = await client.PATCH("/v1/users/me", {
    body: snakenize(
      body as Record<string, unknown>,
    ) as components["schemas"]["UpdateMeRequest"],
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function deleteMe(client: Client<paths>): Promise<void> {
  const { error, response } = await client.DELETE("/v1/users/me", {});
  if (error !== undefined) throwServiceError(error, response);
}
