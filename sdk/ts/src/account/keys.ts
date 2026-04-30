import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";
import { wrap } from "../utils/wrap.js";

export type ApiKey = Camelize<components["schemas"]["Key"]>;
export type ApiKeyWithSecret = Camelize<
  components["schemas"]["CreateResponse"]
>;

export const listKeys = (client: Client<paths>) =>
  wrap(client.GET("/v1/keys", {}));

export async function createKey(
  client: Client<paths>,
  name: string,
  expiresAt?: string,
): Promise<ApiKeyWithSecret> {
  const { data, error, response } = await client.POST("/v1/keys", {
    body: expiresAt !== undefined ? { name, expires_at: expiresAt } : { name },
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function getKey(
  client: Client<paths>,
  id: string,
): Promise<ApiKey> {
  const { data, error, response } = await client.GET("/v1/keys/{id}", {
    params: { path: { id } },
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function deleteKey(
  client: Client<paths>,
  id: string,
): Promise<void> {
  const { error, response } = await client.DELETE("/v1/keys/{id}", {
    params: { path: { id } },
  });
  if (error !== undefined) throwServiceError(error, response);
}
