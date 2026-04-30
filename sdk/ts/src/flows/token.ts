import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";

export type TokenResponse = Camelize<components["schemas"]["TokenResponse"]>;

export async function issueToken(
  client: Client<paths>,
  token: string,
  claims?: Record<string, unknown>,
): Promise<TokenResponse> {
  const { data, error, response } = await client.POST("/v1/tokens", {
    headers: { Authorization: `Bearer ${token}` },
    body: { claims: claims ?? null },
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}
