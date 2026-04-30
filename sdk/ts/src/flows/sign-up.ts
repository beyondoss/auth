import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize, snakenize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";

export type SignUpRequest = Camelize<components["schemas"]["SignupRequest"]>;
export type AuthResponse = Camelize<components["schemas"]["AuthResponse"]>;

export async function signUp(
  client: Client<paths>,
  body: SignUpRequest,
): Promise<AuthResponse> {
  const { data, error, response } = await client.POST("/v1/users", {
    body: snakenize(
      body as Record<string, unknown>,
    ) as components["schemas"]["SignupRequest"],
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}
