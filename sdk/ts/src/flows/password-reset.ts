import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";

export type PasswordResetResponse = Camelize<
  components["schemas"]["PasswordResetResponse"]
>;

export async function requestPasswordReset(
  client: Client<paths>,
  email: string,
): Promise<PasswordResetResponse> {
  const { data, error, response } = await client.POST("/v1/password-resets", {
    body: { email },
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}
