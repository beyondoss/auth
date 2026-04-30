import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";

export type MagicLinkResponse = Camelize<
  components["schemas"]["MagicLinkResponse"]
>;

export async function requestMagicLink(
  client: Client<paths>,
  email: string,
): Promise<MagicLinkResponse> {
  const { data, error, response } = await client.POST("/v1/magic-links", {
    body: { email },
  });
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}
