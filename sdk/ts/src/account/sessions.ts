import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { camelize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { throwServiceError } from "../utils/error.js";
import { wrap } from "../utils/wrap.js";

export type SessionListItem = Camelize<
  components["schemas"]["SessionListItem"]
>;

export const listSessions = (client: Client<paths>) =>
  wrap(client.GET("/v1/sessions", {}));

export async function getCurrentSession(
  client: Client<paths>,
): Promise<Camelize<components["schemas"]["CurrentSessionResponse"]>> {
  const { data, error, response } = await client.GET(
    "/v1/sessions/current",
    {},
  );
  if (error !== undefined) throwServiceError(error, response);
  return camelize(data!);
}

export async function deleteSessionById(
  client: Client<paths>,
  id: string,
): Promise<void> {
  const { error, response } = await client.DELETE("/v1/sessions/{id}", {
    params: { path: { id } },
  });
  if (error !== undefined) throwServiceError(error, response);
}
