import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";

export type Session = Camelize<
  components["schemas"]["SessionListItem"]
>;

export const listSessions = (client: Client<paths>) =>
  wrap(client.GET("/v1/sessions", {}));

export const getCurrentSession = (client: Client<paths>) =>
  wrap(client.GET("/v1/sessions/current", {}));

export const deleteSessionById = (client: Client<paths>, id: string) =>
  wrap(
    client.DELETE("/v1/sessions/{id}", { params: { path: { id } } }),
  );
