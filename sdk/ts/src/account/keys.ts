import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";

export type ApiKey = Camelize<components["schemas"]["Key"]>;
export type ApiKeyWithSecret = Camelize<
  components["schemas"]["CreateResponse"]
>;

export const listKeys = (client: Client<paths>) =>
  wrap(client.GET("/v1/keys", {}));

export const createKey = (
  client: Client<paths>,
  name: string,
  expiresAt?: string,
) =>
  wrap(client.POST("/v1/keys", {
    body: expiresAt !== undefined ? { name, expires_at: expiresAt } : { name },
  }));

export const getKey = (client: Client<paths>, id: string) =>
  wrap(client.GET("/v1/keys/{id}", { params: { path: { id } } }));

export const deleteKey = (client: Client<paths>, id: string) =>
  wrap(client.DELETE("/v1/keys/{id}", { params: { path: { id } } }));
