import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";

export type Email = Camelize<components["schemas"]["EmailRecord"]>;
export type OttTokenResponse = Camelize<
  components["schemas"]["OttTokenResponse"]
>;

export const listEmails = (client: Client<paths>) =>
  wrap(client.GET("/v1/emails", {}));

export const addEmail = (client: Client<paths>, email: string) =>
  wrap(client.POST("/v1/emails", { body: { email } }));

export const deleteEmail = (client: Client<paths>, id: string) =>
  wrap(client.DELETE("/v1/emails/{id}", { params: { path: { id } } }));

export const makeEmailPrimary = (client: Client<paths>, id: string) =>
  wrap(client.PUT("/v1/emails/{id}", { params: { path: { id } } }));

export const createEmailVerification = (client: Client<paths>, id: string) =>
  wrap(
    client.POST("/v1/emails/{id}/verifications", { params: { path: { id } } }),
  );
