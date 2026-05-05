import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { snakenize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";

export type Profile = Camelize<components["schemas"]["MeResponse"]>;
export type UpdateMeRequest = Camelize<
  components["schemas"]["UpdateMeRequest"]
>;

export const getMe = (client: Client<paths>) =>
  wrap(client.GET("/v1/users/me", {}));

export const updateMe = (
  client: Client<paths>,
  body: UpdateMeRequest,
) =>
  wrap(client.PATCH("/v1/users/me", {
    body: snakenize(
      body as Record<string, unknown>,
    ) as components["schemas"]["UpdateMeRequest"],
  }));

export const deleteMe = (client: Client<paths>) =>
  wrap(client.DELETE("/v1/users/me", {}));
