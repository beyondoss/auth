import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";

export type MagicLinkResponse = Camelize<
  components["schemas"]["MagicLinkResponse"]
>;

export const requestMagicLink = (client: Client<paths>, email: string) =>
  wrap(client.POST("/v1/magic-links", { body: { email } }));
