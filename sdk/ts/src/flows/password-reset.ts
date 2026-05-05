import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";

export type PasswordResetResponse = Camelize<
  components["schemas"]["PasswordResetResponse"]
>;

export const requestPasswordReset = (client: Client<paths>, email: string) =>
  wrap(client.POST("/v1/password-resets", { body: { email } }));
