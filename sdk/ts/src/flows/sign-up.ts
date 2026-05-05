import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import { snakenize } from "../utils/camelize.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";

export type SignUpRequest = Camelize<components["schemas"]["SignupRequest"]>;
export type AuthResponse = Camelize<components["schemas"]["AuthResponse"]>;

export const signUp = (client: Client<paths>, body: SignUpRequest) =>
  wrap(client.POST("/v1/users", {
    body: snakenize(
      body as Record<string, unknown>,
    ) as components["schemas"]["SignupRequest"],
  }));
