import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";

export type TokenResponse = Camelize<components["schemas"]["TokenResponse"]>;

export const issueToken = (
  client: Client<paths>,
  token: string,
  claims?: Record<string, unknown>,
) =>
  wrap(client.POST("/v1/tokens", {
    headers: { Authorization: `Bearer ${token}` },
    body: { claims: claims ?? null },
  }));
