import type { Client } from "openapi-fetch";
import type { paths } from "../types.js";
import { wrap } from "../utils/wrap.js";

export const signOut = (client: Client<paths>, token: string) =>
  wrap(client.DELETE("/v1/sessions/current", {
    headers: { Authorization: `Bearer ${token}` },
  }));

export const signOutAll = (
  client: Client<paths>,
  token: string,
  opts?: { exceptCurrent?: boolean },
) =>
  wrap(client.DELETE("/v1/sessions", {
    headers: { Authorization: `Bearer ${token}` },
    params: {
      query: opts?.exceptCurrent !== undefined
        ? { except_current: opts.exceptCurrent }
        : {},
    },
  }));
