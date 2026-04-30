import type { Client } from "openapi-fetch";
import type { paths } from "../types.js";
import { throwServiceError } from "../utils/error.js";

export async function signOut(
  client: Client<paths>,
  token: string,
): Promise<void> {
  const { error, response } = await client.DELETE("/v1/sessions/current", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (error !== undefined) throwServiceError(error, response);
}

export async function signOutAll(
  client: Client<paths>,
  token: string,
  opts?: { exceptCurrent?: boolean },
): Promise<void> {
  const { error, response } = await client.DELETE("/v1/sessions", {
    headers: { Authorization: `Bearer ${token}` },
    params: {
      query: opts?.exceptCurrent !== undefined
        ? { except_current: opts.exceptCurrent }
        : {},
    },
  });
  if (error !== undefined) throwServiceError(error, response);
}
