import createFetchClient, { type Client } from "openapi-fetch";
import type { components, paths } from "../types.js";

export type AuthResponse = components["schemas"]["AuthResponse"];

export function getBaseUrl(): string {
  const url = process.env["BEYOND_AUTH_URL"];
  if (!url) {
    throw new Error("BEYOND_AUTH_URL not set — is globalSetup running?");
  }
  return url;
}

export function getAdminSecret(): string {
  const secret = process.env["BEYOND_AUTH_ADMIN_SECRET"];
  if (!secret) {
    throw new Error(
      "BEYOND_AUTH_ADMIN_SECRET not set — is globalSetup running?",
    );
  }
  return secret;
}

/** Unauthenticated client — public endpoints (signup, login, etc.). */
export function publicClient(): Client<paths> {
  return createFetchClient<paths>({ baseUrl: getBaseUrl() });
}

/** Admin-authenticated client. */
export function adminClient(): Client<paths> {
  return createFetchClient<paths>({
    baseUrl: getBaseUrl(),
    headers: { Authorization: `Bearer ${getAdminSecret()}` },
  });
}

/** Session-authenticated client for a specific bearer token. */
export function authedClient(token: string): Client<paths> {
  return createFetchClient<paths>({
    baseUrl: getBaseUrl(),
    headers: { Authorization: `Bearer ${token}` },
  });
}

export function uniqueEmail(): string {
  return `${crypto.randomUUID()}@test.local`;
}

export async function signup(
  email: string,
  password: string,
): Promise<AuthResponse> {
  const { data, error } = await publicClient().POST("/v1/users", {
    body: { email, password },
  });
  if (!data) throw new Error(`signup failed: ${JSON.stringify(error)}`);
  return data;
}

export async function login(
  email: string,
  password: string,
): Promise<AuthResponse> {
  const { data, error, response } = await publicClient().POST("/v1/sessions", {
    body: { grant_type: "password", email, password },
  });
  if (response.status !== 201 || !data) {
    throw new Error(
      `login failed (${response.status}): ${JSON.stringify(error ?? data)}`,
    );
  }
  // 201 = AuthResponse; 200 = StepUpResponse (MFA). Test users have no MFA.
  return data as AuthResponse;
}
