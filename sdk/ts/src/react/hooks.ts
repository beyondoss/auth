import React from "react";
import type { MeResponse } from "../next/server.js";
import { camelize } from "../utils/camelize.js";
import { useAuthContext } from "./context.js";

export type AuthStatus = "loading" | "authenticated" | "unauthenticated";

export interface UseAuthResult {
  status: AuthStatus;
  user: MeResponse | null;
}

function camelizeMeResponse(data: unknown): MeResponse | null {
  return data != null ? (camelize(data) as unknown as MeResponse) : null;
}

/**
 * Returns the current auth status and user without suspending.
 * Safe to use for auth-gating — won't throw while loading.
 */
export function useAuth(): UseAuthResult {
  const { client, onSessionExpired } = useAuthContext();
  const result = client.useInlineLoader({ path: "GET /v1/users/me" });
  const prevStatus = React.useRef<AuthStatus>("loading");

  const is401 = result.lastError?.response?.status === 401;
  const status: AuthStatus =
    result.status === "fetching" && result.data === undefined
      ? "loading"
      : is401
      ? "unauthenticated"
      : result.data !== undefined
      ? "authenticated"
      : "loading";

  React.useEffect(() => {
    if (
      prevStatus.current === "authenticated"
      && status === "unauthenticated"
      && onSessionExpired
    ) {
      onSessionExpired();
    }
    prevStatus.current = status;
  }, [status, onSessionExpired]);

  return {
    status,
    user: camelizeMeResponse(result.data),
  };
}

/**
 * Returns the current user, suspending until loaded.
 * Use inside authenticated subtrees with a Suspense boundary.
 */
export function useUser(): MeResponse {
  const { client } = useAuthContext();
  const result = client.useLoader({ path: "GET /v1/users/me" });
  return camelizeMeResponse(result.data)!;
}
