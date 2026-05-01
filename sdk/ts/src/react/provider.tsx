import React from "react";
import type { StepUpResponse } from "../flows/sign-in.js";
import type { MeResponse } from "../next/server.js";
import { AuthContext } from "./context.js";
import type { AuthClient } from "./context.js";

export interface AuthProviderProps {
  children: React.ReactNode;
  /**
   * Pre-fetched user from the server (e.g. from getMe() in an RSC layout).
   * Seeds the client-side cache to prevent a loading flash on first render.
   */
  initialUser?: MeResponse | null;
  /**
   * Called when the session transitions from authenticated to unauthenticated.
   * Use this to redirect to the login page.
   */
  onSessionExpired?: () => void;
}

interface Props extends AuthProviderProps {
  client: AuthClient;
}

export function AuthProvider({
  children,
  client,
  initialUser,
  onSessionExpired,
}: Props) {
  const [stepUp, setStepUp] = React.useState<StepUpResponse | null>(null);

  React.useMemo(() => {
    if (initialUser) {
      client.seed("GET /v1/users/me", initialUser as any);
    }
    // Only run once on mount — seed is idempotent when data is already present
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value = React.useMemo(
    () => ({
      client,
      stepUp,
      setStepUp,
      ...(onSessionExpired !== undefined ? { onSessionExpired } : {}),
    }),
    [client, stepUp, setStepUp, onSessionExpired],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
