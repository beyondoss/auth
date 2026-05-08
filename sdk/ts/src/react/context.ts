import React from "react";
import type { StepUpResponse } from "../flows/sign-in.js";
import type { createClient } from "./client.js";
import type { paths } from "./types.js";

export type AuthClient = ReturnType<typeof createClient<paths>>;

export interface AuthContextValue {
  client: AuthClient;
  stepUp: StepUpResponse | null;
  setStepUp: React.Dispatch<React.SetStateAction<StepUpResponse | null>>;
  onSessionExpired?: () => void;
}

export const AuthContext = React.createContext<AuthContextValue | null>(null);

export function useAuthContext(): AuthContextValue {
  const ctx = React.useContext(AuthContext);
  if (!ctx) {
    throw new Error(
      "Beyond Auth hooks must be used inside <AuthProvider>. "
        + "Wrap your app with the AuthProvider returned from createBrowserAuth().",
    );
  }
  return ctx;
}
