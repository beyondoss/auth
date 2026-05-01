import React from "react";
import { isStepUpResponse } from "../flows/sign-in.js";
import type { SignInRequest } from "../flows/sign-in.js";
import type { AuthResponse } from "../flows/sign-up.js";
import { camelize } from "../utils/camelize.js";
import { getRedirectParam } from "../utils/redirect.js";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type SignInStatus = "idle" | "fetching" | "success" | "error";

export interface UseSignInResult {
  signIn(req: SignInRequest): Promise<AuthResponse>;
  status: SignInStatus;
  error: ErrorResponse<any> | null;
}

export function useSignIn(): UseSignInResult {
  const { client, setStepUp } = useAuthContext();
  const action = client.useAction({ path: "POST /v1/sessions" });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const signIn = React.useCallback(
    async (req: SignInRequest): Promise<AuthResponse> => {
      setError(null);
      try {
        const raw = await action.send({
          body: {
            grant_type: "password",
            ...req,
          } as any,
        });

        const data = camelize(raw) as unknown as AuthResponse;

        if (isStepUpResponse(data as any)) {
          setStepUp(data as any);
          return data;
        }

        const redirectTo = getRedirectParam();
        return redirectTo ? { ...data, redirectTo } as AuthResponse : data;
      } catch (err) {
        if (err instanceof ErrorResponse) {
          setError(err);
        }
        throw err;
      }
    },
    [action, setStepUp],
  );

  return { signIn, status: action.status, error };
}
