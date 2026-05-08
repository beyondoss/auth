import React from "react";
import { isStepUpResponse } from "../flows/sign-in.js";
import type { SignInRequest, StepUpResponse } from "../flows/sign-in.js";
import type { AuthResponse } from "../flows/sign-up.js";
import type { paths } from "../types.js";
import { getRedirectParam } from "../utils/redirect.js";
import { ErrorResponse } from "./client.js";
import type { ErrorData } from "./client.js";
import { useAuthContext } from "./context.js";

export type SignInStatus = "idle" | "fetching" | "success" | "error";

export interface UseSignInResult {
  signIn(
    req: SignInRequest,
  ): Promise<AuthResponse & { redirectTo?: string } | StepUpResponse>;
  status: SignInStatus;
  error: ErrorResponse<ErrorData<paths, "/v1/sessions", "post">> | null;
}

export function useSignIn(): UseSignInResult {
  const { client, setStepUp } = useAuthContext();
  const action = client.useAction({ path: "POST /v1/sessions" });
  const [error, setError] = React.useState<
    ErrorResponse<ErrorData<paths, "/v1/sessions", "post">> | null
  >(null);

  const signIn = React.useCallback(
    async (
      req: SignInRequest,
    ): Promise<AuthResponse & { redirectTo?: string } | StepUpResponse> => {
      setError(null);
      try {
        const data = await action.send({ body: req });

        if (isStepUpResponse(data)) {
          setStepUp(data);
          return data;
        }

        const redirectTo = getRedirectParam();
        return redirectTo ? { ...data, redirectTo } : data;
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
