import React from "react";
import type { SignInRequest, StepUpResponse } from "../flows/sign-in.js";
import { isStepUpResponse } from "../flows/sign-in.js";
import type { AuthResponse } from "../flows/sign-up.js";
import { ErrorResponse } from "./client.js";
import type { ErrorData } from "./client.js";
import { useAuthContext } from "./context.js";
import type { paths } from "./types.js";

export type StepUpStatus = "idle" | "fetching" | "error";

export interface UseStepUpResult {
  /** Non-null when a step-up challenge is pending. Render your TOTP form when this is set. */
  stepUp: StepUpResponse | null;
  completeTotpStepUp(code: string): Promise<AuthResponse>;
  completeTotpRecovery(code: string): Promise<AuthResponse>;
  cancel(): void;
  status: StepUpStatus;
  error: ErrorResponse<ErrorData<paths, "/v1/sessions", "post">> | null;
}

export function useStepUp(): UseStepUpResult {
  const { client, stepUp, setStepUp } = useAuthContext();
  const action = client.useAction({ path: "POST /v1/sessions" });
  const [error, setError] = React.useState<
    ErrorResponse<ErrorData<paths, "/v1/sessions", "post">> | null
  >(null);
  const [status, setStatus] = React.useState<StepUpStatus>("idle");

  const complete = React.useCallback(
    async (
      grantType: "totp_step_up" | "totp_recovery",
      code: string,
    ): Promise<AuthResponse> => {
      if (!stepUp) {
        throw new Error("No pending step-up challenge. Call signIn() first.");
      }

      setError(null);
      setStatus("fetching");

      try {
        const body: SignInRequest = grantType === "totp_step_up"
          ? { grantType: "totp_step_up", stepUpToken: stepUp.stepUpToken, code }
          : {
            grantType: "totp_recovery",
            stepUpToken: stepUp.stepUpToken,
            code,
          };
        const data = await action.send({ body });
        if (isStepUpResponse(data)) {
          throw new Error(
            "Unexpected step-up challenge during step-up completion",
          );
        }
        setStepUp(null);
        setStatus("idle");
        return data;
      } catch (err) {
        setStatus("error");
        if (err instanceof ErrorResponse) {
          setError(err);
          // Expired token — clear challenge so user must sign in again
          if (
            err.response?.status === 401
            || err.data?.error?.code === "step_up_token_expired"
          ) {
            setStepUp(null);
          }
          // Wrong code — leave stepUp intact so user can retry
        }
        throw err;
      }
    },
    [action, stepUp, setStepUp],
  );

  const completeTotpStepUp = React.useCallback(
    (code: string) => complete("totp_step_up", code),
    [complete],
  );

  const completeTotpRecovery = React.useCallback(
    (code: string) => complete("totp_recovery", code),
    [complete],
  );

  const cancel = React.useCallback(() => {
    setStepUp(null);
    setError(null);
    setStatus("idle");
  }, [setStepUp]);

  return {
    stepUp,
    completeTotpStepUp,
    completeTotpRecovery,
    cancel,
    status,
    error,
  };
}
