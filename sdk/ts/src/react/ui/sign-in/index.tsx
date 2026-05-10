import React from "react";
import { isStepUpResponse } from "../../../flows/sign-in.js";
import type { AuthResponse } from "../../../flows/sign-up.js";
import { useAuthContext } from "../../context.js";
import { Form } from "../form/index.js";

// ─── Context ─────────────────────────────────────────────────────────────────

type SignInPhase = "password" | "step_up";

interface SignInContextValue {
  phase: SignInPhase;
  stepUpToken: string | null;
  cancelStepUp(): void;
}

const SignInContext = React.createContext<SignInContextValue | null>(null);

export function useSignInContext(): SignInContextValue {
  const ctx = React.useContext(SignInContext);
  if (!ctx) {
    throw new Error("SignIn components must be used inside <SignIn.Root>");
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

export interface SignInRootProps
  extends Omit<React.FormHTMLAttributes<HTMLFormElement>, "action" | "onError">
{
  onSuccess?(result: AuthResponse): void;
  onError?(err: unknown, response: Response): void;
  onSettled?(data: unknown, err: unknown, response: Response | undefined): void;
  children: React.ReactNode;
}

function Root(
  { onSuccess, onError, onSettled, children, ...formProps }: SignInRootProps,
) {
  const { setStepUp } = useAuthContext();
  const [stepUpToken, setStepUpToken] = React.useState<string | null>(null);
  const phase: SignInPhase = stepUpToken ? "step_up" : "password";

  const handlePasswordSuccess = React.useCallback(
    (data: unknown) => {
      if (isStepUpResponse(data as any)) {
        const token = (data as any).stepUpToken as string;
        setStepUpToken(token);
        setStepUp(data as any);
      } else {
        onSuccess?.(data as AuthResponse);
      }
    },
    [setStepUp, onSuccess],
  );

  const handleStepUpSuccess = React.useCallback(
    (data: unknown) => {
      setStepUpToken(null);
      setStepUp(null);
      onSuccess?.(data as AuthResponse);
    },
    [setStepUp, onSuccess],
  );

  const cancelStepUp = React.useCallback(() => {
    setStepUpToken(null);
    setStepUp(null);
  }, [setStepUp]);

  return (
    <SignInContext.Provider value={{ phase, stepUpToken, cancelStepUp }}>
      {phase === "password"
        ? (
          <Form
            path="POST /v1/sessions"
            body={{ grant_type: "password" }}
            onSuccess={handlePasswordSuccess}
            onError={onError as any}
            onSettled={onSettled as any}
            {...formProps}
          >
            {children}
          </Form>
        )
        : (
          <Form
            path="POST /v1/sessions"
            body={{ grant_type: "totp_step_up", step_up_token: stepUpToken }}
            onSuccess={handleStepUpSuccess}
            onError={onError as any}
            onSettled={onSettled as any}
            {...formProps}
          >
            {children}
          </Form>
        )}
    </SignInContext.Provider>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

const PasswordForm = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ children, ...props }, ref) => {
  const { phase } = useSignInContext();
  if (phase !== "password") return null;
  return (
    <div {...props} ref={ref}>
      {children}
    </div>
  );
});
PasswordForm.displayName = "SignIn.PasswordForm";

const StepUpForm = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ children, ...props }, ref) => {
  const { phase } = useSignInContext();
  if (phase !== "step_up") return null;
  return (
    <div {...props} ref={ref}>
      {children}
    </div>
  );
});
StepUpForm.displayName = "SignIn.StepUpForm";

const CancelStepUp = React.forwardRef<
  HTMLButtonElement,
  React.ButtonHTMLAttributes<HTMLButtonElement>
>((props, ref) => {
  const { cancelStepUp } = useSignInContext();
  return <button type="button" onClick={cancelStepUp} {...props} ref={ref} />;
});
CancelStepUp.displayName = "SignIn.CancelStepUp";

// ─── Export ───────────────────────────────────────────────────────────────────

export const SignIn = {
  Root,
  PasswordForm,
  StepUpForm,
  /** Field — use name="email", name="password" for the password step; name="code" for step-up */
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
  CancelStepUp,
};
