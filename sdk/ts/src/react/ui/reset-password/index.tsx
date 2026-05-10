import React from "react";
import { Form } from "../form/index.js";

// ─── Context ──────────────────────────────────────────────────────────────────

type ResetPasswordPhase = "request" | "sent" | "confirm";

interface ResetPasswordContextValue {
  phase: ResetPasswordPhase;
}

const ResetPasswordContext = React.createContext<
  ResetPasswordContextValue | null
>(null);

export function useResetPasswordContext(): ResetPasswordContextValue {
  const ctx = React.useContext(ResetPasswordContext);
  if (!ctx) {
    throw new Error(
      "ResetPassword components must be used inside <ResetPassword.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

export interface ResetPasswordRootProps
  extends Omit<React.FormHTMLAttributes<HTMLFormElement>, "action" | "onError">
{
  /** Token from the reset link. When present, starts in confirm phase. */
  token?: string;
  onSuccess?(data: unknown, response: Response): void;
  onError?(err: unknown, response: Response): void;
  onSettled?(data: unknown, err: unknown, response: Response | undefined): void;
  children: React.ReactNode;
}

function Root(
  { token, onSuccess, onError, onSettled, children, ...formProps }:
    ResetPasswordRootProps,
) {
  const [phase, setPhase] = React.useState<ResetPasswordPhase>(
    token ? "confirm" : "request",
  );

  const handleRequestSuccess = React.useCallback(
    (data: unknown, response: Response) => {
      setPhase("sent");
      onSuccess?.(data, response);
    },
    [onSuccess],
  );

  const formPath = phase === "confirm"
    ? "POST /v1/sessions"
    : "POST /v1/password-resets";
  const formBody = phase === "confirm"
    ? { grant_type: "password_reset", token }
    : undefined;
  const handleSuccess = phase === "request"
    ? handleRequestSuccess
    : onSuccess as any;

  return (
    <ResetPasswordContext.Provider value={{ phase }}>
      <Form
        path={formPath}
        body={formBody as any}
        onSuccess={handleSuccess}
        onError={onError as any}
        onSettled={onSettled as any}
        {...formProps}
      >
        {children}
      </Form>
    </ResetPasswordContext.Provider>
  );
}

// ─── Slots ────────────────────────────────────────────────────────────────────

const RequestForm = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(
  ({ children, ...props }, ref) => {
    const { phase } = useResetPasswordContext();
    if (phase !== "request") return null;
    return <div {...props} ref={ref}>{children}</div>;
  },
);
RequestForm.displayName = "ResetPassword.RequestForm";

const SentMessage = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(
  ({ children, ...props }, ref) => {
    const { phase } = useResetPasswordContext();
    if (phase !== "sent") return null;
    return <div {...props} ref={ref}>{children}</div>;
  },
);
SentMessage.displayName = "ResetPassword.SentMessage";

const ConfirmForm = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(
  ({ children, ...props }, ref) => {
    const { phase } = useResetPasswordContext();
    if (phase !== "confirm") return null;
    return <div {...props} ref={ref}>{children}</div>;
  },
);
ConfirmForm.displayName = "ResetPassword.ConfirmForm";

// ─── Export ───────────────────────────────────────────────────────────────────

export const ResetPassword = {
  Root,
  RequestForm,
  SentMessage,
  ConfirmForm,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
