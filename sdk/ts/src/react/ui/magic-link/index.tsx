import React from "react";
import { Form } from "../form/index.js";

// ─── Context ─────────────────────────────────────────────────────────────────

type MagicLinkPhase = "request" | "sent";

interface MagicLinkContextValue {
  phase: MagicLinkPhase;
}

const MagicLinkContext = React.createContext<MagicLinkContextValue | null>(
  null,
);

export function useMagicLinkContext(): MagicLinkContextValue {
  const ctx = React.useContext(MagicLinkContext);
  if (!ctx) {
    throw new Error(
      "MagicLink components must be used inside <MagicLink.Root>",
    );
  }
  return ctx;
}

// ─── Root ────────────────────────────────────────────────────────────────────

export interface MagicLinkRootProps
  extends Omit<React.FormHTMLAttributes<HTMLFormElement>, "action" | "onError">
{
  onSent?(data: unknown, response: Response): void;
  onError?(err: unknown, response: Response): void;
  onSettled?(data: unknown, err: unknown, response: Response | undefined): void;
  children: React.ReactNode;
}

function Root(
  { onSent, onError, onSettled, children, ...formProps }: MagicLinkRootProps,
) {
  const [phase, setPhase] = React.useState<MagicLinkPhase>("request");

  const handleSuccess = React.useCallback(
    (data: unknown, response: Response) => {
      setPhase("sent");
      onSent?.(data, response);
    },
    [onSent],
  );

  return (
    <MagicLinkContext.Provider value={{ phase }}>
      <Form
        path="POST /v1/magic-links"
        onSuccess={handleSuccess as any}
        onError={onError as any}
        onSettled={onSettled as any}
        {...formProps}
      >
        {children}
      </Form>
    </MagicLinkContext.Provider>
  );
}

// ─── Slots ───────────────────────────────────────────────────────────────────

const RequestForm = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(
  ({ children, ...props }, ref) => {
    const { phase } = useMagicLinkContext();
    if (phase !== "request") return null;
    return <div {...props} ref={ref}>{children}</div>;
  },
);
RequestForm.displayName = "MagicLink.RequestForm";

const SentMessage = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(
  ({ children, ...props }, ref) => {
    const { phase } = useMagicLinkContext();
    if (phase !== "sent") return null;
    return <div {...props} ref={ref}>{children}</div>;
  },
);
SentMessage.displayName = "MagicLink.SentMessage";

// ─── Export ───────────────────────────────────────────────────────────────────

export const MagicLink = {
  Root,
  RequestForm,
  SentMessage,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
