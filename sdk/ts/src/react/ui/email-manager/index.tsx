import React from "react";
import type { Email } from "../../../account/emails.js";
import { camelize } from "../../../utils/camelize.js";
import { useAuthContext } from "../../context.js";
import { Form } from "../form/index.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export interface EmailManagerContextValue {
  emails: Email[];
  isLoading: boolean;
  error: unknown;
  refetch(): void;
}

const EmailManagerContext = React.createContext<
  EmailManagerContextValue | null
>(null);

export function useEmailManagerContext(): EmailManagerContextValue {
  const ctx = React.useContext(EmailManagerContext);
  if (!ctx) {
    throw new Error(
      "EmailManager components must be used inside <EmailManager.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

function Root({ children }: { children: React.ReactNode }) {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({ path: "GET /v1/emails" });
  const emails = React.useMemo(
    () => (result.data
      ? (camelize(result.data) as unknown as { emails: Email[] }).emails
      : []),
    [result.data],
  );

  return (
    <EmailManagerContext.Provider
      value={{
        emails,
        isLoading: result.status === "fetching",
        error: result.error,
        refetch: result.refetch,
      }}
    >
      {children}
    </EmailManagerContext.Provider>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Items({ children }: { children(email: Email): React.ReactNode }) {
  const { emails } = useEmailManagerContext();
  return (
    <>
      {emails.map((e) => (
        <React.Fragment key={e.id}>{children(e)}</React.Fragment>
      ))}
    </>
  );
}

function Remove({
  emailId,
  onSuccess,
  children,
  ...props
}:
  & { emailId: string; onSuccess?(): void; children?: React.ReactNode }
  & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">)
{
  const { refetch } = useEmailManagerContext();
  return (
    <Form
      path="DELETE /v1/emails/{id}"
      params={{ path: { id: emailId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      <Form.Submit {...props}>{children ?? "Remove"}</Form.Submit>
    </Form>
  );
}

function MakePrimary({
  emailId,
  onSuccess,
  children,
  ...props
}:
  & { emailId: string; onSuccess?(): void; children?: React.ReactNode }
  & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">)
{
  const { refetch } = useEmailManagerContext();
  return (
    <Form
      path="PUT /v1/emails/{id}"
      params={{ path: { id: emailId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      <Form.Submit {...props}>{children ?? "Make primary"}</Form.Submit>
    </Form>
  );
}

function SendVerification({
  emailId,
  onSuccess,
  children,
  ...props
}:
  & { emailId: string; onSuccess?(): void; children?: React.ReactNode }
  & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">)
{
  const { refetch } = useEmailManagerContext();
  return (
    <Form
      path="POST /v1/emails/{id}/verifications"
      params={{ path: { id: emailId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      <Form.Submit {...props}>{children ?? "Send verification"}</Form.Submit>
    </Form>
  );
}

function AddForm(
  { onSuccess, children }: { onSuccess?(): void; children: React.ReactNode },
) {
  const { refetch } = useEmailManagerContext();
  return (
    <Form
      path="POST /v1/emails"
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      {children}
    </Form>
  );
}

// ─── Export ───────────────────────────────────────────────────────────────────

export const EmailManager = {
  Root,
  Items,
  Remove,
  MakePrimary,
  SendVerification,
  AddForm,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
