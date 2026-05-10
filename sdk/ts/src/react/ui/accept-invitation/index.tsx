import React from "react";
import type { InvitationView } from "../../useInvitation.js";
import { useInvitation } from "../../useInvitation.js";
import { Form } from "../form/index.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export interface AcceptInvitationContextValue {
  invitation: InvitationView | undefined;
  isLoading: boolean;
  invitationId: string;
  token: string;
}

const AcceptInvitationContext = React.createContext<
  AcceptInvitationContextValue | null
>(null);

export function useAcceptInvitationContext(): AcceptInvitationContextValue {
  const ctx = React.useContext(AcceptInvitationContext);
  if (!ctx) {
    throw new Error(
      "AcceptInvitation components must be used inside <AcceptInvitation.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

export interface AcceptInvitationRootProps {
  invitationId: string;
  token: string;
  children: React.ReactNode;
}

function Root({ invitationId, token, children }: AcceptInvitationRootProps) {
  const { invitation, status } = useInvitation(invitationId, token);

  return (
    <AcceptInvitationContext.Provider
      value={{
        invitation,
        isLoading: status === "fetching",
        invitationId,
        token,
      }}
    >
      {children}
    </AcceptInvitationContext.Provider>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function OrgName(props: React.HTMLAttributes<HTMLSpanElement>) {
  const { invitation } = useAcceptInvitationContext();
  return <span {...props}>{props.children ?? invitation?.orgName}</span>;
}

function Role(props: React.HTMLAttributes<HTMLSpanElement>) {
  const { invitation } = useAcceptInvitationContext();
  return <span {...props}>{props.children ?? invitation?.role}</span>;
}

function Accept(
  { onSuccess, children, ...props }: {
    onSuccess?(): void;
    children?: React.ReactNode;
  } & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">,
) {
  const { invitationId, token } = useAcceptInvitationContext();
  return (
    <Form
      path="POST /v1/invitations/{id}/acceptances"
      params={{ path: { id: invitationId }, query: { token } } as any}
      onSuccess={onSuccess as any}
    >
      <Form.Submit {...props}>{children ?? "Accept invitation"}</Form.Submit>
    </Form>
  );
}

function Decline(
  { onSuccess, children, ...props }: {
    onSuccess?(): void;
    children?: React.ReactNode;
  } & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">,
) {
  const { invitationId, token } = useAcceptInvitationContext();
  return (
    <Form
      path="POST /v1/invitations/{id}/declinations"
      params={{ path: { id: invitationId }, query: { token } } as any}
      onSuccess={onSuccess as any}
    >
      <Form.Submit {...props}>{children ?? "Decline"}</Form.Submit>
    </Form>
  );
}

// ─── Export ───────────────────────────────────────────────────────────────────

export const AcceptInvitation = {
  Root,
  OrgName,
  Role,
  Accept,
  Decline,
  Error: Form.Error,
};
