import React from "react";
import type { Invitation } from "../../useOrgInvitations.js";
import { useOrgInvitations } from "../../useOrgInvitations.js";
import { Form } from "../form/index.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export interface InvitationManagerContextValue {
  orgId: string;
  invitations: Invitation[];
  isLoading: boolean;
  refetch(): void;
}

const InvitationManagerContext = React.createContext<
  InvitationManagerContextValue | null
>(null);

export function useInvitationManagerContext(): InvitationManagerContextValue {
  const ctx = React.useContext(InvitationManagerContext);
  if (!ctx) {
    throw new Error(
      "InvitationManager components must be used inside <InvitationManager.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

function Root(
  { orgId, children }: { orgId: string; children: React.ReactNode },
) {
  const { invitations, status, refetch } = useOrgInvitations(orgId);
  return (
    <InvitationManagerContext.Provider
      value={{ orgId, invitations, isLoading: status === "fetching", refetch }}
    >
      {children}
    </InvitationManagerContext.Provider>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Items(
  { children }: { children(invitation: Invitation): React.ReactNode },
) {
  const { invitations } = useInvitationManagerContext();
  return (
    <>
      {invitations.map((inv) => (
        <React.Fragment key={inv.id}>{children(inv)}</React.Fragment>
      ))}
    </>
  );
}

function InviteForm(
  { onSuccess, children }: { onSuccess?(): void; children: React.ReactNode },
) {
  const { orgId, refetch } = useInvitationManagerContext();
  return (
    <Form
      path="POST /v1/orgs/{id}/invitations"
      params={{ path: { id: orgId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      {children}
    </Form>
  );
}

function Resend({
  invitationId,
  onSuccess,
  children,
  ...props
}:
  & { invitationId: string; onSuccess?(): void; children?: React.ReactNode }
  & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">)
{
  const { orgId, refetch } = useInvitationManagerContext();
  return (
    <Form
      path="POST /v1/orgs/{id}/invitations/{inv_id}/resends"
      params={{ path: { id: orgId, inv_id: invitationId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      <Form.Submit {...props}>{children ?? "Resend"}</Form.Submit>
    </Form>
  );
}

function Revoke({
  invitationId,
  onSuccess,
  children,
  ...props
}:
  & { invitationId: string; onSuccess?(): void; children?: React.ReactNode }
  & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">)
{
  const { orgId, refetch } = useInvitationManagerContext();
  return (
    <Form
      path="DELETE /v1/orgs/{id}/invitations/{inv_id}"
      params={{ path: { id: orgId, inv_id: invitationId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      <Form.Submit {...props}>{children ?? "Revoke"}</Form.Submit>
    </Form>
  );
}

// ─── Export ───────────────────────────────────────────────────────────────────

export const InvitationManager = {
  Root,
  Items,
  InviteForm,
  Resend,
  Revoke,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
