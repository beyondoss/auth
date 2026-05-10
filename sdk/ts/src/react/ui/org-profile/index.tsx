import React from "react";
import { useOrg } from "../../useOrg.js";
import type { OrgMember } from "../../useOrgMembers.js";
import { useOrgMembers } from "../../useOrgMembers.js";
import type { Org } from "../../useOrgs.js";
import { Form } from "../form/index.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export interface OrgProfileContextValue {
  orgId: string;
  org: Org | undefined;
  members: OrgMember[];
  isLoading: boolean;
  refetch(): void;
}

const OrgProfileContext = React.createContext<OrgProfileContextValue | null>(
  null,
);

export function useOrgProfileContext(): OrgProfileContextValue {
  const ctx = React.useContext(OrgProfileContext);
  if (!ctx) {
    throw new Error(
      "OrgProfile components must be used inside <OrgProfile.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

export interface OrgProfileRootProps {
  orgId: string;
  children: React.ReactNode;
}

function Root({ orgId, children }: OrgProfileRootProps) {
  const { org, status: orgStatus, refetch: refetchOrg } = useOrg(orgId);
  const { members, status: membersStatus, refetch: refetchMembers } =
    useOrgMembers(orgId);

  const refetch = React.useCallback(() => {
    refetchOrg();
    refetchMembers();
  }, [refetchOrg, refetchMembers]);

  return (
    <OrgProfileContext.Provider
      value={{
        orgId,
        org,
        members,
        isLoading: orgStatus === "fetching" || membersStatus === "fetching",
        refetch,
      }}
    >
      {children}
    </OrgProfileContext.Provider>
  );
}

// ─── Settings form ────────────────────────────────────────────────────────────

function SettingsForm(
  { onSuccess, children }: { onSuccess?(): void; children: React.ReactNode },
) {
  const { orgId, refetch } = useOrgProfileContext();
  return (
    <Form
      path="PATCH /v1/orgs/{id}"
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

function DeleteButton(
  { onSuccess, children, ...props }: {
    onSuccess?(): void;
    children?: React.ReactNode;
  } & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">,
) {
  const { orgId } = useOrgProfileContext();
  return (
    <Form
      path="DELETE /v1/orgs/{id}"
      params={{ path: { id: orgId } } as any}
      onSuccess={onSuccess as any}
    >
      <Form.Submit {...props}>{children ?? "Delete organization"}</Form.Submit>
    </Form>
  );
}

// ─── Members ──────────────────────────────────────────────────────────────────

function Members(
  { children }: { children(member: OrgMember): React.ReactNode },
) {
  const { members } = useOrgProfileContext();
  return (
    <>
      {members.map((m) => (
        <React.Fragment key={m.userId}>{children(m)}</React.Fragment>
      ))}
    </>
  );
}

function UpdateRoleForm(
  { memberId, onSuccess, children }: {
    memberId: string;
    onSuccess?(): void;
    children: React.ReactNode;
  },
) {
  const { orgId, refetch } = useOrgProfileContext();
  return (
    <Form
      path="PATCH /v1/orgs/{id}/members/{member_id}"
      params={{ path: { id: orgId, member_id: memberId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      {children}
    </Form>
  );
}

function RemoveMember({
  memberId,
  onSuccess,
  children,
  ...props
}:
  & { memberId: string; onSuccess?(): void; children?: React.ReactNode }
  & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">)
{
  const { orgId, refetch } = useOrgProfileContext();
  return (
    <Form
      path="DELETE /v1/orgs/{id}/members/{member_id}"
      params={{ path: { id: orgId, member_id: memberId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      <Form.Submit {...props}>{children ?? "Remove"}</Form.Submit>
    </Form>
  );
}

// ─── Export ───────────────────────────────────────────────────────────────────

export const OrgProfile = {
  Root,
  SettingsForm,
  DeleteButton,
  Members,
  UpdateRoleForm,
  RemoveMember,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
