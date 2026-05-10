// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { describe, expect, it } from "vitest";
import { InvitationManager } from "../../../react/ui/invitation-manager/index.js";
import { getBaseUrl } from "../../harness.js";
import { newUser, renderWithAuth } from "./harness.js";

// ─── Setup helpers ────────────────────────────────────────────────────────────

async function getUserOrgId(token: string): Promise<string> {
  const res = await fetch(`${getBaseUrl()}/v1/orgs`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const { orgs } = await res.json() as { orgs: Array<{ id: string }> };
  return orgs[0]!.id;
}

async function seedInvitation(
  token: string,
  orgId: string,
): Promise<{ id: string; token: string }> {
  const res = await fetch(`${getBaseUrl()}/v1/orgs/${orgId}/invitations`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ role: "member" }),
  });
  return res.json() as Promise<{ id: string; token: string }>;
}

// ─── Render helpers ───────────────────────────────────────────────────────────

function renderInvitationManager(
  token: string,
  orgId: string,
  extra?: React.ReactNode,
) {
  renderWithAuth(
    token,
    <InvitationManager.Root orgId={orgId}>
      <InvitationManager.Items>
        {(inv) => (
          <div key={inv.id} data-testid={`inv-${inv.id}`}>
            <span data-testid={`role-${inv.id}`}>{inv.role}</span>
            <InvitationManager.Resend
              invitationId={inv.id}
              data-testid={`resend-${inv.id}`}
            >
              Resend
            </InvitationManager.Resend>
            <InvitationManager.Revoke
              invitationId={inv.id}
              data-testid={`revoke-${inv.id}`}
            >
              Revoke
            </InvitationManager.Revoke>
          </div>
        )}
      </InvitationManager.Items>
      {extra}
    </InvitationManager.Root>,
  );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("InvitationManager.Items — renders invitation list", () => {
  it("renders empty list when no invitations exist", async () => {
    const { token } = await newUser();
    const orgId = await getUserOrgId(token);

    renderWithAuth(
      token,
      <InvitationManager.Root orgId={orgId}>
        <div data-testid="list">
          <InvitationManager.Items>
            {(inv) => (
              <div key={inv.id} data-testid={`inv-${inv.id}`}>
                {inv.id}
              </div>
            )}
          </InvitationManager.Items>
        </div>
      </InvitationManager.Root>,
    );

    await waitFor(() => expect(screen.getByTestId("list")).toBeInTheDocument());
    // No invitation items should be rendered
    expect(screen.queryByTestId(/^inv-/)).not.toBeInTheDocument();
  });
});

describe("InvitationManager.InviteForm — creates an invitation", () => {
  it("submitting InviteForm with role 'member' creates an invitation that appears in Items", async () => {
    const { token } = await newUser();
    const orgId = await getUserOrgId(token);

    renderWithAuth(
      token,
      <InvitationManager.Root orgId={orgId}>
        <InvitationManager.Items>
          {(inv) => (
            <div key={inv.id} data-testid={`inv-${inv.id}`}>
              {inv.role}
            </div>
          )}
        </InvitationManager.Items>
        <InvitationManager.InviteForm>
          <InvitationManager.Field name="role" aria-label="Role" />
          <InvitationManager.Submit data-testid="invite-btn">
            Send invite
          </InvitationManager.Submit>
        </InvitationManager.InviteForm>
      </InvitationManager.Root>,
    );

    await waitFor(() =>
      expect(screen.getByLabelText("Role")).toBeInTheDocument()
    );

    await userEvent.type(screen.getByLabelText("Role"), "member");
    await userEvent.click(screen.getByTestId("invite-btn"));

    // After onSuccess triggers refetch, invitation appears in list
    await waitFor(
      () =>
        expect(screen.queryAllByTestId(/^inv-/).length).toBeGreaterThanOrEqual(
          1,
        ),
      { timeout: 10_000 },
    );
  });
});

describe("InvitationManager.Revoke — removes an invitation", () => {
  it("clicking Revoke removes the invitation from the list", async () => {
    const { token } = await newUser();
    const orgId = await getUserOrgId(token);
    const { id: invId } = await seedInvitation(token, orgId);

    renderInvitationManager(token, orgId);

    await waitFor(
      () => expect(screen.getByTestId(`inv-${invId}`)).toBeInTheDocument(),
      { timeout: 10_000 },
    );

    await userEvent.click(screen.getByTestId(`revoke-${invId}`));

    await waitFor(
      () =>
        expect(
          screen.queryByTestId(`inv-${invId}`),
        ).not.toBeInTheDocument(),
      { timeout: 10_000 },
    );
  });
});

describe("InvitationManager.Resend — resends an invitation", () => {
  it("clicking Resend transitions the button to success state", async () => {
    const { token } = await newUser();
    const orgId = await getUserOrgId(token);
    const { id: invId } = await seedInvitation(token, orgId);

    renderInvitationManager(token, orgId);

    await waitFor(
      () => expect(screen.getByTestId(`inv-${invId}`)).toBeInTheDocument(),
      { timeout: 10_000 },
    );

    await userEvent.click(screen.getByTestId(`resend-${invId}`));

    await waitFor(
      () =>
        expect(screen.getByTestId(`resend-${invId}`)).toHaveAttribute(
          "data-state",
          "success",
        ),
      { timeout: 10_000 },
    );
  });
});
