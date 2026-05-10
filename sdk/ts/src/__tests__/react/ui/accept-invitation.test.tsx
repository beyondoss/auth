// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { describe, expect, it, vi } from "vitest";
import { AcceptInvitation } from "../../../react/ui/accept-invitation/index.js";
import { getBaseUrl } from "../../harness.js";
import { newUser, renderPublic, renderWithAuth } from "./harness.js";

// ─── Setup helpers ────────────────────────────────────────────────────────────

async function createInvitation(token: string): Promise<{
  orgId: string;
  orgName: string;
  invId: string;
  invToken: string;
}> {
  const orgRes = await fetch(`${getBaseUrl()}/v1/orgs`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const { orgs } = await orgRes.json() as {
    orgs: Array<{ id: string; name: string }>;
  };
  const org = orgs[0]!;

  const createRes = await fetch(
    `${getBaseUrl()}/v1/orgs/${org.id}/invitations`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ role: "member" }),
    },
  );
  const { id: invId, token: invToken } = await createRes.json() as {
    id: string;
    token: string;
  };
  return { orgId: org.id, orgName: org.name, invId, invToken };
}

// ─── Render helpers ───────────────────────────────────────────────────────────

function renderAcceptInvitation(
  renderFn: (ui: React.ReactElement) => void,
  invId: string,
  invToken: string,
  onSuccess = vi.fn(),
  onDeclineSuccess = vi.fn(),
) {
  renderFn(
    <AcceptInvitation.Root invitationId={invId} token={invToken}>
      <AcceptInvitation.OrgName data-testid="org-name" />
      <AcceptInvitation.Role data-testid="role" />
      <AcceptInvitation.Accept
        onSuccess={onSuccess}
        data-testid="accept-btn"
      >
        Accept
      </AcceptInvitation.Accept>
      <AcceptInvitation.Decline
        onSuccess={onDeclineSuccess}
        data-testid="decline-btn"
      >
        Decline
      </AcceptInvitation.Decline>
    </AcceptInvitation.Root>,
  );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("AcceptInvitation — displays invitation details", () => {
  it("OrgName and Role render the org name and role from the invitation", async () => {
    const { token } = await newUser();
    const { orgName, invId, invToken } = await createInvitation(token);

    renderAcceptInvitation(renderPublic, invId, invToken);

    await waitFor(
      () => expect(screen.getByTestId("org-name")).toHaveTextContent(orgName),
      { timeout: 10_000 },
    );

    expect(screen.getByTestId("role")).toHaveTextContent("member");
  });
});

describe("AcceptInvitation.Accept — accepts an invitation", () => {
  it("clicking Accept posts to /v1/invitations/{id}/acceptances and calls onSuccess", async () => {
    const { token: ownerToken } = await newUser();
    const { invId, invToken } = await createInvitation(ownerToken);
    const { token: inviteeToken } = await newUser();

    const onSuccess = vi.fn();
    renderAcceptInvitation(
      (ui) => renderWithAuth(inviteeToken, ui),
      invId,
      invToken,
      onSuccess,
    );

    // Wait for the invitation to load before interacting
    await waitFor(
      () => expect(screen.getByTestId("org-name").textContent).toBeTruthy(),
      { timeout: 10_000 },
    );

    await userEvent.click(screen.getByTestId("accept-btn"));

    await waitFor(
      () => expect(onSuccess).toHaveBeenCalledOnce(),
      { timeout: 10_000 },
    );
  });
});

describe("AcceptInvitation.Decline — declines an invitation", () => {
  it("clicking Decline posts to /v1/invitations/{id}/declinations and calls onSuccess", async () => {
    const { token: ownerToken } = await newUser();
    const { invId, invToken } = await createInvitation(ownerToken);

    const onDeclineSuccess = vi.fn();
    renderAcceptInvitation(
      renderPublic,
      invId,
      invToken,
      vi.fn(),
      onDeclineSuccess,
    );

    // Wait for the invitation to load before interacting
    await waitFor(
      () => expect(screen.getByTestId("org-name").textContent).toBeTruthy(),
      { timeout: 10_000 },
    );

    await userEvent.click(screen.getByTestId("decline-btn"));

    await waitFor(
      () => expect(onDeclineSuccess).toHaveBeenCalledOnce(),
      { timeout: 10_000 },
    );
  });
});
