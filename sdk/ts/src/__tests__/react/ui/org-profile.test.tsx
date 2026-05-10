// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { OrgProfile } from "../../../react/ui/org-profile/index.js";
import { getBaseUrl } from "../../harness.js";
import { newUser, renderWithAuth } from "./harness.js";

// ─── Setup helpers ────────────────────────────────────────────────────────────

async function getUserOrg(
  token: string,
): Promise<{ id: string; name: string }> {
  const res = await fetch(`${getBaseUrl()}/v1/orgs`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await res.json() as {
    orgs: Array<{ id: string; name: string }>;
  };
  return data.orgs[0]!;
}

async function createOrg(token: string, name: string): Promise<{ id: string }> {
  const res = await fetch(`${getBaseUrl()}/v1/orgs`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name }),
  });
  return res.json() as Promise<{ id: string }>;
}

async function createInvitation(
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

async function acceptInvitation(
  token: string,
  invId: string,
  invToken: string,
): Promise<void> {
  const url = `${getBaseUrl()}/v1/invitations/${invId}/acceptances?token=${
    encodeURIComponent(invToken)
  }`;
  await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
}

// ─── Render helpers ───────────────────────────────────────────────────────────

function renderOrgProfile(token: string, orgId: string) {
  renderWithAuth(
    token,
    <OrgProfile.Root orgId={orgId}>
      <OrgProfile.Members>
        {(m) => (
          <div key={m.userId} data-testid={`member-${m.userId}`}>
            <span data-testid={`role-${m.userId}`}>{m.role}</span>
            <OrgProfile.RemoveMember
              memberId={m.userId}
              data-testid={`remove-${m.userId}`}
            />
          </div>
        )}
      </OrgProfile.Members>
    </OrgProfile.Root>,
  );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("OrgProfile.Members — render prop lists org members", () => {
  it("renders at least one member (the owner) with role 'owner'", async () => {
    const { token, auth } = await newUser();
    const org = await getUserOrg(token);

    renderOrgProfile(token, org.id);

    await waitFor(
      () =>
        expect(
          screen.getByTestId(`member-${auth.user.id}`),
        ).toBeInTheDocument(),
      { timeout: 10_000 },
    );

    expect(
      screen.getByTestId(`role-${auth.user.id}`),
    ).toHaveTextContent("owner");
  });
});

describe("OrgProfile.SettingsForm — patches org name", () => {
  it("updating the name field and submitting reaches success state and persists", async () => {
    const { token } = await newUser();
    const org = await getUserOrg(token);
    const newName = `Renamed Org ${Date.now()}`;

    renderWithAuth(
      token,
      <OrgProfile.Root orgId={org.id}>
        <OrgProfile.SettingsForm>
          <OrgProfile.Field name="name" aria-label="Org name" />
          <OrgProfile.Submit data-testid="save-btn">Save</OrgProfile.Submit>
        </OrgProfile.SettingsForm>
      </OrgProfile.Root>,
    );

    await waitFor(
      () => expect(screen.getByLabelText("Org name")).toBeInTheDocument(),
    );

    await userEvent.clear(screen.getByLabelText("Org name"));
    await userEvent.type(screen.getByLabelText("Org name"), newName);
    await userEvent.click(screen.getByTestId("save-btn"));

    await waitFor(
      () =>
        expect(screen.getByTestId("save-btn")).toHaveAttribute(
          "data-state",
          "success",
        ),
      { timeout: 10_000 },
    );

    // Verify the name actually changed server-side
    const updated = await getUserOrg(token);
    expect(updated.name).toBe(newName);
  });
});

describe("OrgProfile.DeleteButton — deletes an org", () => {
  it("clicking DeleteButton removes the org and calls onSuccess", async () => {
    const { token } = await newUser();
    const secondOrg = await createOrg(token, "Delete Me Org");
    const onSuccess = vi.fn();

    renderWithAuth(
      token,
      <OrgProfile.Root orgId={secondOrg.id}>
        <OrgProfile.DeleteButton
          onSuccess={onSuccess}
          data-testid="delete-btn"
        >
          Delete organization
        </OrgProfile.DeleteButton>
      </OrgProfile.Root>,
    );

    await waitFor(
      () => expect(screen.getByTestId("delete-btn")).toBeInTheDocument(),
    );

    await userEvent.click(screen.getByTestId("delete-btn"));

    await waitFor(
      () => expect(onSuccess).toHaveBeenCalledOnce(),
      { timeout: 10_000 },
    );
  });
});

describe("OrgProfile.RemoveMember — removes a member from the org", () => {
  it("clicking RemoveMember for user B removes their entry from the list", async () => {
    const { token: tokenA } = await newUser();
    const { token: tokenB, auth: authB } = await newUser();

    const org = await getUserOrg(tokenA);
    const { id: invId, token: invToken } = await createInvitation(
      tokenA,
      org.id,
    );
    await acceptInvitation(tokenB, invId, invToken);

    renderOrgProfile(tokenA, org.id);

    // Wait for user B to appear in the member list
    await waitFor(
      () =>
        expect(
          screen.getByTestId(`member-${authB.user.id}`),
        ).toBeInTheDocument(),
      { timeout: 10_000 },
    );

    await userEvent.click(screen.getByTestId(`remove-${authB.user.id}`));

    // User B's entry disappears after removal + refetch
    await waitFor(
      () =>
        expect(
          screen.queryByTestId(`member-${authB.user.id}`),
        ).not.toBeInTheDocument(),
      { timeout: 10_000 },
    );
  });
});
