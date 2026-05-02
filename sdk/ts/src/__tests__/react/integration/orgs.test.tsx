// @vitest-environment jsdom
/**
 * React hook integration tests for org/member/invitation hooks against the
 * real auth service running in the testcontainer.
 *
 * jsdom has no httpOnly cookie jar, so we bypass the proxy and call the auth
 * service directly. Authentication is injected via `requestInit` headers on
 * `createClient` — the same client that backs every hook under test.
 */
import { render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { beforeAll, describe, expect, it } from "vitest";
import { createClient } from "../../../react/client.js";
import { AuthProvider } from "../../../react/provider.js";
import { useCreateInvitation } from "../../../react/useCreateInvitation.js";
import type { CreatedInvitation } from "../../../react/useCreateInvitation.js";
import { useCreateOrg } from "../../../react/useCreateOrg.js";
import { useInvitation } from "../../../react/useInvitation.js";
import { useOrg } from "../../../react/useOrg.js";
import { useOrgInvitations } from "../../../react/useOrgInvitations.js";
import { useOrgMembers } from "../../../react/useOrgMembers.js";
import { useOrgs } from "../../../react/useOrgs.js";
import { useResendInvitation } from "../../../react/useResendInvitation.js";
import { useRevokeInvitation } from "../../../react/useRevokeInvitation.js";
import type { paths } from "../../../types.js";
import { getBaseUrl, signup, uniqueEmail } from "../../harness.js";

const PASSWORD = "correct-horse-battery-staple";

/** Create a client that authenticates with a Bearer token instead of cookies.
 *  Mirrors createBrowserAuth's onEachSuccess so mutations refetch active loaders. */
function makeClient(token: string) {
  const client = createClient<paths>({
    baseUrl: getBaseUrl(),
    staleTime: 0,
    requestInit: () => ({ headers: { Authorization: `Bearer ${token}` } }),
    async onEachSuccess() {
      await client.refetch({ match: (_, rc) => rc > 0 });
    },
  });
  return client;
}

/** Render a component inside an AuthProvider backed by the given token. */
function renderWithAuth(token: string, ui: React.ReactElement) {
  const client = makeClient(token);
  return render(<AuthProvider client={client}>{ui}</AuthProvider>);
}

async function newUser() {
  const email = uniqueEmail();
  const auth = await signup(email, PASSWORD);
  return { email, auth, token: auth.session.token };
}

// ---------------------------------------------------------------------------
// useOrgs / useOrg / useCreateOrg
// ---------------------------------------------------------------------------

describe("useOrgs + useOrg + useCreateOrg — integration", () => {
  let token: string;

  beforeAll(async () => {
    ({ token } = await newUser());
  });

  it("useOrgs lists orgs and camelizes fields", async () => {
    function Harness() {
      const { orgs, status } = useOrgs();
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="count">{orgs.length}</span>
          {orgs.map((o) => (
            <span key={o.id} data-testid={`org-${o.id}`}>
              {o.name}|{o.createdAt}
            </span>
          ))}
        </div>
      );
    }

    renderWithAuth(token, <Harness />);

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    });

    // New user always has a personal org created at signup
    const count = parseInt(screen.getByTestId("count").textContent!);
    expect(count).toBeGreaterThanOrEqual(1);
  });

  it("useCreateOrg creates an org and it appears in useOrgs", async () => {
    const created: { id?: string; name?: string } = {};

    function Harness() {
      const { orgs, status: listStatus } = useOrgs();
      const { createOrg, status: createStatus } = useCreateOrg();

      React.useEffect(() => {
        createOrg({ name: "React Integration Org" })
          .then((org) => {
            created.id = org.id;
            created.name = org.name;
          })
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return (
        <div>
          <span data-testid="create-status">{createStatus}</span>
          <span data-testid="list-status">{listStatus}</span>
          <span data-testid="ids">{orgs.map((o) => o.id).join(",")}</span>
        </div>
      );
    }

    renderWithAuth(token, <Harness />);

    await waitFor(() => {
      expect(screen.getByTestId("create-status").textContent).toBe("success");
    }, { timeout: 10_000 });

    expect(created.id).toBeDefined();
    expect(created.name).toBe("React Integration Org");

    // onEachSuccess triggers refetch — newly created org should appear in list
    await waitFor(() => {
      expect(screen.getByTestId("ids").textContent).toContain(created.id!);
    }, { timeout: 5_000 });
  });

  it("useOrg fetches a specific org and camelizes its fields", async () => {
    // Use the owner's personal org (always exists after signup)
    const listRes = await fetch(`${getBaseUrl()}/v1/orgs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const listData = await listRes.json() as {
      orgs: Array<{ id: string; name: string }>;
    };
    const firstOrg = listData.orgs[0]!;

    function Harness({ orgId }: { orgId: string }) {
      const { org: orgData, status } = useOrg(orgId);
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="id">{orgData?.id ?? ""}</span>
          <span data-testid="name">{orgData?.name ?? ""}</span>
          <span data-testid="createdAt">{orgData?.createdAt ?? ""}</span>
        </div>
      );
    }

    renderWithAuth(token, <Harness orgId={firstOrg.id} />);

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    });

    expect(screen.getByTestId("id").textContent).toBe(firstOrg.id);
    expect(screen.getByTestId("name").textContent).toBe(firstOrg.name);
    // createdAt should be a non-empty ISO string — camelized from created_at
    expect(screen.getByTestId("createdAt").textContent).toMatch(/^\d{4}-/);
  });
});

// ---------------------------------------------------------------------------
// useOrgMembers
// ---------------------------------------------------------------------------

describe("useOrgMembers — integration", () => {
  it("lists members and returns camelized userId and role", async () => {
    const { auth, token } = await newUser();
    const orgRes = await fetch(`${getBaseUrl()}/v1/orgs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const { orgs } = await orgRes.json() as { orgs: Array<{ id: string }> };
    const orgId = orgs[0]!.id;

    function Harness() {
      const { members, status } = useOrgMembers(orgId);
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="count">{members.length}</span>
          <span data-testid="userId">{members[0]?.userId ?? ""}</span>
          <span data-testid="role">{members[0]?.role ?? ""}</span>
        </div>
      );
    }

    renderWithAuth(token, <Harness />);

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    });

    expect(screen.getByTestId("count").textContent).toBe("1");
    expect(screen.getByTestId("userId").textContent).toBe(auth.user.id);
    expect(screen.getByTestId("role").textContent).toBe("owner");
  });
});

// ---------------------------------------------------------------------------
// useCreateInvitation / useResendInvitation / useRevokeInvitation
// ---------------------------------------------------------------------------

describe("useCreateInvitation — integration", () => {
  it("creates invitation, returns one-time token and working buildLink", async () => {
    const { token } = await newUser();
    const orgRes = await fetch(`${getBaseUrl()}/v1/orgs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const { orgs } = await orgRes.json() as { orgs: Array<{ id: string }> };
    const orgId = orgs[0]!.id;

    const results: CreatedInvitation[] = [];

    function Harness() {
      const { createInvitation, status } = useCreateInvitation();

      React.useEffect(() => {
        createInvitation(orgId, { role: "member" })
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return <span data-testid="status">{status}</span>;
    }

    renderWithAuth(token, <Harness />);

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    }, { timeout: 10_000 });

    expect(results).toHaveLength(1);
    const result = results[0]!;

    // Token must be a non-empty string
    expect(typeof result.token).toBe("string");
    expect(result.token.length).toBeGreaterThan(0);

    // invitation fields are camelized
    expect(result.invitation.id).toBeDefined();
    expect(result.invitation.orgId).toBe(orgId);
    expect(result.invitation.role).toBe("member");
    expect(result.invitation.createdAt).toBeDefined();
    expect(result.invitation.expiresAt).toBeDefined();

    // buildLink constructs the correct URL
    const link = result.buildLink("https://app.example.com/invite");
    const params = new URL(link).searchParams;
    expect(params.get("id")).toBe(result.invitation.id);
    expect(params.get("token")).toBe(result.token); // URLSearchParams auto-decodes

    // Trailing slash stripped
    const linkSlash = result.buildLink("https://app.example.com/invite/");
    expect(linkSlash).toBe(link);
  });
});

describe("useResendInvitation — integration", () => {
  it("returns a new token and the same buildLink shape", async () => {
    const { token } = await newUser();
    const orgRes = await fetch(`${getBaseUrl()}/v1/orgs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const { orgs } = await orgRes.json() as { orgs: Array<{ id: string }> };
    const orgId = orgs[0]!.id;

    // Create the initial invitation via raw fetch so we have an inv ID
    const createRes = await fetch(
      `${getBaseUrl()}/v1/orgs/${orgId}/invitations`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "member" }),
      },
    );
    const { id: invId, token: originalToken } = await createRes.json() as {
      id: string;
      token: string;
    };

    const results: CreatedInvitation[] = [];

    function Harness() {
      const { resendInvitation, status } = useResendInvitation();

      React.useEffect(() => {
        resendInvitation(orgId, invId)
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return <span data-testid="status">{status}</span>;
    }

    renderWithAuth(token, <Harness />);

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    }, { timeout: 10_000 });

    expect(results).toHaveLength(1);
    const result = results[0]!;

    // New token must differ from original
    expect(result.token).not.toBe(originalToken);
    expect(result.token.length).toBeGreaterThan(0);

    // buildLink works with new token
    const link = result.buildLink("https://app.example.com/invite");
    const params = new URL(link).searchParams;
    expect(params.get("id")).toBe(invId);
    expect(params.get("token")).toBe(result.token);
  });
});

describe("useRevokeInvitation — integration", () => {
  it("revokes an invitation and it no longer appears in useOrgInvitations", async () => {
    const { token } = await newUser();
    const orgRes = await fetch(`${getBaseUrl()}/v1/orgs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const { orgs } = await orgRes.json() as { orgs: Array<{ id: string }> };
    const orgId = orgs[0]!.id;

    // Create invitation to revoke
    const createRes = await fetch(
      `${getBaseUrl()}/v1/orgs/${orgId}/invitations`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "member" }),
      },
    );
    const { id: invId } = await createRes.json() as { id: string };

    const invitationIds: string[][] = [];

    function Harness() {
      const { revokeInvitation, status: revokeStatusVal } =
        useRevokeInvitation();
      const { invitations, status: listStatus } = useOrgInvitations(orgId);

      React.useEffect(() => {
        revokeInvitation(orgId, invId).catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      invitationIds.push(invitations.map((i) => i.id));

      return (
        <div>
          <span data-testid="revoke-status">{revokeStatusVal}</span>
          <span data-testid="list-status">{listStatus}</span>
          <span data-testid="ids">
            {invitations.map((i) => i.id).join(",")}
          </span>
        </div>
      );
    }

    renderWithAuth(token, <Harness />);

    await waitFor(() => {
      expect(screen.getByTestId("revoke-status").textContent).toBe("success");
    }, { timeout: 10_000 });

    // After revoke + refetch, invitation should be gone
    await waitFor(() => {
      expect(screen.getByTestId("ids").textContent).not.toContain(invId);
    }, { timeout: 5_000 });
  });
});

// ---------------------------------------------------------------------------
// useOrgInvitations (loader)
// ---------------------------------------------------------------------------

describe("useOrgInvitations — integration", () => {
  it("lists pending invitations with camelized fields and no token", async () => {
    const { token } = await newUser();
    const orgRes = await fetch(`${getBaseUrl()}/v1/orgs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const { orgs } = await orgRes.json() as { orgs: Array<{ id: string }> };
    const orgId = orgs[0]!.id;

    // Seed one invitation
    await fetch(`${getBaseUrl()}/v1/orgs/${orgId}/invitations`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ role: "member" }),
    });

    function Harness() {
      const { invitations, status } = useOrgInvitations(orgId);
      const inv = invitations[0];
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="count">{invitations.length}</span>
          <span data-testid="orgId">{inv?.orgId ?? ""}</span>
          <span data-testid="role">{inv?.role ?? ""}</span>
          <span data-testid="hasToken">
            {inv && "token" in inv ? "yes" : "no"}
          </span>
        </div>
      );
    }

    renderWithAuth(token, <Harness />);

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    });

    expect(parseInt(screen.getByTestId("count").textContent!))
      .toBeGreaterThanOrEqual(1);
    expect(screen.getByTestId("orgId").textContent).toBe(orgId);
    expect(screen.getByTestId("role").textContent).toBe("member");
    // token must not be present in list responses
    expect(screen.getByTestId("hasToken").textContent).toBe("no");
  });
});

// ---------------------------------------------------------------------------
// useInvitation (unauthenticated invitee preview)
// ---------------------------------------------------------------------------

describe("useInvitation — integration", () => {
  it("shows org name and role before the invitee authenticates", async () => {
    const { token } = await newUser();
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

    function Harness() {
      const { invitation, status } = useInvitation(invId, invToken);
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="id">{invitation?.id ?? ""}</span>
          <span data-testid="orgName">{invitation?.orgName ?? ""}</span>
          <span data-testid="role">{invitation?.role ?? ""}</span>
          <span data-testid="expiresAt">{invitation?.expiresAt ?? ""}</span>
        </div>
      );
    }

    // useInvitation is unauthenticated — use a client with no token
    const anonClient = createClient<paths>({
      baseUrl: getBaseUrl(),
      staleTime: 0,
    });
    render(
      <AuthProvider client={anonClient}>
        <Harness />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    });

    expect(screen.getByTestId("id").textContent).toBe(invId);
    expect(screen.getByTestId("orgName").textContent).toBe(org.name);
    expect(screen.getByTestId("role").textContent).toBe("member");
    expect(screen.getByTestId("expiresAt").textContent).toMatch(/^\d{4}-/);
  });
});
