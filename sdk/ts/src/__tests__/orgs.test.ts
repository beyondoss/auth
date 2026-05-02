import { describe, expect, it } from "vitest";
import { createAuthClient } from "../client.js";
import { getBaseUrl, publicClient, signup, uniqueEmail } from "./harness.js";

const PASSWORD = "correct-horse-battery-staple";

function authClient(token: string) {
  return createAuthClient({ baseUrl: getBaseUrl(), token });
}

async function newUser() {
  const email = uniqueEmail();
  const auth = await signup(email, PASSWORD);
  return { email, auth, client: authClient(auth.session.token) };
}

// ---------------------------------------------------------------------------
// Orgs CRUD
// ---------------------------------------------------------------------------

describe("orgs — create", () => {
  it("returns org with id, name, slug, and createdAt", async () => {
    const { client } = await newUser();
    const { data, error } = await client.orgs.create({ name: "Acme Corp" });
    expect(error).toBeUndefined();
    expect(data?.id).toBeDefined();
    expect(data?.name).toBe("Acme Corp");
    expect(data?.slug).toBeDefined();
    expect(data?.createdAt).toBeDefined();
  });

  it("accepts an explicit slug", async () => {
    const { client } = await newUser();
    const slug = `acme-${crypto.randomUUID().slice(0, 8)}`;
    const { data, error } = await client.orgs.create({
      name: "Acme Corp",
      slug,
    });
    expect(error).toBeUndefined();
    expect(data?.slug).toBe(slug);
  });

  it("accepts optional metadata", async () => {
    const { client } = await newUser();
    const { data, error } = await client.orgs.create({
      name: "Meta Org",
      metadata: { plan: "pro" },
    });
    expect(error).toBeUndefined();
    expect(data?.id).toBeDefined();
  });
});

describe("orgs — get", () => {
  it("returns the same data as the create response", async () => {
    const { client } = await newUser();
    const { data: created } = await client.orgs.create({
      name: "Get Test Org",
    });
    const orgId = created!.id;

    const { data, error } = await client.orgs.get(orgId);
    expect(error).toBeUndefined();
    expect(data?.id).toBe(orgId);
    expect(data?.name).toBe("Get Test Org");
    expect(data?.slug).toBe(created!.slug);
    expect(data?.createdAt).toBeDefined();
  });
});

describe("orgs — list", () => {
  it("includes the newly created org", async () => {
    const { client } = await newUser();
    const { data: created } = await client.orgs.create({ name: "Listed Org" });
    const orgId = created!.id;

    const { data, error } = await client.orgs.list();
    expect(error).toBeUndefined();
    expect(Array.isArray(data?.orgs)).toBe(true);
    expect(data?.orgs.some((o) => o.id === orgId)).toBe(true);
  });
});

describe("orgs — update", () => {
  it("name change is reflected on subsequent get", async () => {
    const { client } = await newUser();
    const { data: created } = await client.orgs.create({
      name: "Old Name",
    });
    const orgId = created!.id;

    const { error: updateError } = await client.orgs.update(orgId, {
      name: "New Name",
    });
    expect(updateError).toBeUndefined();

    const { data } = await client.orgs.get(orgId);
    expect(data?.name).toBe("New Name");
  });
});

describe("orgs — delete", () => {
  it("deleted org no longer appears in list", async () => {
    const { client } = await newUser();
    const { data: created } = await client.orgs.create({ name: "Doomed Org" });
    const orgId = created!.id;

    await client.orgs.delete(orgId);

    const { data } = await client.orgs.list();
    expect(data?.orgs.some((o) => o.id === orgId)).toBe(false);
  });

  it("get on deleted org returns 404", async () => {
    const { client } = await newUser();
    const { data: created } = await client.orgs.create({
      name: "Gone Org",
    });
    const orgId = created!.id;

    await client.orgs.delete(orgId);

    const { data, response } = await client.orgs.get(orgId);
    expect(data).toBeUndefined();
    expect(response.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

describe("orgs — members", () => {
  it("creator is automatically a member with owner role", async () => {
    const { auth, client } = await newUser();
    const { data: org } = await client.orgs.create({
      name: "Creator Org",
    });
    const orgId = org!.id;

    const { data, error } = await client.orgs.members.list(orgId);
    expect(error).toBeUndefined();
    expect(Array.isArray(data?.members)).toBe(true);
    expect(data?.members).toHaveLength(1);

    const member = data!.members[0]!;
    expect(member.userId).toBe(auth.user.id);
    expect(member.role).toBe("owner");
  });

  it("accepted invitee appears in member list", async () => {
    const { auth: ownerAuth, client: ownerClient } = await newUser();
    const { data: org } = await ownerClient.orgs.create({
      name: "Two-Member Org",
    });
    const orgId = org!.id;

    // Create a second user who will be invited
    const { auth: inviteeAuth, client: inviteeClient } = await newUser();

    // Invite them
    const { data: inv } = await ownerClient.orgs.invitations.create(orgId, {
      email: inviteeAuth.email.email,
      role: "member",
    });
    const invId = inv!.id;
    const invToken = inv!.token!;

    // Invitee accepts
    await inviteeClient.invitations.accept(invId, invToken);

    // Both users should appear as members
    const { data: membersData } = await ownerClient.orgs.members.list(orgId);
    const userIds = membersData!.members.map((m) => m.userId);
    expect(userIds).toContain(ownerAuth.user.id);
    expect(userIds).toContain(inviteeAuth.user.id);
  });

  it("can update a member's role", async () => {
    const { client: ownerClient } = await newUser();
    const { data: org } = await ownerClient.orgs.create({
      name: "Role Update Org",
    });
    const orgId = org!.id;

    const { auth: inviteeAuth, client: inviteeClient } = await newUser();
    const { data: inv } = await ownerClient.orgs.invitations.create(orgId, {
      email: inviteeAuth.email.email,
      role: "member",
    });
    await inviteeClient.invitations.accept(inv!.id, inv!.token!);

    const { data: membersData } = await ownerClient.orgs.members.list(orgId);
    const inviteeMember = membersData!.members.find(
      (m) => m.userId === inviteeAuth.user.id,
    )!;
    expect(inviteeMember.role).toBe("member");

    // Promote to admin — member_id is the user's ID
    const { error } = await ownerClient.orgs.members.update(
      orgId,
      inviteeMember.userId,
      { role: "admin" },
    );
    expect(error).toBeUndefined();

    const { data: updated } = await ownerClient.orgs.members.list(orgId);
    const after = updated!.members.find((m) =>
      m.userId === inviteeAuth.user.id
    )!;
    expect(after.role).toBe("admin");
  });

  it("removed member disappears from list", async () => {
    const { client: ownerClient } = await newUser();
    const { data: org } = await ownerClient.orgs.create({
      name: "Remove Member Org",
    });
    const orgId = org!.id;

    const { auth: inviteeAuth, client: inviteeClient } = await newUser();
    const { data: inv } = await ownerClient.orgs.invitations.create(orgId, {
      email: inviteeAuth.email.email,
      role: "member",
    });
    await inviteeClient.invitations.accept(inv!.id, inv!.token!);

    const { data: before } = await ownerClient.orgs.members.list(orgId);
    const inviteeMember = before!.members.find(
      (m) => m.userId === inviteeAuth.user.id,
    )!;

    // member_id is the user's ID
    const { error } = await ownerClient.orgs.members.remove(
      orgId,
      inviteeMember.userId,
    );
    expect(error).toBeUndefined();

    const { data: after } = await ownerClient.orgs.members.list(orgId);
    expect(after!.members.some((m) => m.userId === inviteeAuth.user.id)).toBe(
      false,
    );
  });
});

// ---------------------------------------------------------------------------
// Invitations — inviter side
// ---------------------------------------------------------------------------

describe("orgs — invitations (inviter)", () => {
  it("create returns a non-empty token", async () => {
    const { client } = await newUser();
    const { data: org } = await client.orgs.create({ name: "Token Org" });
    const { data, error } = await client.orgs.invitations.create(org!.id, {
      email: uniqueEmail(),
      role: "member",
    });
    expect(error).toBeUndefined();
    expect(data?.id).toBeDefined();
    expect(typeof data?.token).toBe("string");
    expect((data?.token ?? "").length).toBeGreaterThan(0);
  });

  it("token is null when listing invitations (one-time only)", async () => {
    const { client } = await newUser();
    const { data: org } = await client.orgs.create({ name: "List Token Org" });
    const orgId = org!.id;

    await client.orgs.invitations.create(orgId, {
      email: uniqueEmail(),
      role: "member",
    });

    const { data, error } = await client.orgs.invitations.list(orgId);
    expect(error).toBeUndefined();
    expect(Array.isArray(data?.invitations)).toBe(true);
    expect(data!.invitations.length).toBeGreaterThan(0);

    for (const inv of data!.invitations) {
      // token is omitted from list responses — never returned after creation
      expect(inv.token == null).toBe(true);
    }
  });

  it("created invitation appears in list", async () => {
    const { client } = await newUser();
    const { data: org } = await client.orgs.create({ name: "Inv List Org" });
    const orgId = org!.id;

    const { data: inv } = await client.orgs.invitations.create(orgId, {
      email: uniqueEmail(),
      role: "member",
    });
    const invId = inv!.id;

    const { data } = await client.orgs.invitations.list(orgId);
    expect(data!.invitations.some((i) => i.id === invId)).toBe(true);
  });

  it("revoked invitation disappears from list", async () => {
    const { client } = await newUser();
    const { data: org } = await client.orgs.create({ name: "Revoke Org" });
    const orgId = org!.id;

    const { data: inv } = await client.orgs.invitations.create(orgId, {
      email: uniqueEmail(),
      role: "member",
    });
    const invId = inv!.id;

    const { error } = await client.orgs.invitations.revoke(orgId, invId);
    expect(error).toBeUndefined();

    const { data } = await client.orgs.invitations.list(orgId);
    expect(data!.invitations.some((i) => i.id === invId)).toBe(false);
  });

  it("resend returns a new token and invitation remains in list", async () => {
    const { auth, client } = await newUser();
    const { data: org } = await client.orgs.create({ name: "Resend Org" });
    const orgId = org!.id;

    const { data: inv } = await client.orgs.invitations.create(orgId, {
      email: uniqueEmail(),
      role: "member",
    });
    const invId = inv!.id;
    const originalToken = inv!.token!;

    // Resend via raw client — not yet in the typed SDK
    const raw = publicClient();
    const { data: resent, error, response } = await raw.POST(
      "/v1/orgs/{id}/invitations/{inv_id}/resends",
      {
        params: { path: { id: orgId, inv_id: invId } },
        headers: { Authorization: `Bearer ${auth.session.token}` },
      },
    );
    expect(error).toBeUndefined();
    expect(response.status).toBe(201);
    expect(resent?.token).toBeDefined();
    expect(resent?.token).not.toBe(originalToken);

    // Invitation still exists in list
    const { data: listData } = await client.orgs.invitations.list(orgId);
    expect(listData!.invitations.some((i) => i.id === invId)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Invitations — invitee side
// ---------------------------------------------------------------------------

describe("invitations — invitee view/accept/decline", () => {
  it("view returns org name, role, and expiresAt before accepting", async () => {
    const { client: ownerClient } = await newUser();
    const { data: org } = await ownerClient.orgs.create({ name: "View Org" });
    const orgId = org!.id;

    const { data: inv } = await ownerClient.orgs.invitations.create(orgId, {
      email: uniqueEmail(),
      role: "member",
    });
    const invId = inv!.id;
    const invToken = inv!.token!;

    // view is unauthenticated — any client works; use a fresh user's client
    const { client: viewerClient } = await newUser();
    const { data, error } = await viewerClient.invitations.view(
      invId,
      invToken,
    );
    expect(error).toBeUndefined();
    expect(data?.id).toBe(invId);
    expect(data?.orgName).toBeDefined();
    expect(data?.role).toBeDefined();
    expect(data?.expiresAt).toBeDefined();
  });

  it("accept adds invitee to member list and returns success", async () => {
    const { client: ownerClient } = await newUser();
    const { data: org } = await ownerClient.orgs.create({
      name: "Accept Org",
    });
    const orgId = org!.id;

    const { auth: inviteeAuth, client: inviteeClient } = await newUser();
    const { data: inv } = await ownerClient.orgs.invitations.create(orgId, {
      email: inviteeAuth.email.email,
      role: "member",
    });

    const { error, response } = await inviteeClient.invitations.accept(
      inv!.id,
      inv!.token!,
    );
    expect(error).toBeUndefined();
    // 200 or 204
    expect(response.status).toBeLessThan(300);

    const { data: membersData } = await ownerClient.orgs.members.list(orgId);
    expect(
      membersData!.members.some((m) => m.userId === inviteeAuth.user.id),
    ).toBe(true);
  });

  it("decline returns success and invitation is consumed (removed from list)", async () => {
    const { client: ownerClient } = await newUser();
    const { data: org } = await ownerClient.orgs.create({
      name: "Decline Org",
    });
    const orgId = org!.id;

    const { data: inv } = await ownerClient.orgs.invitations.create(orgId, {
      email: uniqueEmail(),
      role: "member",
    });
    const invId = inv!.id;
    const invToken = inv!.token!;

    // decline is unauthenticated; use a fresh user's client
    const { client: declinerClient } = await newUser();
    const { error, response } = await declinerClient.invitations.decline(
      invId,
      invToken,
    );
    expect(error).toBeUndefined();
    expect(response.status).toBeLessThan(300);

    // Invitation should no longer appear in the list
    const { data } = await ownerClient.orgs.invitations.list(orgId);
    expect(data!.invitations.some((i) => i.id === invId)).toBe(false);
  });

  it("accepting an already-consumed invitation fails with 4xx", async () => {
    const { client: ownerClient } = await newUser();
    const { data: org } = await ownerClient.orgs.create({
      name: "Double Accept Org",
    });
    const orgId = org!.id;

    const { auth: inviteeAuth, client: inviteeClient } = await newUser();
    const { data: inv } = await ownerClient.orgs.invitations.create(orgId, {
      email: inviteeAuth.email.email,
      role: "member",
    });
    const invId = inv!.id;
    const invToken = inv!.token!;

    // First accept succeeds
    await inviteeClient.invitations.accept(invId, invToken);

    // Second accept on the same consumed token should fail
    const { client: otherClient } = await newUser();
    const { response } = await otherClient.invitations.accept(invId, invToken);
    expect(response.status).toBeGreaterThanOrEqual(400);
  });
});
