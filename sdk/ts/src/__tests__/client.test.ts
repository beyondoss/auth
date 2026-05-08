import { describe, expect, it } from "vitest";
import { createAdminClient, createAuthClient } from "../client.js";
import { getAdminToken, getBaseUrl, signup, uniqueEmail } from "./harness.js";

describe("createAdminClient", () => {
  it("creates a user via users.create", async () => {
    const admin = createAdminClient({
      url: getBaseUrl(),
      token: getAdminToken(),
    });
    const email = uniqueEmail();
    const { data, error, response } = await admin.users.create({
      email,
      password: "correct-horse-battery-staple",
    });
    expect(response.status).toBe(201);
    expect(error).toBeUndefined();
    expect(data!.user.id).toBeDefined();
    expect(data!.email.email).toBe(email);
    expect(data!.session.token).toBeDefined();
  });

  it("returns an error body on invalid input", async () => {
    const admin = createAdminClient({
      url: getBaseUrl(),
      token: getAdminToken(),
    });
    const { data, error, response } = await admin.users.create({
      email: "not-an-email",
      password: "pw",
    });
    expect(response.status).toBe(422);
    expect(data).toBeUndefined();
    expect(error).toBeDefined();
  });

  it("looks up a user by email via users.getByEmail", async () => {
    const email = uniqueEmail();
    const created = await signup(email, "correct-horse-battery-staple");
    const admin = createAdminClient({
      url: getBaseUrl(),
      token: getAdminToken(),
    });
    const { data, error, response } = await admin.users.getByEmail(email);
    expect(response.status).toBe(200);
    expect(error).toBeUndefined();
    expect(data!.id).toBe(created.user.id);
  });

  it("looks up a user by id via users.getById", async () => {
    const email = uniqueEmail();
    const created = await signup(email, "correct-horse-battery-staple");
    const admin = createAdminClient({
      url: getBaseUrl(),
      token: getAdminToken(),
    });
    const { data, error, response } = await admin.users.getById(
      created.user.id,
    );
    expect(response.status).toBe(200);
    expect(error).toBeUndefined();
    expect(data!.id).toBe(created.user.id);
  });

  it("gets runtime config via config.get", async () => {
    const admin = createAdminClient({
      url: getBaseUrl(),
      token: getAdminToken(),
    });
    const { data, error, response } = await admin.config.get();
    expect(response.status).toBe(200);
    expect(error).toBeUndefined();
    expect(typeof data!.jwtEnabled).toBe("boolean");
  });

  it("revokes all sessions for a user via users.revokeSessions", async () => {
    const email = uniqueEmail();
    const created = await signup(email, "correct-horse-battery-staple");
    const admin = createAdminClient({
      url: getBaseUrl(),
      token: getAdminToken(),
    });
    const { error, response } = await admin.users.revokeSessions(
      created.user.id,
    );
    expect(response.status).toBe(204);
    expect(error).toBeUndefined();
  });

  it("fires onRequest with semantic command names", async () => {
    const commands: string[] = [];
    const admin = createAdminClient({
      url: getBaseUrl(),
      token: getAdminToken(),
      onRequest: ({ command }) => commands.push(command),
    });
    await admin.config.get();
    expect(commands).toContain("config.get");
  });
});

describe("createAuthClient", () => {
  it("lists identities for the authenticated user", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const client = createAuthClient({
      url: getBaseUrl(),
      token: auth.session.token,
    });
    const { data, error, response } = await client.identities.list();
    expect(response.status).toBe(200);
    expect(error).toBeUndefined();
    expect(Array.isArray(data!.identities)).toBe(true);
  });

  it("lists orgs for the authenticated user", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const client = createAuthClient({
      url: getBaseUrl(),
      token: auth.session.token,
    });
    const { data, error, response } = await client.orgs.list();
    expect(response.status).toBe(200);
    expect(error).toBeUndefined();
    // A newly signed-up user belongs to their default org
    expect(data!.orgs.length).toBeGreaterThanOrEqual(1);
  });

  it("creates and then lists an org invitation", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const client = createAuthClient({
      url: getBaseUrl(),
      token: auth.session.token,
    });

    const orgId = auth.org.id;
    const { data: inv, response: createRes } = await client.orgs.invitations
      .create(orgId, {
        email: uniqueEmail(),
        role: "member",
      });
    expect(createRes.status).toBe(201);
    expect(inv!.id).toBeDefined();

    const { data: list, response: listRes } = await client.orgs.invitations
      .list(orgId);
    expect(listRes.status).toBe(200);
    expect(list!.invitations.some((i) => i.id === inv!.id)).toBe(true);
  });
});
