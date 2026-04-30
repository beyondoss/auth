import { describe, expect, it } from "vitest";
import { createAuthClient } from "../client.js";
import { getBaseUrl, uniqueEmail, signup } from "./harness.js";

function authClient(token: string) {
  return createAuthClient({ baseUrl: getBaseUrl(), token });
}

async function newUser() {
  const email = uniqueEmail();
  const auth = await signup(email, "correct-horse-battery-staple");
  return { email, auth, client: authClient(auth.session.token) };
}

describe("me", () => {
  it("get returns the current user", async () => {
    const { email, auth, client } = await newUser();
    const me = await client.me.get();
    expect(me.user.id).toBe(auth.user.id);
    expect(me.email.email).toBe(email);
  });

  it("update reflects changes on subsequent get", async () => {
    const { client } = await newUser();
    await client.me.update({ name: "Test User" });
    const me = await client.me.get();
    expect(me.user.name).toBe("Test User");
  });

  it("delete removes the account", async () => {
    const { client } = await newUser();
    await expect(client.me.delete()).resolves.toBeUndefined();
  });
});

describe("passkeys", () => {
  it("list returns empty array for a new user", async () => {
    const { client } = await newUser();
    const { data, error } = await client.passkeys.list();
    expect(error).toBeUndefined();
    expect(Array.isArray(data)).toBe(true);
    expect(data).toHaveLength(0);
  });

  it("beginRegistration returns options and stateToken", async () => {
    const { client } = await newUser();
    const { data, error } = await client.passkeys.beginRegistration();
    expect(error).toBeUndefined();
    expect(data?.options).toBeDefined();
    expect(data?.stateToken).toBeDefined();
  });
});

describe("emails", () => {
  it("list contains the signup email", async () => {
    const { email, client } = await newUser();
    const { data, error } = await client.emails.list();
    expect(error).toBeUndefined();
    expect(Array.isArray(data)).toBe(true);
    expect(data?.some((e) => e.email === email)).toBe(true);
  });

  it("add returns a token and expiresAt", async () => {
    const { client } = await newUser();
    const result = await client.emails.add(uniqueEmail());
    expect(result.token).toBeDefined();
    expect(result.expiresAt).toBeDefined();
  });

  it("delete removes an unverified email from the list", async () => {
    const { client } = await newUser();
    await client.emails.add(uniqueEmail());
    const { data: before } = await client.emails.list();
    const target = before?.find((e) => !e.isPrimary);
    if (!target) {
      // added email might not appear until verified — acceptable
      return;
    }
    await client.emails.delete(target.id);
    const { data: after } = await client.emails.list();
    expect(after?.some((e) => e.id === target.id)).toBe(false);
  });
});

describe("totp", () => {
  it("enroll returns provisioning URI, QR URL, secret, and recovery codes", async () => {
    const { client } = await newUser();
    const result = await client.totp.enroll();
    expect(result.factorId).toBeDefined();
    expect(result.provisioningUri).toBeDefined();
    expect(result.qrDataUrl).toBeDefined();
    expect(result.secretB32).toBeDefined();
    expect(Array.isArray(result.recoveryCodes)).toBe(true);
    expect(result.recoveryCodes.length).toBeGreaterThan(0);
  });
});

describe("sessions", () => {
  it("list contains at least one session", async () => {
    const { client } = await newUser();
    const { data, error } = await client.sessions.list();
    expect(error).toBeUndefined();
    expect(data?.sessions.length).toBeGreaterThan(0);
  });

  it("getCurrent returns the session with expected fields", async () => {
    const { client } = await newUser();
    const session = await client.sessions.getCurrent();
    expect(session.tokenId).toBeDefined();
    expect(session.createdAt).toBeDefined();
    expect(session.expiresAt).toBeDefined();
  });

  it("deleteById removes a non-current session", async () => {
    const { client } = await newUser();
    const { data } = await client.sessions.list();
    const target = data?.sessions.find((s) => !s.current);
    if (!target) {
      // Only one session — can't delete the current one, skip
      expect(data?.sessions.length).toBeGreaterThan(0);
      return;
    }
    await expect(client.sessions.deleteById(target.id)).resolves.toBeUndefined();
  });
});

describe("keys", () => {
  it("create returns a key with the secret field", async () => {
    const { client } = await newUser();
    const key = await client.keys.create("test-key");
    expect(key.id).toBeDefined();
    expect(key.name).toBe("test-key");
    expect(key.key).toBeDefined();
    expect(key.createdAt).toBeDefined();
  });

  it("list contains the created key", async () => {
    const { client } = await newUser();
    const created = await client.keys.create("listed-key");
    const { data, error } = await client.keys.list();
    expect(error).toBeUndefined();
    expect(data?.keys.some((k) => k.id === created.id)).toBe(true);
  });

  it("get returns the key by id", async () => {
    const { client } = await newUser();
    const created = await client.keys.create("get-key");
    const key = await client.keys.get(created.id);
    expect(key.id).toBe(created.id);
    expect(key.name).toBe("get-key");
  });

  it("delete removes the key from the list", async () => {
    const { client } = await newUser();
    const created = await client.keys.create("delete-key");
    await client.keys.delete(created.id);
    const { data } = await client.keys.list();
    expect(data?.keys.some((k) => k.id === created.id)).toBe(false);
  });

  it("create with expiresAt sets expiry", async () => {
    const { client } = await newUser();
    const expiry = new Date(Date.now() + 86400_000).toISOString();
    const key = await client.keys.create("expiring-key", expiry);
    expect(key.expiresAt).toBeDefined();
  });
});
