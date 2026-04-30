import { describe, expect, it } from "vitest";
import { AuthServiceError } from "../errors.js";
import { createAuthFlowClient } from "../flows/index.js";
import { createSessionVerifier } from "../session.js";
import { getBaseUrl, uniqueEmail } from "./harness.js";

function flows() {
  return createAuthFlowClient({ baseUrl: getBaseUrl() });
}

describe("signUp", () => {
  it("creates a user and returns a session", async () => {
    const email = uniqueEmail();
    const auth = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    expect(auth.user.id).toBeDefined();
    expect(auth.user.primaryOrgId).toBeDefined();
    expect(auth.email.email).toBe(email);
    expect(auth.session.token).toBeDefined();
    expect(auth.session.expiresAt).toBeDefined();
    expect(auth.org.id).toBeDefined();
  });

  it("throws AuthServiceError on duplicate email", async () => {
    const email = uniqueEmail();
    await flows().signUp({ email, password: "correct-horse-battery-staple" });
    await expect(
      flows().signUp({ email, password: "another-password" }),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthServiceError && e.status === 409,
    );
  });
});

describe("signIn", () => {
  it("signs in with password and returns a session", async () => {
    const email = uniqueEmail();
    await flows().signUp({ email, password: "correct-horse-battery-staple" });
    const result = await flows().signIn({
      grantType: "password",
      email,
      password: "correct-horse-battery-staple",
    });
    expect("session" in result).toBe(true);
    if ("session" in result) {
      expect(result.session.token).toBeDefined();
      expect(result.user.id).toBeDefined();
    }
  });

  it("throws AuthServiceError on wrong password", async () => {
    const email = uniqueEmail();
    await flows().signUp({ email, password: "correct-horse-battery-staple" });
    await expect(
      flows().signIn({ grantType: "password", email, password: "wrong" }),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthServiceError && e.status === 401,
    );
  });
});

describe("requestMagicLink + signIn magic_link", () => {
  it("issues and redeems a magic link", async () => {
    const email = uniqueEmail();
    await flows().signUp({ email, password: "correct-horse-battery-staple" });
    const { token, expiresAt } = await flows().requestMagicLink(email);
    expect(token).toBeDefined();
    expect(expiresAt).toBeDefined();

    const auth = await flows().signIn({ grantType: "magic_link", token });
    expect("session" in auth).toBe(true);
    if ("session" in auth) {
      expect(auth.user.id).toBeDefined();
    }
  });

  it("throws AuthServiceError for unknown email", async () => {
    await expect(
      flows().requestMagicLink(uniqueEmail()),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthServiceError && e.status === 404,
    );
  });
});

describe("requestPasswordReset + signIn password_reset", () => {
  it("issues and redeems a password reset token", async () => {
    const email = uniqueEmail();
    await flows().signUp({ email, password: "correct-horse-battery-staple" });
    const { token, expiresAt } = await flows().requestPasswordReset(email);
    expect(token).toBeDefined();
    expect(expiresAt).toBeDefined();

    const auth = await flows().signIn({
      grantType: "password_reset",
      token,
      newPassword: "new-horse-battery-staple",
    });
    expect("session" in auth).toBe(true);
  });

  it("throws AuthServiceError for unknown email", async () => {
    await expect(
      flows().requestPasswordReset(uniqueEmail()),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthServiceError && e.status === 404,
    );
  });
});

describe("beginPasskeyAuth", () => {
  it("returns WebAuthn options and a state token", async () => {
    const result = await flows().beginPasskeyAuth();
    expect(result.options).toBeDefined();
    expect(result.stateToken).toBeDefined();
  });
});

describe("signOut", () => {
  it("signs out the current session", async () => {
    const email = uniqueEmail();
    const auth = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    const token = auth.session.token;

    await flows().signOut(token);

    const verifier = createSessionVerifier({ baseUrl: getBaseUrl() });
    expect(await verifier.verify(token)).toBeNull();
  });
});

describe("signOutAll", () => {
  it("signs out all sessions", async () => {
    const email = uniqueEmail();
    const auth = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    await flows().signOutAll(auth.session.token);

    const verifier = createSessionVerifier({ baseUrl: getBaseUrl() });
    expect(await verifier.verify(auth.session.token)).toBeNull();
  });

  it("signs out all sessions except current", async () => {
    const email = uniqueEmail();
    const auth = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    await flows().signOutAll(auth.session.token, { exceptCurrent: true });

    const verifier = createSessionVerifier({ baseUrl: getBaseUrl() });
    expect(await verifier.verify(auth.session.token)).not.toBeNull();
  });
});

describe("issueToken", () => {
  it("issues a JWT access token", async () => {
    const email = uniqueEmail();
    const auth = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    const token = await flows().issueToken(auth.session.token);
    expect(token.accessToken).toBeDefined();
    expect(token.tokenType).toBe("Bearer");
    expect(token.expiresIn).toBeGreaterThan(0);
  });

  it("includes custom claims", async () => {
    const email = uniqueEmail();
    const auth = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    const token = await flows().issueToken(auth.session.token, {
      role: "admin",
    });
    expect(token.accessToken).toBeDefined();
  });
});
