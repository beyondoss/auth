import { describe, expect, it } from "vitest";
import { AuthError } from "../errors.js";
import { createAuthFlowClient } from "../flows/index.js";
import { createSessionVerifier } from "../session.js";
import { getBaseUrl, uniqueEmail } from "./harness.js";

function flows() {
  return createAuthFlowClient({ url: getBaseUrl() });
}

describe("signUp", () => {
  it("creates a user and returns a session", async () => {
    const email = uniqueEmail();
    const { data: auth } = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    expect(auth?.user.id).toBeDefined();
    expect(auth?.user.primaryOrgId).toBeDefined();
    expect(auth?.email.email).toBe(email);
    expect(auth?.session.token).toBeDefined();
    expect(auth?.session.expiresAt).toBeDefined();
    expect(auth?.org.id).toBeDefined();
  });

  it("returns AuthError(409) on duplicate email", async () => {
    const email = uniqueEmail();
    await flows().signUp({ email, password: "correct-horse-battery-staple" });
    const { error } = await flows().signUp({
      email,
      password: "another-password",
    });
    expect(error).toSatisfy(
      (e: unknown) => e instanceof AuthError && e.status === 409,
    );
  });
});

describe("signIn", () => {
  it("signs in with password and returns a session", async () => {
    const email = uniqueEmail();
    await flows().signUp({ email, password: "correct-horse-battery-staple" });
    const { data: result } = await flows().signIn({
      grantType: "password",
      email,
      password: "correct-horse-battery-staple",
    });
    expect("session" in result!).toBe(true);
    if (result && "session" in result) {
      expect(result.session.token).toBeDefined();
      expect(result.user.id).toBeDefined();
    }
  });

  it("returns AuthError(401) on wrong password", async () => {
    const email = uniqueEmail();
    await flows().signUp({ email, password: "correct-horse-battery-staple" });
    const { error } = await flows().signIn({
      grantType: "password",
      email,
      password: "wrong",
    });
    expect(error).toSatisfy(
      (e: unknown) => e instanceof AuthError && e.status === 401,
    );
  });
});

describe("requestMagicLink + signIn magic_link", () => {
  it("issues and redeems a magic link", async () => {
    const email = uniqueEmail();
    await flows().signUp({ email, password: "correct-horse-battery-staple" });
    const { data: ml } = await flows().requestMagicLink(email);
    expect(ml?.token).toBeDefined();
    expect(ml?.expiresAt).toBeDefined();

    const { data: auth } = await flows().signIn({
      grantType: "magic_link",
      token: ml!.token,
    });
    expect("session" in auth!).toBe(true);
    if (auth && "session" in auth) {
      expect(auth.user.id).toBeDefined();
    }
  });

  it("returns AuthError(404) for unknown email", async () => {
    const { error } = await flows().requestMagicLink(uniqueEmail());
    expect(error).toSatisfy(
      (e: unknown) => e instanceof AuthError && e.status === 404,
    );
  });
});

describe("requestPasswordReset + signIn password_reset", () => {
  it("issues and redeems a password reset token", async () => {
    const email = uniqueEmail();
    await flows().signUp({ email, password: "correct-horse-battery-staple" });
    const { data: pr } = await flows().requestPasswordReset(email);
    expect(pr?.token).toBeDefined();
    expect(pr?.expiresAt).toBeDefined();

    const { data: auth } = await flows().signIn({
      grantType: "password_reset",
      token: pr!.token,
      newPassword: "new-horse-battery-staple",
    });
    expect("session" in auth!).toBe(true);
  });

  it("returns a syntactically-valid token for unknown emails so callers can't distinguish registered addresses", async () => {
    // POST /v1/password-resets always returns 200 by design — when no
    // matching account or password identity exists, an unstored token is
    // returned that looks identical to a real one. This prevents enumeration
    // of registered email addresses via the password-reset endpoint.
    const known = uniqueEmail();
    await flows().signUp({
      email: known,
      password: "correct-horse-battery-staple",
    });

    const knownResult = await flows().requestPasswordReset(known);
    const unknownResult = await flows().requestPasswordReset(uniqueEmail());

    expect(knownResult.error).toBeUndefined();
    expect(unknownResult.error).toBeUndefined();
    expect(knownResult.data?.token).toBeDefined();
    expect(unknownResult.data?.token).toBeDefined();
    expect(knownResult.data?.expiresAt).toBeDefined();
    expect(unknownResult.data?.expiresAt).toBeDefined();
  });
});

describe("beginPasskeyAuth", () => {
  it("returns WebAuthn options and a state token", async () => {
    const { data: result } = await flows().beginPasskeyAuth();
    expect(result?.options).toBeDefined();
    expect(result?.stateToken).toBeDefined();
  });
});

describe("signOut", () => {
  it("signs out the current session", async () => {
    const email = uniqueEmail();
    const { data: auth } = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    const token = auth!.session.token;

    await flows().signOut(token);

    const verifier = createSessionVerifier({ url: getBaseUrl() });
    expect((await verifier.verify(token)).data).toBeNull();
  });
});

describe("signOutAll", () => {
  it("signs out all sessions", async () => {
    const email = uniqueEmail();
    const { data: auth } = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    await flows().signOutAll(auth!.session.token);

    const verifier = createSessionVerifier({ url: getBaseUrl() });
    expect((await verifier.verify(auth!.session.token)).data).toBeNull();
  });

  it("signs out all sessions except current", async () => {
    const email = uniqueEmail();
    const { data: auth } = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    await flows().signOutAll(auth!.session.token, { exceptCurrent: true });

    const verifier = createSessionVerifier({ url: getBaseUrl() });
    expect((await verifier.verify(auth!.session.token)).data).not.toBeNull();
  });
});

describe("issueToken", () => {
  it("issues a JWT access token", async () => {
    const email = uniqueEmail();
    const { data: auth } = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    const { data: token } = await flows().issueToken(auth!.session.token);
    expect(token?.accessToken).toBeDefined();
    expect(token?.tokenType).toBe("Bearer");
    expect(token?.expiresIn).toBeGreaterThan(0);
  });

  it("includes custom claims", async () => {
    const email = uniqueEmail();
    const { data: auth } = await flows().signUp({
      email,
      password: "correct-horse-battery-staple",
    });
    const { data: token } = await flows().issueToken(auth!.session.token, {
      role: "admin",
    });
    expect(token?.accessToken).toBeDefined();
  });
});
