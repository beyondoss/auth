import { describe, expect, it } from "vitest";
import { type CookieStore, serverAuth } from "../next/server.js";
import { signup, testAuth, uniqueEmail } from "./harness.js";

function makeCookieStore(token: string | null): CookieStore {
  return {
    get: (name) =>
      name === "__Host-session" && token ? { value: token } : undefined,
  };
}

function helpers() {
  return serverAuth(testAuth());
}

describe("getSession", () => {
  it("returns the session for a valid token", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const { getSession } = helpers();
    const session = await getSession(makeCookieStore(auth.session.token));
    expect(session).not.toBeNull();
    expect(session!.id).toBe(auth.session.id);
  });

  it("returns null for an invalid token", async () => {
    const { getSession } = helpers();
    expect(await getSession(makeCookieStore("invalid-token"))).toBeNull();
  });

  it("returns null when no cookie is present", async () => {
    const { getSession } = helpers();
    expect(await getSession(makeCookieStore(null))).toBeNull();
  });
});

describe("getMe", () => {
  it("returns the user profile for a valid token", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const { getMe } = helpers();
    const me = await getMe(makeCookieStore(auth.session.token));
    expect(me).not.toBeNull();
    expect(me!.user.id).toBe(auth.user.id);
  });

  it("returns null for an invalid token", async () => {
    const { getMe } = helpers();
    expect(await getMe(makeCookieStore("invalid-token"))).toBeNull();
  });

  it("returns null when no cookie is present", async () => {
    const { getMe } = helpers();
    expect(await getMe(makeCookieStore(null))).toBeNull();
  });
});
