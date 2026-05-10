import { describe, expect, it } from "vitest";
import { AuthError } from "../errors.js";
import { createSessionVerifier } from "../session.js";
import { authedClient, getBaseUrl, signup, uniqueEmail } from "./harness.js";

describe("createSessionVerifier", () => {
  it("verifies a valid session token", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const result = await createSessionVerifier({
      url: getBaseUrl(),
    }).verify(auth.session.token);
    expect(result.error).toBeUndefined();
    expect(result.data).not.toBeNull();
    expect(result.data!.id).toBe(auth.session.id);
    expect(result.data!.tokenId).toBeDefined();
    expect(result.data!.createdAt).toBeDefined();
    expect(result.data!.expiresAt).toBeDefined();
  });

  it("returns null data for an invalid token", async () => {
    const result = await createSessionVerifier({
      url: getBaseUrl(),
    }).verify("invalid-token");
    expect(result.error).toBeUndefined();
    expect(result.data).toBeNull();
  });

  it("returns null data after the session is revoked", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const verifier = createSessionVerifier({ url: getBaseUrl() });

    expect((await verifier.verify(auth.session.token)).data).not.toBeNull();

    const { error } = await authedClient(auth.session.token).DELETE(
      "/v1/sessions/current",
    );
    expect(error).toBeUndefined();

    expect((await verifier.verify(auth.session.token)).data).toBeNull();
  });

  it("propagates network errors as rejections", async () => {
    // Network failures (not HTTP errors) still propagate as uncaught exceptions.
    // Only HTTP-level service errors are captured in the result object.
    const verifier = createSessionVerifier({ url: "http://127.0.0.1:1" });
    await expect(verifier.verify("tok")).rejects.toSatisfy(
      (e: unknown) => !(e instanceof AuthError),
    );
  });
});
