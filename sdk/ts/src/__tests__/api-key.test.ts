import { beforeAll, describe, expect, it } from "vitest";
import { createApiKeyVerifier } from "../api-key.js";
import { type ApiKeyVerifier } from "../api-key.js";
import { authedClient, getBaseUrl, signup, uniqueEmail } from "./harness.js";

let verifier: ApiKeyVerifier;

beforeAll(() => {
  verifier = createApiKeyVerifier({ baseUrl: getBaseUrl() });
});

describe("createApiKeyVerifier", () => {
  it("returns userId for a valid API key", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const client = authedClient(auth.session.token);
    const { data } = await client.POST("/v1/keys", {
      body: { name: "test-key" },
    });
    expect(data).toBeDefined();

    const ctx = await verifier.verify(data!.key);
    expect(ctx).not.toBeNull();
    expect(ctx!.userId).toBe(auth.user.id);
  });

  it("returns null for an invalid key", async () => {
    const ctx = await verifier.verify("key_thisisnotavalidkey");
    expect(ctx).toBeNull();
  });

  it("returns null for a deleted key", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const client = authedClient(auth.session.token);
    const { data } = await client.POST("/v1/keys", {
      body: { name: "test-key" },
    });
    await client.DELETE("/v1/keys/{id}", {
      params: { path: { id: data!.id } },
    });

    const ctx = await verifier.verify(data!.key);
    expect(ctx).toBeNull();
  });
});
