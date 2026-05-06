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

    const result = await verifier.verify(data!.key);
    expect(result.error).toBeUndefined();
    expect(result.data).not.toBeNull();
    expect(result.data!.userId).toBe(auth.user.id);
  });

  it("returns null data for an invalid key", async () => {
    const result = await verifier.verify("key_thisisnotavalidkey");
    expect(result.error).toBeUndefined();
    expect(result.data).toBeNull();
  });

  it("returns null data for a deleted key", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const client = authedClient(auth.session.token);
    const { data } = await client.POST("/v1/keys", {
      body: { name: "test-key" },
    });
    await client.DELETE("/v1/keys/{id}", {
      params: { path: { id: data!.id } },
    });

    const result = await verifier.verify(data!.key);
    expect(result.error).toBeUndefined();
    expect(result.data).toBeNull();
  });
});
