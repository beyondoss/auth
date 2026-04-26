import { describe, expect, it, vi } from "vitest";
import { AuthServiceError } from "../errors.js";
import { createSessionVerifier } from "../session.js";
import type { components } from "../types.js";

type CurrentSessionResponse = components["schemas"]["CurrentSessionResponse"];

const mockSession: CurrentSessionResponse = {
  id: "ses_1",
  token_id: "tok_id_1",
  created_at: "2024-01-01T00:00:00Z",
  expires_at: "2024-01-02T00:00:00Z",
  ip_address: "127.0.0.1",
  user_agent: "test",
};

function mockFetch(status: number, body: unknown): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    }),
  );
}

describe("createSessionVerifier", () => {
  it("returns session context on 200", async () => {
    const fetchImpl = mockFetch(200, mockSession);
    const original = globalThis.fetch;
    globalThis.fetch = fetchImpl as typeof fetch;
    const verifier = createSessionVerifier({ baseUrl: "http://auth" });
    const ctx = await verifier.verify("tok_abc");
    expect(ctx?.id).toBe("ses_1");
    globalThis.fetch = original;
  });

  it("returns null on 401", async () => {
    const fetchImpl = mockFetch(401, {
      error: { code: "unauthorized", message: "unauthorized" },
    });
    const original = globalThis.fetch;
    globalThis.fetch = fetchImpl as typeof fetch;
    const verifier = createSessionVerifier({ baseUrl: "http://auth" });
    const ctx = await verifier.verify("tok_bad");
    expect(ctx).toBeNull();
    globalThis.fetch = original;
  });

  it("throws AuthServiceError on 500", async () => {
    const fetchImpl = mockFetch(500, {
      error: { code: "internal_error", message: "oops" },
    });
    const original = globalThis.fetch;
    globalThis.fetch = fetchImpl as typeof fetch;
    const verifier = createSessionVerifier({ baseUrl: "http://auth" });
    await expect(verifier.verify("tok_bad")).rejects.toBeInstanceOf(
      AuthServiceError,
    );
    globalThis.fetch = original;
  });

  it("sends Authorization: Bearer header", async () => {
    const fetchImpl = mockFetch(200, mockSession);
    const original = globalThis.fetch;
    globalThis.fetch = fetchImpl as typeof fetch;
    const verifier = createSessionVerifier({ baseUrl: "http://auth" });
    await verifier.verify("tok_xyz");
    const [calledRequest] = (fetchImpl as ReturnType<typeof vi.fn>).mock
      .calls[0] as [Request];
    expect(calledRequest.url).toBe("http://auth/v1/sessions/current");
    expect(calledRequest.headers.get("authorization")).toBe("Bearer tok_xyz");
    globalThis.fetch = original;
  });
});
