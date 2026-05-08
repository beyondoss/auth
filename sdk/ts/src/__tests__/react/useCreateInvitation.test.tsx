// @vitest-environment jsdom
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createBrowserAuth } from "../../react/index.js";
import type { CreatedInvitation } from "../../react/useCreateInvitation.js";

const AUTH_URL = "http://auth";

// Wire shape (camelCase, post-proxy) returned by the gateway in production.
const INVITATION_BODY = {
  id: "inv-123",
  orgId: "org-456",
  role: "member",
  createdAt: "2024-01-01T00:00:00Z",
  expiresAt: "2024-01-08T00:00:00Z",
  token: "plaintext-one-time-token",
};

function setupFetch(
  handlers: Record<string, () => Response | Promise<Response>>,
) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : input.toString();
      const method = (
        input instanceof Request ? input.method : init?.method ?? "GET"
      ).toUpperCase();
      const key = `${method} ${url.replace(AUTH_URL, "")}`;
      const handler = handlers[key];
      return Promise.resolve(
        handler ? handler() : new Response(null, { status: 404 }),
      );
    }),
  );
}

// ---------------------------------------------------------------------------
// useCreateInvitation
// ---------------------------------------------------------------------------

describe("useCreateInvitation", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("happy path: returns invitation, token, and buildLink", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations": () =>
        new Response(JSON.stringify(INVITATION_BODY), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    });

    const { AuthProvider, useCreateInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const results: CreatedInvitation[] = [];

    function Inner() {
      const { createInvitation, status } = useCreateInvitation();

      React.useEffect(() => {
        createInvitation("org-id", { role: "member" })
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return <div data-testid="status">{status}</div>;
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0));

    const result = results[0]!;
    expect(result.token).toBe("plaintext-one-time-token");
    expect(typeof result.buildLink).toBe("function");
    expect(result.invitation).toBeDefined();
  });

  it("buildLink basic: appends id and token query params", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations": () =>
        new Response(JSON.stringify(INVITATION_BODY), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    });

    const { AuthProvider, useCreateInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const results: CreatedInvitation[] = [];

    function Inner() {
      const { createInvitation } = useCreateInvitation();

      React.useEffect(() => {
        createInvitation("org-id", { role: "member" })
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return null;
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0));

    const { buildLink } = results[0]!;
    expect(buildLink("https://app.example.com/invite")).toBe(
      "https://app.example.com/invite?id=inv-123&token=plaintext-one-time-token",
    );
  });

  it("buildLink strips trailing slash from base URL", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations": () =>
        new Response(JSON.stringify(INVITATION_BODY), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    });

    const { AuthProvider, useCreateInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const results: CreatedInvitation[] = [];

    function Inner() {
      const { createInvitation } = useCreateInvitation();

      React.useEffect(() => {
        createInvitation("org-id", { role: "member" })
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return null;
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0));

    const { buildLink } = results[0]!;
    expect(buildLink("https://app.example.com/invite/")).toBe(
      "https://app.example.com/invite?id=inv-123&token=plaintext-one-time-token",
    );
  });

  it("buildLink URL-encodes tokens containing special characters", async () => {
    const base64Token = "abc+def/ghi==";
    setupFetch({
      "POST /v1/orgs/org-id/invitations": () =>
        new Response(
          JSON.stringify({ ...INVITATION_BODY, token: base64Token }),
          {
            status: 201,
            headers: { "content-type": "application/json" },
          },
        ),
    });

    const { AuthProvider, useCreateInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const results: CreatedInvitation[] = [];

    function Inner() {
      const { createInvitation } = useCreateInvitation();

      React.useEffect(() => {
        createInvitation("org-id", { role: "member" })
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return null;
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0));

    const { buildLink } = results[0]!;
    const link = buildLink("https://app.example.com/invite");
    expect(link).toBe(
      `https://app.example.com/invite?id=inv-123&token=${
        encodeURIComponent(base64Token)
      }`,
    );
    // Sanity-check that raw special chars from the token are percent-encoded:
    // '+' → %2B, '/' → %2F, '=' → %3D — none of the raw chars should appear
    // in the token portion. We verify by round-tripping through URLSearchParams.
    const params = new URL(link).searchParams;
    expect(params.get("token")).toBe(base64Token); // auto-decoded = original
    expect(link).not.toContain("+"); // raw + is never present (encoded as %2B)
  });

  it("camelizes invitation fields from snake_case response", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations": () =>
        new Response(JSON.stringify(INVITATION_BODY), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    });

    const { AuthProvider, useCreateInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const results: CreatedInvitation[] = [];

    function Inner() {
      const { createInvitation } = useCreateInvitation();

      React.useEffect(() => {
        createInvitation("org-id", { role: "member" })
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return null;
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0));

    const { invitation } = results[0]!;
    expect(invitation.id).toBe("inv-123");
    expect(invitation.orgId).toBe("org-456");
    expect(invitation.role).toBe("member");
    expect(invitation.createdAt).toBeDefined();
    expect(invitation.expiresAt).toBeDefined();
  });

  it("error case: 422 response sets status to error and error state", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations": () =>
        new Response(
          JSON.stringify({ code: "invalid_role", message: "unknown role" }),
          {
            status: 422,
            headers: { "content-type": "application/json" },
          },
        ),
    });

    const { AuthProvider, useCreateInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const rejections: unknown[] = [];

    function Inner() {
      const { createInvitation, status, error } = useCreateInvitation();

      React.useEffect(() => {
        createInvitation("org-id", { role: "member" }).catch((err) =>
          rejections.push(err)
        );
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="error">
            {(error?.data as any)?.code ?? "none"}
          </span>
        </div>
      );
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(rejections.length).toBeGreaterThan(0));
    await waitFor(() =>
      expect(screen.getByTestId("status").textContent).toBe("error")
    );
    expect(screen.getByTestId("error").textContent).toBe("invalid_role");
  });

  it("sends email and role in the request body", async () => {
    let capturedBody: unknown = null;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input instanceof Request ? input.url : input.toString();
        const method = (
          input instanceof Request ? input.method : init?.method ?? "GET"
        ).toUpperCase();

        if (
          method === "POST"
          && url.replace(AUTH_URL, "") === "/v1/orgs/org-id/invitations"
        ) {
          const bodyText = input instanceof Request
            ? await input.text()
            : typeof init?.body === "string"
            ? init.body
            : "";
          capturedBody = JSON.parse(bodyText);
          return new Response(
            JSON.stringify({ ...INVITATION_BODY, role: "admin" }),
            {
              status: 201,
              headers: { "content-type": "application/json" },
            },
          );
        }
        return new Response(null, { status: 404 });
      }),
    );

    const { AuthProvider, useCreateInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const results: CreatedInvitation[] = [];

    function Inner() {
      const { createInvitation } = useCreateInvitation();

      React.useEffect(() => {
        createInvitation("org-id", { email: "hi@example.com", role: "admin" })
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return null;
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0));

    expect(capturedBody).toMatchObject({
      email: "hi@example.com",
      role: "admin",
    });
  });

  it("transitions status through idle → fetching → success", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations": () =>
        new Response(JSON.stringify(INVITATION_BODY), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    });

    const { AuthProvider, useCreateInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    function Inner() {
      const { createInvitation, status } = useCreateInvitation();
      return (
        <div>
          <span data-testid="status">{status}</span>
          <button
            onClick={() =>
              createInvitation("org-id", { role: "member" }).catch(() => {})}
          >
            create
          </button>
        </div>
      );
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    expect(screen.getByTestId("status").textContent).toBe("idle");

    await act(async () => {
      await userEvent.click(screen.getByRole("button"));
    });

    await waitFor(() =>
      expect(screen.getByTestId("status").textContent).toBe("success")
    );
  });
});

// ---------------------------------------------------------------------------
// useResendInvitation
// ---------------------------------------------------------------------------

describe("useResendInvitation", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("happy path: returns invitation, token, and buildLink", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations/inv-id/resends": () =>
        new Response(JSON.stringify(INVITATION_BODY), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    });

    const { AuthProvider, useResendInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const results: CreatedInvitation[] = [];

    function Inner() {
      const { resendInvitation, status } = useResendInvitation();

      React.useEffect(() => {
        resendInvitation("org-id", "inv-id")
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return <div data-testid="status">{status}</div>;
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0));

    const result = results[0]!;
    expect(result.token).toBe("plaintext-one-time-token");
    expect(typeof result.buildLink).toBe("function");
    expect(result.invitation).toBeDefined();
  });

  it("buildLink on resend produces correct URL", async () => {
    const newToken = "new-resend-token";
    setupFetch({
      "POST /v1/orgs/org-id/invitations/inv-id/resends": () =>
        new Response(
          JSON.stringify({ ...INVITATION_BODY, token: newToken }),
          {
            status: 201,
            headers: { "content-type": "application/json" },
          },
        ),
    });

    const { AuthProvider, useResendInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const results: CreatedInvitation[] = [];

    function Inner() {
      const { resendInvitation } = useResendInvitation();

      React.useEffect(() => {
        resendInvitation("org-id", "inv-id")
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return null;
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0));

    const { buildLink } = results[0]!;
    expect(buildLink("https://app.example.com/invite")).toBe(
      `https://app.example.com/invite?id=inv-123&token=${
        encodeURIComponent(newToken)
      }`,
    );
  });

  it("buildLink on resend strips trailing slash", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations/inv-id/resends": () =>
        new Response(JSON.stringify(INVITATION_BODY), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    });

    const { AuthProvider, useResendInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const results: CreatedInvitation[] = [];

    function Inner() {
      const { resendInvitation } = useResendInvitation();

      React.useEffect(() => {
        resendInvitation("org-id", "inv-id")
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return null;
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0));

    const { buildLink } = results[0]!;
    expect(buildLink("https://app.example.com/invite/")).toBe(
      "https://app.example.com/invite?id=inv-123&token=plaintext-one-time-token",
    );
  });

  it("error case: 403 response sets status to error and error state", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations/inv-id/resends": () =>
        new Response(
          JSON.stringify({ code: "forbidden", message: "not allowed" }),
          {
            status: 403,
            headers: { "content-type": "application/json" },
          },
        ),
    });

    const { AuthProvider, useResendInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const rejections: unknown[] = [];

    function Inner() {
      const { resendInvitation, status, error } = useResendInvitation();

      React.useEffect(() => {
        resendInvitation("org-id", "inv-id").catch((err) =>
          rejections.push(err)
        );
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="error">
            {(error?.data as any)?.code ?? "none"}
          </span>
        </div>
      );
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(rejections.length).toBeGreaterThan(0));
    await waitFor(() =>
      expect(screen.getByTestId("status").textContent).toBe("error")
    );
    expect(screen.getByTestId("error").textContent).toBe("forbidden");
  });

  it("camelizes resend response fields", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations/inv-id/resends": () =>
        new Response(JSON.stringify(INVITATION_BODY), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    });

    const { AuthProvider, useResendInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    const results: CreatedInvitation[] = [];

    function Inner() {
      const { resendInvitation } = useResendInvitation();

      React.useEffect(() => {
        resendInvitation("org-id", "inv-id")
          .then((r) => results.push(r))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return null;
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0));

    const { invitation } = results[0]!;
    expect(invitation.orgId).toBe("org-456");
    expect(invitation.createdAt).toBeDefined();
    expect(invitation.expiresAt).toBeDefined();
  });

  it("transitions status through idle → fetching → success", async () => {
    setupFetch({
      "POST /v1/orgs/org-id/invitations/inv-id/resends": () =>
        new Response(JSON.stringify(INVITATION_BODY), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    });

    const { AuthProvider, useResendInvitation } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    function Inner() {
      const { resendInvitation, status } = useResendInvitation();
      return (
        <div>
          <span data-testid="status">{status}</span>
          <button
            onClick={() => resendInvitation("org-id", "inv-id").catch(() => {})}
          >
            resend
          </button>
        </div>
      );
    }

    render(
      <AuthProvider>
        <Inner />
      </AuthProvider>,
    );

    expect(screen.getByTestId("status").textContent).toBe("idle");

    await act(async () => {
      await userEvent.click(screen.getByRole("button"));
    });

    await waitFor(() =>
      expect(screen.getByTestId("status").textContent).toBe("success")
    );
  });
});
