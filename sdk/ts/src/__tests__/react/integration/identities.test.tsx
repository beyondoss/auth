// @vitest-environment jsdom
/**
 * React hook integration tests for identity hooks against the real auth
 * service running in the testcontainer.
 *
 * jsdom has no httpOnly cookie jar, so we bypass the proxy for read-only
 * tests and call the auth service directly. Authentication is injected via
 * `requestInit` headers on `createClient`.
 *
 * For mutation hooks (useChangePassword, useAddPassword, useUnlinkIdentity),
 * the request bodies use camelCase keys that need the proxy for conversion to
 * snake_case. Those tests use `renderWithAuth` from the UI harness, which
 * creates a client pointed at the proxy URL.
 */
import { render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { beforeAll, describe, expect, it } from "vitest";
import { createClient } from "../../../react/client.js";
import { AuthProvider } from "../../../react/provider.js";
import { useAddPassword } from "../../../react/useAddPassword.js";
import { useChangePassword } from "../../../react/useChangePassword.js";
import { useIdentities } from "../../../react/useIdentities.js";
import { useUnlinkIdentity } from "../../../react/useUnlinkIdentity.js";
import type { paths } from "../../../types.js";
import { getBaseUrl, signup, uniqueEmail } from "../../harness.js";
import { renderWithAuth } from "../ui/harness.js";

const PASSWORD = "correct-horse-battery-staple";

/** Create a client that authenticates with a Bearer token instead of cookies.
 *  Bypasses the proxy — for read-only calls where camelCase bodies are not needed. */
function makeClient(token: string) {
  const client = createClient<paths>({
    baseUrl: getBaseUrl(),
    staleTime: 0,
    requestInit: () => ({ headers: { Authorization: `Bearer ${token}` } }),
    async onEachSuccess() {
      await client.refetch({ match: (_, rc) => rc > 0 });
    },
  });
  return client;
}

async function newUser() {
  const email = uniqueEmail();
  const auth = await signup(email, PASSWORD);
  return { email, auth, token: auth.session.token };
}

// ---------------------------------------------------------------------------
// useIdentities (read-only loader)
// ---------------------------------------------------------------------------

describe("useIdentities — integration", () => {
  let token: string;

  beforeAll(async () => {
    ({ token } = await newUser());
  });

  it("lists identities for a password user: one identity with provider 'password'", async () => {
    function Harness() {
      const { identities, status } = useIdentities();
      const first = identities[0];
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="count">{identities.length}</span>
          <span data-testid="provider">{first?.provider ?? ""}</span>
          <span data-testid="id">{first?.id ?? ""}</span>
        </div>
      );
    }

    const client = makeClient(token);
    render(
      <AuthProvider client={client}>
        <Harness />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    });

    expect(screen.getByTestId("count").textContent).toBe("1");
    expect(screen.getByTestId("provider").textContent).toBe("password");
    expect(screen.getByTestId("id").textContent).not.toBe("");
  });
});

// ---------------------------------------------------------------------------
// useAddPassword
// ---------------------------------------------------------------------------

describe("useAddPassword — integration", () => {
  it("returns 409 error when user already has a password identity", async () => {
    const { token } = await newUser();

    function Harness() {
      const { addPassword, status, error } = useAddPassword();

      React.useEffect(() => {
        addPassword("any-password").catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="status-code">
            {String(error?.response?.status ?? "")}
          </span>
        </div>
      );
    }

    renderWithAuth(token, <Harness />);

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("error");
    }, { timeout: 10_000 });

    expect(screen.getByTestId("status-code").textContent).toBe("409");
  });
});

// ---------------------------------------------------------------------------
// useChangePassword
// ---------------------------------------------------------------------------

describe("useChangePassword — integration", () => {
  it("changes password successfully", async () => {
    const { token } = await newUser();

    // Fetch the identity ID directly from the auth service (snake_case response)
    const res = await fetch(`${getBaseUrl()}/v1/identities`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json() as { identities: Array<{ id: string }> };
    const identityId = data.identities[0]!.id;

    function Harness({ id }: { id: string }) {
      const { changePassword, status } = useChangePassword();

      React.useEffect(() => {
        changePassword(id, PASSWORD, "new-correct-horse-staple").catch(
          () => {},
        );
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return <span data-testid="status">{status}</span>;
    }

    renderWithAuth(token, <Harness id={identityId} />);

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    }, { timeout: 10_000 });
  });

  it("returns 401 on wrong current password", async () => {
    const { token } = await newUser();

    // Fetch the identity ID directly from the auth service
    const res = await fetch(`${getBaseUrl()}/v1/identities`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json() as { identities: Array<{ id: string }> };
    const identityId = data.identities[0]!.id;

    function Harness({ id }: { id: string }) {
      const { changePassword, status, error } = useChangePassword();

      React.useEffect(() => {
        changePassword(id, "wrong-password", "new-pass").catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="status-code">
            {String(error?.response?.status ?? "")}
          </span>
        </div>
      );
    }

    renderWithAuth(token, <Harness id={identityId} />);

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("error");
    }, { timeout: 10_000 });

    expect(screen.getByTestId("status-code").textContent).toBe("401");
  });
});

// ---------------------------------------------------------------------------
// useUnlinkIdentity
// ---------------------------------------------------------------------------

describe("useUnlinkIdentity — integration", () => {
  it("returns 409 when trying to unlink the last identity", async () => {
    const { token } = await newUser();

    // Fetch the identity ID directly from the auth service
    const res = await fetch(`${getBaseUrl()}/v1/identities`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json() as { identities: Array<{ id: string }> };
    const identityId = data.identities[0]!.id;

    function Harness({ id }: { id: string }) {
      const { unlink, status, error } = useUnlinkIdentity();

      React.useEffect(() => {
        unlink(id).catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="status-code">
            {String(error?.response?.status ?? "")}
          </span>
        </div>
      );
    }

    renderWithAuth(token, <Harness id={identityId} />);

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("error");
    }, { timeout: 10_000 });

    expect(screen.getByTestId("status-code").textContent).toBe("409");
  });
});
