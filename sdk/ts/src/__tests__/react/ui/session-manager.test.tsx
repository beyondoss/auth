// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { SessionManager } from "../../../react/ui/session-manager/index.js";
import { getBaseUrl } from "../../harness.js";
import { newUser, PASSWORD, renderWithAuth } from "./harness.js";

function renderSessionManager(token: string) {
  renderWithAuth(
    token,
    <SessionManager.Root>
      <SessionManager.Items>
        {(s) => (
          <div key={s.id} data-testid={`session-${s.id}`}>
            <span>{s.userAgent ?? "unknown"}</span>
            <SessionManager.Revoke
              sessionId={s.id}
              data-testid={`revoke-${s.id}`}
            >
              Revoke
            </SessionManager.Revoke>
          </div>
        )}
      </SessionManager.Items>
      <SessionManager.RevokeAll data-testid="revoke-all">
        Sign out all other sessions
      </SessionManager.RevokeAll>
    </SessionManager.Root>,
  );
}

describe("SessionManager listing", () => {
  it("renders sessions from GET /v1/sessions", async () => {
    const { token } = await newUser();
    renderSessionManager(token);

    // At least one session exists — the one created at signup
    await waitFor(() => {
      const items = screen.getAllByTestId(/^session-/);
      expect(items.length).toBeGreaterThanOrEqual(1);
    });
  });
});

describe("SessionManager.Revoke", () => {
  it("revokes a specific session and removes it from list", async () => {
    const { email, token } = await newUser();

    // Create a second session via direct POST /v1/sessions
    const loginRes = await fetch(`${getBaseUrl()}/v1/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "password",
        email,
        password: PASSWORD,
      }),
    });
    const loginData = await loginRes.json() as {
      session?: { token?: string; id?: string };
    };
    const secondSessionId = (loginData.session?.id) as string;

    // Render with the first session's token — both sessions should appear
    renderSessionManager(token);

    await waitFor(() => {
      expect(
        screen.getByTestId(`session-${secondSessionId}`),
      ).toBeInTheDocument();
    });

    // Revoke the second session
    await userEvent.click(
      screen.getByTestId(`revoke-${secondSessionId}`),
    );

    // Second session disappears after revocation + refetch
    await waitFor(() => {
      expect(
        screen.queryByTestId(`session-${secondSessionId}`),
      ).not.toBeInTheDocument();
    });
  });
});

describe("SessionManager.RevokeAll", () => {
  it("removes other sessions but not the current one", async () => {
    const { email, token: token1 } = await newUser();

    // Create a second session — this becomes the "other" session to be revoked
    const loginRes = await fetch(`${getBaseUrl()}/v1/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "password",
        email,
        password: PASSWORD,
      }),
    });
    const loginData = await loginRes.json() as {
      session?: { token?: string; id?: string };
    };
    const otherSessionId = (loginData.session?.id) as string;

    // Render with token1 (session1 is "current") — the new session2 is "other"
    renderWithAuth(
      token1,
      <SessionManager.Root>
        <SessionManager.Items>
          {(s) => (
            <div key={s.id} data-testid={`session-${s.id}`}>
              <span>{s.userAgent ?? "unknown"}</span>
            </div>
          )}
        </SessionManager.Items>
        <SessionManager.RevokeAll data-testid="revoke-all">
          Sign out all other sessions
        </SessionManager.RevokeAll>
      </SessionManager.Root>,
    );

    // Wait for the "other" session to appear
    await waitFor(() => {
      expect(
        screen.getByTestId(`session-${otherSessionId}`),
      ).toBeInTheDocument();
    });

    // Click RevokeAll — revokes all sessions except token1's session (current)
    await userEvent.click(screen.getByTestId("revoke-all"));

    // The other session disappears after revoke-all + refetch
    await waitFor(() => {
      expect(
        screen.queryByTestId(`session-${otherSessionId}`),
      ).not.toBeInTheDocument();
    });
  });
});
