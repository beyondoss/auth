// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { describe, expect, it } from "vitest";
import {
  PasskeyManager,
  usePasskeyManagerContext,
} from "../../../react/ui/passkey-manager/index.js";
import { newUser, renderWithAuth } from "./harness.js";

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("PasskeyManager listing", () => {
  it("renders empty list for new user", async () => {
    const { token } = await newUser();
    renderWithAuth(
      token,
      <PasskeyManager.Root>
        <div data-testid="list">
          <PasskeyManager.Items>
            {(p) => (
              <div key={p.id} data-testid={`passkey-${p.id}`}>
                {p.nickname ?? p.id}
              </div>
            )}
          </PasskeyManager.Items>
        </div>
      </PasskeyManager.Root>,
    );

    // The list container renders but contains no passkey items
    await waitFor(() => expect(screen.getByTestId("list")).toBeInTheDocument());
    expect(screen.getByTestId("list").children).toHaveLength(0);
  });
});

describe("PasskeyManager begin registration", () => {
  function CeremonyHarness() {
    const { beginRegistration, registering } = usePasskeyManagerContext();
    const [challenge, setChallenge] = React.useState<
      Record<string, unknown> | null
    >(null);
    return (
      <div>
        <span data-testid="registering">{String(registering)}</span>
        <span data-testid="state-token">
          {challenge?.stateToken as string ?? "none"}
        </span>
        <button
          data-testid="begin"
          onClick={() =>
            beginRegistration().then((c) =>
              setChallenge(c as unknown as Record<string, unknown>)
            ).catch(() => {})}
        />
      </div>
    );
  }

  it("beginRegistration returns a real challenge from the server", async () => {
    const { token } = await newUser();
    renderWithAuth(
      token,
      <PasskeyManager.Root>
        <CeremonyHarness />
      </PasskeyManager.Root>,
    );

    await userEvent.click(screen.getByTestId("begin"));

    await waitFor(() => {
      expect(screen.getByTestId("state-token")).not.toHaveTextContent("none");
    });

    // The challenge should have a stateToken (from the real server)
    expect(screen.getByTestId("state-token").textContent).toBeTruthy();
  });
});
