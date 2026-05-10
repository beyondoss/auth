// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { UserButton } from "../../../react/ui/user-button/index.js";
import { newUser, renderWithAuth } from "./harness.js";

function renderUserButton(token: string, onSignOut = vi.fn()) {
  renderWithAuth(
    token,
    <UserButton.Root>
      <UserButton.Trigger aria-label="Open menu" />
      <UserButton.Panel data-testid="panel">
        <UserButton.Email data-testid="email" />
        <UserButton.SignOut onSuccess={onSignOut}>Sign out</UserButton.SignOut>
      </UserButton.Panel>
    </UserButton.Root>,
  );
}

describe("UserButton toggle", () => {
  it("panel is hidden on initial render", async () => {
    const { token } = await newUser();
    renderUserButton(token);
    expect(screen.getByTestId("panel")).not.toBeVisible();
  });

  it("Trigger opens the panel", async () => {
    const { token } = await newUser();
    renderUserButton(token);
    await userEvent.click(screen.getByRole("button", { name: "Open menu" }));
    expect(screen.getByTestId("panel")).toBeVisible();
  });

  it("Trigger toggles closed on second click", async () => {
    const { token } = await newUser();
    renderUserButton(token);
    const trigger = screen.getByRole("button", { name: "Open menu" });
    await userEvent.click(trigger);
    await userEvent.click(trigger);
    expect(screen.getByTestId("panel")).not.toBeVisible();
  });

  it("Trigger has correct aria-expanded attribute", async () => {
    const { token } = await newUser();
    renderUserButton(token);
    const trigger = screen.getByRole("button", { name: "Open menu" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
  });
});

describe("UserButton.Email", () => {
  it("displays user email from auth context", async () => {
    const { email, token } = await newUser();
    renderUserButton(token);

    // Email is fetched from GET /v1/users/me via useAuth — wait for it to load
    await waitFor(() => {
      expect(screen.getByTestId("email")).toHaveTextContent(email);
    });
  });
});

describe("UserButton.SignOut", () => {
  it("calls DELETE /v1/sessions/current and fires onSuccess", async () => {
    const { token } = await newUser();
    const onSignOut = vi.fn();

    renderWithAuth(
      token,
      <UserButton.Root>
        <UserButton.SignOut onSuccess={onSignOut}>Sign out</UserButton.SignOut>
      </UserButton.Root>,
    );

    // Sign out button is always in the DOM (panel visibility is CSS/hidden attr)
    await userEvent.click(
      screen.getByRole("button", { name: "Sign out", hidden: true }),
    );

    await waitFor(() => expect(onSignOut).toHaveBeenCalledOnce());
  });
});
