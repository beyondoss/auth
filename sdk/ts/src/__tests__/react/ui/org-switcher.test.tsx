// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import {
  OrgSwitcher,
  useOrgSwitcherContext,
} from "../../../react/ui/org-switcher/index.js";
import { newUser, renderWithAuth } from "./harness.js";

// Renders org items from context — OrgSwitcher has no built-in Items component
function OrgItems() {
  const { orgs } = useOrgSwitcherContext();
  return (
    <>
      {orgs.map((org) => (
        <OrgSwitcher.Item key={org.id} org={org} data-testid={`item-${org.id}`}>
          {org.name}
        </OrgSwitcher.Item>
      ))}
    </>
  );
}

function renderOrgSwitcher(token: string, onSwitch = vi.fn()) {
  renderWithAuth(
    token,
    <OrgSwitcher.Root onSwitch={onSwitch} data-testid="root">
      <OrgSwitcher.Trigger aria-label="Switch org" data-testid="trigger" />
      <OrgSwitcher.List data-testid="list">
        <OrgItems />
      </OrgSwitcher.List>
    </OrgSwitcher.Root>,
  );
}

describe("OrgSwitcher Trigger has aria-expanded=false initially", () => {
  it("trigger starts closed and list is hidden", async () => {
    const { token } = await newUser();
    renderOrgSwitcher(token);

    const trigger = screen.getByTestId("trigger");
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByTestId("list")).not.toBeVisible();
  });
});

describe("OrgSwitcher Trigger opens the list on click", () => {
  it("clicking Trigger sets aria-expanded=true and reveals the list", async () => {
    const { token } = await newUser();
    renderOrgSwitcher(token);

    await userEvent.click(screen.getByTestId("trigger"));

    expect(screen.getByTestId("trigger")).toHaveAttribute(
      "aria-expanded",
      "true",
    );
    expect(screen.getByTestId("list")).toBeVisible();
  });
});

describe("OrgSwitcher clicking Trigger twice closes the list", () => {
  it("second click toggles list back to hidden", async () => {
    const { token } = await newUser();
    renderOrgSwitcher(token);

    const trigger = screen.getByTestId("trigger");
    await userEvent.click(trigger);
    await userEvent.click(trigger);

    expect(screen.getByTestId("list")).not.toBeVisible();
  });
});

describe("OrgSwitcher org list populates from the server", () => {
  it("at least one org item appears after opening (new user has personal org)", async () => {
    const { token } = await newUser();
    renderOrgSwitcher(token);

    await userEvent.click(screen.getByTestId("trigger"));

    await waitFor(() => {
      const items = screen.getAllByRole("menuitem");
      expect(items.length).toBeGreaterThanOrEqual(1);
    });
  });
});

describe("OrgSwitcher clicking an Item fires onSwitch and closes the list", () => {
  it("onSwitch receives an org with id and name, list closes", async () => {
    const { token } = await newUser();
    const onSwitch = vi.fn();
    renderOrgSwitcher(token, onSwitch);

    await userEvent.click(screen.getByTestId("trigger"));

    // Wait for items to appear
    await waitFor(() => {
      expect(screen.getAllByRole("menuitem").length).toBeGreaterThanOrEqual(1);
    });

    // Click the first org item
    await userEvent.click(screen.getAllByRole("menuitem")[0]!);

    expect(onSwitch).toHaveBeenCalledOnce();
    const calledWith = onSwitch.mock.calls[0]![0] as {
      id: string;
      name: string;
    };
    expect(calledWith).toHaveProperty("id");
    expect(calledWith).toHaveProperty("name");

    // List closes after selecting an item
    expect(screen.getByTestId("list")).not.toBeVisible();
  });
});
