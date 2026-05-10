// @vitest-environment jsdom
import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { ApiKeyManager } from "../../../react/ui/api-key-manager/index.js";
import { getBaseUrl } from "../../harness.js";
import { newUser, renderWithAuth } from "./harness.js";

function renderApiKeyManager(token: string) {
  renderWithAuth(
    token,
    <ApiKeyManager.Root>
      <ApiKeyManager.Items>
        {(key) => (
          <div key={key.id} data-testid={`key-${key.id}`}>
            <span data-testid={`key-name-${key.id}`}>{key.name}</span>
            <ApiKeyManager.Remove
              keyId={key.id}
              data-testid={`remove-${key.id}`}
            >
              Revoke
            </ApiKeyManager.Remove>
          </div>
        )}
      </ApiKeyManager.Items>
      <ApiKeyManager.CreateForm>
        <ApiKeyManager.Field name="name" aria-label="Key name" />
        <ApiKeyManager.Submit>Create key</ApiKeyManager.Submit>
      </ApiKeyManager.CreateForm>
      <ApiKeyManager.CreatedSecret data-testid="secret" />
    </ApiKeyManager.Root>,
  );
}

describe("renders API keys from GET /v1/keys", () => {
  let token: string;
  let createdKeyId: string;

  beforeAll(async () => {
    ({ token } = await newUser());
    const res = await fetch(`${getBaseUrl()}/v1/keys`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: "Test Key" }),
    });
    const data = await res.json() as { id: string; name: string; key: string };
    createdKeyId = data.id;
  });

  it("key created via direct API call appears in the rendered list", async () => {
    renderApiKeyManager(token);
    await waitFor(() =>
      expect(screen.getByTestId(`key-${createdKeyId}`)).toBeInTheDocument()
    );
    expect(screen.getByTestId(`key-name-${createdKeyId}`)).toHaveTextContent(
      "Test Key",
    );
  });
});

describe("reveals secret after CreateForm submission", () => {
  let token: string;

  beforeAll(async () => {
    ({ token } = await newUser());
  });

  it("fill in key name, submit, CreatedSecret shows the key value", async () => {
    renderApiKeyManager(token);

    expect(screen.queryByTestId("secret")).not.toBeInTheDocument();

    await waitFor(() =>
      expect(screen.getByLabelText("Key name")).toBeInTheDocument()
    );

    await userEvent.type(screen.getByLabelText("Key name"), "My New Key");
    await userEvent.click(screen.getByRole("button", { name: "Create key" }));

    await waitFor(() =>
      expect(screen.getByTestId("secret")).toBeInTheDocument()
    );
    // The secret is a non-empty string from the server
    expect(screen.getByTestId("secret").textContent).toBeTruthy();
  });
});

describe("refetches key list after creation", () => {
  let token: string;

  beforeAll(async () => {
    ({ token } = await newUser());
  });

  it("submit form, new key appears in the list", async () => {
    renderApiKeyManager(token);

    await waitFor(() =>
      expect(screen.getByLabelText("Key name")).toBeInTheDocument()
    );

    await userEvent.type(screen.getByLabelText("Key name"), "Refetch Key");
    await userEvent.click(screen.getByRole("button", { name: "Create key" }));

    await waitFor(() =>
      expect(screen.getByTestId("secret")).toBeInTheDocument()
    );

    // After onEachSuccess triggers a refetch, the new key should appear in Items
    await waitFor(() =>
      expect(screen.getByText("Refetch Key")).toBeInTheDocument()
    );
  });
});

describe("removes a key via Remove button", () => {
  let token: string;
  let createdKeyId: string;

  beforeAll(async () => {
    ({ token } = await newUser());
    const res = await fetch(`${getBaseUrl()}/v1/keys`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: "Removable Key" }),
    });
    const data = await res.json() as { id: string; name: string; key: string };
    createdKeyId = data.id;
  });

  it("click Remove, key disappears from the list", async () => {
    renderApiKeyManager(token);

    await waitFor(() =>
      expect(screen.getByTestId(`key-${createdKeyId}`)).toBeInTheDocument()
    );

    await userEvent.click(screen.getByTestId(`remove-${createdKeyId}`));

    await waitFor(() =>
      expect(
        screen.queryByTestId(`key-${createdKeyId}`),
      ).not.toBeInTheDocument()
    );
  });
});

describe("auto-clear CreatedSecret after 30 seconds", () => {
  let token: string;

  beforeAll(async () => {
    ({ token } = await newUser());
  });

  it("create key, advance 30s, secret disappears", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });

    renderApiKeyManager(token);

    await waitFor(() =>
      expect(screen.getByLabelText("Key name")).toBeInTheDocument()
    );

    await userEvent.type(screen.getByLabelText("Key name"), "Timer Key");
    await userEvent.click(screen.getByRole("button", { name: "Create key" }));

    await waitFor(() =>
      expect(screen.getByTestId("secret")).toBeInTheDocument()
    );

    await act(async () => {
      vi.advanceTimersByTime(30_000);
    });

    await waitFor(() =>
      expect(screen.queryByTestId("secret")).not.toBeInTheDocument()
    );

    vi.useRealTimers();
  });
});
