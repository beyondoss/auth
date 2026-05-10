// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Form } from "../../../react/ui/form/index.js";
import { newUser, PASSWORD, renderPublic } from "./harness.js";

describe("Form.Error", () => {
  it("renders nothing when idle", () => {
    renderPublic(
      <Form path="POST /v1/sessions">
        <Form.Error data-testid="err" />
        <Form.Submit>go</Form.Submit>
      </Form>,
    );
    expect(screen.queryByTestId("err")).not.toBeInTheDocument();
  });

  it("renders after a failed submission", async () => {
    const { email } = await newUser();

    renderPublic(
      <Form path="POST /v1/sessions">
        <Form.Field name="email" aria-label="Email" />
        <Form.Field name="password" aria-label="Password" type="password" />
        <Form.Error data-testid="err" />
        <Form.Submit>go</Form.Submit>
      </Form>,
    );

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.type(screen.getByLabelText("Password"), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: "go" }));

    await waitFor(() => {
      expect(screen.getByTestId("err")).toBeInTheDocument();
    });
  });

  it("clears after a subsequent successful submission", async () => {
    const { email } = await newUser();

    renderPublic(
      <Form path="POST /v1/sessions" body={{ grant_type: "password" }}>
        <Form.Field name="email" aria-label="Email" />
        <Form.Field name="password" aria-label="Password" type="password" />
        <Form.Error data-testid="err" />
        <Form.Submit>go</Form.Submit>
      </Form>,
    );

    const emailInput = screen.getByLabelText("Email");
    const passwordInput = screen.getByLabelText("Password");
    const btn = screen.getByRole("button", { name: "go" });

    // First submit with wrong password → error
    await userEvent.type(emailInput, email);
    await userEvent.type(passwordInput, "wrong-password");
    await userEvent.click(btn);
    await waitFor(() => expect(screen.getByTestId("err")).toBeInTheDocument());

    // Clear password field and enter correct password → success → error gone
    await userEvent.clear(passwordInput);
    await userEvent.type(passwordInput, PASSWORD);
    await userEvent.click(btn);
    await waitFor(() =>
      expect(screen.queryByTestId("err")).not.toBeInTheDocument()
    );
  });
});

describe("Form body merging", () => {
  it("sends static body merged with collected field values", async () => {
    const { email } = await newUser();
    const onSuccess = vi.fn();

    renderPublic(
      <Form
        path="POST /v1/sessions"
        body={{ grant_type: "password" }}
        onSuccess={onSuccess}
      >
        <Form.Field name="email" aria-label="Email" />
        <Form.Field name="password" aria-label="Password" type="password" />
        <Form.Submit>Sign in</Form.Submit>
      </Form>,
    );

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.type(screen.getByLabelText("Password"), PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    // onSuccess fires only if the merged body (grant_type + email + password) was accepted
    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());
  });
});

describe("Form.Field value collection", () => {
  it("updates value as user types", async () => {
    renderPublic(
      <Form path="POST /v1/sessions">
        <Form.Field name="email" aria-label="Email" />
        <Form.Submit>go</Form.Submit>
      </Form>,
    );

    const field = screen.getByLabelText("Email");
    await userEvent.type(field, "hello@example.com");
    expect(field).toHaveValue("hello@example.com");
  });
});

describe("Form.Error custom children", () => {
  it("renders custom children instead of the server error message", async () => {
    const { email } = await newUser();

    renderPublic(
      <Form path="POST /v1/sessions">
        <Form.Field name="email" aria-label="Email" />
        <Form.Field name="password" aria-label="Password" type="password" />
        <Form.Error>Custom error text</Form.Error>
        <Form.Submit>go</Form.Submit>
      </Form>,
    );

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.type(screen.getByLabelText("Password"), "bad-password");
    await userEvent.click(screen.getByRole("button", { name: "go" }));

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("Custom error text")
    );
  });
});
