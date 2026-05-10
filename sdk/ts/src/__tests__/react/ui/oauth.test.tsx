// @vitest-environment jsdom
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OAuth } from "../../../react/ui/oauth/index.js";
import { newUser, renderWithAuth } from "./harness.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OAuth.Button", () => {
  it("renders with correct data-provider, data-state, and children", async () => {
    const { token } = await newUser();
    renderWithAuth(
      token,
      <OAuth.Button provider="google">Sign in with Google</OAuth.Button>,
    );

    const btn = screen.getByRole("button", { name: "Sign in with Google" });
    expect(btn).toHaveAttribute("data-provider", "google");
    expect(btn).toHaveAttribute("data-state", "idle");
    expect(btn).not.toBeDisabled();
  });

  it("reflects the given provider in data-provider for different providers", async () => {
    const { token } = await newUser();
    renderWithAuth(
      token,
      <OAuth.Button provider="github">Sign in with GitHub</OAuth.Button>,
    );

    const btn = screen.getByRole("button", { name: "Sign in with GitHub" });
    expect(btn).toHaveAttribute("data-provider", "github");
  });

  it("e.preventDefault() on onClick skips signInWithOAuth — onError is not called", async () => {
    const { token } = await newUser();
    const onClick = vi.fn((e: React.MouseEvent) => e.preventDefault());
    const onError = vi.fn();

    renderWithAuth(
      token,
      <OAuth.Button provider="google" onClick={onClick} onError={onError}>
        Sign in with Google
      </OAuth.Button>,
    );

    await userEvent.click(
      screen.getByRole("button", { name: "Sign in with Google" }),
    );

    expect(onClick).toHaveBeenCalledOnce();
    expect(onError).not.toHaveBeenCalled();
  });
});
