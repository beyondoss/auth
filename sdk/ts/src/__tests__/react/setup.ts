import "@testing-library/jest-dom/vitest";
import { configure } from "@testing-library/react";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

configure({ asyncUtilTimeout: 10_000 });

afterEach(() => {
  cleanup();
});
