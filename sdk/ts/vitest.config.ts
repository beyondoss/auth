import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globalSetup: ["./src/__tests__/global-setup.ts"],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    include: ["src/__tests__/**/*.test.{ts,tsx}"],
    environmentMatchGlobs: [["src/__tests__/react/**", "jsdom"]],
    setupFiles: ["./src/__tests__/react/setup.ts"],
  },
});
