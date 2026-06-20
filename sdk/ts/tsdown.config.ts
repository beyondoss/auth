import { defineConfig } from "tsdown";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "next/index": "src/next/index.ts",
    "react/index": "src/react/index.ts",
    "react/ui": "src/react/ui/index.ts",
    "server/index": "src/server/index.ts",
    "hono/index": "src/hono/index.ts",
    "fastify/index": "src/fastify/index.ts",
    "express/index": "src/express/index.ts",
  },
  format: "esm",
  dts: true,
  clean: true,
  treeshake: true,
  deps: { neverBundle: ["next", "react", "react-dom"] },
});
