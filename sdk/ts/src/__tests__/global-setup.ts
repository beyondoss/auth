import { PostgreSqlContainer } from "@testcontainers/postgresql";
import express from "express";
import { execSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import http from "node:http";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { arch } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { proxy } from "../express/index.js";
import { testAuth } from "./harness.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const ADMIN_SECRET = "test-admin-secret";
// 32 zero bytes in base64url (no padding) — mirrors src/test_server.rs ENC_KEY constant
const ENC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

let serverProcess: ChildProcess | undefined;
let stopContainer: (() => Promise<void>) | undefined;
let proxyServer: http.Server | undefined;

function findFreePort(): Promise<number> {
  return new Promise((res) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as AddressInfo).port;
      srv.close(() => res(port));
    });
  });
}

async function waitForHealthy(url: string, timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${url}/readyz`);
      if (res.ok) return;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(
    `beyond-auth did not become healthy at ${url} within ${timeoutMs}ms`,
  );
}

export async function setup(): Promise<void> {
  const binaryPath = process.env["BEYOND_AUTH_BINARY"]
    ?? resolve(__dirname, "../../../../target/debug/beyond-auth");

  if (!existsSync(binaryPath)) {
    throw new Error(
      `beyond-auth binary not found at ${binaryPath}\n`
        + `Run \`mise run build\` first, or set BEYOND_AUTH_BINARY to the binary path.`,
    );
  }

  // Mount the beyond-auth-extension .so — build it automatically if not present.
  const repoRoot = resolve(__dirname, "../../../..");
  const soCandidates = [
    "target/aarch64-unknown-linux-gnu/release/libbeyond_auth_extension.so",
    "target/x86_64-unknown-linux-gnu/release/libbeyond_auth_extension.so",
    "target/release/libbeyond_auth_extension.so",
  ].map((p) => resolve(repoRoot, p));

  let soPath = soCandidates.find(existsSync);
  if (!soPath) {
    const task = arch() === "arm64"
      ? "extension:build:linux:arm64"
      : "extension:build:linux:amd64";
    console.log(
      `[global-setup] beyond-auth-extension .so not found — building via \`mise run ${task}\`...`,
    );
    execSync(`mise run ${task}`, { stdio: "inherit", cwd: repoRoot });
    soPath = soCandidates.find(existsSync);
    if (!soPath) {
      throw new Error("extension build succeeded but .so still not found");
    }
  }

  let builder = new PostgreSqlContainer("postgres:18")
    .withDatabase("testdb")
    .withUsername("postgres")
    .withPassword("postgres")
    .withCopyFilesToContainer([
      {
        source: soPath,
        target: "/usr/lib/postgresql/18/lib/beyond_auth_extension.so",
        mode: 0o755,
      },
    ]);

  const container = await builder.start();

  stopContainer = () => container.stop().then(() => undefined);

  // Build the URL explicitly so sqlx gets the exact postgres:// scheme it expects
  const dbUrl =
    `postgres://${container.getUsername()}:${container.getPassword()}`
    + `@${container.getHost()}:${container.getMappedPort(5432)}`
    + `/${container.getDatabase()}?options=-csearch_path%3Dauth%2Cpublic`;

  const port = await findFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;

  serverProcess = spawn(binaryPath, ["serve"], {
    env: {
      ...process.env,
      DATABASE_URL: dbUrl,
      ADDRESS: `127.0.0.1:${port}`,
      SIGNING_KEY_ENCRYPTION_KEY: ENC_KEY,
      ADMIN_SECRET,
      WEBAUTHN_RP_ID: "localhost",
      WEBAUTHN_RP_ORIGIN: "http://localhost",
      PUBLIC_URL: baseUrl,
      LOG_LEVEL: "error",
    },
    stdio: ["pipe", "pipe", "inherit"],
  });

  serverProcess.on("error", (err) => {
    throw new Error(`Failed to spawn beyond-auth: ${err.message}`);
  });

  await waitForHealthy(baseUrl);

  process.env["BEYOND_AUTH_URL"] = baseUrl;
  process.env["BEYOND_AUTH_ADMIN_SECRET"] = ADMIN_SECRET;

  // Enable JWT issuance for the lifetime of this test server.
  await fetch(`${baseUrl}/v1/admin/config`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ADMIN_SECRET}`,
    },
    body: JSON.stringify({ jwt_enabled: true }),
  });

  // Start a TypeScript proxy server so React UI tests hit the full stack
  // (camelization, cookie management, admin-route blocking) rather than the
  // raw Rust service. Bearer-token auth still works via the proxy's fallback.
  const proxyApp = express();
  proxyApp.use("/", proxy(testAuth()));
  proxyServer = await new Promise<http.Server>((resolve) => {
    const srv = proxyApp.listen(0, "127.0.0.1", () => resolve(srv));
  });
  const proxyPort = (proxyServer.address() as AddressInfo).port;
  process.env["BEYOND_AUTH_PROXY_URL"] = `http://127.0.0.1:${proxyPort}`;
}

export async function teardown(): Promise<void> {
  await new Promise<void>((resolve) => {
    if (proxyServer) proxyServer.close(() => resolve());
    else resolve();
  });
  serverProcess?.kill("SIGTERM");
  await stopContainer?.();
}
