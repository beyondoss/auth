import { PostgreSqlContainer } from "@testcontainers/postgresql";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const ADMIN_SECRET = "test-admin-secret";
// 32 zero bytes in base64url (no padding) — mirrors src/test_server.rs ENC_KEY constant
const ENC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

let serverProcess: ChildProcess | undefined;
let stopContainer: (() => Promise<void>) | undefined;

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
      const res = await fetch(`${url}/healthz`);
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

  // Mirror the Rust harness: mount the authz_extension .so if it's been built,
  // so migration 4's C function declarations can resolve the library.
  const repoRoot = resolve(__dirname, "../../../..");
  const soPath = [
    "target/aarch64-unknown-linux-gnu/release/libauthz_extension.so",
    "target/x86_64-unknown-linux-gnu/release/libauthz_extension.so",
    "target/release/libauthz_extension.so",
  ]
    .map((p) => resolve(repoRoot, p))
    .find(existsSync);

  if (!soPath) {
    throw new Error(
      "authz_extension .so not found. Build it first:\n"
        + "  mise run extension:build:linux      # linux/arm64 (Apple Silicon)\n"
        + "  mise run extension:build:linux:x86  # linux/x86_64",
    );
  }

  let builder = new PostgreSqlContainer("postgres:18")
    .withDatabase("testdb")
    .withUsername("postgres")
    .withPassword("postgres")
    .withCopyFilesToContainer([
      {
        source: soPath,
        target: "/usr/lib/postgresql/18/lib/authz_extension.so",
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
}

export async function teardown(): Promise<void> {
  serverProcess?.kill("SIGTERM");
  await stopContainer?.();
}
