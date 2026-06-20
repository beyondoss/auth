/**
 * mTLS e2e test.
 *
 * Spins up its own beyond-auth server instance configured with TLS, generates
 * a CA + server cert + client cert using @peculiar/x509 + WebCrypto, verifies
 * that an AdminClient configured with TLS options can connect, and asserts that
 * a client without TLS options fails.
 */
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { PostgreSqlContainer } from "@testcontainers/postgresql";
import { execSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { arch, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAdminClient } from "../client.js";
import { buildTlsFetch } from "../utils/tls.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const ADMIN_SECRET = "tls-test-admin-secret";
const ENC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

function findFreePort(): Promise<number> {
  return new Promise((res) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as AddressInfo).port;
      srv.close(() => res(port));
    });
  });
}

/** Base64-encode an ArrayBuffer into a PEM block. */
function toPem(label: string, buf: ArrayBuffer): string {
  const b64 = Buffer.from(buf).toString("base64");
  const lines = b64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

interface GeneratedPki {
  caPem: string;
  serverCertPem: string;
  serverKeyPem: string;
  clientCertPem: string;
  clientKeyPem: string;
}

async function generatePki(): Promise<GeneratedPki> {
  // ---- CA ----
  const caKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=Test CA",
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000 * 365),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys: caKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });
  const caPem = caCert.toString("pem");

  // ---- Server cert ----
  const serverKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const serverCert = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    subject: "CN=localhost",
    issuer: caCert.subject,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000 * 365),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    publicKey: serverKeys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
      new x509.SubjectAlternativeNameExtension(
        [
          { type: "dns", value: "localhost" },
          { type: "ip", value: "127.0.0.1" },
        ],
        false,
      ),
    ],
  });
  const serverCertPem = serverCert.toString("pem");
  const serverKeyPem = toPem(
    "PRIVATE KEY",
    await crypto.subtle.exportKey("pkcs8", serverKeys.privateKey),
  );

  // ---- Client cert ----
  const clientKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const clientCert = await x509.X509CertificateGenerator.create({
    serialNumber: "03",
    subject: "CN=test-client",
    issuer: caCert.subject,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000 * 365),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    publicKey: clientKeys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
    ],
  });
  const clientCertPem = clientCert.toString("pem");
  const clientKeyPem = toPem(
    "PRIVATE KEY",
    await crypto.subtle.exportKey("pkcs8", clientKeys.privateKey),
  );

  return { caPem, serverCertPem, serverKeyPem, clientCertPem, clientKeyPem };
}

// --------------------------------------------------------------------------
// Test lifecycle
// --------------------------------------------------------------------------

let serverProcess: ChildProcess | undefined;
let stopContainer: (() => Promise<void>) | undefined;
let tlsServerUrl: string;
let pki: GeneratedPki;
let tmpDir: string;

beforeAll(async () => {
  // Locate binary
  const binaryPath = process.env["BEYOND_AUTH_BINARY"]
    ?? resolve(__dirname, "../../../../target/debug/beyond-auth");

  if (!existsSync(binaryPath)) {
    throw new Error(
      `beyond-auth binary not found at ${binaryPath}\nRun \`mise run build\` first.`,
    );
  }

  // Find the extension .so (needed for postgres)
  const repoRoot = resolve(__dirname, "../../../..");
  const soCandidates = [
    "target/aarch64-unknown-linux-gnu/release/libbeyond_auth.so",
    "target/x86_64-unknown-linux-gnu/release/libbeyond_auth.so",
    "target/release/libbeyond_auth.so",
  ].map((p) => resolve(repoRoot, p));

  let soPath = soCandidates.find(existsSync);
  if (!soPath) {
    const task = arch() === "arm64"
      ? "extension:build:linux:arm64"
      : "extension:build:linux:amd64";
    execSync(`mise run ${task}`, { stdio: "inherit", cwd: repoRoot });
    soPath = soCandidates.find(existsSync);
    if (!soPath) throw new Error("extension .so not found after build");
  }

  // Generate PKI material
  pki = await generatePki();

  // Write PEM files to a temp directory
  tmpDir = mkdtempSync(join(tmpdir(), "beyond-tls-test-"));
  const caPath = join(tmpDir, "ca.pem");
  const certPath = join(tmpDir, "server-cert.pem");
  const keyPath = join(tmpDir, "server-key.pem");
  writeFileSync(caPath, pki.caPem);
  writeFileSync(certPath, pki.serverCertPem);
  writeFileSync(keyPath, pki.serverKeyPem);

  // Start a postgres container
  const container = await new PostgreSqlContainer("postgres:18")
    .withDatabase("testdb")
    .withUsername("postgres")
    .withPassword("postgres")
    .withCopyFilesToContainer([
      {
        source: soPath,
        target: "/usr/lib/postgresql/18/lib/beyond_auth.so",
        mode: 0o755,
      },
    ])
    .start();

  stopContainer = () => container.stop().then(() => undefined);

  const dbUrl =
    `postgres://${container.getUsername()}:${container.getPassword()}`
    + `@${container.getHost()}:${container.getMappedPort(5432)}`
    + `/${container.getDatabase()}?options=-csearch_path%3Dauth%2Cpublic`;

  const port = await findFreePort();
  tlsServerUrl = `https://127.0.0.1:${port}`;

  // Override BEYOND_DATA_DIR; default `/var/lib/beyond-auth` is not
  // writable by test runners.
  const dataDir = mkdtempSync(join(tmpdir(), "beyond-auth-ts-tls-test-"));

  serverProcess = spawn(binaryPath, ["serve"], {
    env: {
      ...process.env,
      DATABASE_URL: dbUrl,
      ADDRESS: `127.0.0.1:${port}`,
      SIGNING_KEY_ENCRYPTION_KEY: ENC_KEY,
      ADMIN_SECRET,
      WEBAUTHN_RP_ID: "localhost",
      WEBAUTHN_RP_ORIGIN: "https://localhost",
      PUBLIC_URL: tlsServerUrl,
      LOG_LEVEL: "error",
      BEYOND_TLS_CERT: certPath,
      BEYOND_TLS_KEY: keyPath,
      BEYOND_TLS_CA: caPath,
      BEYOND_DATA_DIR: dataDir,
    },
    stdio: ["pipe", "pipe", "inherit"],
  });

  serverProcess.on("error", (err) => {
    throw new Error(`Failed to spawn beyond-auth TLS server: ${err.message}`);
  });

  // Wait for the HTTPS server to be healthy using a TLS-aware fetch
  const tlsFetch = await buildTlsFetch({
    ca: pki.caPem,
    cert: pki.clientCertPem,
    key: pki.clientKeyPem,
  });
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    try {
      const res = await tlsFetch(`${tlsServerUrl}/readyz`);
      if (res.ok) break;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  if (Date.now() >= deadline) {
    throw new Error(
      `beyond-auth TLS server did not become healthy at ${tlsServerUrl} within 60s`,
    );
  }
}, 120_000);

afterAll(async () => {
  serverProcess?.kill("SIGTERM");
  await stopContainer?.();
  if (tmpDir) {
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // best effort cleanup
    }
  }
});

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

describe("mTLS AdminClient", () => {
  it("connects to an mTLS server and succeeds", async () => {
    const admin = createAdminClient({
      url: tlsServerUrl,
      token: ADMIN_SECRET,
      tls: {
        ca: pki.caPem,
        cert: pki.clientCertPem,
        key: pki.clientKeyPem,
      },
    });

    // Fetch the admin config — this exercises a real authenticated request over mTLS
    const { data, error } = await admin.config.get();
    expect(error).toBeUndefined();
    expect(data).toBeDefined();
  });

  it("fails when TLS options are omitted (plain HTTPS with no CA trust)", async () => {
    // Build a fetch that uses undici with no custom CA — the self-signed CA
    // won't be trusted, so the connection should fail.
    const _undici = "undici";
    let undiciFetch: typeof globalThis.fetch;
    try {
      const { fetch: f, Agent } = await (import(_undici) as Promise<any>);
      // Explicitly disable rejectUnauthorized so Node default fetch is bypassed
      // but use an Agent with strictSSL effectively by NOT passing ca.
      const agent = new Agent({
        allowH2: true,
        connect: { rejectUnauthorized: true },
      });
      undiciFetch = (url: any, init?: any) =>
        f(url, { ...(init ?? {}), dispatcher: agent });
    } catch {
      // If undici unavailable skip the reject test
      console.warn("undici not available, skipping reject test");
      return;
    }

    const admin = createAdminClient({
      url: tlsServerUrl,
      token: ADMIN_SECRET,
      fetch: undiciFetch,
    });

    await expect(admin.config.get()).rejects.toThrow();
  });
});
