import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { JwtVerificationError } from "../errors.js";
import { createJwtVerifier } from "../jwt.js";

const ISSUER = "https://auth.example.com";
const JWKS_URI = "https://auth.example.com/v1/jwks.json";
const KID = "test-key-1";

let privateKey: CryptoKey;
let jwksResponse: string;

beforeAll(async () => {
  const { privateKey: priv, publicKey } = await generateKeyPair("RS256");
  privateKey = priv;
  const jwk = await exportJWK(publicKey);
  jwk.kid = KID;
  jwk.alg = "RS256";
  jwksResponse = JSON.stringify({ keys: [jwk] });
});

function mockJwks(responseBody = jwksResponse, status = 200): void {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(responseBody, {
      status,
      headers: { "content-type": "application/json" },
    }),
  );
}

async function signToken(
  payload: Record<string, unknown> = {},
  opts: { expiresIn?: string; issuer?: string; omitSub?: boolean } = {},
): Promise<string> {
  const builder = new SignJWT({ sub: "usr_1", ...payload })
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setIssuedAt()
    .setIssuer(opts.issuer ?? ISSUER)
    .setExpirationTime(opts.expiresIn ?? "1h");
  if (opts.omitSub) {
    return new SignJWT(payload)
      .setProtectedHeader({ alg: "RS256", kid: KID })
      .setIssuedAt()
      .setIssuer(opts.issuer ?? ISSUER)
      .setExpirationTime(opts.expiresIn ?? "1h")
      .sign(privateKey);
  }
  return builder.sign(privateKey);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("createJwtVerifier", () => {
  it("returns claims for a valid token", async () => {
    mockJwks();
    const verifier = createJwtVerifier({ jwksUri: JWKS_URI, issuer: ISSUER });
    const claims = await verifier.verify(await signToken());
    expect(claims.sub).toBe("usr_1");
    expect(claims.iss).toBe(ISSUER);
  });

  it("throws JwtVerificationError for an expired token", async () => {
    mockJwks();
    const verifier = createJwtVerifier({ jwksUri: JWKS_URI, issuer: ISSUER });
    const token = await signToken({}, { expiresIn: "-31s" });
    await expect(verifier.verify(token)).rejects.toBeInstanceOf(
      JwtVerificationError,
    );
  });

  it("throws JwtVerificationError for a wrong issuer", async () => {
    mockJwks();
    const verifier = createJwtVerifier({ jwksUri: JWKS_URI, issuer: ISSUER });
    const token = await signToken({}, { issuer: "https://evil.example.com" });
    await expect(verifier.verify(token)).rejects.toBeInstanceOf(
      JwtVerificationError,
    );
  });

  it("throws JwtVerificationError for a token missing sub", async () => {
    mockJwks();
    const verifier = createJwtVerifier({ jwksUri: JWKS_URI, issuer: ISSUER });
    const token = await signToken({}, { omitSub: true });
    const err = await verifier.verify(token).catch((e) => e);
    expect(err).toBeInstanceOf(JwtVerificationError);
    expect((err as JwtVerificationError).message).toMatch(/sub/);
  });

  it("throws JwtVerificationError for a wrong audience", async () => {
    mockJwks();
    const verifier = createJwtVerifier({
      jwksUri: JWKS_URI,
      issuer: ISSUER,
      audience: "my-app",
    });
    const token = await signToken();
    await expect(verifier.verify(token)).rejects.toBeInstanceOf(
      JwtVerificationError,
    );
  });

  it("accepts a token with the correct audience", async () => {
    mockJwks();
    const verifier = createJwtVerifier({
      jwksUri: JWKS_URI,
      issuer: ISSUER,
      audience: "my-app",
    });
    const token = await new SignJWT({ sub: "usr_1" })
      .setProtectedHeader({ alg: "RS256", kid: KID })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setAudience("my-app")
      .setExpirationTime("1h")
      .sign(privateKey);
    const claims = await verifier.verify(token);
    expect(claims.sub).toBe("usr_1");
  });

  it("marks JWKS fetch failures as retryable", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(
      new TypeError("fetch failed"),
    );
    const verifier = createJwtVerifier({ jwksUri: JWKS_URI, issuer: ISSUER });
    const token = await signToken();
    const err = await verifier.verify(token).catch((e) => e);
    expect(err).toBeInstanceOf(JwtVerificationError);
    expect((err as JwtVerificationError).retryable).toBe(true);
  });

  it("does not mark bad-signature errors as retryable", async () => {
    mockJwks();
    // Generate a second key pair; sign with it but serve the first key's JWKS.
    const { privateKey: otherKey } = await generateKeyPair("RS256");
    const token = await new SignJWT({ sub: "usr_1" })
      .setProtectedHeader({ alg: "RS256", kid: KID })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setExpirationTime("1h")
      .sign(otherKey);
    const verifier = createJwtVerifier({ jwksUri: JWKS_URI, issuer: ISSUER });
    const err = await verifier.verify(token).catch((e) => e);
    expect(err).toBeInstanceOf(JwtVerificationError);
    expect((err as JwtVerificationError).retryable).toBe(false);
  });

  // ── Audience edge cases ────────────────────────────────────────────────────

  it("accepts a token that carries aud when verifier has no audience configured", async () => {
    // jose skips audience validation when verifyOptions.audience is unset,
    // so an extra aud claim in the token is silently ignored.
    mockJwks();
    const verifier = createJwtVerifier({ jwksUri: JWKS_URI, issuer: ISSUER });
    const token = await new SignJWT({ sub: "usr_1" })
      .setProtectedHeader({ alg: "RS256", kid: KID })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setAudience("some-other-app")
      .setExpirationTime("1h")
      .sign(privateKey);
    const claims = await verifier.verify(token);
    expect(claims.sub).toBe("usr_1");
  });

  it("rejects a token with no aud when verifier expects an audience", async () => {
    mockJwks();
    const verifier = createJwtVerifier({
      jwksUri: JWKS_URI,
      issuer: ISSUER,
      audience: "my-app",
    });
    // signToken() produces no aud claim
    const token = await signToken();
    await expect(verifier.verify(token)).rejects.toBeInstanceOf(
      JwtVerificationError,
    );
  });
});
