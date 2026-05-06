import { describe, expect, it } from "vitest";
import { JwtVerificationError } from "../errors.js";
import { createJwtVerifier } from "../jwt.js";
import { authedClient, getBaseUrl, signup, uniqueEmail } from "./harness.js";

// The server uses app_config.issuer_url when set, otherwise this default.
const DEFAULT_ISSUER = "https://auth.beyond.internal";

function jwksUri(): string {
  return `${getBaseUrl()}/v1/jwks.json`;
}

function b64url(obj: object): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

describe("createJwtVerifier", () => {
  it("verifies a JWT issued by the server", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const { data, error } = await authedClient(auth.session.token).POST(
      "/v1/tokens",
      { body: {} },
    );
    if (!data) {
      throw new Error(`POST /v1/tokens failed: ${JSON.stringify(error)}`);
    }

    const result = await createJwtVerifier({
      jwksUri: jwksUri(),
      issuer: DEFAULT_ISSUER,
    }).verify(data.access_token);

    expect(result.error).toBeUndefined();
    expect(result.data!.sub).toBe(auth.user.id);
    expect(result.data!.iss).toBe(DEFAULT_ISSUER);
  });

  it("returns JwtVerificationError for a tampered signature", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const { data } = await authedClient(auth.session.token).POST("/v1/tokens", {
      body: {},
    });

    const parts = data!.access_token.split(".");
    parts[2] = parts[2]!.split("").reverse().join("");
    const tampered = parts.join(".");

    const result = await createJwtVerifier({
      jwksUri: jwksUri(),
      issuer: DEFAULT_ISSUER,
    }).verify(
      tampered,
    );
    expect(result.error).toBeInstanceOf(JwtVerificationError);
  });

  it("returns JwtVerificationError for the wrong issuer", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const { data } = await authedClient(auth.session.token).POST("/v1/tokens", {
      body: {},
    });

    const result = await createJwtVerifier({
      jwksUri: jwksUri(),
      issuer: "https://wrong.example.com",
    }).verify(data!.access_token);
    expect(result.error).toBeInstanceOf(JwtVerificationError);
  });

  it("marks JWKS fetch failures as retryable", async () => {
    // Syntactically valid JWT so jose reaches the JWKS fetch before failing.
    // The signature is garbage — we never get that far.
    const fakeJwt = [
      b64url({ alg: "RS256", kid: "test" }),
      b64url({ sub: "u", iss: DEFAULT_ISSUER, iat: 0, exp: 9_999_999_999 }),
      "aW52YWxpZA",
    ].join(".");

    const result = await createJwtVerifier({
      jwksUri: "http://127.0.0.1:1/v1/jwks.json",
      issuer: DEFAULT_ISSUER,
    }).verify(fakeJwt);

    expect(result.error).toBeInstanceOf(JwtVerificationError);
    expect((result.error as JwtVerificationError).retryable).toBe(true);
  });

  it("retries on transient JWKS failures and eventually returns an error", async () => {
    const fakeJwt = [
      b64url({ alg: "RS256", kid: "test" }),
      b64url({ sub: "u", iss: DEFAULT_ISSUER, iat: 0, exp: 9_999_999_999 }),
      "aW52YWxpZA",
    ].join(".");

    const result = await createJwtVerifier({
      jwksUri: "http://127.0.0.1:1/v1/jwks.json",
      issuer: DEFAULT_ISSUER,
      retryAttempts: 2,
      retryDelay: 10,
    }).verify(fakeJwt);

    expect(result.error).toBeInstanceOf(JwtVerificationError);
    expect((result.error as JwtVerificationError).retryable).toBe(true);
  });

  it("does not retry non-retryable failures", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const { data } = await authedClient(auth.session.token).POST("/v1/tokens", {
      body: {},
    });

    const parts = data!.access_token.split(".");
    parts[2] = parts[2]!.split("").reverse().join("");
    const tampered = parts.join(".");

    const result = await createJwtVerifier({
      jwksUri: jwksUri(),
      issuer: DEFAULT_ISSUER,
      retryAttempts: 3,
      retryDelay: 10,
    }).verify(tampered);

    expect(result.error).toBeInstanceOf(JwtVerificationError);
    expect((result.error as JwtVerificationError).retryable).toBe(false);
  });

  it("succeeds normally when retryAttempts is configured", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const { data } = await authedClient(auth.session.token).POST("/v1/tokens", {
      body: {},
    });

    const result = await createJwtVerifier({
      jwksUri: jwksUri(),
      issuer: DEFAULT_ISSUER,
      retryAttempts: 2,
    }).verify(data!.access_token);

    expect(result.error).toBeUndefined();
    expect(result.data!.sub).toBe(auth.user.id);
  });
});
