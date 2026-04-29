# Releasing

There are two independently versioned components:

| Component          | Tag pattern | Output                         |
| ------------------ | ----------- | ------------------------------ |
| Server + extension | `server/v*` | GitHub Release with 6 tarballs |
| TypeScript SDK     | `sdk/v*`    | npm publish `@beyond.dev/auth` |

The server binary and Postgres extension share a tag because they're tightly coupled — the extension ABI must match the server.

## Releasing the server and extension

1. Bump the version in `Cargo.toml` (root package) and `authz_extension/Cargo.toml`
2. Commit and push to `main`
3. Tag and push:
   ```sh
   git tag server/v1.2.3 && git push origin server/v1.2.3
   ```

This triggers `.github/workflows/release-server.yml`, which builds 6 artifacts and creates a GitHub Release:

- `beyond-auth-v{VERSION}-linux-amd64.tar.gz`
- `beyond-auth-v{VERSION}-linux-arm64.tar.gz`
- `authz_extension-v{VERSION}-pg17-linux-amd64.tar.gz`
- `authz_extension-v{VERSION}-pg17-linux-arm64.tar.gz`
- `authz_extension-v{VERSION}-pg18-linux-amd64.tar.gz`
- `authz_extension-v{VERSION}-pg18-linux-arm64.tar.gz`

## Releasing the SDK

1. Bump the version in `sdk/ts/package.json`
2. Commit and push to `main`
3. Tag and push:
   ```sh
   git tag sdk/v1.2.3 && git push origin sdk/v1.2.3
   ```

This triggers `.github/workflows/release-sdk.yml`, which builds and publishes `@beyond.dev/auth` to npm.

## Installation

On **app servers** (downloads the `beyond-auth` binary):

```sh
curl -fsSL https://raw.githubusercontent.com/beyond-dev/auth/main/scripts/install-server.sh | bash
# or pin to a version:
curl -fsSL https://raw.githubusercontent.com/beyond-dev/auth/main/scripts/install-server.sh | bash -s 1.2.3
```

On **database servers** (downloads the extension `.so` into Postgres's pkglibdir):

```sh
curl -fsSL https://raw.githubusercontent.com/beyond-dev/auth/main/scripts/install-extension.sh | bash
# or pin to a version:
curl -fsSL https://raw.githubusercontent.com/beyond-dev/auth/main/scripts/install-extension.sh | bash -s 1.2.3
```

Both scripts auto-detect architecture (`amd64`/`arm64`) and, for the extension, the installed Postgres major version via `pg_config`.
