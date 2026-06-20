#!/usr/bin/env bash
set -euo pipefail

REPO="beyond-dev/auth"
VERSION="${1:-}"

case "$(uname -m)" in
  x86_64)          ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if ! command -v pg_config &>/dev/null; then
  echo "pg_config not found — install PostgreSQL or add it to PATH" >&2
  exit 1
fi
PG_VERSION=$(pg_config --version | grep -oE '[0-9]+' | head -1)

if [[ -z "$VERSION" ]]; then
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
    | grep '"tag_name"' | grep '"server/v' | head -1 | cut -d'"' -f4)
  VERSION=${TAG#server/v}
else
  TAG="server/v${VERSION}"
fi

PGLIB=$(pg_config --pkglibdir)
echo "Installing beyond-auth-extension v${VERSION} (linux/${ARCH}, pg${PG_VERSION}) → ${PGLIB}..."

curl -fsSL "https://github.com/${REPO}/releases/download/${TAG}/beyond-auth-extension-v${VERSION}-pg${PG_VERSION}-linux-${ARCH}.tar.gz" \
  | tar -xz -C "${PGLIB}/"

echo "Installed: ${PGLIB}/libbeyond_auth.so"
echo ""
echo "Next step: CREATE EXTENSION beyond_auth;"
