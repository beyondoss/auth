#!/usr/bin/env bash
set -euo pipefail

REPO="beyond-dev/auth"
VERSION="${1:-}"

case "$(uname -m)" in
  x86_64)          ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [[ -z "$VERSION" ]]; then
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
    | grep '"tag_name"' | grep '"server/v' | head -1 | cut -d'"' -f4)
  VERSION=${TAG#server/v}
else
  TAG="server/v${VERSION}"
fi

echo "Installing beyond-auth v${VERSION} (linux/${ARCH})..."

curl -fsSL "https://github.com/${REPO}/releases/download/${TAG}/beyond-auth-v${VERSION}-linux-${ARCH}.tar.gz" \
  | tar -xz -C /usr/local/bin/
chmod +x /usr/local/bin/beyond-auth

echo "Installed: /usr/local/bin/beyond-auth"
echo ""
echo "Next steps:"
echo "  1. Configure beyond-auth (DATABASE_URL, signing keys, etc.)"
echo "  2. Run: beyond-auth migrate"
