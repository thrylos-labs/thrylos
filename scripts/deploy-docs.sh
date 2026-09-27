#!/usr/bin/env bash
set -euo pipefail

# Builds the docs site (docs-site, mdBook) and copies it to the alpha VPS.
#
#   scripts/deploy-docs.sh                      # uses the defaults below
#   VPS=root@host KEY=~/.ssh/key scripts/deploy-docs.sh
#
# Needs mdBook: cargo install mdbook --locked

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VPS="${VPS:-root@157.230.10.32}"
KEY="${KEY:-$HOME/.ssh/id_ed25519_thrylos_alpha}"
DEST="${DEST:-/srv/thrylos/docs/}"
SRC=docs-site

command -v mdbook >/dev/null || { echo "error: mdbook not found; cargo install mdbook --locked" >&2; exit 1; }

rm -rf "$SRC/book"
(cd "$SRC" && mdbook build)
[ -f "$SRC/book/index.html" ] || { echo "error: $SRC/book/index.html was not built" >&2; exit 1; }

# --delete: a page removed from SUMMARY.md is removed on the server too, not left
# behind as a dangling published URL.
rsync -rltv --delete --no-owner --no-group -e "ssh -i $KEY -o IdentitiesOnly=yes -o ConnectTimeout=15" \
  "$SRC/book/" "$VPS:$DEST"

# What is served is owned by root and cannot be changed by the account the web
# server runs as. (macOS's rsync has no --chown, so this is set on the server.)
ssh -i "$KEY" -o IdentitiesOnly=yes -o ConnectTimeout=15 "$VPS" \
  "chown -R root:root '$DEST' && find '$DEST' -type d -exec chmod 755 {} + && find '$DEST' -type f -exec chmod 644 {} +"
