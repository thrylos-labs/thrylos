#!/usr/bin/env bash
set -euo pipefail

# Copies the browser wallet (deploy/wallet) to the alpha VPS.
#
# Cloudflare tells browsers to cache .js files for four hours, and a page that
# loads an old script next to a new index.html is a broken (or, for the names
# rule, an unsafe) wallet. So the script's URL carries a hash of its contents:
# a changed app.js is a new URL, which no browser has cached. The stamp goes
# into a temporary copy of index.html; the file in the repository is untouched.
#
#   scripts/deploy-wallet.sh                      # uses the defaults below
#   VPS=root@host KEY=~/.ssh/key scripts/deploy-wallet.sh

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VPS="${VPS:-root@157.230.10.32}"
KEY="${KEY:-$HOME/.ssh/id_ed25519_thrylos_alpha}"
DEST="${DEST:-/srv/thrylos/wallet/}"
SRC=deploy/wallet

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp "$SRC/index.html" "$SRC/app.js" "$SRC/noble.js" "$stage/"

if command -v sha256sum >/dev/null; then
  version="$(sha256sum "$SRC/app.js" | cut -c1-10)"
else
  version="$(shasum -a 256 "$SRC/app.js" | cut -c1-10)"
fi

if ! grep -q 'src="app.js"' "$stage/index.html"; then
  echo "error: index.html does not load app.js as src=\"app.js\"" >&2
  exit 1
fi
sed "s#src=\"app.js\"#src=\"app.js?v=$version\"#" "$stage/index.html" > "$stage/index.html.stamped"
mv "$stage/index.html.stamped" "$stage/index.html"
echo "app.js version stamp: $version"

rsync -rltv --no-owner --no-group -e "ssh -i $KEY -o IdentitiesOnly=yes -o ConnectTimeout=15" \
  "$stage/index.html" "$stage/app.js" "$stage/noble.js" "$VPS:$DEST"

# What is served is owned by root and cannot be changed by the account the web
# server runs as. (macOS's rsync has no --chown, so this is set on the server.)
ssh -i "$KEY" -o IdentitiesOnly=yes -o ConnectTimeout=15 "$VPS" \
  "chown -R root:root '$DEST' && find '$DEST' -type d -exec chmod 755 {} + && find '$DEST' -type f -exec chmod 644 {} +"
