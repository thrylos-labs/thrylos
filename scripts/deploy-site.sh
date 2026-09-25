#!/usr/bin/env bash
set -euo pipefail

# Copies the thrylos.org landing page (deploy/site) to the alpha VPS.
#
# Cloudflare tells browsers to cache .css/.js/.png for four hours, so a changed
# stylesheet or script next to a cached page would not show. Each asset's URL
# therefore carries a hash of its own contents (site.css?v=..., site.js?v=...),
# stamped into a temporary copy of index.html; the repository's file is untouched.
#
#   scripts/deploy-site.sh
#   VPS=root@host KEY=~/.ssh/key scripts/deploy-site.sh

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VPS="${VPS:-root@157.230.10.32}"
KEY="${KEY:-$HOME/.ssh/id_ed25519_thrylos_alpha}"
DEST="${DEST:-/srv/thrylos/site/}"
SRC=deploy/site

digest() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -c1-10; else shasum -a 256 "$1" | cut -c1-10; fi
}

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
ASSETS=(site.css site.js thrylos-mark.svg favicon.svg favicon-32.png apple-touch-icon.png)
cp "$SRC"/index.html "${ASSETS[@]/#/$SRC/}" "$stage/"

for asset in "${ASSETS[@]}"; do
  grep -q "\"$asset\"" "$stage/index.html" || { echo "error: index.html does not reference \"$asset\"" >&2; exit 1; }
  sed "s#\"$asset\"#\"$asset?v=$(digest "$SRC/$asset")\"#g" "$stage/index.html" > "$stage/index.html.stamped"
  mv "$stage/index.html.stamped" "$stage/index.html"
done
grep -o '"[a-z0-9-]*\.[a-z0-9]*?v=[0-9a-f]*"' "$stage/index.html"

rsync -rltv --no-owner --no-group -e "ssh -i $KEY -o IdentitiesOnly=yes -o ConnectTimeout=15" \
  "$stage/index.html" "${ASSETS[@]/#/$stage/}" "$VPS:$DEST"

# What is served is owned by root and cannot be changed by the account the web
# server runs as. (macOS's rsync has no --chown, so this is set on the server.)
ssh -i "$KEY" -o IdentitiesOnly=yes -o ConnectTimeout=15 "$VPS" \
  "chown -R root:root '$DEST' && find '$DEST' -type d -exec chmod 755 {} + && find '$DEST' -type f -exec chmod 644 {} +"
