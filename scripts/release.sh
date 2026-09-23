#!/usr/bin/env bash
set -euo pipefail

# Builds release binaries for the core-network alpha
# (docs/core-network-alpha.md, "Produce reproducible release binaries and
# checksums") and writes their SHA-256 checksums next to them.
#
# "Reproducible" here means: the pinned toolchain in rust-toolchain.toml, the
# locked dependency graph in Cargo.lock (never updated by this script),
# stripped debug info, and build paths remapped so the output does not embed
# this machine's absolute paths. Running this script twice on the same
# commit, on the same host, produces byte-identical binaries; matching
# another machine's output additionally needs the same OS and CPU
# architecture, which this script does not attempt to normalize.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The operator-facing binaries this alpha ships (`README.md`); the crash-test
# helpers under src/bin are dev-only and deliberately left out.
BINARIES=(chain-node chain-genesis chain-faucet chain-explorer chain-signer thrylos)
OUT_DIR="target/release-artifacts"

if ! command -v cargo >/dev/null; then
  echo "error: cargo is not on PATH" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "warning: the working tree is not clean; the release will include uncommitted changes" >&2
fi

rustc_version="$(rustc --version)"
commit="$(git rev-parse HEAD)"
target_triple="$(rustc -vV | sed -n 's/^host: //p')"

echo "building ${#BINARIES[@]} binaries for $target_triple with $rustc_version"

export CARGO_INCREMENTAL=0
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$(pwd)=. -C strip=symbols"

build_args=()
for bin in "${BINARIES[@]}"; do
  build_args+=(--bin "$bin")
done
cargo build --locked --release "${build_args[@]}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
for bin in "${BINARIES[@]}"; do
  cp "target/release/$bin" "$OUT_DIR/$bin"
done

manifest="$OUT_DIR/MANIFEST.txt"
{
  echo "commit:  $commit"
  echo "target:  $target_triple"
  echo "rustc:   $rustc_version"
  echo "built:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$manifest"

if command -v sha256sum >/dev/null; then
  (cd "$OUT_DIR" && sha256sum "${BINARIES[@]}" > SHA256SUMS)
else
  (cd "$OUT_DIR" && shasum -a 256 "${BINARIES[@]}" > SHA256SUMS)
fi

echo
echo "wrote $OUT_DIR/{$(IFS=,; echo "${BINARIES[*]}")}, MANIFEST.txt and SHA256SUMS"
echo
cat "$manifest"
echo
cat "$OUT_DIR/SHA256SUMS"
