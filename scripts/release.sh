#!/usr/bin/env bash
set -euo pipefail

# Builds release binaries for the core-network alpha
# (docs/core-network-alpha.md, "Produce reproducible release binaries and
# checksums") and writes their SHA-256 checksums next to them.
#
# "Reproducible" here means: the pinned toolchain in rust-toolchain.toml, the
# locked dependency graph in Cargo.lock (never updated by this script),
# stripped debug info, build paths remapped so the output does not embed
# this machine's absolute paths, and the C dependencies' build date and time
# fixed. On Linux, one commit gives the same bytes in any directory; matching
# another machine's output additionally needs the same OS and CPU
# architecture, which this script does not attempt to normalize.
#
# The reference platform is Linux (CI's `reproducible` job builds the commit
# in two directories and compares checksums). On macOS two builds of one
# commit are identical except for 48 bytes: the linker's per-build LC_UUID and
# the ad-hoc code signature that covers it. Leaving the UUID out is not an
# option there (dyld refuses to run binaries without one, build scripts
# included), so a macOS build is not byte-reproducible and is not a release.

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
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$(pwd)=. --remap-path-prefix=$cargo_home=/cargo -C strip=symbols"
# The C dependencies (libmdbx) stamp `__DATE__` and `__TIME__` into the
# binary, which alone made two builds of one commit differ. Fixing them to a
# constant is what makes the bytes repeatable. (No path goes in these flags:
# libmdbx records its own compile flags in the binary, so a checkout path
# there would itself make two checkouts differ.)
export CFLAGS="${CFLAGS:-} -Wno-builtin-macro-redefined -D__DATE__=\"redacted\" -D__TIME__=\"redacted\""

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

# Signing. The checksums are only as trustworthy as who vouches for them, so
# a release meant for anyone else is signed: set THRYLOS_SIGNING_KEY to the
# path of an SSH private key (ideally one held on a hardware token) and this
# writes SHA256SUMS.sig with `ssh-keygen -Y sign`. Verify with
#   ssh-keygen -Y verify -f allowed_signers -I <identity> \
#     -n thrylos-release -s SHA256SUMS.sig < SHA256SUMS
# See docs/release-signing.md for who signs and how the key is held.
if [[ -n "${THRYLOS_SIGNING_KEY:-}" ]]; then
  (cd "$OUT_DIR" && ssh-keygen -Y sign -f "$THRYLOS_SIGNING_KEY" -n thrylos-release SHA256SUMS)
  echo "signed SHA256SUMS -> $OUT_DIR/SHA256SUMS.sig"
else
  echo "note: THRYLOS_SIGNING_KEY is not set; SHA256SUMS is not signed" >&2
fi

echo
echo "wrote $OUT_DIR/{$(IFS=,; echo "${BINARIES[*]}")}, MANIFEST.txt and SHA256SUMS"
echo
cat "$manifest"
echo
cat "$OUT_DIR/SHA256SUMS"
