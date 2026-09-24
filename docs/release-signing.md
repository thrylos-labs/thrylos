# Release integrity: building, checking and signing

`docs/spec.md` treats release integrity as part of the threat model: the
largest thefts on record were operational compromises of the approval path,
not contract bugs. This is the process, and what is still open.

## Building

`scripts/release.sh` builds the operator-facing binaries with the toolchain
pinned in `rust-toolchain.toml`, the dependency graph locked by `Cargo.lock`
(`cargo build --locked`), debug info stripped and every build-machine path
(the checkout, the Cargo registry and git checkouts, the Rust sysroot)
remapped, so the same commit gives the same bytes wherever it is checked out.
It writes the binaries, `MANIFEST.txt` and `SHA256SUMS` to
`target/release-artifacts/`.

Matching another machine's output also needs the same operating system and CPU
architecture; the script does not try to normalise those. CI's `reproducible`
job builds the commit twice in two directories on Linux and fails if the
checksums differ.

Two things had to be fixed for that to hold: the bundled libmdbx C code stamps
`__DATE__` and `__TIME__` into the binary (the script now fixes them to a
constant), and Cargo's registry paths were embedded (now remapped). **A macOS
build is not reproducible**: two builds of one commit differ in exactly 48
bytes, the linker's per-build UUID and the code signature over it, and the UUID
cannot be dropped because macOS refuses to run binaries without one. Release
builds are therefore made on Linux. The Linux result has been checked in CI
only, not by hand; treat the first CI run of the `reproducible` job as the
real test.

## Checking dependencies

CI runs `cargo deny check` (licences, sources, advisories) and `cargo audit`
(the same advisory database, read separately). Every ignored advisory is listed
with its reason in `deny.toml`; the `audit` job's ignore list must match it.

## Signing

A release for anyone else is signed with an SSH key:

```bash
THRYLOS_SIGNING_KEY=~/.ssh/thrylos_release scripts/release.sh
```

This writes `SHA256SUMS.sig` (namespace `thrylos-release`). A downloader checks
it against the published `allowed_signers` file:

```bash
ssh-keygen -Y verify -f allowed_signers -I release@thrylos.org \
  -n thrylos-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS
```

### Who signs and how the key is held (to be settled)

Not yet decided, and needed before anything but the alpha:

- **Signers.** More than one person should be able to sign, and a release
  should need two. `ssh-keygen -Y` signs with one key, so two signatures means
  two `.sig` files, both checked.
- **Custody.** The signing key should live on a hardware token (a FIDO2
  `sk-ssh-ed25519` key), never on a build machine or in CI, so that
  compromising the build environment cannot sign a release.
- **Publication.** The `allowed_signers` file and each signer's key fingerprint
  should be published somewhere separate from the release downloads (the
  website, the repository and the team's own channels), so a swap in one place
  is noticed.
- **Rotation and revocation.** How a lost or suspect key is retired, and how
  users learn of it.
