#!/usr/bin/env bash
set -uo pipefail

# Nightly backup of the alpha's data (the chain databases, every signer and
# network key, the faucet wallet and the name registry) to /root/backups, run
# from cron on the VPS at 03:17. Installed at /root/backup.sh.
#
# The archives hold every secret on the machine, so each one is **encrypted with
# `age` to a public key** (/root/backup-recipient.txt, one line, `age1...`) as it is
# written: the plain archive never touches the disk, and nothing on this machine can
# read what it wrote. The private key lives only on the operator's own computer, which
# pulls the archives (`scripts/pull-backups.sh`). Files and directory stay private to
# root (0700 / 0600) as well.
#
# To restore: `age -d -i <private key file> thrylos-alpha-<stamp>.tar.gz.age | tar xzf - -C /root`
# (see docs/operations-vps.md).
#
# `tar` is not a single instant: reading everything takes several seconds, during
# which the live chain keeps committing, and this backs up several small files a
# restored node cannot start without agreeing with each other and with the state
# database. Two things this script does about that, both found by an actual restore
# rehearsal on 2026-09-27 (see docs/operations-vps.md):
#
# 1. **Order.** A node's `commits.log` (the beacon seed and vote history a restart
#    needs) is read *after* its state database (`data/chain`, the large part), not
#    before. A validator writes its consensus log entry for a height and flushes it
#    before committing that height to its state database (see
#    `chain_consensus::host::commit`), so at any instant the log is never behind the
#    database; reading the log first in a backup that takes several seconds can
#    invert that, and a node restored from the result halts at once with "no beacon
#    seed is recorded for the next height".
#
# 2. **Verified, stable copies of the files that get rewritten in place.**
#    `wal.log` and `signed.log` are rewritten this way roughly once a height (an
#    atomic replace: a temporary file, then a rename over the old one — see
#    `chain_db::HeightLog::rewrite`), and so is a validator's own `signer.mark`. In
#    testing, a `tar` of the live, several-seconds-long kind sometimes wrote a
#    different one of these small files' bytes under one of these paths — not a
#    torn file, a **wrong but complete** one, so it was invisible until a restored
#    node refused to start ("not a height log"). Cause not fully understood; the
#    fix does not depend on understanding it, since it does not trust a raw read of
#    these paths at all: each is copied aside first and re-read until its own header
#    is what it should be, and only that checked copy is archived.
#
# Both together restore the property this script relies on: a node built from one of
# these archives always finds its own state, its own consensus log, and its own
# signer mark agreeing with each other, the same as it would after an ordinary
# restart.

umask 077
BACKUPS=/root/backups
RECIPIENT_FILE=/root/backup-recipient.txt
mkdir -p "$BACKUPS"
chmod 700 "$BACKUPS"

if [ ! -s "$RECIPIENT_FILE" ]; then
  echo "backup FAILED: $RECIPIENT_FILE is missing or empty (the public key to encrypt to)" >&2
  exit 1
fi
RECIPIENT=$(head -n 1 "$RECIPIENT_FILE")
case "$RECIPIENT" in age1*) ;; *) echo "backup FAILED: $RECIPIENT_FILE does not hold an age public key" >&2; exit 1 ;; esac

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$BACKUPS/thrylos-alpha-${STAMP}.tar.gz.age"

STAGE=$(mktemp -d)
FILELIST=$(mktemp)
STAGELIST=$(mktemp)
cleanup() { rm -rf "$STAGE"; rm -f "$FILELIST" "$STAGELIST"; }
trap cleanup EXIT

# `wal.log` and `signed.log` (rewritten in place, live, roughly once a height) and a
# validator's `signer.mark` (the same): copied to $STAGE, re-read until the copy's own
# header is right, so what is archived for these is never a snapshot caught wrong.
# `HEIGHT_LOG_MAGIC` is `chain_db::height_log::HEADER`; `MARK_MAGIC` is
# `chain_node::mark_store::MAGIC` (or the older `MAGIC_V1`, still accepted by the
# reader). A path that never shows a right header in 50 tries is a real problem, not a
# timing one, and fails the backup rather than silently archiving it wrong again.
HEIGHT_LOG_MAGIC='THRYLOS-HEIGHT-LOG-1'
# Any one of the remaining arguments read at the start of the copy is accepted (a
# validator's mark file may be the older `THRYMARK` or the current `THRYMRK2`; the
# reader takes either, so this does too).
stage_verified() {
  local rel="$1" dst="$STAGE/$1" tries=0
  shift
  mkdir -p "$(dirname "$dst")"
  while :; do
    tries=$((tries + 1))
    if cp -p -- "/root/$rel" "$dst.new" 2>/dev/null; then
      for magic in "$@"; do
        if head -c "${#magic}" "$dst.new" 2>/dev/null | grep -qF "$magic"; then
          mv -f -- "$dst.new" "$dst"
          echo "$rel" >>"$STAGELIST"
          return 0
        fi
      done
    fi
    rm -f -- "$dst.new"
    if [ "$tries" -ge 50 ]; then
      echo "backup FAILED: $rel never read back with its own header in $tries tries" >&2
      exit 1
    fi
    sleep 0.05
  done
}
while IFS= read -r -d '' path; do
  rel=${path#/root/}
  case "$rel" in
  *signer.mark) stage_verified "$rel" 'THRYMRK2' 'THRYMARK' ;;
  *) stage_verified "$rel" "$HEIGHT_LOG_MAGIC" ;;
  esac
done < <(find /root/.thrylos-alpha -type f \( -name signed.log -o -name wal.log -o -name signer.mark \) -print0)

# The rest of the file list, in the order tar reads them: everything except the
# files just staged and `commits.log` (append-only; never rewritten in place, so
# not at risk the same way, but still read after the state database — see above),
# then `commits.log`. `find` only lists files, so directories with nothing else
# notable in them are still created on extraction, since tar makes a file's parent
# directories as it writes it.
{
  find /root/.thrylos-alpha -type f ! -name '*.sock' ! -name commits.log \
    ! -name signed.log ! -name wal.log ! -name signer.mark -print
  find /root/.thrylos-alpha -type f -name commits.log -print
} | sed 's#^/root/##' >"$FILELIST"

# tar | gzip | age, so the archive is encrypted before it reaches the disk. Two
# `-C`/`--files-from` pairs in one invocation: the live tree, then the staged,
# verified copies, landing at the same final paths (GNU tar keeps applying the most
# recent `-C` to each `--files-from` that follows it).
tar -cf - \
  -C /root --files-from="$FILELIST" \
  -C "$STAGE" --files-from="$STAGELIST" \
  | gzip | age -r "$RECIPIENT" -o "$OUT"
STATUSES=("${PIPESTATUS[@]}")
TAR_STATUS=${STATUSES[0]}
# tar exit 1 = some files changed while being read (expected for a live
# database; mdbx is copy-on-write, so the snapshot is still consistent,
# the same as surviving an unclean shutdown). Only >1 is a real failure, in
# tar or in either stage after it.
if [ "$TAR_STATUS" -gt 1 ] || [ "${STATUSES[1]}" -ne 0 ] || [ "${STATUSES[2]}" -ne 0 ]; then
  echo "backup FAILED (tar ${STATUSES[0]}, gzip ${STATUSES[1]}, age ${STATUSES[2]})" >&2
  rm -f "$OUT"
  exit 1
fi
chmod 600 "$OUT"

# Keep the 14 most recent backups, drop older ones.
ls -1t "$BACKUPS"/thrylos-alpha-*.tar.gz.age 2>/dev/null | tail -n +15 | xargs -r rm --
echo "backup written: $OUT ($(du -h "$OUT" | cut -f1), encrypted)"
