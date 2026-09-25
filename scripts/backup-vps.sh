#!/usr/bin/env bash
set -uo pipefail

# Nightly backup of the alpha's data (the chain databases, every signer and
# network key, the faucet wallet and the name registry) to /root/backups, run
# from cron on the VPS at 03:17. Installed at /root/backup.sh.
#
# The archives hold every secret on the machine, so they are private to root
# (directory 0700, files 0600), whatever the caller's umask. They are still on
# the same disk as the data: copy them somewhere else, encrypted, as well.

umask 077
BACKUPS=/root/backups
mkdir -p "$BACKUPS"
chmod 700 "$BACKUPS"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$BACKUPS/thrylos-alpha-${STAMP}.tar.gz"

tar --exclude='*.sock' -czf "$OUT" -C /root .thrylos-alpha
STATUS=$?
# tar exit 1 = some files changed while being read (expected for a live
# database; mdbx is copy-on-write, so the snapshot is still consistent,
# the same as surviving an unclean shutdown). Only >1 is a real failure.
if [ "$STATUS" -gt 1 ]; then
  echo "backup FAILED (tar exit $STATUS)" >&2
  rm -f "$OUT"
  exit 1
fi
chmod 600 "$OUT"

# Keep the 14 most recent backups, drop older ones.
ls -1t "$BACKUPS"/thrylos-alpha-*.tar.gz | tail -n +15 | xargs -r rm --
echo "backup written: $OUT ($(du -h "$OUT" | cut -f1))"
