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

# tar | gzip | age, so the archive is encrypted before it reaches the disk.
tar --exclude='*.sock' -cf - -C /root .thrylos-alpha | gzip | age -r "$RECIPIENT" -o "$OUT"
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
