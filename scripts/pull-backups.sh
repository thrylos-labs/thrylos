#!/usr/bin/env bash
# Copy the VPS's newest encrypted backups to this computer. Run it by hand or on a
# schedule (see docs/operations-vps.md). It only reads: nothing on the VPS changes, and
# the archives stay encrypted here too (the private key is never used by this script).
#
# It fetches the newest KEEP archives the VPS has (default 5) that are not here yet, and
# deletes local ones beyond the newest KEEP, so the folder does not grow without bound
# (an archive is several hundred MB). Set KEEP higher to hold more.
#
# usage: pull-backups.sh [destination-dir]      (default: ~/thrylos-backups)
set -euo pipefail

dest="${1:-$HOME/thrylos-backups}"
key="${THRYLOS_SSH_KEY:-$HOME/.ssh/id_ed25519_thrylos_alpha}"
host="${THRYLOS_HOST:-root@157.230.10.32}"
keep="${KEEP:-5}"
ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=20)

mkdir -p "$dest"
chmod 700 "$dest"

# The newest ones the VPS has, by name (the name is a UTC timestamp, so name order is time order).
newest=$(ssh "${ssh_opts[@]}" "$host" "ls -1 /root/backups/thrylos-alpha-*.tar.gz.age | sort | tail -n $keep")
[ -n "$newest" ] || { echo "the VPS has no encrypted backups" >&2; exit 1; }
for path in $newest; do
  name=$(basename "$path")
  [ -e "$dest/$name" ] && continue
  # To a temporary name first, so an interrupted copy is never mistaken for a backup.
  rsync -a --partial -e "ssh ${ssh_opts[*]}" "$host:$path" "$dest/.$name.part"
  mv "$dest/.$name.part" "$dest/$name"
  echo "fetched $name"
done

# Local ones beyond the newest KEEP.
ls -1 "$dest"/thrylos-alpha-*.tar.gz.age | sort | awk -v keep="$keep" '{ names[NR] = $0 } END { for (i = 1; i <= NR - keep; i++) print names[i] }' | while read -r old; do rm -- "$old"; done
count=$(ls -1 "$dest"/thrylos-alpha-*.tar.gz.age | wc -l | tr -d ' ')
echo "$count encrypted backup(s) in $dest; newest: $(ls -1 "$dest"/thrylos-alpha-*.tar.gz.age | sort | tail -n 1 | xargs basename)"
