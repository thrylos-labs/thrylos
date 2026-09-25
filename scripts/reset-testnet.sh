#!/usr/bin/env bash
# Start the alpha testnet over from a new genesis, keeping its operators, its
# faucet key and its settings. Used for the reset that publishing Move packages
# needs (the parameters and the genesis state both changed, so an old chain
# cannot be read by the new binaries), and rehearsed by rehearse-reset.sh.
#
# Only the data steps. Stopping and starting services, taking the backup and
# checking the public endpoints are the runbook's (docs/rollout-move-reset.md).
#
# usage: reset-testnet.sh <alpha-dir> <bin-dir> <new-chain-id> [faucet-allocation]
#   alpha-dir          the directory holding network/, operators/, faucet/, names/
#   bin-dir            where thrylos, chain-node and chain-faucet are
#   new-chain-id       must differ from the old one: a chain id reused would let
#                      the old chain's signed transactions replay on the new
#   faucet-allocation  what the faucet is given at genesis (default 100,000 THRY)
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  sed -n '2,/^set -e/p' "$0" | sed 's/^# \{0,1\}//' | head -n -1 >&2
  exit 2
fi
alpha="$1"; bin="$2"; new_id="$3"; allocation="${4:-100,000}"

net="$alpha/network"
[ -d "$net" ] || { echo "no network at $net" >&2; exit 1; }
for f in thrylos chain-node; do
  [ -x "$bin/$f" ] || { echo "$bin/$f is missing" >&2; exit 1; }
done

# The old chain id, read from a node's genesis.
old_id=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['chain_id'])" "$net/node1/genesis.json")
if [ "$old_id" = "$new_id" ]; then
  echo "the new chain id $new_id is the old one; choose another" >&2
  exit 1
fi

# Nothing may be running against these directories: a leftover signer holds its
# lock, and a running node would keep writing the chain being moved away.
if pgrep -f "$net" >/dev/null 2>&1; then
  echo "processes are still running against $net; stop them first" >&2
  pgrep -fl "$net" >&2
  exit 1
fi

# The operators: one wallet key each, in operators/. Their public keys go into
# the new genesis; the keys themselves are only read by `thrylos address`.
operator_flags=()
for key in "$alpha"/operators/node*.key; do
  pub=$("$bin/thrylos" address --hex --wallet "$key")
  operator_flags+=(--operator "$pub")
done
[ "${#operator_flags[@]}" -gt 0 ] || { echo "no operator keys in $alpha/operators" >&2; exit 1; }

faucet_pub=$("$bin/thrylos" address --hex --wallet "$alpha/faucet/faucet.key")

# Take the old chain out of the way, whole, and keep it.
stamp=$(date -u +%Y%m%dT%H%M%SZ)
old="$alpha/network.old-$old_id-$stamp"
mv "$net" "$old"
echo "old chain moved to $old"

# Same shape as before: one node per operator, the same ports and pace.
read -r base_port interval < <(python3 - "$old/node1/node.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
print(int(c["listen"].rsplit(":", 1)[1]), c.get("tuning", {}).get("block_interval_ms", 1000))
PY
)
"$bin/chain-node" testnet init "$net" --chain-id "$new_id" \
  --base-port "$base_port" --block-interval-ms "$interval" \
  "${operator_flags[@]}" --allocate "$faucet_pub:$allocation"

# A state file emptied of its records but otherwise as it was, so it has the
# shape the running service expects and never a guess at it.
emptied() {
  python3 - "$1" "$2" <<'PY'
import json, sys
old = json.load(open(sys.argv[1]))
new = {k: ([] if isinstance(v, list) else {} if isinstance(v, dict) else v)
       for k, v in old.items()}
json.dump(new, open(sys.argv[2], "w"), indent=2)
PY
}

# The faucet keeps its key and settings but forgets the old chain's requests.
if [ -f "$alpha/faucet/state.json" ]; then
  mv "$alpha/faucet/state.json" "$alpha/faucet/state.json.old-$old_id"
  emptied "$alpha/faucet/state.json.old-$old_id" "$alpha/faucet/state.json"
  chmod --reference="$alpha/faucet/state.json.old-$old_id" "$alpha/faucet/state.json" 2>/dev/null || true
fi

# Reserved names commit to the chain id, so none of them can carry over.
if [ -f "$alpha/names/names.json" ]; then
  mv "$alpha/names/names.json" "$alpha/names/names.json.old-$old_id"
  emptied "$alpha/names/names.json.old-$old_id" "$alpha/names/names.json"
  chmod --reference="$alpha/names/names.json.old-$old_id" "$alpha/names/names.json" 2>/dev/null || true
fi
if [ -f "$alpha/names/names-config.json" ]; then
  python3 - "$alpha/names/names-config.json" "$new_id" <<'PY'
import json, sys
path, new_id = sys.argv[1], int(sys.argv[2])
config = json.load(open(path))
config["chain_id"] = new_id
json.dump(config, open(path, "w"), indent=2)
PY
fi

echo "reset done: chain $old_id -> $new_id. Start the services, then check the RPC."
