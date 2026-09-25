#!/usr/bin/env bash
# Rehearse reset-testnet.sh on this machine, in a scratch copy of the VPS's
# layout, with the binaries in target/debug (or the directory given). It makes
# an "old" alpha, runs the reset, starts the new network, and then does what a
# user does: fund a wallet from the faucet, publish a package, call it.
#
# usage: rehearse-reset.sh [bin-dir]
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
bin="${1:-$here/target/debug}"
fixture="$here/crates/node/tests/fixtures/demo.mv"
# Unix socket paths are short-limited, so the scratch root is short too.
root="$(mktemp -d /tmp/rr.XXXXXX)"
alpha="$root/a"
pid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
  pkill -f "$alpha" 2>/dev/null || true
  rm -rf "$root"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
rpc_port_base=$((23000 + RANDOM % 5000))

step "an old alpha: operators, faucet, names, a running chain"
mkdir -p "$alpha/operators"
for n in 1 2 3 4; do "$bin/thrylos" setup --wallet "$alpha/operators/node$n.key" >/dev/null; done
"$bin/chain-faucet" init "$alpha/faucet" >/dev/null
"$bin/chain-names" init "$alpha/names" --chain-id 111 >/dev/null
faucet_pub=$("$bin/thrylos" address --hex --wallet "$alpha/faucet/faucet.key")
ops=()
for n in 1 2 3 4; do ops+=(--operator "$("$bin/thrylos" address --hex --wallet "$alpha/operators/node$n.key")"); done
"$bin/chain-node" testnet init "$alpha/network" --chain-id 111 --base-port "$rpc_port_base" \
  --block-interval-ms 200 "${ops[@]}" --allocate "$faucet_pub:100,000" >/dev/null
echo "old chain 111 written"
# The old names service, run once so it has written its registry file.
names_port=$((rpc_port_base + 500))
"$bin/chain-names" run "$alpha/names" --listen "127.0.0.1:$names_port" >/dev/null 2>&1 &
names_pid=$!
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$names_port/names/available/test" >/dev/null && break; sleep 0.3; done
kill "$names_pid"; wait "$names_pid" 2>/dev/null || true
ls "$alpha/names"

step "the reset"
"$here/scripts/reset-testnet.sh" "$alpha" "$bin" 222
# The rehearsal's own ports and pace, as the old one had (init resets them).
grep -q '"chain_id": 222' "$alpha/network/node1/genesis.json" || { echo "new genesis is not chain 222"; exit 1; }
ls "$alpha"/network.old-111-* >/dev/null
python3 -c "import json,sys;d=json.load(open(sys.argv[1]));sys.exit(0 if d['requests']==[] else 1)" "$alpha/faucet/state.json" || { echo "faucet state was not reset"; exit 1; }
ls "$alpha"/faucet/state.json.old-111 >/dev/null
grep -q '"chain_id": 222' "$alpha/names/names-config.json" || { echo "names chain id not updated"; exit 1; }
echo "old chain kept, new chain 222 in place, faucet and names reset"

step "the new network starts and makes blocks"
"$bin/chain-node" devnet start "$alpha/network" > "$root/net.log" 2>&1 &
pid=$!
rpc=$(python3 -c "import json;print(json.load(open('$alpha/network/node1/node.json'))['rpc']['listen'])")
for _ in $(seq 1 120); do
  h=$(curl -s -X POST "http://$rpc/" -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"status"}' | python3 -c "import json,sys;d=json.load(sys.stdin)['result'];print(d['latest']['height'] if d.get('halted') is None else -1)" 2>/dev/null || echo -1)
  [ "$h" -ge 3 ] 2>/dev/null && break
  sleep 1
done
[ "${h:-0}" -ge 3 ] || { echo "the new chain never reached height 3"; tail -20 "$root/net.log"; exit 1; }
echo "height $h"

step "the names service opens its reset registry, with the new chain id"
"$bin/chain-names" run "$alpha/names" --listen "127.0.0.1:$names_port" >/dev/null 2>&1 &
names_pid=$!
ok=""
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$names_port/names/available/test" >/dev/null && ok=1 && break; sleep 0.3; done
kill "$names_pid"; wait "$names_pid" 2>/dev/null || true
[ -n "$ok" ] || { echo "the names service did not start after the reset"; exit 1; }
echo "names service answers"

step "the faucet's balance is its genesis allocation"
faucet_addr=$("$bin/thrylos" address --wallet "$alpha/faucet/faucet.key")
"$bin/thrylos" balance "$faucet_addr" --rpc "$rpc" | tee "$root/faucet.bal"
grep -q "Balance: 100,000" "$root/faucet.bal" || grep -q "100000" "$root/faucet.bal" || { echo "unexpected faucet balance"; exit 1; }

step "a user: a wallet, THRY from the faucet, a package, a call"
"$bin/thrylos" setup --wallet "$root/user.key" >/dev/null
user=$("$bin/thrylos" address --wallet "$root/user.key")
# The faucet reads the chain from faucet.json's rpc; point it at this network.
python3 - "$alpha/faucet/faucet.json" "$rpc" <<'PY'
import json, sys
c = json.load(open(sys.argv[1])); c["rpc"] = sys.argv[2]
json.dump(c, open(sys.argv[1], "w"), indent=2)
PY
"$bin/chain-faucet" request "$alpha/faucet" rehearsal-user "$user" >/dev/null
"$bin/chain-faucet" work "$alpha/faucet" | tail -3
"$bin/thrylos" balance --rpc "$rpc" --wallet "$root/user.key"
out=$("$bin/thrylos" move publish "$fixture" --yes --rpc "$rpc" --wallet "$root/user.key")
echo "$out" | tail -3
package=$(echo "$out" | sed -n 's/^Package address: //p')
[ -n "$package" ] || { echo "no package address"; exit 1; }
"$bin/thrylos" move call "$package" demo sum_is_ten u64:4 u64:6 --yes --rpc "$rpc" --wallet "$root/user.key" | tail -2
"$bin/thrylos" move call "$package" demo hashes --yes --rpc "$rpc" --wallet "$root/user.key" | tail -2
if "$bin/thrylos" move call "$package" demo sum_is_ten u64:1 u64:1 --yes --rpc "$rpc" --wallet "$root/user.key" 2>"$root/abort.err"; then
  echo "a failing call succeeded"; exit 1
fi
grep -q ExecutionFailed "$root/abort.err" && echo "a failing call aborted as it should"

step "REHEARSAL PASSED"
