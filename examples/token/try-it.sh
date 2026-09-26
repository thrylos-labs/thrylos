#!/usr/bin/env bash
# Try the token on your own machine: a one-validator local network, two wallets, a
# token made, sent, and read back. Nothing here touches the public testnet.
#
# usage: examples/token/try-it.sh [bin-dir]      (default: target/debug of this repository)
set -euo pipefail

here="$(cd "$(dirname "$0")/../.." && pwd)"
bin="${1:-$here/target/debug}"
root="$(mktemp -d /tmp/tok.XXXXXX)"
pid=""
cleanup() { [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true; pkill -f "$root" 2>/dev/null || true; rm -rf "$root"; }
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }

step "a local network with one validator"
"$bin/chain-node" devnet init "$root/net" --validators 1 >/dev/null
"$bin/chain-node" devnet start "$root/net" >"$root/net.log" 2>&1 &
pid=$!
rpc=$(python3 -c "import json;print(json.load(open('$root/net/node1/node.json'))['rpc']['listen'])")
for _ in $(seq 1 60); do
  curl -sf -X POST "http://$rpc/" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"status"}' >/dev/null && break; sleep 1
done

step "two wallets, funded"
for who in alice bob; do
  "$bin/thrylos" setup --wallet "$root/$who.key" >/dev/null
  "$bin/chain-node" devnet fund "$root/net" "$("$bin/thrylos" address --wallet "$root/$who.key")" --node 1 --account 1 --amount 50 >/dev/null
done
alice=$("$bin/thrylos" address --wallet "$root/alice.key")
bob=$("$bin/thrylos" address --wallet "$root/bob.key")
t() { who=$1; shift; "$bin/thrylos" "$@" --yes --rpc "$rpc" --wallet "$root/$who.key"; }

step "test and publish the package"
"$bin/thrylos" move test "$here/examples/token" | tail -1
"$bin/thrylos" move build "$here/examples/token" | tail -1
out=$(t alice move publish "$here/examples/token")
token=$(echo "$out" | sed -n 's/^Package address: //p')
echo "package $token"

step "alice makes token 1 with 1,000 units and sends 250 to bob"
t alice move call "$token" token create u64:1 u64:1000 | tail -1
t alice move call "$token" token transfer u64:1 "address:$bob" u64:250 --input "$bob" | tail -1

step "reading it back"
view() { sleep 1.2; "$bin/thrylos" move view "$token" token "$@" --rpc "$rpc" --wallet "$root/alice.key" | sed -n 's/^Returns\[0\]: //p'; }
echo "alice holds $(view balance_of "address:$alice" u64:1 --input "$alice")"
echo "bob holds   $(view balance_of "address:$bob" u64:1 --input "$bob")"
echo "supply      $(view total_supply "address:$alice" u64:1 --input "$alice")"

step "what should not work"
if t alice move call "$token" token transfer u64:1 "address:$bob" u64:100000 --input "$bob" >"$root/big.out" 2>&1; then echo "an overdraft succeeded"; exit 1; fi
grep -q "abort\|Aborted\|ExecutionFailed" "$root/big.out" && echo "sending more than alice has aborts (code 2), as it should"
if t bob move call "$token" token burn u64:1 u64:10 >"$root/burn.out" 2>&1; then echo "bob burned"; exit 1; fi
echo "bob cannot burn: only the creator holds the supply record"

step "DONE"
