#!/usr/bin/env bash
# Try the guestbook on your own machine: a one-validator local network, three wallets,
# a book opened, signed by two visitors, read back, and a removal. Nothing here touches
# the public testnet.
#
# usage: examples/guestbook/try-it.sh [bin-dir]     (default: target/debug of this repository)
set -euo pipefail

here="$(cd "$(dirname "$0")/../.." && pwd)"
bin="${1:-$here/target/debug}"
root="$(mktemp -d /tmp/gb.XXXXXX)"
pid=""
cleanup() { [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true; pkill -f "$root" 2>/dev/null || true; rm -rf "$root" "$here/examples/guestbook/build"; }
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

step "three wallets, funded"
for who in alice bob carol; do
  "$bin/thrylos" setup --wallet "$root/$who.key" >/dev/null
  "$bin/chain-node" devnet fund "$root/net" "$("$bin/thrylos" address --wallet "$root/$who.key")" --node 1 --account 1 --amount 50 >/dev/null
done
alice=$("$bin/thrylos" address --wallet "$root/alice.key")
bob=$("$bin/thrylos" address --wallet "$root/bob.key")
carol=$("$bin/thrylos" address --wallet "$root/carol.key")
t() { who=$1; shift; "$bin/thrylos" "$@" --yes --rpc "$rpc" --wallet "$root/$who.key"; }

step "test and publish the package"
"$bin/thrylos" move test "$here/examples/guestbook" | tail -1
out=$(t alice move publish "$here/examples/guestbook")
book=$(echo "$out" | sed -n 's/^Package address: //p')
echo "package $book"

step "alice opens her book; bob and carol sign it"
t alice move call "$book" guestbook open "string:Alice's visitors" | tail -1
t bob move call "$book" guestbook sign "address:$alice" "string:Hello from Bob" | tail -1
t carol move call "$book" guestbook sign "address:$alice" "string:Carol was here" | tail -1
t bob move call "$book" guestbook sign "address:$alice" "string:Bob again" | tail -1

step "reading it back (views are limited to one a second per node)"
view() { sleep 1.2; "$bin/thrylos" move view "$book" guestbook "$@" --rpc "$rpc" --wallet "$root/alice.key" | sed -n 's/^Returns\[0\]: //p'; }
# A vector<u8> comes back as a list of numbers, with the words beside it: show the words.
words() { view "$@" | sed -n 's/.*(as text: \(.*\))$/\1/p'; }
echo "title    $(words title "address:$alice")"
echo "written  $(view written "address:$alice")"
for i in 0 1 2; do
  echo "entry $i  $(words message "address:$alice" u64:$i)  by $(view author "address:$alice" u64:$i | cut -c1-20)…"
done
"$bin/thrylos" move resources "$alice" --rpc "$rpc"

step "what should not work"
fails() { if "$@" >"$root/out" 2>&1; then echo "SHOULD HAVE FAILED: $*"; exit 1; fi; }
fails t bob move call "$book" guestbook sign "address:$alice" "string:"
echo "an empty message is refused (code 3)"
fails t bob move call "$book" guestbook sign "address:$bob" "string:Nobody has opened this book"
echo "signing a book that was never opened is refused (code 2)"
fails t bob move call "$book" guestbook remove u64:0
echo "bob cannot remove entries: he has no book of his own to remove from"
fails t alice move call "$book" guestbook open "string:again"
echo "a second book at one address is refused (code 1)"

step "alice removes entry 1"
t alice move call "$book" guestbook remove u64:1 | tail -1
sleep 1.2
if "$bin/thrylos" move view "$book" guestbook message "address:$alice" u64:1 --rpc "$rpc" --wallet "$root/alice.key" >"$root/out" 2>&1; then echo "the removed entry is still there"; exit 1; fi
echo "entry 1 is gone: $(grep -o 'aborted with code [0-9]*' "$root/out" | head -1)"
echo "the others are still there: $(words message "address:$alice" u64:2)"

step "DONE"
