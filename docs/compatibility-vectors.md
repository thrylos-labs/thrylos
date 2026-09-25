# Consensus compatibility vectors

These vectors freeze the consensus encodings used by the first single-host
testnet. They are assertions in the ordinary workspace test suite, so changing
one fails CI. A vector changes only as an explicit protocol change; updating an
expected value just to make a failing test pass is not a fix.

All hexadecimal strings are lowercase and have no `0x` prefix.

## Trie commitment V2

The commitment version is `2`.

| State | Expected root |
|---|---|
| Empty | `565219c4b409726ea0ed96963220f6397dababec294808e1e9143bdc02ea7165` |
| One entry: key `61` (`a`), value `6263` (`bc`) | `442b5be0d7fb2680b5ee6d1edbe9d1460a81f07b8051a0e38293067d1f20cd0b` |

The executable assertions are in `chain-state::trie::tests`.

## Development genesis

The input is the deterministic four-validator configuration returned by
`chain_genesis::devnet::config`.

| Commitment | Expected hash |
|---|---|
| Genesis configuration | `1e441e8b66d3f61a3a08c762e38614a28038b0bb68b6dd1c06730fdbf50d844d` |
| Materialised genesis state | `880924bb68774bf30cf720e9b550ff386eb70e55f65071f12ce96ff588cdf81d` |

The executable assertions are in `chain-genesis::devnet::tests`.

*Changed 2026-09-25, on purpose:* the gas recalibration (`gas-calibration.md`) moved the
genesis block gas limit from 60,000,000 to 300,000, which is in the configuration and so in both
hashes. They were `c9275496…0d35` and `9cca51a3…1503`.

## Signed transaction

The executable vector is `chain-types::transaction::tests::signed_transaction_matches_the_golden_vector`.
It fixes the sender public key, canonical signing bytes, Ed25519 signature,
complete transaction encoding, and transaction hash for the deterministic
seed `03` repeated 32 times. Keeping the long byte strings beside the encoder
makes a field-order or length-encoding change immediately visible in review.

