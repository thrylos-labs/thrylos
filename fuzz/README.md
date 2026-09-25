# Continuous fuzzing

The five targets correspond to the audit boundaries in `docs/spec.md`:

- `codecs`: malformed canonical, consensus-wire and durable-record bytes;
- `state_transitions`: direct full-state mutation versus incremental
  `StateDiff` application, including roots after every block;
- `protocol_calls`: all seven fixed staking/governance entry points with
  structured and malformed arguments; and
- `move_publish`: publishing arbitrary bytes, real compiled modules
  (`fuzz/seeds`) with their tables edited (a type handle retargeted, a signature
  swapped, a call redirected: `fuzz/oracle.rs`) and with bytes changed, as a Move
  package. It must never panic or reject its block, and only succeed or be refused.
  Seeds include modules that use `thrylos::store` well and badly (a thief and its
  victim, a module generic over the stored type), and whatever the chain publishes
  is checked by code of our own (`oracle::violations`, a second opinion that walks
  the instruction stream) never to keep a type it does not define in a drawer.
  `crates/exec/tests/publish_mutations.rs` runs the same checks deterministically
  on every test run (3,000 rounds of byte edits, 6,000 of table edits); and
- `metering_ratio`: the same protocol calls, with libFuzzer coverage buckets
  biased toward larger elapsed-time-per-gas ratios and a hard ceiling.

CI smoke-fuzzes every target on every change and runs longer scheduled jobs.
The metering ceiling defaults to `1,000,000 ns/gas` and can be tightened with
`THRYLOS_MAX_NS_PER_GAS` after reference hardware is named and calibrated. It
is deliberately described as provisional evidence, not a production gas
schedule.

Run a target locally with nightly Rust and `cargo-fuzz`:

```bash
cargo +nightly fuzz run codecs -- -max_len=4096 -max_total_time=60
cargo +nightly fuzz run state_transitions -- -max_len=4096 -max_total_time=60
cargo +nightly fuzz run protocol_calls -- -max_len=4096 -max_total_time=60
cargo +nightly fuzz run move_publish -- -max_len=4096 -max_total_time=60
cargo +nightly fuzz run metering_ratio -- -max_len=4096 -max_total_time=60
```
