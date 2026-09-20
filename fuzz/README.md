# Continuous fuzzing

The four targets correspond to the audit boundaries in `docs/spec.md`:

- `codecs`: malformed canonical, consensus-wire and durable-record bytes;
- `state_transitions`: direct full-state mutation versus incremental
  `StateDiff` application, including roots after every block;
- `protocol_calls`: all seven fixed staking/governance entry points with
  structured and malformed arguments; and
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
cargo +nightly fuzz run metering_ratio -- -max_len=4096 -max_total_time=60
```
