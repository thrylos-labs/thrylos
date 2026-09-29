# Medium-severity audit remediation — 2026-09

This records the disposition of the six medium findings from the independent
CertiK-style review. “Closed” means the vulnerable behavior is prevented and
covered by tests. It does not mean CertiK reviewed or certified the change.

| Finding | Status | Remediation |
|---|---|---|
| M-01 proposer beacon withholding | Open, design-gated | The correct fix remains threshold randomness with DKG/resharing. `beacon-withholding-design.md` explains why a proposer penalty is only an interim economic deterrent and why resharing must be designed with validator admission. Do not describe the current beacon as bias-resistant. |
| M-02 no weak-subjectivity checkpoint | Closed | Node configuration accepts an optional trusted height, block hash and state root. The durable engine checks an already-advanced database at startup and refuses a mismatching block before finalisation while catching up. The node configuration is the authenticated distribution channel. State snapshots remain a performance feature, not a prerequisite for the trust anchor. |
| M-03 block payload not bound to proposer | Closed | Every full and compact block now carries the existing signed consensus proposal. Before retaining or logging the payload, the host verifies chain, height, block hash, selected proposer and BLS signature. Only one payload per proposer/round is retained, and future-height payloads are not cached. This is a wire/WAL format break and requires coordinated rollout/reset. |
| M-04 genesis-fixed validator membership | Open, design-gated | On-chain admission is intentionally still disabled. Enabling it before authenticated transport endpoint/key registration, rotation and removal would admit validators that peers cannot authenticate or reach. This work must ship together with the threshold-beacon resharing design. |
| M-05 delegator exit queue saturation | Closed | A validator/staker pair may have one open exit, and delegation admission conservatively reserves one of the 512 bounded evidence-processing slots for every current share holder. Saturation can refuse a new delegator, but cannot trap stake already admitted. |
| M-06 browser-wallet custody exposure | Mitigated; not mainnet custody | Minimum passwords are 12 characters, encrypted wallets lock after five minutes of inactivity and immediately on backgrounding, live seed buffers are overwritten when possible, and hidden private-key text is removed from the DOM. JavaScript cannot guarantee erasure of engine-internal copies, so the wallet remains explicitly testnet-only; hardware/external signing is the mainnet closure. |

## Verification expected before merge

- `cargo test --workspace --all-targets`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `node --check deploy/wallet/app.js`

M-01 and M-04 are coupled protocol projects, not safe local patches. Their
open status is deliberate and must remain visible in release notes and risk
disclosures until threshold beacon and transport-aware admission are shipped.
