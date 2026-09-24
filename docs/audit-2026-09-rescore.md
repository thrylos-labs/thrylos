# Simulated security audit and re-score, September 2026

This records a self-review of the Thrylos alpha and what has been done about
it. **It is not an independent audit and not a CertiK engagement.** The scores
are the reviewer's own rubric. Read them with these limits in mind:

- **Self-review.** The same person (an AI assistant working in this
  repository) wrote much of the code under review, including the wallet, the
  faucet, the storage deposit and the proposer fix, and then wrote the fixes.
  A reviewer grading their own fixes is generous by construction, and a real
  auditor would likely find new problems in the code added since.
- **Mostly unrun.** Findings were confirmed by reading code, by tests, and in
  two cases by reproducing them. Nothing was fuzzed, load-tested, simulated
  economically or formally verified against the code.
- **Scope.** The Move VM and Malachite were not reviewed.

| | Initial | Re-score |
|---|---|---|
| Overall | **68 / 100** | **74 / 100** |
| Verdict | Controlled testnet; not mainnet-ready | Public testnet; not mainnet-ready |

The initial review covered commit `091af14` plus uncommitted work. The re-score
is against the code live on the alpha VPS (`586188d`, deployed 2026-09-24 in two
batches; see `rollout-audit-fixes.md` and `rollout-batch-2.md`).

## Findings and their status

### High

| # | Finding | Status | What was done |
|---|---|---|---|
| 1 | Zero-gas transactions are free and create accounts with no deposit, bypassing the storage deposit. Reproduced end to end (state grew 7 to 10 entries). | **Fixed** | `MIN_GAS_LIMIT` = 1,000 enforced in the mempool, the executor and `propose_block`, and the least fee charged. Checked live: 500 gas gets `GasLimitTooLow`. |
| 2 | Governance can empty the validator set: `min_self_stake` had no upper clamp. | **Fixed** | A static clamp, plus a state-aware ceiling so 2/3 of stake stays qualified. |
| 3 | One Byzantine validator can fill the 64 block slots with blocks needing only its own valid reveal, dropping the real proposer's block. | **Mostly fixed** | Per-proposer quota (4) for unvouched blocks; a block named by a verified proposal is always kept. Blocks are still not bound to the drawn proposer (see below). |
| 4 | Browser wallet key exposure: `innerHTML` with RPC text, crypto libraries from a CDN with no integrity, no CSP, seed in plaintext `localStorage`. | **Mostly fixed** | `textContent`/text nodes only; crypto vendored as one bundle; a CSP allowing only same-origin scripts and `rpc.thrylos.org`; the seed is now encrypted under a password (AES-256-GCM, PBKDF2-SHA-256 at 600,000 rounds). |

### Medium

| Finding | Status | What was done |
|---|---|---|
| Sync answers could exceed the transport frame cap | **Fixed** | 8 MiB byte budget per answer; always at least one block. |
| `propose_block` cloned the whole state per candidate; no protocol-call cap | **Fixed** | Applies to a running scratch, copies only after a state-cap breach; stops at 64 protocol calls. |
| Free state paths (governance snapshots, stake shares) | **Mostly fixed** | 0.01 THRY per new entry on `stake` and `submit_proposal`. `vote`, `unjail` and evidence stay free deliberately. |
| Unbonding queue can be filled to lock others out | **Cost raised** | Each entry burns 0.03 THRY from its own proceeds (dust buys none); the operator has 7 reserved slots. Real-stake filling remains. |
| Signer: no `flock`; a missing mark file reads as "never signed" | **Fixed** | Exclusive lock on the mark's `.lock` file; a missing mark with an existing lock is refused. |
| Mempool: gapped transactions crowd out real ones and use proposal gas | **Fixed** | Far-ahead sequence numbers refused; non-runnable transactions evicted first; only a sender's next runnable transaction is offered. |
| Slowloris on the hand-written servers | **Fixed** | Whole-request deadline on the RPC server; the faucet and explorer now serve up to 16 connections concurrently with a 10 s deadline. |
| Faucet sybil | **Mitigated** | Discord accounts under 7 days refused (age read from the snowflake); an optional server-membership gate exists and is **off**. |
| Release builds not reproducible | **Partly done** | Fixed the libmdbx build timestamp and Cargo path leaks; optional SSH-signed checksums; `cargo-audit` and a Linux reproducibility CI job written. Neither job has run; macOS builds cannot be byte-reproducible. |

### Low

| Finding | Status |
|---|---|
| `BTreeMap` decoding accepted non-canonical bytes | **Fixed**: keys must be strictly ascending |
| No size cap on the RPC clients' reads | **Fixed**: 16 MiB |
| CI actions pinned by tag | **Fixed**: pinned to commit hashes |

## Scores by area

| Area | Initial | Re-score | Why |
|---|---|---|---|
| Cryptography and encoding | 85 | 85 | Unchanged; nothing exploitable found, and the canonical-decoding Low is closed. |
| Engineering and process | 88 | 89 | Many tests, most with mutation checks; the whole workspace passes. The new CI jobs have not run. |
| Execution and economics | 60 | 76 | Findings 1 and 2, the free state paths and the proposal cost are closed. Flat deposits without refunds and the residual unbonding attack hold it back. |
| Consensus and networking | 62 | 74 | Sync frame problem gone; slot flooding bounded. Blocks still not bound to the proposer; untested beyond one machine. |
| Key custody and signer | 72 | 78 | Lock and missing-mark check added. |
| Off-chain surface | 68 | 76 | Wallet, RPC server, faucet and explorer fixed. The wallet seed still depends on the user's password. |
| Dependencies | 55 | 56 | The Move VM and Malachite remain unaudited and only pinned; `cargo-audit` added in CI. This alone blocks mainnet. |

The unweighted mean of the re-scores is 76. The initial 68 sat about two points
below its own unweighted mean (70), so the same discount gives 74.

## What remains

**Deliberately left partly closed**
- **Blocks bound to the drawn proposer.** Would need a proposer signature on
  the block message, a wire-format change in consensus-critical code. The quota
  already bounds slot flooding (it would take at least 16 colluding validators
  to fill the 64 slots with unvouched blocks, and vouched blocks always win).
- **Per-byte deposits and refunds.** Only meaningful once objects or modules
  can be created and deleted; neither exists yet.
- **Unbonding queue.** An attacker locking real stake in all 512 slots can
  still fill it for 21 days.
- **Wallet seed.** Encrypted, but a phished or key-logged password exposes it.
- **Faucet abuse.** Aged or bought accounts still claim, bounded by the
  100 claims a day cap (at most 1,000 THRY of a valueless testnet coin).

**Needs a decision from the project**
- **Release signing.** Who signs, whether two signers are required, where the
  key is held (a hardware token, not a build machine or CI), and where the
  signers list is published. See `release-signing.md`.
- **Versioned rule changes.** A version and an activation height. Until then a
  consensus-rule change is safe only while every validator restarts together,
  which holds while the alpha is one machine. Needed before any second operator.

**Needs outside people or tools**
- Independent review of the Move VM and Malachite.
- A Linux run of the reproducibility and `cargo-audit` CI jobs.
- Fuzzing, load testing and economic simulation of the new code (deposits,
  block quota, scratch-state proposal, connection limits).
- Formal checking of the TLA+ model against the code.

**Not confirmed live**
The faucet age gate with real Discord accounts, the fresh-address deposit on a
real transfer, and a real send from the wallet. Each was tested in code, or in
the browser locally, but not observed on the live alpha.
