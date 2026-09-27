# Beacon withholding: what a fix actually needs

Status: **design for review. Nothing is built.** Written 2026-09-27, following the finding
recorded in `spec.md`, "Consensus", "Known risk, not yet mitigated: beacon withholding", and
tracked as an open decision there ("Threshold randomness for the beacon").

## The finding, restated

The beacon (`crates/types/src/beacon.rs`) chains one BLS signature per height: the decided
block's proposer signs `(height, seed)`, and that signature alone becomes the next seed. The
selected proposer can compute its own reveal — and so the exact next seed — before deciding
whether to propose, and can withhold when the resulting schedule doesn't suit it. Nothing
penalises this today. Not exploitable for profit while one operator holds every validator key
and there is no stake or reward riding on proposer timing; both of those change before mainnet.

## Two fixes, not one, and they don't compete

**The proper fix — threshold randomness.** No single validator, including the proposer, is ever
able to compute a seed alone; the seed only exists once t-of-n validators have each contributed
their share. This is what actually removes the bias, and it is real new consensus machinery: a
DKG (or a trusted-dealer split, given today's single-operator validator set) to hand each
validator a share of a beacon key, a new "partial reveal" message and its aggregation, and a
resharing story for whenever the validator set changes. **Gated to real validator admission, not
to a date**: it earns nothing while one operator holds every key, and is out of place before then
— see `spec.md`'s design principle "reuse rather than invent" and the audit surface that a
hand-rolled DKG would open. Build it as part of the same work that publishes the
transport/key-rotation design for post-testnet validator admission (`spec.md`, "Open decisions
before genesis").

**The interim fix — price the bit instead of removing it.** Jail a proposer that fails to propose
in its own round, the same way `jail_for_downtime` already jails for general unavailability
(`crates/modules/src/registry.rs`) — except that function is not called from anywhere yet; there
is no automatic on-chain liveness penalty at all today, of any kind. This does not close the bias
(a jailed validator still knew what it was giving up before it chose), but it stops withholding
from being free, which is the right size of fix while there is no threshold scheme yet.

## Why the interim fix is a protocol change, not a wiring job

State-transition logic must be something every validator computes identically and agrees on
byte-for-byte. "Which validator missed its round" has to become canonical, agreed-upon input to
that computation — it cannot be one validator's private observation. Today it cannot be, because:

- **`Block` carries no round.** `crates/engine-api/src/block.rs`'s `Block` has
  `parent_block_hash`, `height`, `timestamp_millis`, `transactions` — nothing about which BFT
  round it was decided at. The round exists only in `chain-consensus`'s own types
  (`crates/consensus/src/types.rs`), which the executor never sees.
- **Proposer selection lives in the wrong crate for this.** `ConsensusValidatorSet::from_infos`
  (which turns a seed and a validator set into a proposer) is in `chain-consensus`. For
  `chain-exec`'s block-application hooks (`crates/exec/src/hooks.rs`, which already runs
  end-of-block module logic in a fixed order) to independently re-derive "who was supposed to
  propose at round *r* of height *h*" and jail them deterministically, that function — or an
  equivalent the executor can call without depending on the consensus crate's internals — needs
  to live somewhere both can reach, respecting the crate layering in `spec.md`, "Crate layout and
  trust tiers".
- **Both of the above are wire-format and protocol changes.** Adding a field to `Block` changes
  what is inside a block for every validator, the same class of change gas recalibration and
  storage were, and so needs a reset, exactly like those did.

## What "done" looks like, in order

1. A `round` (or equivalent) field on `Block`, filled in by consensus at the point it already
   knows the decided round, encoded and hashed like every other field, with a compatibility
   vector pinned the same way `docs/compatibility-vectors.md` pins the others.
2. The proposer-selection function (seed × validator set → proposer) available to `chain-exec`
   without a dependency on `chain-consensus`, either moved to a shared crate both depend on, or
   duplicated deliberately with a test that keeps the two copies in lock step.
3. A new `chain-exec` hook, after the existing four in `hooks.rs`: for a block decided at round
   *r* > 0, recompute the proposer for rounds `0..r` and jail each via
   `StakingRegistry::jail_for_downtime`, with its own test proving every validator reaches the
   same jailing decision from the same block.
4. Ships with a reset, bundled with whatever else is ready by then — not urgent enough on its own
   to force one.

Threshold randomness is not blocked on any of the above; it is blocked on real validator
admission, and is the fix to build first when that milestone is actually being planned.
