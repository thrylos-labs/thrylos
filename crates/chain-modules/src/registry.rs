//! The staking registry: which validators exist, what each has staked
//! and who staked it, what is on its way out through the unbonding
//! queue, and — derived from those — the active validator set consensus
//! runs on. `docs/spec.md`, "Native modules": the state behind `stake`,
//! `unstake` and `read_validator_set`.
//!
//! [`crate::staking::StakingPool`] is one validator's share-price
//! accounting in isolation; this is the layer that gives every validator
//! one, wires slashing to them, and answers the questions everything
//! else was passing in as arguments — a validator's stake, the total
//! bonded, the weights consensus votes with.
//!
//! # Storage
//!
//! All state lives in a [`Store`], one entry per entity, so an operation
//! touches a handful of keys however many validators and stakers exist,
//! and the chain's per-block diff is exactly what changed:
//!
//! | key | value |
//! |---|---|
//! | `VALIDATOR ‖ id` | operator, consensus key, pool totals |
//! | `SHARES ‖ id ‖ staker` | the staker's shares in that pool (absent: none) |
//! | `CONSENSUS_KEY ‖ key` | the validator that registered it |
//! | `UNBONDING ‖ seq` | one unbonding entry |
//! | `UNBONDING_BY_MATURITY ‖ matures_ms ‖ seq` | index: what is due, oldest first |
//! | `UNBONDING_BY_VALIDATOR ‖ id ‖ seq` | index: what a slash can reach |
//! | `UNBONDING_PAIR_COUNT ‖ staker ‖ id` | open entries, for the per-pair cap |
//! | `REGISTRY_META` | the next unbonding sequence number |
//!
//! plus what [`crate::slashing`] keeps for the same validators. Numbers in
//! keys are big-endian so byte order is numeric order.
//!
//! Every mutating method runs on an [`Overlay`] and reaches the store
//! only if it returns `Ok`, so a refusal — or a corrupt record found
//! halfway — leaves nothing behind. The chain's own executor does the
//! same one level up, discarding an aborted transaction's writes.
//!
//! Some reads are scans and cost as much as their subject is large:
//! [`StakingRegistry::active_set`] and the totals read every validator,
//! and a slash reads every unbonding entry of the offender. None of that
//! is per-transaction: the active set is read when consensus needs it and
//! a slash follows evidence. But a slash's cost grows with the number of
//! open entries against one validator, which a delegator can raise by
//! opening entries of one unit each (bounded per staker, not in total);
//! a minimum unstake amount, or slashing entries lazily, would bound it.
//! Neither is built.
//!
//! # Unbonding stays slashable
//!
//! `docs/spec.md` requires unbonding (21 days) to exceed max evidence age
//! (14) "so a validator cannot equivocate and complete unbonding before
//! the evidence is admissible". That only works if stake in the unbonding
//! queue can still be burned. So it can: a slash is split, pro rata by
//! amount, between the validator's pool and every unbonding entry that
//! began *after* the infraction — stake that was bonded when the
//! validator misbehaved, and would otherwise have escaped by leaving.
//! Entries that began before the infraction are untouched; that stake
//! wasn't at risk.
//!
//! # What "stake at the infraction" means here
//!
//! Slashing prices an offence against the validator's stake when it
//! happened. Keeping a stake snapshot per height would be a large state
//! cost for a check that runs rarely, so it is reconstructed from what
//! exists now: the pool's stake plus the qualifying unbonding stake. That
//! is exact for everything present at the infraction and still present,
//! and wrong in exactly one direction — a deposit made *after* the
//! infraction and before the evidence arrives (at most the evidence
//! window, 14 days) is counted, and so bears part of the burn for
//! something that predates it. It is never wrong in the offender's favour.
//!
//! A pool burn is shared by every share in it, including the pool's
//! dead shares (`crate::staking::DEAD_SHARES`), so stakers together bear
//! a hair less than the ordered amount — by at most the dead shares'
//! fraction of the pool, which is negligible next to real stake. What is
//! burned is exactly what was ordered; only who bears it shifts, and
//! towards the unowned dead shares, not towards the offender.
//!
//! # Bounded
//!
//! Unbonding entries are capped per (staker, validator) pair
//! ([`MAX_UNBONDING_ENTRIES_PER_PAIR`]) and [`StakingRegistry::process`]
//! matures at most [`MAX_MATURING_PER_CALL`] per call, so no block does
//! unbounded work however many entries pile up. The number of *registered
//! validators* is not capped: entry is permissionless (`docs/spec.md`),
//! and the cost that deters spam is the minimum self-stake.
//!
//! # Deliberately not here
//!
//! - **`claim_rewards`.** In a share-price system rewards compound into
//!   the price; claiming just the gain would need each staker's cost
//!   basis, which the pool doesn't track. Deferred to the native
//!   boundary, where its shape (a partial unstake of the gain?) is a
//!   real design decision. [`StakingRegistry::credit_rewards`] is the
//!   inflow side.
//! - **A separate reward recipient**, the spec's third key role. With no
//!   validator commission there is nothing for it to receive.
//! - **Consensus-key rotation** ("rotatable, with a delay"): the key is
//!   fixed at registration.
//! - **`StakeReceipt` as an object.** Shares here are an address ledger,
//!   not transferable receipts; whether the native layer models them as
//!   Move resources is its decision.

use ruint::aliases::U256;

use chain_types::bls::BlsSignature;
use chain_types::codec::{decode_field, CodecError, Decode, Encode};
use chain_types::{Address, BlsPublicKey, DuplicateVoteEvidence};

use crate::params::GovernedParams;
use crate::slashing::{
    status_in, EvidenceRejection, JailError, SlashingTracker, UnjailError, ValidatorStatus,
};
use crate::staking::{StakingError, StakingPool};
use crate::store::{
    apply_changes, be64, load, prefix_end, read_be64, save, tag, Corrupt, Overlay, Store,
};

/// `docs/spec.md`, "Consensus": "Active validator set: 128, by stake".
pub const MAX_ACTIVE_VALIDATORS: usize = 128;

/// **A choice** (Cosmos' own): how many unbonding entries one staker can
/// have open against one validator at once.
pub const MAX_UNBONDING_ENTRIES_PER_PAIR: usize = 7;

/// **A choice.** The most entries [`StakingRegistry::process`] matures in
/// one call; the rest wait for the next.
pub const MAX_MATURING_PER_CALL: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidatorId(pub Address);

impl Encode for ValidatorId {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for ValidatorId {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (address, used) = Address::decode(input)?;
        Ok((Self(address), used))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Validator {
    /// Owns the validator's self-stake and answers for it: the account
    /// whose remaining stake decides whether the validator may be active.
    operator: Address,
    consensus_key: BlsPublicKey,
    pool: StakingPool,
}

impl Encode for Validator {
    fn encode(&self, out: &mut Vec<u8>) {
        self.operator.encode(out);
        self.consensus_key.encode(out);
        self.pool.encode(out);
    }
}

impl Decode for Validator {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (operator, offset) = Address::decode(input)?;
        let (consensus_key, offset) = decode_field::<BlsPublicKey>(input, offset)?;
        let (pool, offset) = decode_field::<StakingPool>(input, offset)?;
        Ok((
            Self {
                operator,
                consensus_key,
                pool,
            },
            offset,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnbondingEntry {
    staker: Address,
    validator: ValidatorId,
    /// What is still owed: reduced if a slash reaches this entry.
    amount: u128,
    started_at_ms: u64,
    /// Fixed when the entry was made: a later change to the unbonding
    /// period does not move it.
    matures_at_ms: u64,
}

impl Encode for UnbondingEntry {
    fn encode(&self, out: &mut Vec<u8>) {
        self.staker.encode(out);
        self.validator.encode(out);
        self.amount.encode(out);
        self.started_at_ms.encode(out);
        self.matures_at_ms.encode(out);
    }
}

impl Decode for UnbondingEntry {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (staker, offset) = Address::decode(input)?;
        let (validator, offset) = decode_field::<ValidatorId>(input, offset)?;
        let (amount, offset) = decode_field::<u128>(input, offset)?;
        let (started_at_ms, offset) = decode_field::<u64>(input, offset)?;
        let (matures_at_ms, offset) = decode_field::<u64>(input, offset)?;
        Ok((
            Self {
                staker,
                validator,
                amount,
                started_at_ms,
                matures_at_ms,
            },
            offset,
        ))
    }
}

/// Stake that finished unbonding and is now the staker's to be paid
/// back — the registry holds no coins, so crediting `staker` is the
/// caller's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Matured {
    pub staker: Address,
    pub validator: ValidatorId,
    pub amount: u128,
}

/// One member of the active set, as consensus needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveValidator {
    pub id: ValidatorId,
    pub consensus_key: BlsPublicKey,
    /// The validator's bonded stake.
    pub stake: u128,
    /// The weight consensus votes with: `stake`, scaled down if needed
    /// to fit `u64` (see [`StakingRegistry::active_set`]).
    pub voting_power: u64,
}

/// What a slash did to one validator: `ordered` is what the slashing
/// policy called for, `burned` what was actually available to burn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlashApplied {
    pub validator: ValidatorId,
    pub ordered: u128,
    pub burned: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    AlreadyRegistered,
    /// Another validator already registered this consensus key.
    ConsensusKeyInUse,
    /// The proof of possession does not verify: registering a key needs
    /// a signature by that key over itself, which defeats rogue-key
    /// attacks on the aggregate signatures.
    InvalidProofOfPossession,
    SelfStakeBelowMinimum,
    UnknownValidator,
    /// The validator was convicted of equivocation; nobody may stake
    /// with it any more (staking already there can still leave).
    ValidatorTombstoned,
    TooManyUnbondingEntries,
    UnbondingSequenceExhausted,
    Staking(StakingError),
    Evidence(EvidenceRejection),
    Jail(JailError),
    Unjail(UnjailError),
    /// The operator's remaining stake is below the minimum self-stake,
    /// so the validator may not rejoin the active set.
    SelfStakeTooLowToUnjail,
    /// A stored record no longer decodes, or the store's indexes
    /// disagree with each other. Nothing about a transaction can cause
    /// this; it means the state itself is damaged.
    CorruptState,
}

impl From<StakingError> for RegistryError {
    fn from(err: StakingError) -> Self {
        Self::Staking(err)
    }
}

impl From<Corrupt> for RegistryError {
    fn from(_: Corrupt) -> Self {
        Self::CorruptState
    }
}

/// `floor(a * b / c)` in `U256`, so the product cannot overflow. `0` if
/// `c` is zero or the result doesn't fit `u128` (neither is reachable in
/// this module: every use has `b <= c`).
fn mul_div(a: u128, b: u128, c: u128) -> u128 {
    U256::from(a)
        .saturating_mul(U256::from(b))
        .checked_div(U256::from(c))
        .and_then(|value| u128::try_from(&value).ok())
        .unwrap_or(0)
}

/// Scales `stakes` so their sum fits `u64`, preserving proportions: the
/// same right-shift for every entry, the smallest that makes the shifted
/// sum fit. Unchanged when the total already fits. Malachite's
/// `VotingPower` is a `u64`; stake is a `u128`.
fn scale_to_u64(stakes: &[u128]) -> Vec<u64> {
    // The sum is taken *after* shifting, entry by entry: shifting the
    // total instead would round each entry down separately and could
    // leave the parts summing to more than the whole. A saturated sum
    // is still over `u64::MAX`, so saturation cannot make a bad shift
    // look good. A shift of 128 empties every entry, so the search
    // always finds one.
    let fits = |shift: u32| {
        stakes.iter().fold(0u128, |sum, stake| {
            sum.saturating_add(stake.checked_shr(shift).unwrap_or(0))
        }) <= u128::from(u64::MAX)
    };
    let shift = (0u32..=128).find(|shift| fits(*shift)).unwrap_or(128);
    stakes
        .iter()
        .map(|stake| u64::try_from(stake.checked_shr(shift).unwrap_or(0)).unwrap_or(u64::MAX))
        .collect()
}

// ---- keys ------------------------------------------------------------

fn keyed(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut key = vec![tag];
    for part in parts {
        key.extend_from_slice(part);
    }
    key
}

fn validator_key(id: &ValidatorId) -> Vec<u8> {
    keyed(tag::VALIDATOR, &[id.0.as_bytes()])
}

fn shares_key(id: &ValidatorId, staker: &Address) -> Vec<u8> {
    keyed(tag::SHARES, &[id.0.as_bytes(), staker.as_bytes()])
}

fn shares_prefix(id: &ValidatorId) -> Vec<u8> {
    keyed(tag::SHARES, &[id.0.as_bytes()])
}

fn consensus_key_key(key: &BlsPublicKey) -> Vec<u8> {
    keyed(tag::CONSENSUS_KEY, &[&key.to_bytes()])
}

fn unbonding_key(seq: u64) -> Vec<u8> {
    keyed(tag::UNBONDING, &[&be64(seq)])
}

fn by_maturity_key(matures_at_ms: u64, seq: u64) -> Vec<u8> {
    keyed(
        tag::UNBONDING_BY_MATURITY,
        &[&be64(matures_at_ms), &be64(seq)],
    )
}

fn by_validator_key(id: &ValidatorId, seq: u64) -> Vec<u8> {
    keyed(tag::UNBONDING_BY_VALIDATOR, &[id.0.as_bytes(), &be64(seq)])
}

fn by_validator_prefix(id: &ValidatorId) -> Vec<u8> {
    keyed(tag::UNBONDING_BY_VALIDATOR, &[id.0.as_bytes()])
}

fn pair_count_key(staker: &Address, id: &ValidatorId) -> Vec<u8> {
    keyed(
        tag::UNBONDING_PAIR_COUNT,
        &[staker.as_bytes(), id.0.as_bytes()],
    )
}

fn next_seq_key() -> Vec<u8> {
    vec![tag::REGISTRY_META, 0]
}

/// The registry, over a [`Store`]. See the module docs for what it keeps
/// there and how operations are made atomic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StakingRegistry<S> {
    store: S,
}

impl<S: Store> StakingRegistry<S> {
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    pub const fn store(&self) -> &S {
        &self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    /// Runs `op` against an overlay of the store and applies what it
    /// wrote only if it returns `Ok`.
    fn atomic<T>(
        &mut self,
        op: impl FnOnce(&mut StakingRegistry<&mut Overlay<'_, S>>) -> Result<T, RegistryError>,
    ) -> Result<T, RegistryError> {
        let mut overlay = Overlay::new(&self.store);
        let result = op(&mut StakingRegistry::new(&mut overlay));
        if result.is_ok() {
            let changes = overlay.into_changes();
            apply_changes(&mut self.store, changes);
        }
        result
    }

    // ---- reads ---------------------------------------------------------

    fn validator(&self, id: &ValidatorId) -> Result<Option<Validator>, Corrupt> {
        load(&self.store, &validator_key(id))
    }

    fn entry(&self, seq: u64) -> Result<Option<UnbondingEntry>, Corrupt> {
        load(&self.store, &unbonding_key(seq))
    }

    /// How many validators are registered. A scan; see the module docs.
    pub fn validator_count(&self) -> usize {
        self.store.scan_prefix(&[tag::VALIDATOR], usize::MAX).len()
    }

    pub fn is_registered(&self, id: &ValidatorId) -> bool {
        self.store.get(&validator_key(id)).is_some()
    }

    pub fn operator_of(&self, id: &ValidatorId) -> Result<Option<Address>, RegistryError> {
        Ok(self.validator(id)?.map(|v| v.operator))
    }

    pub fn consensus_key_of(
        &self,
        id: &ValidatorId,
    ) -> Result<Option<BlsPublicKey>, RegistryError> {
        Ok(self.validator(id)?.map(|v| v.consensus_key))
    }

    /// The validator's pool totals.
    pub fn pool(&self, id: &ValidatorId) -> Result<Option<StakingPool>, RegistryError> {
        Ok(self.validator(id)?.map(|v| v.pool))
    }

    pub fn status(&self, id: &ValidatorId) -> Result<ValidatorStatus, RegistryError> {
        Ok(status_in(&self.store, &id.0)?)
    }

    /// What `staker`'s stake with `id` is worth now.
    pub fn stake_of(&self, id: &ValidatorId, staker: &Address) -> Result<u128, RegistryError> {
        let Some(validator) = self.validator(id)? else {
            return Ok(0);
        };
        Ok(validator.pool.redeemable_for(self.shares_of(id, staker)?))
    }

    pub fn shares_of(&self, id: &ValidatorId, staker: &Address) -> Result<u128, RegistryError> {
        Ok(load(&self.store, &shares_key(id, staker))?.unwrap_or(0))
    }

    /// Every validator, decoded, in id order.
    fn all_validators(&self) -> Result<Vec<(ValidatorId, Validator)>, Corrupt> {
        self.store
            .scan_prefix(&[tag::VALIDATOR], usize::MAX)
            .into_iter()
            .map(|(key, bytes)| {
                let id = key
                    .get(1..)
                    .and_then(|rest| chain_types::codec::decode_exact::<Address>(rest).ok())
                    .map(ValidatorId)
                    .ok_or(Corrupt)?;
                let validator = chain_types::codec::decode_exact(&bytes).map_err(|_| Corrupt)?;
                Ok((id, validator))
            })
            .collect()
    }

    /// Total stake bonded across every validator, net of dead shares.
    /// A scan; see the module docs.
    pub fn total_bonded(&self) -> Result<u128, RegistryError> {
        Ok(self.all_validators()?.iter().fold(0u128, |sum, (_, v)| {
            sum.saturating_add(v.pool.attributable_stake())
        }))
    }

    /// Everything currently in every pool, dead shares' stake included.
    pub fn total_pooled_stake(&self) -> Result<u128, RegistryError> {
        Ok(self.all_validators()?.iter().fold(0u128, |sum, (_, v)| {
            sum.saturating_add(v.pool.total_stake())
        }))
    }

    /// Everything currently on its way out through the unbonding queue.
    pub fn total_unbonding(&self) -> Result<u128, RegistryError> {
        let mut total = 0u128;
        for (_, bytes) in self.store.scan_prefix(&[tag::UNBONDING], usize::MAX) {
            let entry: UnbondingEntry =
                chain_types::codec::decode_exact(&bytes).map_err(|_| Corrupt)?;
            total = total.saturating_add(entry.amount);
        }
        Ok(total)
    }

    pub fn unbonding_entry_count(&self) -> usize {
        self.store.scan_prefix(&[tag::UNBONDING], usize::MAX).len()
    }

    /// Checks everything that should always hold, by reading all of it:
    /// every pool's price identity and that its holders' shares plus the
    /// dead shares equal its total shares (`docs/spec.md`: "a block-level
    /// invariant that halts block production if violated"), and that the
    /// unbonding queue's entries, both indexes and the per-pair counts
    /// all agree. O(state): for tests and periodic audits, not for every
    /// transaction.
    pub fn assert_invariants(&self) -> Result<(), RegistryError> {
        for (id, validator) in self.all_validators()? {
            let mut holders = 0u128;
            for (_, bytes) in self.store.scan_prefix(&shares_prefix(&id), usize::MAX) {
                let shares: u128 = chain_types::codec::decode_exact(&bytes).map_err(|_| Corrupt)?;
                holders = holders.checked_add(shares).ok_or(StakingError::Overflow)?;
            }
            validator.pool.assert_invariant(holders)?;
        }

        let entries = self.store.scan_prefix(&[tag::UNBONDING], usize::MAX).len();
        let by_maturity = self
            .store
            .scan_prefix(&[tag::UNBONDING_BY_MATURITY], usize::MAX)
            .len();
        let by_validator = self
            .store
            .scan_prefix(&[tag::UNBONDING_BY_VALIDATOR], usize::MAX)
            .len();
        let mut counted = 0usize;
        for (_, bytes) in self
            .store
            .scan_prefix(&[tag::UNBONDING_PAIR_COUNT], usize::MAX)
        {
            let count: u64 = chain_types::codec::decode_exact(&bytes).map_err(|_| Corrupt)?;
            counted = counted.saturating_add(usize::try_from(count).map_err(|_| Corrupt)?);
        }
        if entries != by_maturity || entries != by_validator || entries != counted {
            return Err(StakingError::InvariantViolated.into());
        }
        Ok(())
    }

    // ---- validators ----------------------------------------------------

    /// Registers a new validator with `self_stake` of its own staked
    /// under `operator`. The consensus key must come with a valid proof
    /// of possession and be unused; the self-stake must meet the
    /// governed minimum. Nothing changes unless all of that holds.
    pub fn register_validator(
        &mut self,
        params: &GovernedParams,
        id: ValidatorId,
        operator: Address,
        consensus_key: BlsPublicKey,
        proof_of_possession: &BlsSignature,
        self_stake: u128,
    ) -> Result<(), RegistryError> {
        self.atomic(|reg| {
            reg.do_register(
                params,
                id,
                operator,
                consensus_key,
                proof_of_possession,
                self_stake,
            )
        })
    }

    fn do_register(
        &mut self,
        params: &GovernedParams,
        id: ValidatorId,
        operator: Address,
        consensus_key: BlsPublicKey,
        proof_of_possession: &BlsSignature,
        self_stake: u128,
    ) -> Result<(), RegistryError> {
        if self.is_registered(&id) {
            return Err(RegistryError::AlreadyRegistered);
        }
        if self.store.get(&consensus_key_key(&consensus_key)).is_some() {
            return Err(RegistryError::ConsensusKeyInUse);
        }
        if self_stake < params.values().min_self_stake {
            return Err(RegistryError::SelfStakeBelowMinimum);
        }
        consensus_key
            .verify_proof_of_possession(proof_of_possession)
            .map_err(|_| RegistryError::InvalidProofOfPossession)?;

        let mut pool = StakingPool::genesis();
        let minted = pool.deposit(self_stake)?;

        save(&mut self.store, consensus_key_key(&consensus_key), &id);
        save(
            &mut self.store,
            validator_key(&id),
            &Validator {
                operator,
                consensus_key,
                pool,
            },
        );
        save(&mut self.store, shares_key(&id, &operator), &minted);
        Ok(())
    }

    /// Stakes `amount` with `id` on behalf of `staker`, returning the
    /// shares minted. Refused for a tombstoned validator.
    pub fn delegate(
        &mut self,
        id: &ValidatorId,
        staker: Address,
        amount: u128,
    ) -> Result<u128, RegistryError> {
        self.atomic(|reg| reg.do_delegate(id, staker, amount))
    }

    fn do_delegate(
        &mut self,
        id: &ValidatorId,
        staker: Address,
        amount: u128,
    ) -> Result<u128, RegistryError> {
        if self.status(id)? == ValidatorStatus::Tombstoned {
            return Err(RegistryError::ValidatorTombstoned);
        }
        let mut validator = self.validator(id)?.ok_or(RegistryError::UnknownValidator)?;
        let minted = validator.pool.deposit(amount)?;
        let held = self
            .shares_of(id, &staker)?
            .checked_add(minted)
            .ok_or(StakingError::Overflow)?;
        save(&mut self.store, shares_key(id, &staker), &held);
        save(&mut self.store, validator_key(id), &validator);
        Ok(minted)
    }

    /// Credits `amount` of newly minted rewards to `id`'s pool, raising
    /// the share price for everyone in it. Where the amount comes from
    /// (the inflation schedule) is not this module's concern.
    pub fn credit_rewards(&mut self, id: &ValidatorId, amount: u128) -> Result<(), RegistryError> {
        self.atomic(|reg| {
            let mut validator = reg.validator(id)?.ok_or(RegistryError::UnknownValidator)?;
            validator.pool.accrue_rewards(amount)?;
            save(&mut reg.store, validator_key(id), &validator);
            Ok(())
        })
    }

    // ---- unbonding -----------------------------------------------------

    /// Starts unbonding `shares` of `staker`'s stake with `id`: the
    /// shares leave the pool now, at the current price, and the stake
    /// they were worth becomes an entry that matures after the governed
    /// unbonding period. Returns that amount. Works on a tombstoned
    /// validator too — delegates may always leave.
    ///
    /// The entry's maturity is fixed here: a later change to the
    /// unbonding period does not move it.
    pub fn begin_unstake(
        &mut self,
        params: &GovernedParams,
        id: &ValidatorId,
        staker: Address,
        shares: u128,
        now_ms: u64,
    ) -> Result<u128, RegistryError> {
        self.atomic(|reg| reg.do_begin_unstake(params, id, staker, shares, now_ms))
    }

    fn do_begin_unstake(
        &mut self,
        params: &GovernedParams,
        id: &ValidatorId,
        staker: Address,
        shares: u128,
        now_ms: u64,
    ) -> Result<u128, RegistryError> {
        let mut validator = self.validator(id)?.ok_or(RegistryError::UnknownValidator)?;
        let open = self.open_entries(&staker, id)?;
        if usize::try_from(open).map_or(true, |open| open >= MAX_UNBONDING_ENTRIES_PER_PAIR) {
            return Err(RegistryError::TooManyUnbondingEntries);
        }

        if shares == 0 {
            return Err(StakingError::ZeroAmount.into());
        }
        let held = self.shares_of(id, &staker)?;
        if shares > held {
            return Err(StakingError::InsufficientShares.into());
        }
        let amount = validator.pool.withdraw(shares)?;

        let remaining = held.saturating_sub(shares);
        if remaining == 0 {
            self.store.delete(&shares_key(id, &staker));
        } else {
            save(&mut self.store, shares_key(id, &staker), &remaining);
        }
        save(&mut self.store, validator_key(id), &validator);

        // A withdrawal so small it rounds to no stake leaves nothing to
        // wait for: the shares are gone (rounding goes against the
        // staker) and there is no entry to make.
        if amount > 0 {
            let seq = load::<u64>(&self.store, &next_seq_key())?.unwrap_or(0);
            let next_seq = seq
                .checked_add(1)
                .ok_or(RegistryError::UnbondingSequenceExhausted)?;
            save(&mut self.store, next_seq_key(), &next_seq);
            self.insert_entry(
                seq,
                &UnbondingEntry {
                    staker,
                    validator: *id,
                    amount,
                    started_at_ms: now_ms,
                    matures_at_ms: now_ms.saturating_add(params.values().unbonding_period_ms),
                },
                open.saturating_add(1),
            );
        }
        Ok(amount)
    }

    fn open_entries(&self, staker: &Address, id: &ValidatorId) -> Result<u64, Corrupt> {
        Ok(load(&self.store, &pair_count_key(staker, id))?.unwrap_or(0))
    }

    fn set_open_entries(&mut self, staker: &Address, id: &ValidatorId, count: u64) {
        if count == 0 {
            self.store.delete(&pair_count_key(staker, id));
        } else {
            save(&mut self.store, pair_count_key(staker, id), &count);
        }
    }

    /// Writes an entry and both its indexes, and sets its pair's count.
    fn insert_entry(&mut self, seq: u64, entry: &UnbondingEntry, open_after: u64) {
        save(&mut self.store, unbonding_key(seq), entry);
        self.store
            .put(by_maturity_key(entry.matures_at_ms, seq), Vec::new());
        self.store
            .put(by_validator_key(&entry.validator, seq), Vec::new());
        self.set_open_entries(&entry.staker, &entry.validator, open_after);
    }

    /// Removes an entry and both its indexes, and frees its pair's slot.
    fn remove_entry(&mut self, seq: u64, entry: &UnbondingEntry) -> Result<(), Corrupt> {
        self.store.delete(&unbonding_key(seq));
        self.store
            .delete(&by_maturity_key(entry.matures_at_ms, seq));
        self.store.delete(&by_validator_key(&entry.validator, seq));
        let open = self.open_entries(&entry.staker, &entry.validator)?;
        self.set_open_entries(&entry.staker, &entry.validator, open.saturating_sub(1));
        Ok(())
    }

    /// Matures every unbonding entry due by `now_ms`, oldest first, up
    /// to [`MAX_MATURING_PER_CALL`]; anything beyond that waits for the
    /// next call. Returns what to pay out.
    pub fn process(&mut self, now_ms: u64) -> Result<Vec<Matured>, RegistryError> {
        self.atomic(|reg| reg.do_process(now_ms))
    }

    fn do_process(&mut self, now_ms: u64) -> Result<Vec<Matured>, RegistryError> {
        let start = vec![tag::UNBONDING_BY_MATURITY];
        // Everything with a maturity up to and including `now_ms`.
        let end = prefix_end(&keyed(tag::UNBONDING_BY_MATURITY, &[&be64(now_ms)]));
        let due = self
            .store
            .range(&start, end.as_deref(), MAX_MATURING_PER_CALL);

        let mut matured = Vec::with_capacity(due.len());
        for (index_key, _) in due {
            // `UNBONDING_BY_MATURITY ‖ matures (8) ‖ seq (8)`
            let seq = index_key
                .get(9..)
                .and_then(read_be64)
                .ok_or(RegistryError::CorruptState)?;
            let entry = self.entry(seq)?.ok_or(RegistryError::CorruptState)?;
            self.remove_entry(seq, &entry)?;
            matured.push(Matured {
                staker: entry.staker,
                validator: entry.validator,
                amount: entry.amount,
            });
        }
        Ok(matured)
    }

    // ---- the active set ------------------------------------------------

    /// The validators consensus runs on: registered, not jailed or
    /// tombstoned, whose operator still holds at least the governed
    /// minimum self-stake, with some bonded stake — the top
    /// [`MAX_ACTIVE_VALIDATORS`] by stake, ties broken by id, so the
    /// order is fully determined.
    ///
    /// Voting power is the stake itself when the total fits `u64`, and
    /// otherwise every stake shifted right by the same amount, the
    /// smallest that makes the total fit. A validator whose stake shifts
    /// to zero has no vote and is left out.
    ///
    /// Reads every validator; see the module docs.
    pub fn active_set(
        &self,
        params: &GovernedParams,
    ) -> Result<Vec<ActiveValidator>, RegistryError> {
        let minimum = params.values().min_self_stake;
        let mut candidates: Vec<(ValidatorId, BlsPublicKey, u128)> = Vec::new();
        for (id, validator) in self.all_validators()? {
            if self.status(&id)? != ValidatorStatus::Active {
                continue;
            }
            let operator_stake = validator
                .pool
                .redeemable_for(self.shares_of(&id, &validator.operator)?);
            let stake = validator.pool.attributable_stake();
            if operator_stake >= minimum && stake > 0 {
                candidates.push((id, validator.consensus_key, stake));
            }
        }

        candidates.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        candidates.truncate(MAX_ACTIVE_VALIDATORS);

        let stakes: Vec<u128> = candidates.iter().map(|(_, _, stake)| *stake).collect();
        Ok(candidates
            .into_iter()
            .zip(scale_to_u64(&stakes))
            .filter(|(_, power)| *power > 0)
            .map(
                |((id, consensus_key, stake), voting_power)| ActiveValidator {
                    id,
                    consensus_key,
                    stake,
                    voting_power,
                },
            )
            .collect())
    }

    // ---- slashing ------------------------------------------------------

    /// Admits `evidence` of equivocation and burns what the slashing
    /// policy orders, from pools and unbonding entries alike. Returns one
    /// [`SlashApplied`] per validator burned — the offender, and anyone
    /// earlier in the correlation window whose penalty this raised.
    ///
    /// `infraction_time_ms` must be the timestamp of the block at
    /// `evidence.height()`, taken from chain state — never from the
    /// evidence or whoever submitted it. The validator's key comes from
    /// the registry, so a submitter cannot choose which key to be judged
    /// against. Nothing changes unless the evidence is admitted.
    pub fn submit_evidence(
        &mut self,
        evidence: &DuplicateVoteEvidence,
        infraction_time_ms: u64,
        now_ms: u64,
    ) -> Result<Vec<SlashApplied>, RegistryError> {
        self.atomic(|reg| reg.do_submit_evidence(evidence, infraction_time_ms, now_ms))
    }

    fn do_submit_evidence(
        &mut self,
        evidence: &DuplicateVoteEvidence,
        infraction_time_ms: u64,
        now_ms: u64,
    ) -> Result<Vec<SlashApplied>, RegistryError> {
        let id = ValidatorId(evidence.validator());
        let validator = self
            .validator(&id)?
            .ok_or(RegistryError::UnknownValidator)?;

        // The offender's stake back then: what is in the pool plus what
        // began unbonding since — see the module docs for the caveat.
        let (_, unbonding_at_risk) = self.unbonding_at_risk(&id, infraction_time_ms)?;
        let stake = validator
            .pool
            .attributable_stake()
            .saturating_add(unbonding_at_risk);
        let total = self.total_bonded()?.saturating_add(unbonding_at_risk);

        let orders = SlashingTracker::new(&mut self.store)
            .submit_evidence(
                evidence,
                &validator.consensus_key,
                infraction_time_ms,
                stake,
                total,
                now_ms,
            )
            .map_err(RegistryError::Evidence)?;

        let mut applied = Vec::with_capacity(orders.len());
        for order in orders {
            let target = ValidatorId(order.validator);
            // Each order is priced against *that* validator's own
            // infraction, which for a top-up is not this evidence's.
            let when = SlashingTracker::new(&mut self.store)
                .infraction_time_ms(&order.validator)?
                .unwrap_or(infraction_time_ms);
            let burned = self.burn(target, when, order.burn)?;
            applied.push(SlashApplied {
                validator: target,
                ordered: order.burn,
                burned,
            });
        }
        Ok(applied)
    }

    /// The unbonding entries of `id` that began at or after
    /// `infraction_ms` — the ones whose stake was bonded at the
    /// infraction — in queue order (by maturity, then sequence), with
    /// their total.
    fn unbonding_at_risk(
        &self,
        id: &ValidatorId,
        infraction_ms: u64,
    ) -> Result<(Vec<(u64, UnbondingEntry)>, u128), Corrupt> {
        let mut entries = Vec::new();
        for (index_key, _) in self.store.scan_prefix(&by_validator_prefix(id), usize::MAX) {
            // `UNBONDING_BY_VALIDATOR ‖ id (32) ‖ seq (8)`
            let seq = index_key.get(33..).and_then(read_be64).ok_or(Corrupt)?;
            let entry = self.entry(seq)?.ok_or(Corrupt)?;
            if entry.started_at_ms >= infraction_ms {
                entries.push((seq, entry));
            }
        }
        entries.sort_by_key(|(seq, entry)| (entry.matures_at_ms, *seq));
        let total = entries
            .iter()
            .fold(0u128, |sum, (_, entry)| sum.saturating_add(entry.amount));
        Ok((entries, total))
    }

    /// Burns up to `amount` from `id`, split pro rata between its pool
    /// and its at-risk unbonding entries, and returns what was burned.
    fn burn(
        &mut self,
        id: ValidatorId,
        infraction_ms: u64,
        amount: u128,
    ) -> Result<u128, RegistryError> {
        let (entries, unbonding_total) = self.unbonding_at_risk(&id, infraction_ms)?;
        let Some(mut validator) = self.validator(&id)? else {
            return Ok(0);
        };

        let pooled = validator.pool.total_stake();
        let from_unbonding = mul_div(
            amount,
            unbonding_total,
            pooled.saturating_add(unbonding_total),
        );
        let pool_target = amount.saturating_sub(from_unbonding);
        let pool_burned = validator.pool.slash(pool_target);
        save(&mut self.store, validator_key(&id), &validator);

        // A pool that can't cover its share (it never gives up its last
        // unit) passes the shortfall to the unbonding entries.
        let unbonding_target = from_unbonding
            .saturating_add(pool_target.saturating_sub(pool_burned))
            .min(unbonding_total);
        let unbonding_burned =
            self.burn_from_entries(entries, unbonding_total, unbonding_target)?;

        Ok(pool_burned.saturating_add(unbonding_burned))
    }

    /// Takes `target` (at most `total`, the entries' combined amount) out
    /// of `entries`: each in proportion to its size, rounded down, then
    /// any remainder a unit at a time in the order given, so the split is
    /// fully determined. Entries emptied are removed.
    fn burn_from_entries(
        &mut self,
        mut entries: Vec<(u64, UnbondingEntry)>,
        total: u128,
        target: u128,
    ) -> Result<u128, RegistryError> {
        let mut burned = 0u128;
        for (_, entry) in &mut entries {
            let share = mul_div(target, entry.amount, total).min(entry.amount);
            entry.amount = entry.amount.saturating_sub(share);
            burned = burned.saturating_add(share);
        }
        let mut leftover = target.saturating_sub(burned);
        for (_, entry) in &mut entries {
            if leftover == 0 {
                break;
            }
            let take = leftover.min(entry.amount);
            entry.amount = entry.amount.saturating_sub(take);
            burned = burned.saturating_add(take);
            leftover = leftover.saturating_sub(take);
        }
        for (seq, entry) in &entries {
            if entry.amount == 0 {
                self.remove_entry(*seq, entry)?;
            } else {
                save(&mut self.store, unbonding_key(*seq), entry);
            }
        }
        Ok(burned)
    }

    // ---- jailing -------------------------------------------------------

    /// Jails `id` for downtime: out of the active set, nothing burned.
    /// See `crate::slashing` for the duration and what is not built.
    pub fn jail_for_downtime(
        &mut self,
        id: &ValidatorId,
        now_ms: u64,
    ) -> Result<(), RegistryError> {
        self.atomic(|reg| {
            if !reg.is_registered(id) {
                return Err(RegistryError::UnknownValidator);
            }
            SlashingTracker::new(&mut reg.store)
                .jail_for_downtime(id.0, now_ms)
                .map_err(RegistryError::Jail)
        })
    }

    /// Returns a jailed validator to the active set, once its jail has
    /// run and its operator's self-stake is back at the governed minimum.
    pub fn unjail(
        &mut self,
        params: &GovernedParams,
        id: &ValidatorId,
        now_ms: u64,
    ) -> Result<(), RegistryError> {
        self.atomic(|reg| {
            let validator = reg.validator(id)?.ok_or(RegistryError::UnknownValidator)?;
            let operator_stake = validator
                .pool
                .redeemable_for(reg.shares_of(id, &validator.operator)?);
            if operator_stake < params.values().min_self_stake {
                return Err(RegistryError::SelfStakeTooLowToUnjail);
            }
            SlashingTracker::new(&mut reg.store)
                .unjail(&id.0, now_ms)
                .map_err(RegistryError::Unjail)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::params::{ParamValues, DAY_MS, MIN_UNBONDING_PERIOD_MS};
    use crate::slashing::DOWNTIME_JAIL_MS;
    use crate::store::MemStore;
    use blst::min_pk::SecretKey;
    use chain_types::bls::{DST_PROOF_OF_POSSESSION, DST_VOTE};
    use chain_types::{BlockHeight, Hash, Round, Vote, VoteKind};
    use proptest::prelude::*;

    type Reg = StakingRegistry<MemStore>;

    fn new_registry() -> Reg {
        StakingRegistry::new(MemStore::new())
    }

    const T0: u64 = 200 * DAY_MS;
    const MIN_SELF_STAKE: u128 = 1_000;

    fn params_with(unbonding_period_ms: u64) -> GovernedParams {
        GovernedParams::new(ParamValues {
            max_block_gas: 60_000_000,
            base_fee_change_denominator: 8,
            min_self_stake: MIN_SELF_STAKE,
            inflation_bps: 400,
            unbonding_period_ms,
            quorum_bps: 3_340,
            veto_threshold_bps: 3_340,
        })
        .unwrap()
    }

    fn params() -> GovernedParams {
        params_with(MIN_UNBONDING_PERIOD_MS)
    }

    fn id_of(seed: u8) -> ValidatorId {
        ValidatorId(Address::from_bytes([seed; 32]))
    }

    fn operator_of(seed: u8) -> Address {
        Address::from_bytes([seed.wrapping_add(128); 32])
    }

    fn staker(n: u8) -> Address {
        Address::from_bytes([n.wrapping_add(64); 32])
    }

    fn secret(seed: u8) -> SecretKey {
        SecretKey::key_gen(&[seed; 32], &[]).unwrap()
    }

    fn public(sk: &SecretKey) -> BlsPublicKey {
        BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap()
    }

    fn proof_of_possession(sk: &SecretKey) -> BlsSignature {
        let pk = public(sk);
        BlsSignature::from_bytes(
            sk.sign(&pk.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
                .to_bytes(),
        )
        .unwrap()
    }

    /// Registers validator `seed` with `self_stake`.
    fn register(reg: &mut Reg, seed: u8, self_stake: u128) {
        let sk = secret(seed);
        reg.register_validator(
            &params(),
            id_of(seed),
            operator_of(seed),
            public(&sk),
            &proof_of_possession(&sk),
            self_stake,
        )
        .unwrap();
    }

    /// Real, verifiable equivocation by validator `seed`.
    fn offence(seed: u8) -> DuplicateVoteEvidence {
        let sk = secret(seed);
        let vote = |value: u8| Vote {
            height: BlockHeight(10),
            round: Round(0),
            value: Some(Hash::from_bytes([value; 32])),
            kind: VoteKind::Prevote,
            validator: id_of(seed).0,
        };
        let sign = |v: &Vote| {
            BlsSignature::from_bytes(sk.sign(&v.signing_bytes(), DST_VOTE, &[]).to_bytes()).unwrap()
        };
        let (a, b) = (vote(1), vote(2));
        DuplicateVoteEvidence {
            signature_a: sign(&a),
            signature_b: sign(&b),
            vote_a: a,
            vote_b: b,
        }
    }

    // ---- registering ---------------------------------------------------

    #[test]
    fn a_registered_validator_holds_its_self_stake_under_its_operator() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);

        assert!(reg.is_registered(&id_of(1)));
        assert_eq!(reg.operator_of(&id_of(1)).unwrap(), Some(operator_of(1)));
        assert_eq!(
            reg.consensus_key_of(&id_of(1)).unwrap(),
            Some(public(&secret(1)))
        );
        assert_eq!(reg.stake_of(&id_of(1), &operator_of(1)).unwrap(), 5_000);
        assert_eq!(reg.total_bonded().unwrap(), 5_000);
        reg.assert_invariants().unwrap();
    }

    #[test]
    fn a_proof_of_possession_from_a_different_key_is_refused() {
        let mut reg = new_registry();
        let result = reg.register_validator(
            &params(),
            id_of(1),
            operator_of(1),
            public(&secret(1)),
            &proof_of_possession(&secret(2)),
            5_000,
        );
        assert_eq!(result, Err(RegistryError::InvalidProofOfPossession));
        assert_eq!(reg, new_registry(), "a refusal must leave no trace");
    }

    #[test]
    fn a_consensus_key_can_only_be_registered_once() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        let sk = secret(1);
        let result = reg.register_validator(
            &params(),
            id_of(2),
            operator_of(2),
            public(&sk),
            &proof_of_possession(&sk),
            5_000,
        );
        assert_eq!(result, Err(RegistryError::ConsensusKeyInUse));
        assert!(!reg.is_registered(&id_of(2)));
    }

    #[test]
    fn a_validator_id_can_only_be_registered_once() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        let sk = secret(9);
        let result = reg.register_validator(
            &params(),
            id_of(1),
            operator_of(9),
            public(&sk),
            &proof_of_possession(&sk),
            5_000,
        );
        assert_eq!(result, Err(RegistryError::AlreadyRegistered));
    }

    #[test]
    fn the_governed_minimum_self_stake_is_enforced() {
        let mut reg = new_registry();
        let sk = secret(1);
        let register_with = |reg: &mut Reg, stake| {
            reg.register_validator(
                &params(),
                id_of(1),
                operator_of(1),
                public(&sk),
                &proof_of_possession(&sk),
                stake,
            )
        };
        assert_eq!(
            register_with(&mut reg, MIN_SELF_STAKE - 1),
            Err(RegistryError::SelfStakeBelowMinimum)
        );
        assert_eq!(register_with(&mut reg, MIN_SELF_STAKE), Ok(()));
    }

    // ---- delegating and unbonding --------------------------------------

    #[test]
    fn delegating_mints_shares_and_adds_bonded_stake() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        let shares = reg.delegate(&id_of(1), staker(1), 2_000).unwrap();
        assert_eq!(shares, 2_000);
        assert_eq!(reg.stake_of(&id_of(1), &staker(1)).unwrap(), 2_000);
        assert_eq!(reg.total_bonded().unwrap(), 7_000);
        assert_eq!(
            reg.delegate(&id_of(9), staker(1), 1),
            Err(RegistryError::UnknownValidator)
        );
    }

    #[test]
    fn unstaking_takes_the_stake_out_of_the_pool_at_once_and_pays_after_the_period() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 3_000).unwrap();

        let amount = reg
            .begin_unstake(&params(), &id_of(1), staker(1), 3_000, T0)
            .unwrap();
        assert_eq!(amount, 3_000);
        assert_eq!(reg.total_bonded().unwrap(), 5_000, "no longer bonded");
        assert_eq!(reg.total_unbonding().unwrap(), 3_000);

        let matures = T0 + MIN_UNBONDING_PERIOD_MS;
        assert!(
            reg.process(matures - 1).unwrap().is_empty(),
            "not a moment early"
        );
        assert_eq!(
            reg.process(matures).unwrap(),
            vec![Matured {
                staker: staker(1),
                validator: id_of(1),
                amount: 3_000
            }]
        );
        assert_eq!(reg.total_unbonding().unwrap(), 0);
        assert!(
            reg.process(matures + DAY_MS).unwrap().is_empty(),
            "paid out once"
        );
        reg.assert_invariants().unwrap();
    }

    #[test]
    fn a_later_change_to_the_unbonding_period_does_not_move_an_open_entry() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 3_000).unwrap();
        reg.begin_unstake(&params(), &id_of(1), staker(1), 3_000, T0)
            .unwrap();

        // Governance stretches the period afterwards; this entry keeps
        // the maturity it was given.
        let _longer = params_with(60 * DAY_MS);
        assert_eq!(reg.process(T0 + MIN_UNBONDING_PERIOD_MS).unwrap().len(), 1);
    }

    #[test]
    fn unstaking_more_than_owned_or_nothing_is_refused_without_effect() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 1_000).unwrap();
        let before = reg.clone();

        assert_eq!(
            reg.begin_unstake(&params(), &id_of(1), staker(1), 1_001, T0),
            Err(RegistryError::Staking(StakingError::InsufficientShares))
        );
        assert_eq!(
            reg.begin_unstake(&params(), &id_of(1), staker(1), 0, T0),
            Err(RegistryError::Staking(StakingError::ZeroAmount))
        );
        assert_eq!(
            reg.begin_unstake(&params(), &id_of(9), staker(1), 1, T0),
            Err(RegistryError::UnknownValidator)
        );
        assert_eq!(reg, before);
    }

    #[test]
    fn open_unbonding_entries_are_capped_per_staker_and_validator() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        register(&mut reg, 2, 5_000);
        reg.delegate(&id_of(1), staker(1), 100).unwrap();
        reg.delegate(&id_of(2), staker(1), 100).unwrap();

        for _ in 0..MAX_UNBONDING_ENTRIES_PER_PAIR {
            reg.begin_unstake(&params(), &id_of(1), staker(1), 1, T0)
                .unwrap();
        }
        assert_eq!(
            reg.begin_unstake(&params(), &id_of(1), staker(1), 1, T0),
            Err(RegistryError::TooManyUnbondingEntries)
        );
        // A different validator, or a different staker, has its own allowance.
        assert!(reg
            .begin_unstake(&params(), &id_of(2), staker(1), 1, T0)
            .is_ok());

        // Maturing one frees a slot.
        reg.process(T0 + MIN_UNBONDING_PERIOD_MS).unwrap();
        assert!(reg
            .begin_unstake(
                &params(),
                &id_of(1),
                staker(1),
                1,
                T0 + MIN_UNBONDING_PERIOD_MS
            )
            .is_ok());
        reg.assert_invariants().unwrap();
    }

    #[test]
    fn maturing_is_bounded_per_call_and_the_rest_wait() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        // 40 stakers x 7 entries = 280 entries, more than one call's worth.
        for n in 0..40u8 {
            reg.delegate(&id_of(1), staker(n), 100).unwrap();
            for _ in 0..MAX_UNBONDING_ENTRIES_PER_PAIR {
                reg.begin_unstake(&params(), &id_of(1), staker(n), 1, T0)
                    .unwrap();
            }
        }
        assert_eq!(reg.unbonding_entry_count(), 280);

        let due = T0 + MIN_UNBONDING_PERIOD_MS;
        assert_eq!(reg.process(due).unwrap().len(), MAX_MATURING_PER_CALL);
        assert_eq!(reg.process(due).unwrap().len(), 280 - MAX_MATURING_PER_CALL);
        assert_eq!(reg.unbonding_entry_count(), 0);
        reg.assert_invariants().unwrap();
    }

    #[test]
    fn a_withdrawal_worth_no_stake_burns_the_shares_and_makes_no_entry() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        register(&mut reg, 2, 5_000);
        reg.delegate(&id_of(1), staker(1), 100).unwrap();
        // Half of all stake equivocating: the penalty is 100%, which
        // leaves each share worth a fraction of a unit.
        reg.submit_evidence(&offence(1), T0, T0).unwrap();
        assert!(reg.stake_of(&id_of(1), &staker(1)).unwrap() < 100);

        let amount = reg
            .begin_unstake(&params(), &id_of(1), staker(1), 1, T0)
            .unwrap();
        assert_eq!(amount, 0);
        assert_eq!(reg.unbonding_entry_count(), 0, "no entry for nothing");
        assert_eq!(
            reg.shares_of(&id_of(1), &staker(1)).unwrap(),
            99,
            "the share is gone"
        );
        reg.assert_invariants().unwrap();
    }

    // ---- the active set ------------------------------------------------

    fn ids(set: &[ActiveValidator]) -> Vec<ValidatorId> {
        set.iter().map(|v| v.id).collect()
    }

    #[test]
    fn the_active_set_is_ordered_by_stake_then_id() {
        let mut reg = new_registry();
        register(&mut reg, 3, 2_000);
        register(&mut reg, 1, 9_000);
        register(&mut reg, 2, 2_000); // ties with 3
        assert_eq!(
            ids(&reg.active_set(&params()).unwrap()),
            vec![id_of(1), id_of(2), id_of(3)]
        );
    }

    #[test]
    fn a_delegation_can_change_the_order() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        register(&mut reg, 2, 4_000);
        reg.delegate(&id_of(2), staker(1), 2_000).unwrap();
        assert_eq!(
            ids(&reg.active_set(&params()).unwrap()),
            vec![id_of(2), id_of(1)]
        );
    }

    #[test]
    fn jailed_and_tombstoned_validators_are_not_active() {
        let mut reg = new_registry();
        for seed in 1..=3 {
            register(&mut reg, seed, 5_000);
        }
        reg.jail_for_downtime(&id_of(2), T0).unwrap();
        reg.submit_evidence(&offence(3), T0, T0).unwrap();

        assert_eq!(ids(&reg.active_set(&params()).unwrap()), vec![id_of(1)]);
    }

    #[test]
    fn a_validator_whose_operator_falls_below_the_minimum_self_stake_is_inactive() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        register(&mut reg, 2, 5_000);
        // The operator withdraws until under the minimum; delegates keep
        // the validator's total large.
        reg.delegate(&id_of(2), staker(1), 50_000).unwrap();
        reg.begin_unstake(&params(), &id_of(2), operator_of(2), 4_500, T0)
            .unwrap();
        assert_eq!(reg.stake_of(&id_of(2), &operator_of(2)).unwrap(), 500);

        assert_eq!(ids(&reg.active_set(&params()).unwrap()), vec![id_of(1)]);
    }

    #[test]
    fn a_validator_with_no_bonded_stake_is_not_active() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.begin_unstake(&params(), &id_of(1), operator_of(1), 5_000, T0)
            .unwrap();
        assert!(reg.active_set(&params()).unwrap().is_empty());
    }

    #[test]
    fn the_active_set_is_capped_at_128_by_stake() {
        let mut reg = new_registry();
        for seed in 0..130u8 {
            register(&mut reg, seed, 1_000 + u128::from(seed));
        }
        let set = reg.active_set(&params()).unwrap();
        assert_eq!(set.len(), MAX_ACTIVE_VALIDATORS);
        // The two smallest (seeds 0 and 1) missed the cut.
        assert!(!ids(&set).contains(&id_of(0)));
        assert!(!ids(&set).contains(&id_of(1)));
        assert_eq!(set.first().unwrap().id, id_of(129));
    }

    #[test]
    fn voting_power_is_the_stake_when_it_fits_u64() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        register(&mut reg, 2, 3_000);
        let set = reg.active_set(&params()).unwrap();
        assert_eq!(
            set.iter().map(|v| v.voting_power).collect::<Vec<_>>(),
            vec![5_000, 3_000]
        );
    }

    #[test]
    fn voting_power_is_scaled_uniformly_when_stake_overflows_u64() {
        let big = u128::from(u64::MAX);
        let mut reg = new_registry();
        register(&mut reg, 1, big * 4);
        register(&mut reg, 2, big * 2);
        register(&mut reg, 3, big);

        let set = reg.active_set(&params()).unwrap();
        let powers: Vec<u64> = set.iter().map(|v| v.voting_power).collect();
        let total: u128 = powers.iter().map(|p| u128::from(*p)).sum();
        assert!(
            total <= u128::from(u64::MAX),
            "the scaled total must fit u64"
        );
        // Proportions survive: 4 : 2 : 1, to within the shifted-out bits.
        assert!(powers[0] / 2 >= powers[1] - 1 && powers[0] / 2 <= powers[1] + 1);
        assert!(powers[1] / 2 >= powers[2] - 1 && powers[1] / 2 <= powers[2] + 1);
        // And it reports real stake alongside.
        assert_eq!(set[0].stake, big * 4);
    }

    #[test]
    fn scaling_never_lets_the_total_exceed_u64_however_large_the_stakes() {
        for stakes in [
            vec![u128::MAX],
            vec![u128::MAX, u128::MAX],
            vec![u128::MAX / 3; 5],
            vec![u128::from(u64::MAX) + 1],
            vec![1, 2, 3],
            vec![],
        ] {
            let powers = scale_to_u64(&stakes);
            assert_eq!(powers.len(), stakes.len());
            let total: u128 = powers.iter().map(|p| u128::from(*p)).sum();
            assert!(total <= u128::from(u64::MAX), "{stakes:?}");
        }
    }

    // ---- slashing ------------------------------------------------------

    #[test]
    fn evidence_burns_the_pool_pro_rata_and_tombstones_the_validator() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 5_000).unwrap();
        register(&mut reg, 2, 990_000); // ~99% of stake elsewhere

        // 10_000 of ~1_000_000 bonded: 1% -> 3% scaled -> floor of 5%.
        let applied = reg.submit_evidence(&offence(1), T0, T0).unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].validator, id_of(1));
        assert_eq!(applied[0].ordered, 500, "5% of 10_000");
        assert_eq!(applied[0].burned, 500);

        // The delegate and the operator lost the same. The full 500 came
        // out of the pool, of which the dead shares bore their 1_000/11_000
        // share (45), so the two of them together bore 455 (see the module
        // docs) — a hair under 5% each.
        let (delegate, operator) = (
            reg.stake_of(&id_of(1), &staker(1)).unwrap(),
            reg.stake_of(&id_of(1), &operator_of(1)).unwrap(),
        );
        assert_eq!(delegate, operator);
        assert_eq!(delegate, 4_772);
        assert_eq!(reg.pool(&id_of(1)).unwrap().unwrap().total_stake(), 10_500);

        assert_eq!(reg.status(&id_of(1)).unwrap(), ValidatorStatus::Tombstoned);
        assert_eq!(
            reg.delegate(&id_of(1), staker(2), 100),
            Err(RegistryError::ValidatorTombstoned)
        );
        assert!(!ids(&reg.active_set(&params()).unwrap()).contains(&id_of(1)));
        reg.assert_invariants().unwrap();
    }

    #[test]
    fn stake_that_began_unbonding_after_the_infraction_is_slashed_too() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 5_000).unwrap();
        register(&mut reg, 2, 990_000);

        // The delegate leaves *after* the infraction (at T0), before the
        // evidence arrives.
        reg.begin_unstake(&params(), &id_of(1), staker(1), 5_000, T0 + DAY_MS)
            .unwrap();
        assert_eq!(reg.total_unbonding().unwrap(), 5_000);

        let applied = reg
            .submit_evidence(&offence(1), T0, T0 + 2 * DAY_MS)
            .unwrap();
        assert_eq!(applied[0].burned, applied[0].ordered);

        // Half of what was at risk sat in the pool, half in the queue: the
        // burn reaches both, and the leaver did not escape it.
        let paid = reg.process(T0 + DAY_MS + MIN_UNBONDING_PERIOD_MS).unwrap();
        assert_eq!(paid.len(), 1);
        assert!(
            paid[0].amount < 5_000,
            "the entry was slashed: {}",
            paid[0].amount
        );
        assert!(reg.stake_of(&id_of(1), &operator_of(1)).unwrap() < 5_000);
        reg.assert_invariants().unwrap();
    }

    #[test]
    fn stake_that_began_unbonding_before_the_infraction_is_not_touched() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 5_000).unwrap();
        register(&mut reg, 2, 990_000);

        // Left a day *before* the infraction: that stake wasn't at risk.
        reg.begin_unstake(&params(), &id_of(1), staker(1), 5_000, T0 - DAY_MS)
            .unwrap();
        reg.submit_evidence(&offence(1), T0, T0).unwrap();

        let paid = reg.process(T0 - DAY_MS + MIN_UNBONDING_PERIOD_MS).unwrap();
        assert_eq!(paid.len(), 1);
        assert_eq!(paid[0].amount, 5_000, "paid in full");
    }

    #[test]
    fn unbonding_that_began_at_the_infraction_instant_is_at_risk_but_a_moment_before_is_not() {
        // Stake leaving at the very timestamp of the infraction was
        // still bonded for it, so the boundary is inclusive.
        let leaver_paid = |began_at: u64| {
            let mut reg = new_registry();
            register(&mut reg, 1, 5_000);
            reg.delegate(&id_of(1), staker(1), 5_000).unwrap();
            register(&mut reg, 2, 990_000);
            reg.begin_unstake(&params(), &id_of(1), staker(1), 5_000, began_at)
                .unwrap();
            reg.submit_evidence(&offence(1), T0, T0 + DAY_MS).unwrap();
            reg.process(began_at + MIN_UNBONDING_PERIOD_MS).unwrap()[0].amount
        };
        assert!(leaver_paid(T0) < 5_000, "at the instant: slashed");
        assert_eq!(
            leaver_paid(T0 - 1),
            5_000,
            "a millisecond before: untouched"
        );
    }

    #[test]
    fn a_validator_cannot_escape_slashing_by_unstaking_everything() {
        let mut reg = new_registry();
        register(&mut reg, 1, 50_000);
        register(&mut reg, 2, 50_000);

        // The offender sees the evidence coming and pulls out all of it.
        reg.begin_unstake(&params(), &id_of(1), operator_of(1), 50_000, T0 + DAY_MS)
            .unwrap();
        assert_eq!(reg.stake_of(&id_of(1), &operator_of(1)).unwrap(), 0);

        let applied = reg
            .submit_evidence(&offence(1), T0, T0 + 2 * DAY_MS)
            .unwrap();
        // Half of all bonded stake equivocating: the full penalty, taken
        // out of the queue since the pool has nothing left to give.
        assert!(applied[0].burned > 0, "something must have been burned");
        let paid = reg.process(T0 + DAY_MS + MIN_UNBONDING_PERIOD_MS).unwrap();
        assert!(
            paid[0].amount < 50_000,
            "the operator got back less than they put in: {}",
            paid[0].amount
        );
        reg.assert_invariants().unwrap();
    }

    #[test]
    fn a_burn_the_pool_cannot_fully_cover_is_finished_from_the_queue() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 100).unwrap();
        reg.begin_unstake(&params(), &id_of(1), staker(1), 100, T0)
            .unwrap();
        // 6_000 pooled (5_000 + the dead shares' 1_000), 100 unbonding.
        // The pool never gives up its last unit, so of a 6_099 burn its
        // pro-rata 6_000 falls one short; the queue makes up the unit.
        let burned = reg.burn(id_of(1), T0, 6_099).unwrap();
        assert_eq!(
            burned, 6_099,
            "nothing is left unburned while stake remains"
        );
        assert_eq!(reg.total_unbonding().unwrap(), 0, "the entry was emptied");
        assert_eq!(reg.unbonding_entry_count(), 0, "and removed");
        assert_eq!(reg.pool(&id_of(1)).unwrap().unwrap().total_stake(), 1);
        reg.assert_invariants().unwrap();
    }

    #[test]
    fn a_burn_from_several_entries_is_exact_and_split_in_queue_order() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        for n in 0..3u8 {
            reg.delegate(&id_of(1), staker(n), 3).unwrap();
            reg.begin_unstake(&params(), &id_of(1), staker(n), 3, T0)
                .unwrap();
        }
        let (entries, total) = reg.unbonding_at_risk(&id_of(1), T0).unwrap();
        assert_eq!((entries.len(), total), (3, 9));

        // 4 of 9 over three equal entries: each rounds down to 1, and the
        // leftover unit comes off the first in the queue — sequence 0,
        // which the entries were made in.
        assert_eq!(reg.burn_from_entries(entries, 9, 4).unwrap(), 4);
        let left: Vec<u128> = (0..3u64)
            .map(|seq| reg.entry(seq).unwrap().unwrap().amount)
            .collect();
        assert_eq!(left, vec![1, 2, 2]);
        reg.assert_invariants().unwrap();
    }

    #[test]
    fn the_queue_is_ordered_by_maturity_before_sequence() {
        // The first entry was made under a longer unbonding period, so it
        // matures *after* the two made later: the queue puts it last.
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        let periods = [
            params_with(30 * DAY_MS),
            params_with(MIN_UNBONDING_PERIOD_MS),
            params_with(MIN_UNBONDING_PERIOD_MS),
        ];
        for (n, period) in periods.iter().enumerate() {
            let staker = staker(u8::try_from(n).unwrap());
            reg.delegate(&id_of(1), staker, 3).unwrap();
            reg.begin_unstake(period, &id_of(1), staker, 3, T0).unwrap();
        }
        let (entries, _) = reg.unbonding_at_risk(&id_of(1), T0).unwrap();
        let order: Vec<u64> = entries.iter().map(|(seq, _)| *seq).collect();
        assert_eq!(order, vec![1, 2, 0]);

        // So the leftover unit of a 4-of-9 burn comes off sequence 1.
        reg.burn_from_entries(entries, 9, 4).unwrap();
        let left: Vec<u128> = (0..3u64)
            .map(|seq| reg.entry(seq).unwrap().unwrap().amount)
            .collect();
        assert_eq!(left, vec![2, 1, 2]);
    }

    #[test]
    fn evidence_against_an_unknown_validator_is_refused() {
        let mut reg = new_registry();
        register(&mut reg, 2, 5_000);
        assert_eq!(
            reg.submit_evidence(&offence(1), T0, T0),
            Err(RegistryError::UnknownValidator)
        );
    }

    #[test]
    fn evidence_is_judged_against_the_registered_key_not_a_submitted_one() {
        // Validator 1's evidence, but re-signed by someone else's key:
        // it must not convict validator 1.
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        register(&mut reg, 2, 5_000);
        let mut forged = offence(2);
        forged.vote_a.validator = id_of(1).0;
        forged.vote_b.validator = id_of(1).0;

        let result = reg.submit_evidence(&forged, T0, T0);
        assert!(matches!(
            result,
            Err(RegistryError::Evidence(EvidenceRejection::Invalid(_)))
        ));
        assert_eq!(reg.status(&id_of(1)).unwrap(), ValidatorStatus::Active);
        assert_eq!(reg.stake_of(&id_of(1), &operator_of(1)).unwrap(), 5_000);
    }

    #[test]
    fn a_later_offender_tops_an_earlier_one_up_from_its_own_infraction() {
        let mut reg = new_registry();
        register(&mut reg, 1, 20_000);
        register(&mut reg, 2, 20_000);
        register(&mut reg, 3, 60_000);

        let first = reg.submit_evidence(&offence(1), T0, T0).unwrap();
        assert_eq!(first.len(), 1);
        let second = reg.submit_evidence(&offence(2), T0, T0).unwrap();
        assert_eq!(
            second.len(),
            2,
            "the second offence raised the first's penalty"
        );
        let raised = second.iter().find(|a| a.validator == id_of(1)).unwrap();
        assert!(raised.burned > 0);
        reg.assert_invariants().unwrap();
    }

    // ---- jailing -------------------------------------------------------

    #[test]
    fn jailing_removes_a_validator_and_unjailing_after_the_term_restores_it() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        register(&mut reg, 2, 5_000);
        reg.jail_for_downtime(&id_of(1), T0).unwrap();
        assert_eq!(ids(&reg.active_set(&params()).unwrap()), vec![id_of(2)]);
        assert_eq!(
            reg.stake_of(&id_of(1), &operator_of(1)).unwrap(),
            5_000,
            "nothing burned"
        );

        assert!(matches!(
            reg.unjail(&params(), &id_of(1), T0 + DOWNTIME_JAIL_MS - 1),
            Err(RegistryError::Unjail(UnjailError::StillJailed { .. }))
        ));
        reg.unjail(&params(), &id_of(1), T0 + DOWNTIME_JAIL_MS)
            .unwrap();
        assert_eq!(ids(&reg.active_set(&params()).unwrap()).len(), 2);
    }

    #[test]
    fn a_jailed_validator_cannot_rejoin_below_the_minimum_self_stake() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.jail_for_downtime(&id_of(1), T0).unwrap();
        reg.begin_unstake(&params(), &id_of(1), operator_of(1), 4_500, T0)
            .unwrap();

        assert_eq!(
            reg.unjail(&params(), &id_of(1), T0 + DOWNTIME_JAIL_MS),
            Err(RegistryError::SelfStakeTooLowToUnjail)
        );
    }

    #[test]
    fn jailing_or_unjailing_an_unknown_validator_is_refused() {
        let mut reg = new_registry();
        assert_eq!(
            reg.jail_for_downtime(&id_of(1), T0),
            Err(RegistryError::UnknownValidator)
        );
        assert_eq!(
            reg.unjail(&params(), &id_of(1), T0),
            Err(RegistryError::UnknownValidator)
        );
    }

    // ---- conservation --------------------------------------------------

    #[derive(Debug, Clone)]
    enum Op {
        Delegate {
            validator: u8,
            staker: u8,
            amount: u128,
        },
        Unstake {
            validator: u8,
            staker: u8,
            fraction: u8,
        },
        Advance {
            days: u64,
        },
        Evidence {
            validator: u8,
        },
        Rewards {
            validator: u8,
            amount: u128,
        },
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..3, 0u8..4, 1u128..20_000).prop_map(|(validator, staker, amount)| Op::Delegate {
                validator,
                staker,
                amount
            }),
            (0u8..3, 0u8..4, 1u8..=100).prop_map(|(validator, staker, fraction)| Op::Unstake {
                validator,
                staker,
                fraction
            }),
            (0u64..30).prop_map(|days| Op::Advance { days }),
            (0u8..3).prop_map(|validator| Op::Evidence { validator }),
            (0u8..3, 1u128..5_000)
                .prop_map(|(validator, amount)| Op::Rewards { validator, amount }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        /// Every unit of stake that goes in is somewhere at all times:
        /// in a pool, in the unbonding queue, paid out, or burned. No
        /// sequence of operations creates or loses any, and the pool
        /// invariants hold throughout.
        #[test]
        fn stake_is_conserved_through_any_sequence_of_operations(
            ops in proptest::collection::vec(op_strategy(), 1..40)
        ) {
            let mut reg = new_registry();
            let mut injected = 0u128;
            for seed in 1..=3u8 {
                register(&mut reg, seed, 5_000);
                injected += 5_000 + crate::staking::DEAD_SHARES;
            }
            let (mut paid, mut burned) = (0u128, 0u128);
            let mut now = T0;

            for op in ops {
                match op {
                    Op::Delegate { validator, staker: s, amount } => {
                        if reg.delegate(&id_of(validator + 1), staker(s), amount).is_ok() {
                            injected += amount;
                        }
                    }
                    Op::Unstake { validator, staker: s, fraction } => {
                        let owned = reg.shares_of(&id_of(validator + 1), &staker(s)).unwrap();
                        let shares = (owned * u128::from(fraction) / 100).max(u128::from(owned > 0));
                        if shares > 0 {
                            let _ = reg.begin_unstake(&params(), &id_of(validator + 1), staker(s), shares, now);
                        }
                    }
                    Op::Advance { days } => {
                        now += days * DAY_MS;
                        paid += reg.process(now).unwrap().iter().map(|m| m.amount).sum::<u128>();
                    }
                    Op::Evidence { validator } => {
                        if let Ok(applied) = reg.submit_evidence(&offence(validator + 1), now, now) {
                            burned += applied.iter().map(|a| a.burned).sum::<u128>();
                        }
                    }
                    Op::Rewards { validator, amount } => {
                        if reg.credit_rewards(&id_of(validator + 1), amount).is_ok() {
                            injected += amount;
                        }
                    }
                }
                reg.assert_invariants().unwrap();
                prop_assert_eq!(
                    reg.total_pooled_stake().unwrap() + reg.total_unbonding().unwrap() + paid + burned,
                    injected
                );
            }
        }
    }

    // ---- storage -------------------------------------------------------

    /// How many keys differ between two stores: written, changed or
    /// removed.
    fn keys_changed(before: &MemStore, after: &MemStore) -> usize {
        let keys: std::collections::BTreeSet<&Vec<u8>> =
            before.iter().chain(after.iter()).map(|(k, _)| k).collect();
        keys.into_iter()
            .filter(|key| before.get(key) != after.get(key))
            .count()
    }

    fn key_count(store: &MemStore, tag: u8) -> usize {
        store.scan_prefix(&[tag], usize::MAX).len()
    }

    #[test]
    fn an_operation_touches_a_handful_of_keys_however_many_validators_and_stakers_exist() {
        // The point of one entry per entity: cost does not grow with the
        // size of the state. Measured against a registry with many of both.
        let mut reg = new_registry();
        for seed in 0..40u8 {
            register(&mut reg, seed, 5_000);
            for n in 0..10u8 {
                reg.delegate(&id_of(seed), staker(n), 100).unwrap();
            }
        }

        let before = reg.store().clone();
        reg.delegate(&id_of(7), staker(200), 500).unwrap();
        assert_eq!(
            keys_changed(&before, reg.store()),
            2,
            "a delegation writes the staker's shares and the pool's totals"
        );

        let before = reg.store().clone();
        reg.begin_unstake(&params(), &id_of(7), staker(3), 50, T0)
            .unwrap();
        // shares, pool totals, the entry, its two indexes, the pair
        // count, and the sequence counter.
        assert_eq!(keys_changed(&before, reg.store()), 7);

        let before = reg.store().clone();
        reg.credit_rewards(&id_of(7), 1_000).unwrap();
        assert_eq!(
            keys_changed(&before, reg.store()),
            1,
            "only the pool's totals"
        );
    }

    #[test]
    fn a_matured_entry_and_its_indexes_leave_the_state_entirely() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 300).unwrap();
        reg.begin_unstake(&params(), &id_of(1), staker(1), 300, T0)
            .unwrap();
        for unbonding_tag in [
            tag::UNBONDING,
            tag::UNBONDING_BY_MATURITY,
            tag::UNBONDING_BY_VALIDATOR,
            tag::UNBONDING_PAIR_COUNT,
        ] {
            assert_eq!(
                key_count(reg.store(), unbonding_tag),
                1,
                "tag {unbonding_tag}"
            );
        }

        reg.process(T0 + MIN_UNBONDING_PERIOD_MS).unwrap();
        for unbonding_tag in [
            tag::UNBONDING,
            tag::UNBONDING_BY_MATURITY,
            tag::UNBONDING_BY_VALIDATOR,
            tag::UNBONDING_PAIR_COUNT,
        ] {
            assert_eq!(
                key_count(reg.store(), unbonding_tag),
                0,
                "tag {unbonding_tag}"
            );
        }
    }

    #[test]
    fn withdrawing_every_share_removes_the_stakers_balance_entry() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 300).unwrap();
        assert_eq!(
            key_count(reg.store(), tag::SHARES),
            2,
            "operator and delegate"
        );

        reg.begin_unstake(&params(), &id_of(1), staker(1), 300, T0)
            .unwrap();
        assert_eq!(
            key_count(reg.store(), tag::SHARES),
            1,
            "only the operator's"
        );
        assert_eq!(reg.shares_of(&id_of(1), &staker(1)).unwrap(), 0);
    }

    #[test]
    fn everything_is_in_the_store_so_a_new_registry_over_a_copy_of_it_is_the_same_registry() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        register(&mut reg, 2, 8_000);
        reg.delegate(&id_of(1), staker(1), 2_000).unwrap();
        reg.begin_unstake(&params(), &id_of(2), operator_of(2), 1_000, T0)
            .unwrap();
        reg.jail_for_downtime(&id_of(2), T0).unwrap();
        reg.submit_evidence(&offence(1), T0, T0).unwrap();

        let restarted = StakingRegistry::new(reg.store().clone());
        assert_eq!(restarted, reg);
        assert_eq!(
            restarted.active_set(&params()).unwrap(),
            reg.active_set(&params()).unwrap()
        );
        assert_eq!(
            restarted.total_bonded().unwrap(),
            reg.total_bonded().unwrap()
        );
        assert_eq!(
            restarted.total_unbonding().unwrap(),
            reg.total_unbonding().unwrap()
        );
        assert_eq!(
            restarted.status(&id_of(1)).unwrap(),
            ValidatorStatus::Tombstoned
        );
        // And it carries on from where the first left off.
        let mut restarted = restarted;
        assert_eq!(
            restarted
                .process(T0 + MIN_UNBONDING_PERIOD_MS)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn records_round_trip_through_their_encodings() {
        let validator = Validator {
            operator: operator_of(1),
            consensus_key: public(&secret(1)),
            pool: {
                let mut pool = StakingPool::genesis();
                pool.deposit(4_321).unwrap();
                pool
            },
        };
        let mut bytes = Vec::new();
        validator.encode(&mut bytes);
        assert_eq!(
            chain_types::codec::decode_exact::<Validator>(&bytes).unwrap(),
            validator
        );
        assert!(chain_types::codec::decode_exact::<Validator>(&bytes[1..]).is_err());

        let entry = UnbondingEntry {
            staker: staker(3),
            validator: id_of(1),
            amount: 77,
            started_at_ms: 5,
            matures_at_ms: 9,
        };
        let mut bytes = Vec::new();
        entry.encode(&mut bytes);
        assert_eq!(
            chain_types::codec::decode_exact::<UnbondingEntry>(&bytes).unwrap(),
            entry
        );
        bytes.push(0);
        assert!(chain_types::codec::decode_exact::<UnbondingEntry>(&bytes).is_err());
    }

    // ---- corruption ----------------------------------------------------

    /// A registry whose store is `reg`'s with `edit` applied to it.
    fn tampered(reg: Reg, edit: impl FnOnce(&mut MemStore)) -> Reg {
        let mut store = reg.into_store();
        edit(&mut store);
        StakingRegistry::new(store)
    }

    #[test]
    fn a_validator_record_that_does_not_decode_is_corruption_not_absence() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        let mut reg = tampered(reg, |store| {
            store.put(validator_key(&id_of(1)), vec![1, 2, 3]);
        });

        assert_eq!(reg.operator_of(&id_of(1)), Err(RegistryError::CorruptState));
        assert_eq!(
            reg.delegate(&id_of(1), staker(1), 100),
            Err(RegistryError::CorruptState),
            "not UnknownValidator: the record is there, and bad"
        );
        assert_eq!(reg.total_bonded(), Err(RegistryError::CorruptState));
        assert!(reg.active_set(&params()).is_err());
    }

    #[test]
    fn a_corrupt_record_found_halfway_leaves_nothing_changed() {
        // Two entries are due; the second is corrupted. `process` must
        // not pay out or delete the first and then fail.
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 100).unwrap();
        reg.begin_unstake(&params(), &id_of(1), staker(1), 10, T0)
            .unwrap();
        reg.begin_unstake(&params(), &id_of(1), staker(1), 10, T0)
            .unwrap();
        let mut reg = tampered(reg, |store| {
            store.put(unbonding_key(1), vec![0xFF]);
        });
        let before = reg.store().clone();

        assert_eq!(
            reg.process(T0 + MIN_UNBONDING_PERIOD_MS),
            Err(RegistryError::CorruptState)
        );
        assert_eq!(
            reg.store(),
            &before,
            "the healthy entry was not removed either"
        );
    }

    #[test]
    fn an_index_entry_without_its_entry_is_corruption() {
        let mut reg = new_registry();
        register(&mut reg, 1, 5_000);
        reg.delegate(&id_of(1), staker(1), 100).unwrap();
        reg.begin_unstake(&params(), &id_of(1), staker(1), 10, T0)
            .unwrap();
        let mut reg = tampered(reg, |store| store.delete(&unbonding_key(0)));

        assert_eq!(
            reg.process(T0 + MIN_UNBONDING_PERIOD_MS),
            Err(RegistryError::CorruptState)
        );
    }

    #[test]
    fn the_invariant_check_notices_a_ledger_or_index_that_no_longer_adds_up() {
        let build = || {
            let mut reg = new_registry();
            register(&mut reg, 1, 5_000);
            reg.delegate(&id_of(1), staker(1), 100).unwrap();
            reg.begin_unstake(&params(), &id_of(1), staker(1), 10, T0)
                .unwrap();
            reg.assert_invariants().unwrap();
            reg
        };

        // A staker's balance changed without the pool's totals following.
        let reg = tampered(build(), |store| {
            store.put(shares_key(&id_of(1), &staker(1)), {
                let mut bytes = Vec::new();
                999u128.encode(&mut bytes);
                bytes
            });
        });
        assert_eq!(
            reg.assert_invariants(),
            Err(RegistryError::Staking(StakingError::InvariantViolated))
        );

        // An unbonding entry lost one of its indexes.
        let reg = tampered(build(), |store| {
            store.delete(&by_validator_key(&id_of(1), 0));
        });
        assert_eq!(
            reg.assert_invariants(),
            Err(RegistryError::Staking(StakingError::InvariantViolated))
        );
    }
}
