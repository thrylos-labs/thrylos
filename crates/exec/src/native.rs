//! The native module boundary: transactions that call into staking and
//! governance.
//!
//! `docs/spec.md`, "Native module boundary": "a frozen list of entry
//! points ... the entire surface between the two trust worlds." This is
//! that surface for the accounts that can reach it today — a signed
//! transaction whose call names a reserved system package — and it is
//! deliberately the *only* place a transaction touches the modules'
//! state. The Move-callable form (`stake(Coin, ValidatorId) ->
//! StakeReceipt` from inside a contract) needs `Coin` and receipts as Move
//! resources and VM natives, which need module publishing and object
//! creation the executor does not have; the entry points below are what
//! those natives will call.
//!
//! # The calls
//!
//! Each argument of the call is one byte string, encoded as the Move type
//! it stands for would be: integers little-endian at their width, an
//! address as its 32 bytes, and a `vector<u8>` in BCS (a ULEB128 length,
//! then the bytes). The validator's identity is its operator's address —
//! one validator per operator — so no call needs to name its own.
//!
//! | package | function | arguments | effect |
//! |---|---|---|---|
//! | `staking` | `register_validator` | consensus key, proof of possession, self-stake `u128` | registers the sender as a validator |
//! | `staking` | `stake` | validator address, amount `u128` | delegates |
//! | `staking` | `unstake` | validator address, shares `u128` | begins unbonding |
//! | `staking` | `unjail` | none | the sender's validator rejoins |
//! | `staking` | `submit_evidence` | evidence, `vector<u8>` | slashes an equivocator |
//! | `governance` | `submit_proposal` | proposal, `vector<u8>` | opens a proposal |
//! | `governance` | `vote` | proposal id `u64`, choice `u8` | votes |
//!
//! `claim_rewards` is not among them. In a share-price pool rewards
//! compound into the price of every share, so a staker realises them by
//! unstaking; claiming only the gain would need each staker's cost basis,
//! which the pool does not track.
//!
//! # Coin
//!
//! The registry holds no coin; this layer moves it. A call that puts coin
//! into staking debits the sender's balance by exactly that, *after*
//! setting aside the most the transaction's fee could come to, so the fee
//! can always still be paid. Registering also costs the pool's dead shares
//! (see `chain_modules::DEAD_SHARES`), locked for good, so a validator's
//! pool is entirely funded by the coin that went in. Slashing burns
//! coin: the supply falls by exactly what was taken. Unbonding that has
//! matured is paid out by the block hooks, not by any call.
//!
//! Every failure a *transaction* can cause is an abort (the sender still
//! pays and their sequence number still advances); only damage to the
//! state itself rejects the block.
//!
//! # What is not built
//!
//! Gas: a protocol call is charged its declared `gas_limit` and is not yet
//! metered. Move bytecode uses the VM meter separately. A conservative
//! intrinsic floor and per-block call cap in the executor bound this work
//! until measured schedules replace them. Several calls here do work that grows with the
//! state (the proposal snapshot reads the whole active set; a slash reads
//! every unbonding entry of the offender), so metering them by measurement
//! — the spec's rule for every native — is required before this carries
//! real value.

use chain_engine_api::AbortReason;
use chain_modules::governance::{ProposalId, ProposalKind, VoteChoice};
use chain_modules::registry::RegistryError;
use chain_modules::store::Overlay;
use chain_modules::{Governance, GovernanceError, StakingRegistry, ValidatorId, DEAD_SHARES};
use chain_state::{Account, StateKey, StateValue};
use chain_types::bls::{BlsSignature, BLS_SIGNATURE_LEN};
use chain_types::codec::{decode_exact, Encode};
use chain_types::collections::BTreeMap;
use chain_types::{Address, BlsPublicKey, DuplicateVoteEvidence, Transaction};

use crate::accounting::read_supply;
use crate::effects::{BlockCtx, CallEffects, CallError};
use crate::hooks::infraction_time;
use crate::keys::supply_key;
use crate::module_store::{state_changes, StateView};

pub const STAKING_PACKAGE_ADDRESS: [u8; 32] = [4; 32];
pub const GOVERNANCE_PACKAGE_ADDRESS: [u8; 32] = [5; 32];
pub const STAKING_MODULE_NAME: &str = "staking";
pub const GOVERNANCE_MODULE_NAME: &str = "governance";

pub const REGISTER_VALIDATOR: &str = "register_validator";
pub const STAKE: &str = "stake";
pub const UNSTAKE: &str = "unstake";
pub const UNJAIL: &str = "unjail";
pub const SUBMIT_EVIDENCE: &str = "submit_evidence";
pub const SUBMIT_PROPOSAL: &str = "submit_proposal";
pub const VOTE: &str = "vote";

/// Conservative intrinsic gas for any protocol-native call until each call
/// has a measured schedule. Checked before the call performs any work.
pub const MIN_PROTOCOL_CALL_GAS: u64 = 1_000;
/// Independent bound on unmetered protocol-native calls in one block.
pub const MAX_PROTOCOL_CALLS_PER_BLOCK: usize = 64;

type State = BTreeMap<StateKey, StateValue>;
type Changes = Vec<(StateKey, Option<StateValue>)>;

// ---- argument decoding ---------------------------------------------------

fn arg_u128(bytes: &[u8]) -> Option<u128> {
    Some(u128::from_le_bytes(<[u8; 16]>::try_from(bytes).ok()?))
}

fn arg_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(<[u8; 8]>::try_from(bytes).ok()?))
}

fn arg_address(bytes: &[u8]) -> Option<Address> {
    Some(Address::from_bytes(<[u8; 32]>::try_from(bytes).ok()?))
}

/// A `vector<u8>` argument: a ULEB128 length and then exactly that many
/// bytes, with nothing after. The length must be minimally encoded and fit
/// a `u32`, as BCS requires.
pub(crate) fn arg_bytes(bytes: &[u8]) -> Option<&[u8]> {
    let mut length: u64 = 0;
    let mut used = 0usize;
    loop {
        let byte = *bytes.get(used)?;
        let payload = u64::from(byte & 0x7F);
        length |= payload.checked_shl(u32::try_from(used.checked_mul(7)?).ok()?)?;
        used = used.checked_add(1)?;
        if byte & 0x80 == 0 {
            // A trailing zero group is a longer spelling of a shorter number.
            if byte == 0 && used > 1 {
                return None;
            }
            break;
        }
        if used >= 5 {
            return None;
        }
    }
    if length > u64::from(u32::MAX) {
        return None;
    }
    let body = bytes.get(used..)?;
    (u64::try_from(body.len()).ok()? == length).then_some(body)
}

// ---- errors --------------------------------------------------------------

fn staking_error(err: RegistryError) -> CallError {
    match err {
        RegistryError::CorruptState => CallError::Internal,
        _ => AbortReason::StakingRefused.into(),
    }
}

fn evidence_error(err: RegistryError) -> CallError {
    match err {
        RegistryError::CorruptState
        | RegistryError::Evidence(chain_modules::EvidenceRejection::CorruptState) => {
            CallError::Internal
        }
        _ => AbortReason::EvidenceRefused.into(),
    }
}

fn governance_error(err: GovernanceError) -> CallError {
    match err {
        GovernanceError::CorruptState | GovernanceError::NotInitialised => CallError::Internal,
        _ => AbortReason::GovernanceRefused.into(),
    }
}

// ---- running a call ------------------------------------------------------

/// Runs `op` against an overlay of `state`, returning what it wrote as
/// changes to the flat state. The state itself is not touched.
fn run<T>(
    state: &State,
    op: impl FnOnce(&mut Overlay<'_, StateView<'_>>) -> Result<T, CallError>,
) -> Result<(T, Changes), CallError> {
    let view = StateView::new(state);
    let mut overlay = Overlay::new(&view);
    let out = op(&mut overlay)?;
    Ok((out, state_changes(overlay.into_changes())))
}

/// Debits the sender's balance by `amount`, out of what is left after
/// setting aside the most their fee can come to.
fn debit_sender(
    state: &State,
    tx: &Transaction,
    amount: u128,
    changes: &mut Changes,
) -> Result<(), CallError> {
    let sender = tx.sender_address();
    let account =
        chain_state::account::read_account(state, sender).map_err(|_| CallError::Internal)?;
    let fee_reserve =
        u128::from(tx.body.gas_limit.0).saturating_mul(u128::from(tx.body.max_fee_per_gas.0));
    if amount > account.balance.saturating_sub(fee_reserve) {
        return Err(AbortReason::InsufficientBalance.into());
    }
    let updated = Account {
        balance: account.balance.saturating_sub(amount),
        ..account
    };
    let mut bytes = Vec::new();
    updated.encode(&mut bytes);
    changes.push((
        chain_state::account::account_key(sender),
        Some(StateValue::new(bytes)),
    ));
    Ok(())
}

fn effects(tx: &Transaction, changes: Changes) -> CallEffects {
    CallEffects {
        changes,
        // Unmetered: see the module docs.
        gas_used: tx.body.gas_limit.0,
    }
}

/// Executes `tx`'s call if it names one of the native packages; `None` if
/// it does not, so the caller can try something else.
pub(crate) fn call(
    state: &State,
    tx: &Transaction,
    ctx: &BlockCtx,
) -> Option<Result<CallEffects, CallError>> {
    let call = &tx.body.call;
    let package = *call.module_address.as_bytes();
    let (module, function) = (call.module_name.as_slice(), call.function_name.as_slice());

    if package == STAKING_PACKAGE_ADDRESS && module == STAKING_MODULE_NAME.as_bytes() {
        let result = match function {
            f if f == REGISTER_VALIDATOR.as_bytes() => register_validator(state, tx, ctx),
            f if f == STAKE.as_bytes() => stake(state, tx, ctx),
            f if f == UNSTAKE.as_bytes() => unstake(state, tx, ctx),
            f if f == UNJAIL.as_bytes() => unjail(state, tx, ctx),
            f if f == SUBMIT_EVIDENCE.as_bytes() => submit_evidence(state, tx, ctx),
            _ => Err(AbortReason::UnknownFunction.into()),
        };
        return Some(result);
    }
    if package == GOVERNANCE_PACKAGE_ADDRESS && module == GOVERNANCE_MODULE_NAME.as_bytes() {
        let result = match function {
            f if f == SUBMIT_PROPOSAL.as_bytes() => submit_proposal(state, tx, ctx),
            f if f == VOTE.as_bytes() => vote(state, tx, ctx),
            _ => Err(AbortReason::UnknownFunction.into()),
        };
        return Some(result);
    }
    None
}

/// Whether the transaction targets a reserved protocol-native package. This
/// is intentionally package-level: an unknown function in a reserved package
/// still consumes one bounded native-call slot.
pub(crate) fn is_protocol_call(tx: &Transaction) -> bool {
    let package = *tx.body.call.module_address.as_bytes();
    package == STAKING_PACKAGE_ADDRESS || package == GOVERNANCE_PACKAGE_ADDRESS
}

// ---- staking -------------------------------------------------------------

fn register_validator(
    state: &State,
    tx: &Transaction,
    ctx: &BlockCtx,
) -> Result<CallEffects, CallError> {
    let [key_arg, pop_arg, stake_arg] = tx.body.call.arguments.as_slice() else {
        return Err(AbortReason::InvalidArguments.into());
    };
    let key_bytes = arg_bytes(key_arg).ok_or(AbortReason::InvalidArguments)?;
    let consensus_key = BlsPublicKey::from_bytes(
        <[u8; chain_types::bls::BLS_PUBLIC_KEY_LEN]>::try_from(key_bytes)
            .map_err(|_| AbortReason::InvalidArguments)?,
    )
    .map_err(|_| AbortReason::InvalidArguments)?;
    let pop_bytes = arg_bytes(pop_arg).ok_or(AbortReason::InvalidArguments)?;
    let proof = BlsSignature::from_bytes(
        <[u8; BLS_SIGNATURE_LEN]>::try_from(pop_bytes)
            .map_err(|_| AbortReason::InvalidArguments)?,
    )
    .map_err(|_| AbortReason::InvalidArguments)?;
    let self_stake = arg_u128(stake_arg).ok_or(AbortReason::InvalidArguments)?;
    // The pool is funded entirely by what goes in: the stake, plus the
    // dead shares' worth that stays locked.
    let cost = self_stake
        .checked_add(DEAD_SHARES)
        .ok_or(AbortReason::InvalidArguments)?;

    let sender = tx.sender_address();
    let ((), mut changes) = run(state, |overlay| {
        StakingRegistry::new(overlay)
            .register_validator(
                &ctx.params,
                ValidatorId(sender),
                sender,
                consensus_key,
                &proof,
                self_stake,
            )
            .map_err(staking_error)
    })?;
    debit_sender(state, tx, cost, &mut changes)?;
    Ok(effects(tx, changes))
}

fn stake(state: &State, tx: &Transaction, _ctx: &BlockCtx) -> Result<CallEffects, CallError> {
    let [validator_arg, amount_arg] = tx.body.call.arguments.as_slice() else {
        return Err(AbortReason::InvalidArguments.into());
    };
    let validator = arg_address(validator_arg).ok_or(AbortReason::InvalidArguments)?;
    let amount = arg_u128(amount_arg).ok_or(AbortReason::InvalidArguments)?;

    let sender = tx.sender_address();
    let (_shares, mut changes) = run(state, |overlay| {
        StakingRegistry::new(overlay)
            .delegate(&ValidatorId(validator), sender, amount)
            .map_err(staking_error)
    })?;
    debit_sender(state, tx, amount, &mut changes)?;
    Ok(effects(tx, changes))
}

fn unstake(state: &State, tx: &Transaction, ctx: &BlockCtx) -> Result<CallEffects, CallError> {
    let [validator_arg, shares_arg] = tx.body.call.arguments.as_slice() else {
        return Err(AbortReason::InvalidArguments.into());
    };
    let validator = arg_address(validator_arg).ok_or(AbortReason::InvalidArguments)?;
    let shares = arg_u128(shares_arg).ok_or(AbortReason::InvalidArguments)?;

    let sender = tx.sender_address();
    let (_amount, changes) = run(state, |overlay| {
        StakingRegistry::new(overlay)
            .begin_unstake(
                &ctx.params,
                &ValidatorId(validator),
                sender,
                shares,
                ctx.timestamp_ms,
            )
            .map_err(staking_error)
    })?;
    Ok(effects(tx, changes))
}

fn unjail(state: &State, tx: &Transaction, ctx: &BlockCtx) -> Result<CallEffects, CallError> {
    if !tx.body.call.arguments.is_empty() {
        return Err(AbortReason::InvalidArguments.into());
    }
    let sender = tx.sender_address();
    let ((), changes) = run(state, |overlay| {
        StakingRegistry::new(overlay)
            .unjail(&ctx.params, &ValidatorId(sender), ctx.timestamp_ms)
            .map_err(staking_error)
    })?;
    Ok(effects(tx, changes))
}

fn submit_evidence(
    state: &State,
    tx: &Transaction,
    ctx: &BlockCtx,
) -> Result<CallEffects, CallError> {
    let [evidence_arg] = tx.body.call.arguments.as_slice() else {
        return Err(AbortReason::InvalidArguments.into());
    };
    let evidence_bytes = arg_bytes(evidence_arg).ok_or(AbortReason::InvalidArguments)?;
    let evidence: DuplicateVoteEvidence =
        decode_exact(evidence_bytes).map_err(|_| AbortReason::InvalidArguments)?;

    // When the equivocation happened comes from the chain's own record of
    // block times, never from the evidence or its submitter.
    let infraction_ms =
        infraction_time(state, evidence.height().0).ok_or(AbortReason::EvidenceRefused)?;

    let (applied, mut changes) = run(state, |overlay| {
        StakingRegistry::new(overlay)
            .submit_evidence(&evidence, infraction_ms, ctx.timestamp_ms)
            .map_err(evidence_error)
    })?;

    // What was burned leaves the supply.
    let burned = applied
        .iter()
        .fold(0u128, |total, slash| total.saturating_add(slash.burned));
    let supply = read_supply(state).ok_or(CallError::Internal)?;
    let supply_after = supply.checked_sub(burned).ok_or(CallError::Internal)?;
    let mut bytes = Vec::new();
    supply_after.encode(&mut bytes);
    changes.push((supply_key(), Some(StateValue::new(bytes))));
    Ok(effects(tx, changes))
}

// ---- governance ----------------------------------------------------------

fn submit_proposal(
    state: &State,
    tx: &Transaction,
    ctx: &BlockCtx,
) -> Result<CallEffects, CallError> {
    let [kind_arg] = tx.body.call.arguments.as_slice() else {
        return Err(AbortReason::InvalidArguments.into());
    };
    let kind_bytes = arg_bytes(kind_arg).ok_or(AbortReason::InvalidArguments)?;
    let kind: ProposalKind = decode_exact(kind_bytes).map_err(|_| AbortReason::InvalidArguments)?;

    let sender = tx.sender_address();
    let ((), changes) = run(state, |overlay| {
        // Who may vote, and with how much, is fixed now: the operators of
        // the validators in the active set, each with their validator's
        // stake. Only one of them may open a proposal, which is what
        // bounds how many can be opened.
        let voters = {
            let registry = StakingRegistry::new(&mut *overlay);
            let active = registry.active_set(&ctx.params).map_err(staking_error)?;
            let mut voters = Vec::with_capacity(active.len());
            for validator in &active {
                let operator = registry
                    .operator_of(&validator.id)
                    .map_err(staking_error)?
                    .ok_or(CallError::Internal)?;
                voters.push((operator, validator.stake));
            }
            voters
        };
        if !voters.iter().any(|(operator, _)| *operator == sender) {
            return Err(AbortReason::Unauthorised.into());
        }
        Governance::new(overlay)
            .submit_with_snapshot(kind, ctx.timestamp_ms, &voters)
            .map_err(governance_error)?;
        Ok(())
    })?;
    Ok(effects(tx, changes))
}

fn vote(state: &State, tx: &Transaction, ctx: &BlockCtx) -> Result<CallEffects, CallError> {
    let [proposal_arg, choice_arg] = tx.body.call.arguments.as_slice() else {
        return Err(AbortReason::InvalidArguments.into());
    };
    let proposal = ProposalId(arg_u64(proposal_arg).ok_or(AbortReason::InvalidArguments)?);
    let choice: VoteChoice = decode_exact(choice_arg).map_err(|_| AbortReason::InvalidArguments)?;

    let sender = tx.sender_address();
    let ((), changes) = run(state, |overlay| {
        Governance::new(overlay)
            .vote_snapshotted(proposal, sender, choice, ctx.timestamp_ms)
            .map_err(governance_error)
    })?;
    Ok(effects(tx, changes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bcs_vector_argument_is_its_length_then_exactly_that_many_bytes() {
        assert_eq!(arg_bytes(&[0]), Some(&[][..]));
        assert_eq!(arg_bytes(&[3, 9, 8, 7]), Some(&[9, 8, 7][..]));
        // Too few, too many, and no length at all.
        assert_eq!(arg_bytes(&[3, 9, 8]), None);
        assert_eq!(arg_bytes(&[3, 9, 8, 7, 6]), None);
        assert_eq!(arg_bytes(&[]), None);
    }

    #[test]
    fn a_length_of_128_or_more_takes_more_than_one_byte() {
        let mut long = vec![0x80, 0x01]; // 128
        long.extend(std::iter::repeat_n(7u8, 128));
        assert_eq!(arg_bytes(&long).map(<[u8]>::len), Some(128));
    }

    #[test]
    fn a_length_spelled_longer_than_it_needs_to_be_is_refused() {
        // 3 written as 0x83 0x00: a valid varint, not a canonical BCS one.
        assert_eq!(arg_bytes(&[0x83, 0x00, 1, 2, 3]), None);
        assert_eq!(arg_bytes(&[0x80, 0x00]), None, "zero, spelled long");
    }

    #[test]
    fn a_length_that_never_ends_or_overflows_a_u32_is_refused() {
        assert_eq!(arg_bytes(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]), None);
        // 2^32: one past what BCS allows.
        assert_eq!(arg_bytes(&[0x80, 0x80, 0x80, 0x80, 0x10]), None);
        assert_eq!(arg_bytes(&[0xFF; 3]), None, "runs off the end");
    }

    #[test]
    fn integer_and_address_arguments_are_fixed_width() {
        assert_eq!(arg_u128(&7u128.to_le_bytes()), Some(7));
        assert_eq!(arg_u128(&[0; 15]), None);
        assert_eq!(arg_u128(&[0; 17]), None);
        assert_eq!(arg_u64(&9u64.to_le_bytes()), Some(9));
        assert_eq!(arg_u64(&[0; 16]), None);
        assert_eq!(arg_address(&[1; 32]), Some(Address::from_bytes([1; 32])));
        assert_eq!(arg_address(&[1; 31]), None);
    }
}
