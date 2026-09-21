//! The genesis configuration: everything that defines a chain's first
//! state — its id and start time, its governed parameters, who holds how
//! much, and which validators start it.
//!
//! [`GenesisConfig`] is *valid by construction*, the way
//! `chain_modules::GovernedParams` is: the only ways to get one are
//! [`GenesisConfig::new`] and decoding, and both check everything, so an
//! `Executor` built from one has nothing left to refuse. That includes the
//! cryptography: each validator's proof of possession is verified here, so
//! a rogue-key registration cannot start a chain any more than it can join
//! one.
//!
//! It knows nothing of files. Parsing a human-editable format is I/O and a
//! parser's worth of dependencies, neither of which belongs in a tier-A
//! crate; `chain-genesis` does that and hands over one of these.
//!
//! # Canonical form
//!
//! The genesis hash — what the first block's parent hash commits to —
//! must not depend on how a file happened to order its entries, so
//! allocations and validators are kept sorted by address, with no
//! duplicates. [`GenesisConfig::new`] sorts what it is given; decoding
//! *refuses* input that is not already sorted rather than quietly
//! reordering it, so two byte strings never decode to the same
//! configuration.
//!
//! # What is and isn't in it
//!
//! Accounts are named by Ed25519 public key, not by address. An address is
//! a hash, and coin sent to a mistyped or mis-derived one is gone; a public
//! key is validated as a curve point, and the address follows from it. (
//! Ed25519 is the only scheme accepted at launch, so nothing that could
//! hold coin is left out.)
//!
//! A validator's stake is *created* at genesis as bonded stake, on top of
//! the allocations, together with the dead shares every pool starts with
//! (`chain_modules::DEAD_SHARES`). The total supply is therefore the
//! allocations plus, for each validator, its self-stake and those dead
//! shares — [`GenesisConfig::total_supply`]. A validator operator who also
//! wants spendable coin is listed in the allocations as well.
//!
//! At least one validator is required: a chain with none cannot make its
//! first block. Beyond that nothing is asked of the validator set — a
//! single-validator devnet is a legitimate genesis — so whether a set is
//! large or spread enough to be *safe* is for whoever writes the file, and
//! for `chain-genesis check` to report.

use chain_modules::params::{GovernedParams, ParamError, ParamValues};
use chain_modules::registry::RegistryError;
use chain_modules::{DEAD_SHARES, MAX_REGISTERED_VALIDATORS};
use chain_types::bls::BlsSignature;
use chain_types::codec::{decode_field, CodecError, Decode, Encode};
use chain_types::collections::BTreeSet;
use chain_types::hash::{hash_with_domain, DomainTag};
use chain_types::{Address, BlsPublicKey, ChainId, Hash, PublicKey};

/// An amount of coin credited to an account at genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocation {
    pub owner: PublicKey,
    pub amount: u128,
}

/// A validator that exists from the first block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisValidator {
    /// The operator's account: owns the self-stake, and is the validator's
    /// identity (`chain_modules::ValidatorId`).
    pub operator: PublicKey,
    pub consensus_key: BlsPublicKey,
    /// Proves the operator holds the consensus key's secret, so it cannot
    /// have been chosen to cancel out someone else's in an aggregate.
    pub proof_of_possession: BlsSignature,
    pub self_stake: u128,
}

impl Allocation {
    fn address(&self) -> Address {
        Address::from_public_key(&self.owner)
    }
}

impl GenesisValidator {
    fn address(&self) -> Address {
        Address::from_public_key(&self.operator)
    }
}

/// Why a configuration is not a valid genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisConfigError {
    /// The parameters are outside their clamps.
    Parameters(ParamError),
    /// No validators: the chain could not produce a block.
    NoValidators,
    /// More validators than the first-testnet transport and bounded registry
    /// can carry.
    TooManyValidators,
    /// The materialised genesis state exceeds the execution protocol's
    /// entry or byte ceiling.
    StateLimitExceeded,
    /// An allocation of nothing.
    ZeroAllocation { owner: Address },
    /// The same account is allocated to twice.
    DuplicateAllocation { owner: Address },
    /// The same operator is listed twice.
    DuplicateValidator { operator: Address },
    /// Two validators share a consensus key.
    DuplicateConsensusKey { operator: Address },
    /// A self-stake under the governed minimum.
    SelfStakeBelowMinimum { operator: Address },
    /// The proof of possession does not verify against the key.
    InvalidProofOfPossession { operator: Address },
    /// The allocations and validator stakes add up to more than a `u128`.
    SupplyOverflow,
    /// The registry refused a validator when the state was built. Nothing
    /// [`GenesisConfig::new`] passed can cause this; it means the checks
    /// here and the registry's have drifted apart.
    Registry {
        operator: Address,
        error: RegistryError,
    },
}

impl core::fmt::Display for GenesisConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parameters(err) => write!(f, "parameters: {err}"),
            Self::NoValidators => f.write_str("at least one validator is required"),
            Self::TooManyValidators => write!(
                f,
                "at most {MAX_REGISTERED_VALIDATORS} validators may be present at genesis"
            ),
            Self::StateLimitExceeded => {
                f.write_str("the genesis state exceeds the protocol state-size limit")
            }
            Self::ZeroAllocation { .. } => f.write_str("an allocation of zero"),
            Self::DuplicateAllocation { .. } => f.write_str("an account is allocated to twice"),
            Self::DuplicateValidator { .. } => f.write_str("a validator operator is listed twice"),
            Self::DuplicateConsensusKey { .. } => {
                f.write_str("two validators share a consensus key")
            }
            Self::SelfStakeBelowMinimum { .. } => {
                f.write_str("a validator's self-stake is under the minimum")
            }
            Self::InvalidProofOfPossession { .. } => {
                f.write_str("a validator's proof of possession does not verify")
            }
            Self::SupplyOverflow => f.write_str("the total supply overflows a u128"),
            Self::Registry { error, .. } => {
                write!(f, "the registry refused a validator: {error:?}")
            }
        }
    }
}

impl std::error::Error for GenesisConfigError {}

/// A complete, validated, canonically ordered genesis. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisConfig {
    chain_id: ChainId,
    genesis_time_ms: u64,
    parameters: ParamValues,
    allocations: Vec<Allocation>,
    validators: Vec<GenesisValidator>,
    total_supply: u128,
}

impl GenesisConfig {
    /// Builds a configuration, sorting `allocations` and `validators` into
    /// canonical order and checking everything: the parameters against
    /// their clamps, every amount, every duplicate, every validator's
    /// stake and proof of possession, and that the supply fits.
    pub fn new(
        chain_id: ChainId,
        genesis_time_ms: u64,
        parameters: ParamValues,
        mut allocations: Vec<Allocation>,
        mut validators: Vec<GenesisValidator>,
    ) -> Result<Self, GenesisConfigError> {
        allocations.sort_by_key(Allocation::address);
        validators.sort_by_key(GenesisValidator::address);
        Self::validated(
            chain_id,
            genesis_time_ms,
            parameters,
            allocations,
            validators,
        )
    }

    /// The checks, on input already in canonical order (so a duplicate is
    /// always the next entry).
    fn validated(
        chain_id: ChainId,
        genesis_time_ms: u64,
        parameters: ParamValues,
        allocations: Vec<Allocation>,
        validators: Vec<GenesisValidator>,
    ) -> Result<Self, GenesisConfigError> {
        GovernedParams::new(parameters).map_err(GenesisConfigError::Parameters)?;
        if validators.is_empty() {
            return Err(GenesisConfigError::NoValidators);
        }
        if validators.len() > MAX_REGISTERED_VALIDATORS {
            return Err(GenesisConfigError::TooManyValidators);
        }

        let mut supply = 0u128;
        let mut previous: Option<Address> = None;
        for allocation in &allocations {
            let owner = allocation.address();
            if allocation.amount == 0 {
                return Err(GenesisConfigError::ZeroAllocation { owner });
            }
            if previous == Some(owner) {
                return Err(GenesisConfigError::DuplicateAllocation { owner });
            }
            previous = Some(owner);
            supply = supply
                .checked_add(allocation.amount)
                .ok_or(GenesisConfigError::SupplyOverflow)?;
        }

        let mut previous: Option<Address> = None;
        let mut consensus_keys = BTreeSet::new();
        for validator in &validators {
            let operator = validator.address();
            if previous == Some(operator) {
                return Err(GenesisConfigError::DuplicateValidator { operator });
            }
            previous = Some(operator);
            if !consensus_keys.insert(validator.consensus_key.to_bytes()) {
                return Err(GenesisConfigError::DuplicateConsensusKey { operator });
            }
            if validator.self_stake < parameters.min_self_stake {
                return Err(GenesisConfigError::SelfStakeBelowMinimum { operator });
            }
            validator
                .consensus_key
                .verify_proof_of_possession(&validator.proof_of_possession)
                .map_err(|_| GenesisConfigError::InvalidProofOfPossession { operator })?;
            // Created here, not allocated: the stake and the dead shares
            // the pool starts with.
            supply = supply
                .checked_add(validator.self_stake)
                .and_then(|total| total.checked_add(DEAD_SHARES))
                .ok_or(GenesisConfigError::SupplyOverflow)?;
        }

        Ok(Self {
            chain_id,
            genesis_time_ms,
            parameters,
            allocations,
            validators,
            total_supply: supply,
        })
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// The timestamp of the genesis state: the first block's must be
    /// strictly later.
    pub const fn genesis_time_ms(&self) -> u64 {
        self.genesis_time_ms
    }

    pub const fn parameters(&self) -> &ParamValues {
        &self.parameters
    }

    /// In ascending order of the owner's address.
    pub fn allocations(&self) -> &[Allocation] {
        &self.allocations
    }

    /// In ascending order of the operator's address.
    pub fn validators(&self) -> &[GenesisValidator] {
        &self.validators
    }

    /// Every unit that exists at genesis: the allocations, plus each
    /// validator's self-stake and its pool's dead shares.
    pub const fn total_supply(&self) -> u128 {
        self.total_supply
    }

    /// The hash of the canonical encoding. The chain's first block names it
    /// as its parent, so a block from a network with a different genesis is
    /// not a block on this one.
    pub fn hash(&self) -> Hash {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        hash_with_domain(DomainTag::GenesisConfigV1, &bytes)
    }
}

impl Encode for Allocation {
    fn encode(&self, out: &mut Vec<u8>) {
        self.owner.encode(out);
        self.amount.encode(out);
    }
}

impl Decode for Allocation {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (owner, offset) = PublicKey::decode(input)?;
        let (amount, offset) = decode_field::<u128>(input, offset)?;
        Ok((Self { owner, amount }, offset))
    }
}

impl Encode for GenesisValidator {
    fn encode(&self, out: &mut Vec<u8>) {
        self.operator.encode(out);
        self.consensus_key.encode(out);
        self.proof_of_possession.encode(out);
        self.self_stake.encode(out);
    }
}

impl Decode for GenesisValidator {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (operator, offset) = PublicKey::decode(input)?;
        let (consensus_key, offset) = decode_field::<BlsPublicKey>(input, offset)?;
        let (proof_of_possession, offset) = decode_field::<BlsSignature>(input, offset)?;
        let (self_stake, offset) = decode_field::<u128>(input, offset)?;
        Ok((
            Self {
                operator,
                consensus_key,
                proof_of_possession,
                self_stake,
            },
            offset,
        ))
    }
}

impl Encode for GenesisConfig {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.genesis_time_ms.encode(out);
        self.parameters.encode(out);
        self.allocations.encode(out);
        self.validators.encode(out);
    }
}

/// Whether `keys` is strictly ascending: sorted, and with no repeats.
fn strictly_ascending(keys: impl Iterator<Item = Address>) -> bool {
    let mut previous: Option<Address> = None;
    for key in keys {
        if previous.is_some_and(|earlier| earlier >= key) {
            return false;
        }
        previous = Some(key);
    }
    true
}

/// Decoding is strict twice over: the bytes must be the canonical encoding
/// (entries already sorted, none repeated — a configuration is never
/// quietly reordered), and what they describe must be a valid genesis,
/// proofs of possession included.
impl Decode for GenesisConfig {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (chain_id, offset) = ChainId::decode(input)?;
        let (genesis_time_ms, offset) = decode_field::<u64>(input, offset)?;
        let (parameters, offset) = decode_field::<ParamValues>(input, offset)?;
        let (allocations, offset) = decode_field::<Vec<Allocation>>(input, offset)?;
        let (validators, offset) = decode_field::<Vec<GenesisValidator>>(input, offset)?;
        if !strictly_ascending(allocations.iter().map(Allocation::address))
            || !strictly_ascending(validators.iter().map(GenesisValidator::address))
        {
            return Err(CodecError::InvalidValue);
        }
        let config = Self::validated(
            chain_id,
            genesis_time_ms,
            parameters,
            allocations,
            validators,
        )
        .map_err(|_| CodecError::InvalidValue)?;
        Ok((config, offset))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use blst::min_pk::SecretKey;
    use chain_modules::params::GENESIS_PARAM_VALUES;
    use chain_types::bls::DST_PROOF_OF_POSSESSION;
    use chain_types::codec::decode_exact;

    const MIN: u128 = GENESIS_PARAM_VALUES.min_self_stake;

    fn ed25519(seed: u8) -> PublicKey {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap()
    }

    fn bls(seed: u8) -> (BlsPublicKey, BlsSignature) {
        let sk = SecretKey::key_gen(&[seed; 32], &[]).unwrap();
        let key = BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap();
        let proof = BlsSignature::from_bytes(
            sk.sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
                .to_bytes(),
        )
        .unwrap();
        (key, proof)
    }

    fn validator(seed: u8, stake: u128) -> GenesisValidator {
        let (consensus_key, proof_of_possession) = bls(seed);
        GenesisValidator {
            operator: ed25519(seed),
            consensus_key,
            proof_of_possession,
            self_stake: stake,
        }
    }

    fn allocation(seed: u8, amount: u128) -> Allocation {
        Allocation {
            owner: ed25519(seed),
            amount,
        }
    }

    fn config(
        allocations: Vec<Allocation>,
        validators: Vec<GenesisValidator>,
    ) -> Result<GenesisConfig, GenesisConfigError> {
        GenesisConfig::new(
            ChainId(7),
            1_700_000_000_000,
            GENESIS_PARAM_VALUES,
            allocations,
            validators,
        )
    }

    fn valid() -> GenesisConfig {
        config(
            vec![allocation(10, 500), allocation(11, 700)],
            vec![validator(1, MIN), validator(2, 3 * MIN)],
        )
        .unwrap()
    }

    // ---- validity --------------------------------------------------------

    #[test]
    fn a_valid_configuration_reports_what_it_was_given_and_the_supply_it_creates() {
        let c = valid();
        assert_eq!(c.chain_id(), ChainId(7));
        assert_eq!(c.genesis_time_ms(), 1_700_000_000_000);
        assert_eq!(*c.parameters(), GENESIS_PARAM_VALUES);
        assert_eq!(c.allocations().len(), 2);
        assert_eq!(c.validators().len(), 2);
        // Allocations, plus each validator's stake and its pool's dead shares.
        assert_eq!(
            c.total_supply(),
            500 + 700 + MIN + DEAD_SHARES + 3 * MIN + DEAD_SHARES
        );
    }

    #[test]
    fn at_least_one_validator_is_required_but_no_allocation_is() {
        assert_eq!(
            config(vec![allocation(10, 5)], vec![]),
            Err(GenesisConfigError::NoValidators)
        );
        let bare = config(vec![], vec![validator(1, MIN)]).unwrap();
        assert_eq!(bare.total_supply(), MIN + DEAD_SHARES);
    }

    #[test]
    fn genesis_cannot_exceed_the_first_testnet_validator_cap() {
        let repeated = validator(1, MIN);
        let validators = vec![repeated; MAX_REGISTERED_VALIDATORS + 1];
        assert_eq!(
            config(vec![], validators),
            Err(GenesisConfigError::TooManyValidators)
        );
    }

    #[test]
    fn parameters_outside_their_clamps_are_refused() {
        let mut bad = GENESIS_PARAM_VALUES;
        bad.inflation_bps = 9_999;
        let result = GenesisConfig::new(ChainId(1), 0, bad, vec![], vec![validator(1, MIN)]);
        assert!(matches!(result, Err(GenesisConfigError::Parameters(_))));
    }

    #[test]
    fn a_zero_allocation_or_a_repeated_account_is_refused() {
        assert!(matches!(
            config(vec![allocation(10, 0)], vec![validator(1, MIN)]),
            Err(GenesisConfigError::ZeroAllocation { .. })
        ));
        assert!(matches!(
            config(
                vec![allocation(10, 5), allocation(10, 6)],
                vec![validator(1, MIN)]
            ),
            Err(GenesisConfigError::DuplicateAllocation { .. })
        ));
    }

    #[test]
    fn a_repeated_operator_or_consensus_key_is_refused() {
        assert!(matches!(
            config(vec![], vec![validator(1, MIN), validator(1, MIN)]),
            Err(GenesisConfigError::DuplicateValidator { .. })
        ));
        // A second operator presenting the first one's (valid) key and proof.
        let mut borrowed = validator(2, MIN);
        let first = validator(1, MIN);
        borrowed.consensus_key = first.consensus_key;
        borrowed.proof_of_possession = first.proof_of_possession;
        assert!(matches!(
            config(vec![], vec![first, borrowed]),
            Err(GenesisConfigError::DuplicateConsensusKey { .. })
        ));
    }

    #[test]
    fn the_minimum_self_stake_is_enforced_exactly() {
        assert!(matches!(
            config(vec![], vec![validator(1, MIN - 1)]),
            Err(GenesisConfigError::SelfStakeBelowMinimum { .. })
        ));
        assert!(config(vec![], vec![validator(1, MIN)]).is_ok());
    }

    #[test]
    fn a_proof_of_possession_by_another_key_is_refused() {
        let mut forged = validator(1, MIN);
        forged.proof_of_possession = bls(2).1;
        assert!(matches!(
            config(vec![], vec![forged]),
            Err(GenesisConfigError::InvalidProofOfPossession { .. })
        ));
    }

    #[test]
    fn a_supply_that_overflows_is_refused() {
        assert_eq!(
            config(vec![allocation(10, u128::MAX)], vec![validator(1, MIN)]),
            Err(GenesisConfigError::SupplyOverflow)
        );
        assert_eq!(
            config(
                vec![allocation(10, u128::MAX - 5), allocation(11, 5)],
                vec![validator(1, MIN)]
            ),
            Err(GenesisConfigError::SupplyOverflow),
            "each fits; the sum does not"
        );
    }

    // ---- canonical form --------------------------------------------------

    #[test]
    fn the_order_entries_are_given_in_does_not_matter() {
        let forward = config(
            vec![allocation(10, 5), allocation(11, 6), allocation(12, 7)],
            vec![validator(1, MIN), validator(2, MIN), validator(3, MIN)],
        )
        .unwrap();
        let shuffled = config(
            vec![allocation(12, 7), allocation(10, 5), allocation(11, 6)],
            vec![validator(3, MIN), validator(1, MIN), validator(2, MIN)],
        )
        .unwrap();
        assert_eq!(forward, shuffled);
        assert_eq!(forward.hash(), shuffled.hash());
    }

    #[test]
    fn entries_are_kept_in_ascending_address_order() {
        let c = config(
            vec![allocation(12, 7), allocation(10, 5), allocation(11, 6)],
            vec![validator(3, MIN), validator(1, MIN), validator(2, MIN)],
        )
        .unwrap();
        let owners: Vec<Address> = c
            .allocations()
            .iter()
            .map(|a| Address::from_public_key(&a.owner))
            .collect();
        assert!(owners.windows(2).all(|w| w[0] < w[1]));
        let operators: Vec<Address> = c
            .validators()
            .iter()
            .map(|v| Address::from_public_key(&v.operator))
            .collect();
        assert!(operators.windows(2).all(|w| w[0] < w[1]));
    }

    // ---- encoding --------------------------------------------------------

    fn encoded(config: &GenesisConfig) -> Vec<u8> {
        let mut bytes = Vec::new();
        config.encode(&mut bytes);
        bytes
    }

    #[test]
    fn a_configuration_round_trips_through_its_canonical_encoding() {
        let c = valid();
        let bytes = encoded(&c);
        assert_eq!(decode_exact::<GenesisConfig>(&bytes).unwrap(), c);
        // What decodes re-encodes to the very same bytes.
        assert_eq!(
            encoded(&decode_exact::<GenesisConfig>(&bytes).unwrap()),
            bytes
        );
    }

    #[test]
    fn decoding_refuses_trailing_bytes_and_every_truncation() {
        let bytes = encoded(&valid());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode_exact::<GenesisConfig>(&longer).is_err());
        for cut in 0..bytes.len() {
            assert!(
                decode_exact::<GenesisConfig>(&bytes[..cut]).is_err(),
                "a {cut}-byte prefix decoded"
            );
        }
    }

    /// The encoding of a configuration whose allocations and validators are
    /// in the *given* order, bypassing the sort that `new` applies.
    fn encoded_unsorted(
        allocations: Vec<Allocation>,
        validators: Vec<GenesisValidator>,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        ChainId(7).encode(&mut bytes);
        1_700_000_000_000u64.encode(&mut bytes);
        GENESIS_PARAM_VALUES.encode(&mut bytes);
        allocations.encode(&mut bytes);
        validators.encode(&mut bytes);
        bytes
    }

    #[test]
    fn decoding_refuses_entries_that_are_not_already_in_canonical_order() {
        let c = valid();
        let mut allocations = c.allocations().to_vec();
        let mut validators = c.validators().to_vec();
        // Sanity: the sorted form decodes.
        assert!(decode_exact::<GenesisConfig>(&encoded_unsorted(
            allocations.clone(),
            validators.clone()
        ))
        .is_ok());

        allocations.reverse();
        assert!(
            decode_exact::<GenesisConfig>(&encoded_unsorted(allocations, c.validators().to_vec()))
                .is_err(),
            "allocations out of order"
        );
        validators.reverse();
        assert!(
            decode_exact::<GenesisConfig>(&encoded_unsorted(c.allocations().to_vec(), validators))
                .is_err(),
            "validators out of order"
        );
    }

    #[test]
    fn decoding_refuses_a_repeated_entry_even_though_it_is_in_order() {
        let c = valid();
        let mut allocations = c.allocations().to_vec();
        allocations.push(allocations[1]);
        assert!(decode_exact::<GenesisConfig>(&encoded_unsorted(
            allocations,
            c.validators().to_vec()
        ))
        .is_err());
    }

    #[test]
    fn decoding_refuses_a_configuration_that_is_not_a_valid_genesis() {
        // A proof of possession damaged in the encoding.
        let c = valid();
        let mut bytes = encoded(&c);
        let proof = c.validators()[0].proof_of_possession.to_bytes();
        let at = bytes
            .windows(proof.len())
            .position(|window| window == proof)
            .unwrap();
        bytes[at + 10] ^= 1;
        assert!(decode_exact::<GenesisConfig>(&bytes).is_err());
    }

    // ---- the hash --------------------------------------------------------

    #[test]
    fn the_hash_is_stable_and_domain_separated() {
        let c = valid();
        assert_eq!(c.hash(), valid().hash());
        assert_ne!(
            c.hash(),
            hash_with_domain(DomainTag::TrieLeafV1, &encoded(&c)),
            "not the same as hashing those bytes in another domain"
        );
    }

    #[test]
    fn changing_anything_changes_the_hash() {
        let base = valid();
        let variant = |chain_id: u64,
                       time: u64,
                       params: ParamValues,
                       allocations: Vec<Allocation>,
                       validators: Vec<GenesisValidator>| {
            GenesisConfig::new(ChainId(chain_id), time, params, allocations, validators)
                .unwrap()
                .hash()
        };
        let allocations = || vec![allocation(10, 500), allocation(11, 700)];
        let validators = || vec![validator(1, MIN), validator(2, 3 * MIN)];
        let p = GENESIS_PARAM_VALUES;
        assert_eq!(
            variant(7, 1_700_000_000_000, p, allocations(), validators()),
            base.hash(),
            "the control"
        );

        let mut differing = vec![
            variant(8, 1_700_000_000_000, p, allocations(), validators()),
            variant(7, 1_700_000_000_001, p, allocations(), validators()),
            variant(
                7,
                1_700_000_000_000,
                p,
                vec![allocation(10, 501), allocation(11, 700)],
                validators(),
            ),
            variant(
                7,
                1_700_000_000_000,
                p,
                vec![allocation(10, 500), allocation(12, 700)],
                validators(),
            ),
            variant(
                7,
                1_700_000_000_000,
                p,
                vec![allocation(10, 500)],
                validators(),
            ),
            variant(
                7,
                1_700_000_000_000,
                p,
                allocations(),
                vec![validator(1, MIN), validator(2, 3 * MIN + 1)],
            ),
            variant(
                7,
                1_700_000_000_000,
                p,
                allocations(),
                vec![validator(1, MIN), validator(3, 3 * MIN)],
            ),
            variant(
                7,
                1_700_000_000_000,
                p,
                allocations(),
                vec![validator(1, MIN)],
            ),
        ];
        for tweak in [
            |p: &mut ParamValues| p.max_block_gas += 1,
            |p: &mut ParamValues| p.base_fee_change_denominator += 1,
            |p: &mut ParamValues| p.min_self_stake -= 1,
            |p: &mut ParamValues| p.inflation_bps += 1,
            |p: &mut ParamValues| p.unbonding_period_ms += 1,
            |p: &mut ParamValues| p.quorum_bps += 1,
            |p: &mut ParamValues| p.veto_threshold_bps += 1,
        ] {
            let mut params = p;
            tweak(&mut params);
            differing.push(variant(
                7,
                1_700_000_000_000,
                params,
                allocations(),
                validators(),
            ));
        }
        let distinct: std::collections::BTreeSet<Hash> = differing.iter().copied().collect();
        assert_eq!(distinct.len(), differing.len(), "no two variants collide");
        assert!(
            !distinct.contains(&base.hash()),
            "and none equals the original"
        );
    }
}
