//! Turning what Malachite detects into what this chain slashes on.
//!
//! Malachite's core consensus already notices a validator voting twice
//! for the same height, round and kind and hands the pairs back with
//! [`Effect::Finalize`](malachite_core_consensus::Effect::Finalize), as a
//! [`MisbehaviorEvidence`]. So the detection half of "evidence detection"
//! is the dependency's; what this crate owes is the translation into
//! `chain-types`' [`DuplicateVoteEvidence`], the form that can be
//! verified and slashed on without the consensus engine at all.
//!
//! The translation is deliberately not trusted in the other direction:
//! Malachite verifies signatures as votes arrive, but slashing
//! re-verifies the evidence itself (`DuplicateVoteEvidence::verify`), so a
//! bug or a malicious peer upstream of this function cannot convict
//! anyone.
//!
//! Proposal equivocation (two different proposals for one height and
//! round) is detected by Malachite too, in `MisbehaviorEvidence::
//! proposals`, and is not translated here: `docs/spec.md` names slashing
//! for double-*signing* votes, and a slashable proposal-evidence type is
//! separate, later work.

use chain_types::DuplicateVoteEvidence;
use malachite_core_consensus::MisbehaviorEvidence;

use crate::context::ThrylosContext;

/// Every pair of conflicting votes in `evidence`, as slashable
/// evidence, in a deterministic order (by validator address, then the
/// order Malachite recorded them in).
pub fn duplicate_vote_evidence(
    evidence: &MisbehaviorEvidence<ThrylosContext>,
) -> Vec<DuplicateVoteEvidence> {
    let mut out = Vec::new();
    for (_validator, pairs) in &evidence.votes {
        for (first, second) in pairs {
            out.push(DuplicateVoteEvidence {
                vote_a: first.message.to_vote(),
                signature_a: first.signature,
                vote_b: second.message.to_vote(),
                signature_b: second.signature,
            });
        }
    }
    out
}
