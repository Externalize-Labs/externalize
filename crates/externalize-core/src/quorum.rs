//! Federated quorum-set evaluation.
//!
//! A quorum set is a threshold over validators and nested quorum sets. These
//! functions mirror the structural rules and satisfaction semantics of
//! stellar-core's `QuorumSetUtils`.

use std::collections::BTreeSet;

use stellar_xdr::{Limits, NodeId, PublicKey, ScpQuorumSet, Uint256, WriteXdr};

use crate::{Error, sha256};

/// Deepest nesting stellar-core accepts (`MAXIMUM_QUORUM_NESTING_LEVEL`).
pub const MAX_NESTING: usize = 4;

/// Raw Ed25519 key of a validator.
pub type NodeKey = [u8; 32];

/// Extracts the raw key from a `NodeId`.
pub fn node_key(node: &NodeId) -> NodeKey {
    let NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(k))) = node;
    *k
}

/// Checks the structural rules stellar-core applies before accepting a quorum set.
///
/// Every level needs `1 <= threshold <= entries`, nesting may not exceed
/// [`MAX_NESTING`], and no validator may appear twice anywhere in the tree.
pub fn validate(qset: &ScpQuorumSet) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    validate_level(qset, 0, &mut seen)
}

fn validate_level(q: &ScpQuorumSet, depth: usize, seen: &mut BTreeSet<NodeKey>) -> Result<(), Error> {
    if depth > MAX_NESTING {
        return Err(Error::InvalidQuorumSet("nesting exceeds 4 levels"));
    }
    let entries = q.validators.len().saturating_add(q.inner_sets.len());
    if q.threshold == 0 {
        return Err(Error::InvalidQuorumSet("threshold must be at least 1"));
    }
    if q.threshold as usize > entries {
        return Err(Error::InvalidQuorumSet("threshold exceeds number of entries"));
    }
    for v in q.validators.iter() {
        if !seen.insert(node_key(v)) {
            return Err(Error::InvalidQuorumSet("validator listed more than once"));
        }
    }
    for inner in q.inner_sets.iter() {
        validate_level(inner, depth.saturating_add(1), seen)?;
    }
    Ok(())
}

/// Returns true when `signers` meets the threshold at every level it needs to.
pub fn is_satisfied(qset: &ScpQuorumSet, signers: &BTreeSet<NodeKey>) -> bool {
    let direct = qset.validators.iter().filter(|v| signers.contains(&node_key(v))).count();
    let nested = qset.inner_sets.iter().filter(|q| is_satisfied(q, signers)).count();
    direct.saturating_add(nested) >= qset.threshold as usize
}

/// All validators referenced anywhere in the quorum set.
pub fn members(qset: &ScpQuorumSet) -> BTreeSet<NodeKey> {
    let mut out: BTreeSet<NodeKey> = qset.validators.iter().map(node_key).collect();
    for inner in qset.inner_sets.iter() {
        out.extend(members(inner));
    }
    out
}

/// SHA-256 of the XDR encoding, as referenced by `commitQuorumSetHash`.
pub fn hash(qset: &ScpQuorumSet) -> Result<[u8; 32], Error> {
    qset.to_xdr(Limits::none()).map(sha256).map_err(|e| Error::xdr("quorum set", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: u8) -> NodeId {
        NodeId(PublicKey::PublicKeyTypeEd25519(Uint256([b; 32])))
    }

    fn qset(threshold: u32, validators: &[u8], inner: Vec<ScpQuorumSet>) -> ScpQuorumSet {
        ScpQuorumSet {
            threshold,
            validators: validators.iter().map(|b| node(*b)).collect::<Vec<_>>().try_into().unwrap_or_default(),
            inner_sets: inner.try_into().unwrap_or_default(),
        }
    }

    fn signed(keys: &[u8]) -> BTreeSet<NodeKey> {
        keys.iter().map(|b| [*b; 32]).collect()
    }

    /// Shape of the live tier-1: orgs of three, two of three per org, `t` of the orgs.
    fn tier1(t: u32) -> ScpQuorumSet {
        qset(t, &[], vec![qset(2, &[1, 2, 3], vec![]), qset(2, &[4, 5, 6], vec![]), qset(2, &[7, 8, 9], vec![])])
    }

    #[test]
    fn nested_thresholds_are_respected() {
        let q = tier1(2);
        assert!(is_satisfied(&q, &signed(&[1, 2, 4, 5])));
        assert!(!is_satisfied(&q, &signed(&[1, 2, 4])), "second org has only one signer");
        assert!(!is_satisfied(&q, &signed(&[1, 4, 7])), "one signer per org satisfies no org");
        assert!(is_satisfied(&q, &signed(&[2, 3, 8, 9])));
    }

    #[test]
    fn mixed_validators_and_inner_sets_count_together() {
        let q = qset(2, &[10], vec![qset(1, &[11], vec![])]);
        assert!(is_satisfied(&q, &signed(&[10, 11])));
        assert!(!is_satisfied(&q, &signed(&[10])));
    }

    #[test]
    fn structural_rules() {
        assert!(validate(&tier1(3)).is_ok());
        assert_eq!(validate(&tier1(4)), Err(Error::InvalidQuorumSet("threshold exceeds number of entries")));
        assert_eq!(validate(&qset(0, &[1], vec![])), Err(Error::InvalidQuorumSet("threshold must be at least 1")));
        assert_eq!(
            validate(&qset(1, &[1], vec![qset(1, &[1], vec![])])),
            Err(Error::InvalidQuorumSet("validator listed more than once"))
        );
        let mut deep = qset(1, &[1], vec![]);
        for _ in 0..MAX_NESTING {
            deep = qset(1, &[], vec![deep]);
        }
        assert!(validate(&deep).is_ok(), "exactly MAX_NESTING levels below the root is allowed");
        assert_eq!(validate(&qset(1, &[], vec![deep])), Err(Error::InvalidQuorumSet("nesting exceeds 4 levels")));
    }

    #[test]
    fn members_flattens_the_tree() {
        assert_eq!(members(&tier1(2)).len(), 9);
    }
}
