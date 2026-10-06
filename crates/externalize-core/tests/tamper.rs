//! Random corruption of a real mainnet bundle never yields a false proof.
//!
//! Some corruptions are harmless (one of 30 SCP signatures broken still
//! leaves a satisfied quorum), so the property is not "always rejects" but
//! "never certifies anything other than the original ledger and claims".

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, missing_docs)]

use externalize_core::xdr::{Limits, ReadXdr, WriteXdr};
use externalize_core::{Bundle, TrustSet};
use proptest::prelude::*;

const BUNDLE: &str = include_str!("fixtures/mainnet/bundle-64791359.json");

fn trust() -> TrustSet {
    TrustSet::from_toml(include_str!("../../../trust/public.toml")).unwrap()
}

/// Flips one bit of `v`'s XDR; returns None if the result no longer decodes.
fn flip<T: ReadXdr + WriteXdr>(v: &T, at: usize, bit: u8) -> Option<T> {
    let mut bytes = v.to_xdr(Limits::none()).unwrap();
    let i = at % bytes.len();
    bytes[i] ^= 1 << (bit % 8);
    T::from_xdr(bytes, Limits::none()).ok()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn corrupted_bundles_never_prove_something_else(part in 0usize..4, at in any::<usize>(), bit in any::<u8>()) {
        let original = Bundle::from_json(BUNDLE).unwrap();
        let reference = original.verify(&trust()).unwrap();
        let mut b = original.clone();
        let changed = match part {
            0 => flip(&b.ledger.0, at, bit).map(|v| b.ledger.0 = v).is_some(),
            1 => flip(&b.scp.0, at, bit).map(|v| b.scp.0 = v).is_some(),
            2 => flip(&b.results.as_ref().unwrap().0, at, bit).map(|v| b.results.as_mut().unwrap().0 = v).is_some(),
            _ => {
                let externalize_core::bundle::Claim::Invocation { events, .. } = &mut b.claims[1] else { unreachable!() };
                let i = at % events.len();
                flip(&events[i].0, at / 7, bit).map(|v| events[i].0 = v).is_some()
            }
        };
        prop_assume!(changed);
        if let Ok(v) = b.verify(&trust()) {
            prop_assert_eq!(v.ledger.hash(), reference.ledger.hash());
            prop_assert_eq!(&v.claims, &reference.claims);
            prop_assert!(part == 1, "only SCP redundancy may absorb a corruption, not part {}", part);
        }
    }
}
