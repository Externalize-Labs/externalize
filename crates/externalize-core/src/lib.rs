//! Verify Stellar ledgers, transactions and Soroban contract events from the
//! validators' own signatures, without trusting an RPC, Horizon or archive.
//!
//! ```text
//! validator signatures ─▶ ledger header ─▶ result set ─▶ tx result ─▶ return value + events
//!     Certificate          CertifiedLedger  verify_results  find_result   verify_invocation
//! ```
//!
//! Start with a [`TrustSet`] (which validators you believe), then verify a
//! [`Bundle`] in one call, or use [`Certificate`] and [`inclusion`] directly.
//!
//! ```
//! use externalize_core::{Bundle, TrustSet};
//!
//! let trust = TrustSet::from_toml(&std::fs::read_to_string("../../trust/public.toml")?)?;
//! let json = std::fs::read_to_string("tests/fixtures/mainnet/bundle-64791359.json")?;
//! let verified = Bundle::from_json(&json)?.verify(&trust)?;
//!
//! assert_eq!(verified.ledger.sequence(), 64_791_359);
//! assert_eq!(verified.ledger.signers().len(), 30);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#[cfg(feature = "archive")]
pub mod archive;
#[cfg(feature = "bundle")]
pub mod bundle;
pub mod certificate;
mod error;
pub mod inclusion;
mod network;
pub mod quorum;
pub mod scp;
mod trust;

#[cfg(feature = "bundle")]
pub use bundle::Bundle;
pub use certificate::{Certificate, CertifiedLedger, verify_ancestors};
pub use error::Error;
pub use network::Network;
pub use trust::TrustSet;

/// The XDR crate this library is built against.
pub use stellar_xdr as xdr;

pub(crate) fn sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data.as_ref()).into()
}
