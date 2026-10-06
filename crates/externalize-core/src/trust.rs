//! The validators a verifier is willing to believe.

use std::collections::BTreeSet;

use stellar_xdr::ScpQuorumSet;

use crate::quorum::{self, NodeKey};
use crate::{Error, Network};

/// A network plus the quorum set the verifier treats as its own quorum slice.
///
/// A ledger is accepted only when validators satisfying this set have signed
/// EXTERNALIZE for it. This is the same decision a watcher node makes with
/// the same configuration; see `docs/trust-model.md`.
#[derive(Clone, Debug)]
pub struct TrustSet {
    network: Network,
    quorum: ScpQuorumSet,
    members: BTreeSet<NodeKey>,
    org_names: Vec<String>,
}

impl TrustSet {
    /// Builds a trust set after checking the quorum set's structure.
    pub fn new(network: Network, quorum: ScpQuorumSet) -> Result<Self, Error> {
        quorum::validate(&quorum)?;
        let members = quorum::members(&quorum);
        Ok(Self { network, quorum, members, org_names: Vec::new() })
    }

    /// Human-readable name of inner set `index`, when the trust file gave one.
    pub fn org_name(&self, index: usize) -> Option<&str> {
        self.org_names.get(index).map(String::as_str)
    }

    /// The network this trust set applies to.
    pub fn network(&self) -> &Network {
        &self.network
    }

    /// The trusted quorum set.
    pub fn quorum(&self) -> &ScpQuorumSet {
        &self.quorum
    }

    /// Whether `node` appears anywhere in the trust set.
    pub fn contains(&self, node: &NodeKey) -> bool {
        self.members.contains(node)
    }

    /// Whether `signers` satisfies the trust set.
    pub fn is_satisfied_by(&self, signers: &BTreeSet<NodeKey>) -> bool {
        quorum::is_satisfied(&self.quorum, signers)
    }
}

#[cfg(feature = "config")]
mod file {
    use serde::Deserialize;
    use stellar_xdr::{NodeId, ScpQuorumSet, VecM};

    use super::TrustSet;
    use crate::{Error, Network};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        network: String,
        threshold: u32,
        #[serde(default)]
        validators: Vec<String>,
        #[serde(default, rename = "org")]
        orgs: Vec<Org>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Org {
        name: String,
        #[serde(default)]
        #[allow(dead_code, reason = "documents the org; not used in verification")]
        home_domain: Option<String>,
        threshold: u32,
        validators: Vec<String>,
    }

    fn err(reason: impl ToString) -> Error {
        Error::Format { what: "trust set", reason: reason.to_string() }
    }

    fn nodes(keys: &[String]) -> Result<VecM<NodeId>, Error> {
        keys.iter()
            .map(|k| k.parse::<NodeId>().map_err(|_| err(format!("not a validator public key: {k}"))))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| err("too many validators"))
    }

    impl TrustSet {
        /// Parses a trust file. See `trust/public.toml` for the format.
        pub fn from_toml(text: &str) -> Result<Self, Error> {
            let f: File = toml::from_str(text).map_err(err)?;
            let inner = f
                .orgs
                .iter()
                .map(|o| {
                    Ok(ScpQuorumSet {
                        threshold: o.threshold,
                        validators: nodes(&o.validators)?,
                        inner_sets: VecM::default(),
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let quorum = ScpQuorumSet {
                threshold: f.threshold,
                validators: nodes(&f.validators)?,
                inner_sets: inner.try_into().map_err(|_| err("too many orgs"))?,
            };
            let mut trust = Self::new(Network::from_name(&f.network), quorum)?;
            trust.org_names = f.orgs.into_iter().map(|o| o.name).collect();
            Ok(trust)
        }
    }
}

#[cfg(all(test, feature = "config"))]
mod tests {
    use super::*;

    const PUBLIC: &str = include_str!("../../../trust/public.toml");

    #[test]
    fn shipped_public_trust_set_parses() {
        let t = TrustSet::from_toml(PUBLIC).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(t.network(), &Network::public());
        assert_eq!(t.quorum().inner_sets.len(), 10);
        assert_eq!(t.members.len(), 30);
        assert_eq!(t.org_name(1), Some("Stellar Development Foundation"));
    }

    #[test]
    fn rejects_unknown_fields_and_bad_keys() {
        assert!(TrustSet::from_toml("network = \"public\"\nthreshold = 1\nvalidators = [\"nope\"]").is_err());
        assert!(TrustSet::from_toml("network = \"public\"\nthreshold = 1\nsurprise = true").is_err());
    }

    #[test]
    fn rejects_impossible_threshold() {
        let toml = "network = \"public\"\nthreshold = 2\nvalidators = [\"GABMKJM6I25XI4K7U6XWMULOUQIQ27BCTMLS6BYYSOWKTBUXVRJSXHYQ\"]";
        assert!(matches!(TrustSet::from_toml(toml), Err(Error::InvalidQuorumSet(_))));
    }
}
