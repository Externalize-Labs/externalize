use sha2::{Digest, Sha256};

/// A Stellar network, identified by the SHA-256 of its passphrase.
///
/// Every SCP signature and transaction hash is domain-separated by this ID, so a
/// signature from testnet can never certify a mainnet ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    passphrase: String,
    id: [u8; 32],
}

impl Network {
    /// Passphrase of the public network (mainnet).
    pub const PUBLIC: &'static str = "Public Global Stellar Network ; September 2015";
    /// Passphrase of the SDF test network.
    pub const TESTNET: &'static str = "Test SDF Network ; September 2015";

    /// Builds a network from its passphrase.
    pub fn new(passphrase: impl Into<String>) -> Self {
        let passphrase = passphrase.into();
        let id = Sha256::digest(passphrase.as_bytes()).into();
        Self { passphrase, id }
    }

    /// The public network.
    pub fn public() -> Self {
        Self::new(Self::PUBLIC)
    }

    /// The SDF test network.
    pub fn testnet() -> Self {
        Self::new(Self::TESTNET)
    }

    /// Resolves `"public"`, `"testnet"`, or a literal passphrase.
    pub fn from_name(name: &str) -> Self {
        match name {
            "public" | "mainnet" => Self::public(),
            "testnet" => Self::testnet(),
            other => Self::new(other),
        }
    }

    /// The network passphrase.
    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }

    /// SHA-256 of the passphrase.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_network_id_is_well_known() {
        assert_eq!(
            hex::encode(Network::public().id()),
            "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979"
        );
    }

    #[test]
    fn names_resolve() {
        assert_eq!(Network::from_name("mainnet"), Network::public());
        assert_eq!(Network::from_name("testnet").passphrase(), Network::TESTNET);
        assert_eq!(
            Network::from_name("Standalone Network ; February 2017").passphrase(),
            "Standalone Network ; February 2017"
        );
    }
}
