use thiserror::Error;

/// Every way a verification can fail.
///
/// Verification is fail-closed: an `Err` means the input proves nothing.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input could not be decoded as the expected XDR type.
    #[error("malformed XDR in {what}: {reason}")]
    Xdr {
        /// Which input was being decoded.
        what: &'static str,
        /// Decoder message.
        reason: String,
    },

    /// A trust set or quorum set violates the structural rules stellar-core enforces.
    #[error("invalid quorum set: {0}")]
    InvalidQuorumSet(&'static str),

    /// The bundle or trust file targets a different network than the verifier.
    #[error("network mismatch: expected {expected:?}, got {actual:?}")]
    NetworkMismatch {
        /// Passphrase the verifier was configured with.
        expected: String,
        /// Passphrase found in the input.
        actual: String,
    },

    /// `LedgerHeaderHistoryEntry.hash` is not the SHA-256 of its header.
    #[error("ledger {ledger}: header hash does not match header contents")]
    HeaderHashMismatch {
        /// Ledger sequence.
        ledger: u32,
    },

    /// Two inputs that must describe the same ledger do not.
    #[error("ledger sequence mismatch: expected {expected}, got {actual}")]
    LedgerMismatch {
        /// Sequence of the ledger being verified.
        expected: u32,
        /// Sequence found in the other input.
        actual: u32,
    },

    /// A trusted validator signed EXTERNALIZE for a value other than the header's.
    ///
    /// Either the header is forged or the trusted set equivocated. Both are
    /// reasons to stop, never to fall back.
    #[error("ledger {ledger}: trusted validator {node} externalized a different value")]
    Equivocation {
        /// Ledger sequence.
        ledger: u32,
        /// Validator public key (strkey).
        node: String,
    },

    /// The validly signed EXTERNALIZE statements do not satisfy the trust set.
    #[error("ledger {ledger}: {signers} trusted signatures do not satisfy the trust set")]
    QuorumNotSatisfied {
        /// Ledger sequence.
        ledger: u32,
        /// Number of distinct trusted validators that signed.
        signers: usize,
    },

    /// A hash committed in the header does not match the supplied data.
    #[error("ledger {ledger}: {what} hash does not match the ledger header")]
    CommitmentMismatch {
        /// Ledger sequence.
        ledger: u32,
        /// `"transaction set"` or `"result set"`.
        what: &'static str,
    },

    /// The ledger was closed with a pre-protocol-20 transaction set, which is unsupported.
    #[error("ledger {0}: legacy (non-generalized) transaction sets are not supported")]
    LegacyTransactionSet(u32),

    /// An older header does not chain to the trusted one.
    #[error("ledger {0}: header is not an ancestor of the trusted ledger")]
    BrokenChain(u32),

    /// The transaction is not in the ledger's result set.
    #[error("transaction {0} is not part of the ledger")]
    TransactionNotFound(String),

    /// The transaction failed, so none of its operations had effects.
    #[error("transaction {0} did not succeed")]
    TransactionFailed(String),

    /// `op_index` does not point at a successful `InvokeHostFunction` result.
    #[error("operation {index} of transaction {tx} is not a successful contract invocation")]
    NotAnInvocation {
        /// Transaction hash (hex).
        tx: String,
        /// Operation index.
        index: u32,
    },

    /// Return value and events do not hash to the committed invocation result.
    #[error("invocation {index} of transaction {tx}: return value and events do not match the committed hash")]
    InvocationMismatch {
        /// Transaction hash (hex).
        tx: String,
        /// Operation index.
        index: u32,
    },

    /// A bundle claim needs data the bundle does not carry.
    #[error("bundle is missing {0}")]
    MissingData(&'static str),

    /// The bundle or trust file is not valid JSON/TOML or has an unknown format tag.
    #[error("invalid {what}: {reason}")]
    Format {
        /// `"bundle"` or `"trust set"`.
        what: &'static str,
        /// Parser message.
        reason: String,
    },
}

impl Error {
    pub(crate) fn xdr(what: &'static str, e: stellar_xdr::Error) -> Self {
        Self::Xdr { what, reason: e.to_string() }
    }
}
