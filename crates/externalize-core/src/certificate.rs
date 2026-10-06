//! Certifying a ledger header from SCP EXTERNALIZE statements.

use std::collections::BTreeSet;

use stellar_xdr::{
    LedgerHeader, LedgerHeaderHistoryEntry, Limits, NodeId, PublicKey, ScpHistoryEntry, ScpStatementPledges, Uint256,
    WriteXdr,
};

use crate::quorum::NodeKey;
use crate::{Error, TrustSet, scp, sha256};

/// A ledger header and the SCP messages that claim it was externalized.
///
/// Both come straight from a history archive (`ledger-*.xdr.gz` and
/// `scp-*.xdr.gz`) or from any other untrusted source.
#[derive(Clone, Debug)]
pub struct Certificate {
    /// The header being certified.
    pub header: LedgerHeaderHistoryEntry,
    /// SCP messages recorded for the same ledger.
    pub scp: ScpHistoryEntry,
}

/// A header the trust set has signed off on.
#[derive(Clone, Debug)]
pub struct CertifiedLedger {
    header: LedgerHeader,
    hash: [u8; 32],
    signers: Vec<NodeId>,
}

impl CertifiedLedger {
    /// The certified header.
    pub fn header(&self) -> &LedgerHeader {
        &self.header
    }

    /// SHA-256 of the header XDR.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Ledger sequence number.
    pub fn sequence(&self) -> u32 {
        self.header.ledger_seq
    }

    /// Close time, seconds since the Unix epoch.
    pub fn close_time(&self) -> u64 {
        self.header.scp_value.close_time.0
    }

    /// Trusted validators whose valid EXTERNALIZE signatures were counted.
    pub fn signers(&self) -> &[NodeId] {
        &self.signers
    }
}

impl Certificate {
    /// Certifies the header, or explains why it cannot be.
    ///
    /// 1. The header hash must be the SHA-256 of the header.
    /// 2. Every envelope whose signature verifies on the trust set's network
    ///    and that comes from a trusted validator must EXTERNALIZE exactly
    ///    the header's `scpValue` for this slot; any other value from a trusted
    ///    validator is [`Error::Equivocation`].
    /// 3. The trusted signers must satisfy the trust set.
    ///
    /// Envelopes from untrusted validators, for other slots, with invalid
    /// signatures, or carrying non-EXTERNALIZE statements are ignored.
    pub fn verify(&self, trust: &TrustSet) -> Result<CertifiedLedger, Error> {
        let header = &self.header.header;
        let seq = header.ledger_seq;
        let header_xdr = header.to_xdr(Limits::none()).map_err(|e| Error::xdr("ledger header", e))?;
        let hash = sha256(header_xdr);
        if hash != self.header.hash.0 {
            return Err(Error::HeaderHashMismatch { ledger: seq });
        }

        let ScpHistoryEntry::V0(entry) = &self.scp;
        let msgs = &entry.ledger_messages;
        if msgs.ledger_seq != seq {
            return Err(Error::LedgerMismatch { expected: seq, actual: msgs.ledger_seq });
        }

        let value = header.scp_value.to_xdr(Limits::none()).map_err(|e| Error::xdr("StellarValue", e))?;
        let mut signers: BTreeSet<NodeKey> = BTreeSet::new();
        for env in msgs.messages.iter() {
            let ScpStatementPledges::Externalize(ext) = &env.statement.pledges else { continue };
            if env.statement.slot_index != u64::from(seq) {
                continue;
            }
            let Some(node) = scp::verified_signer(trust.network(), env) else { continue };
            if !trust.contains(&node) {
                continue;
            }
            if ext.commit.value.0.as_slice() != value.as_slice() {
                return Err(Error::Equivocation { ledger: seq, node: env.statement.node_id.to_string() });
            }
            signers.insert(node);
        }

        if !trust.is_satisfied_by(&signers) {
            return Err(Error::QuorumNotSatisfied { ledger: seq, signers: signers.len() });
        }

        Ok(CertifiedLedger {
            header: header.clone(),
            hash,
            signers: signers.into_iter().map(|k| NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(k)))).collect(),
        })
    }
}

/// Verifies headers older than a certified one by walking `previousLedgerHash`.
///
/// `older` may be in any order but must be contiguous down from
/// `trusted.sequence() - 1`. Returns the sequences that were verified, newest
/// first. The chain only runs backwards: a certified ledger vouches for its
/// ancestors, never for its descendants.
pub fn verify_ancestors(trusted: &CertifiedLedger, older: &[LedgerHeaderHistoryEntry]) -> Result<Vec<u32>, Error> {
    let mut sorted: Vec<&LedgerHeaderHistoryEntry> = older.iter().collect();
    sorted.sort_by_key(|e| std::cmp::Reverse(e.header.ledger_seq));

    let mut expected_hash = trusted.header.previous_ledger_hash.0;
    let mut expected_seq = trusted.sequence();
    let mut out = Vec::with_capacity(sorted.len());
    for entry in sorted {
        expected_seq = expected_seq.checked_sub(1).ok_or(Error::BrokenChain(entry.header.ledger_seq))?;
        let seq = entry.header.ledger_seq;
        let hash = sha256(entry.header.to_xdr(Limits::none()).map_err(|e| Error::xdr("ledger header", e))?);
        if seq != expected_seq || hash != expected_hash || entry.hash.0 != hash {
            return Err(Error::BrokenChain(seq));
        }
        out.push(seq);
        expected_hash = entry.header.previous_ledger_hash.0;
    }
    Ok(out)
}
