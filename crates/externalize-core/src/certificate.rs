//! Certifying a ledger header from SCP EXTERNALIZE statements.
//!
//! Validators sign only a ledger's `StellarValue`, which header N repeats as
//! `scpValue`. The rest of header N (results, previous ledger, bucket list) is
//! bound by ledger N+1: its externalized value names a transaction set, and
//! that set names `SHA-256(header N)` as its previous ledger.

use std::collections::BTreeSet;

use stellar_xdr::{
    LedgerHeader, LedgerHeaderHistoryEntry, Limits, NodeId, PublicKey, ReadXdr, ScpHistoryEntry, ScpStatementPledges,
    StellarValue, TransactionHistoryEntry, Uint256, WriteXdr,
};

use crate::quorum::NodeKey;
use crate::{Error, TrustSet, inclusion, scp, sha256};

/// A ledger header, the SCP messages that claim it was externalized, and the
/// next ledger's SCP messages and transaction set, which commit to the header.
///
/// All of it comes straight from a history archive (`ledger-*`, `scp-*` and
/// `transactions-*` files) or from any other untrusted source.
#[derive(Clone, Debug)]
pub struct Certificate {
    /// The header being certified (ledger N).
    pub header: LedgerHeaderHistoryEntry,
    /// SCP messages recorded for ledger N.
    pub scp: ScpHistoryEntry,
    /// SCP messages recorded for ledger N+1.
    pub next_scp: ScpHistoryEntry,
    /// Ledger N+1's transaction set, whose `previousLedgerHash` names header N.
    pub next_transactions: TransactionHistoryEntry,
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
    /// Certifies the whole header, or explains why it cannot be.
    ///
    /// 1. The header hash must be the SHA-256 of the header.
    /// 2. Trusted validators satisfying the trust set must EXTERNALIZE exactly
    ///    the header's `scpValue` for slot N.
    /// 3. Trusted validators satisfying the trust set must EXTERNALIZE one
    ///    value V for slot N+1.
    /// 4. `next_transactions` must be ledger N+1's and hash to `V.txSetHash`.
    /// 5. Its `previousLedgerHash` must be the header's hash.
    ///
    /// In 2 and 3, a trusted validator that validly signed any other value is
    /// [`Error::Equivocation`]. Envelopes from untrusted validators, for other
    /// slots, with invalid signatures, or carrying non-EXTERNALIZE statements
    /// are ignored.
    pub fn verify(&self, trust: &TrustSet) -> Result<CertifiedLedger, Error> {
        let header = &self.header.header;
        let seq = header.ledger_seq;
        let header_xdr = header.to_xdr(Limits::none()).map_err(|e| Error::xdr("ledger header", e))?;
        let hash = sha256(header_xdr);
        if hash != self.header.hash.0 {
            return Err(Error::HeaderHashMismatch { ledger: seq });
        }

        let value = header.scp_value.to_xdr(Limits::none()).map_err(|e| Error::xdr("StellarValue", e))?;
        let (_, signers) = externalized(trust, &self.scp, seq, Some(&value))?;

        // Slot N signs only scpValue; slot N+1's value binds the rest of the header.
        let next = seq.checked_add(1).ok_or(Error::MissingSuccessor(seq))?;
        let (next_value, _) = externalized(trust, &self.next_scp, next, None)?;
        let limits = Limits { depth: 64, len: next_value.len() };
        let next_value = StellarValue::from_xdr(next_value, limits).map_err(|e| Error::xdr("next StellarValue", e))?;
        if self.next_transactions.ledger_seq != next {
            return Err(Error::LedgerMismatch { expected: next, actual: self.next_transactions.ledger_seq });
        }
        let (set_hash, previous) = inclusion::tx_set_hash(&self.next_transactions)?;
        if set_hash != next_value.tx_set_hash.0 {
            return Err(Error::SuccessorTxSetMismatch(next));
        }
        if previous != hash {
            return Err(Error::HeaderNotCommitted(seq));
        }

        Ok(CertifiedLedger {
            header: header.clone(),
            hash,
            signers: signers.into_iter().map(|k| NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(k)))).collect(),
        })
    }
}

/// The value trusted validators satisfying the trust set EXTERNALIZEd for
/// `slot`, and who signed it.
///
/// Every counted envelope must carry one value: `expected` if given, else the
/// first one counted. A trusted validator with any other is
/// [`Error::Equivocation`].
fn externalized<'a>(
    trust: &TrustSet,
    entry: &'a ScpHistoryEntry,
    slot: u32,
    expected: Option<&'a [u8]>,
) -> Result<(&'a [u8], BTreeSet<NodeKey>), Error> {
    let ScpHistoryEntry::V0(entry) = entry;
    let msgs = &entry.ledger_messages;
    if msgs.ledger_seq != slot {
        return Err(Error::LedgerMismatch { expected: slot, actual: msgs.ledger_seq });
    }

    let mut value = expected;
    let mut signers: BTreeSet<NodeKey> = BTreeSet::new();
    for env in msgs.messages.iter() {
        let ScpStatementPledges::Externalize(ext) = &env.statement.pledges else { continue };
        if env.statement.slot_index != u64::from(slot) {
            continue;
        }
        let Some(node) = scp::verified_signer(trust.network(), env) else { continue };
        if !trust.contains(&node) {
            continue;
        }
        let signed = ext.commit.value.0.as_slice();
        if *value.get_or_insert(signed) != signed {
            return Err(Error::Equivocation { ledger: slot, node: env.statement.node_id.to_string() });
        }
        signers.insert(node);
    }

    match value {
        Some(v) if trust.is_satisfied_by(&signers) => Ok((v, signers)),
        _ => Err(Error::QuorumNotSatisfied { ledger: slot, signers: signers.len() }),
    }
}

/// Proves ledger `target`, older than `trusted`, from archived headers, and
/// returns its header.
///
/// `headers` may hold whole archive `ledger-*` files: only the entries from
/// `target` up to the ledger just before `trusted` are used, and every one of
/// them must be present, since each links to the next by its hash.
pub fn prove_ancestor(
    trusted: &CertifiedLedger,
    headers: &[LedgerHeaderHistoryEntry],
    target: u32,
) -> Result<LedgerHeaderHistoryEntry, Error> {
    let newest = trusted.sequence();
    if target >= newest {
        return Err(Error::NotAnAncestor { ledger: target, trusted: newest });
    }
    let mut by_seq = std::collections::BTreeMap::new();
    for entry in headers.iter().filter(|e| (target..newest).contains(&e.header.ledger_seq)) {
        let seq = entry.header.ledger_seq;
        if by_seq.get(&seq).is_some_and(|known| *known != entry) {
            return Err(Error::BrokenChain(seq)); // two different headers claim the same ledger
        }
        by_seq.insert(seq, entry);
    }
    // Report the gap nearest the trusted ledger: that is where the walk stops.
    if let Some(missing) = (target..newest).rev().find(|s| !by_seq.contains_key(s)) {
        return Err(Error::MissingHeader(missing));
    }
    let chain: Vec<LedgerHeaderHistoryEntry> = by_seq.values().map(|e| (*e).clone()).collect();
    verify_ancestors(trusted, &chain)?;
    by_seq.get(&target).map(|e| (*e).clone()).ok_or(Error::MissingHeader(target))
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
