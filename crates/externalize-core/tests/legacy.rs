//! A protocol 19 mainnet ledger, 50000000, certified through 50000001's
//! legacy (pre-generalized) transaction set.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use externalize_core::xdr::{
    Hash, LedgerHeaderHistoryEntry, ScpHistoryEntry, TransactionHistoryEntry, TransactionHistoryEntryExt,
};
use externalize_core::{Certificate, Error, TrustSet, archive};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/legacy");
const N: u32 = 50_000_000;

fn open<T: externalize_core::xdr::ReadXdr>(name: &str) -> Vec<T> {
    archive::read_gz_frames(std::fs::File::open(format!("{DIR}/{name}")).unwrap()).unwrap()
}

/// The tier-1 of the time, derived from that checkpoint's SCP messages.
fn trust() -> TrustSet {
    TrustSet::from_toml(include_str!("fixtures/legacy/trust.toml")).unwrap()
}

fn certificate() -> Certificate {
    let headers: Vec<LedgerHeaderHistoryEntry> = open("ledger-50000000.xdr.gz");
    let scp: Vec<ScpHistoryEntry> = open("scp-50000000.xdr.gz");
    let txs: Vec<TransactionHistoryEntry> = open("transactions-50000001.xdr.gz");
    let mut certs = archive::certificates(headers, &scp, &txs);
    assert_eq!(certs.len(), 1);
    certs.remove(0).unwrap()
}

#[test]
fn a_legacy_transaction_set_certifies_its_previous_ledger() {
    let c = certificate();
    assert_eq!(c.header.header.ledger_version, 19);
    assert!(matches!(c.next_transactions.ext, TransactionHistoryEntryExt::V0));
    assert!(!c.next_transactions.tx_set.txs.is_empty());
    let ledger = c.verify(&trust()).unwrap();
    assert_eq!(ledger.sequence(), N);
    assert!(!ledger.signers().is_empty());
}

#[test]
fn a_legacy_set_naming_another_previous_ledger_is_rejected() {
    let mut c = certificate();
    c.next_transactions.tx_set.previous_ledger_hash = Hash([7; 32]);
    assert_eq!(c.verify(&trust()).unwrap_err(), Error::SuccessorTxSetMismatch(N + 1));
}

#[test]
fn a_reordered_legacy_set_is_rejected() {
    let mut c = certificate();
    let mut txs = c.next_transactions.tx_set.txs.to_vec();
    txs.swap(0, 1);
    c.next_transactions.tx_set.txs = txs.try_into().unwrap();
    assert_eq!(c.verify(&trust()).unwrap_err(), Error::SuccessorTxSetMismatch(N + 1));
}
