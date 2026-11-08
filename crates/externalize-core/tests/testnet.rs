//! Testnet checkpoint 5052927, certified by SDF's three testnet validators.
//! Its last ledger is certified through 5052928, the next checkpoint's first.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]

use externalize_core::xdr::{
    LedgerHeaderHistoryEntry, ScpHistoryEntry, TransactionHistoryEntry, TransactionHistoryEntryExt,
};
use externalize_core::{Error, TrustSet, archive, verify_ancestors};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/testnet");
const LAST: u32 = 5_052_927;

fn open<T: externalize_core::xdr::ReadXdr>(name: &str) -> Vec<T> {
    archive::read_gz_frames(std::fs::File::open(format!("{DIR}/{name}")).unwrap()).unwrap()
}

fn trust() -> TrustSet {
    TrustSet::from_toml(include_str!("../../../trust/testnet.toml")).unwrap()
}

fn scp() -> Vec<ScpHistoryEntry> {
    let mut scp: Vec<ScpHistoryEntry> = open("scp-004d19ff.xdr.gz");
    scp.extend(open::<ScpHistoryEntry>("scp-004d1a3f.xdr.gz"));
    scp
}

fn transactions() -> Vec<TransactionHistoryEntry> {
    let mut txs: Vec<TransactionHistoryEntry> = open("transactions-004d19ff.xdr.gz");
    txs.extend(open::<TransactionHistoryEntry>("transactions-5052928.xdr.gz"));
    txs
}

#[test]
fn every_testnet_ledger_is_certified_and_chained() {
    let trust = trust();
    let headers: Vec<LedgerHeaderHistoryEntry> = open("ledger-004d19ff.xdr.gz");
    let certs: Vec<_> = archive::certificates(headers, &scp(), &transactions()).into_iter().map(Result::unwrap).collect();
    assert_eq!(certs.len(), 64);
    for c in &certs {
        assert!(c.verify(&trust).unwrap().signers().len() >= 2);
        // Testnet runs generalized transaction sets.
        assert!(matches!(c.next_transactions.ext, TransactionHistoryEntryExt::V1(_)));
    }
    let mut certs = certs;
    let newest = certs.pop().unwrap().verify(&trust).unwrap();
    assert_eq!(newest.sequence(), LAST);
    assert_eq!(verify_ancestors(&newest, &certs.into_iter().map(|c| c.header).collect::<Vec<_>>()).unwrap().len(), 63);
}

#[test]
fn a_checkpoints_last_ledger_needs_the_next_checkpoint() {
    let headers: Vec<LedgerHeaderHistoryEntry> = open("ledger-004d19ff.xdr.gz");
    let scp: Vec<ScpHistoryEntry> = open("scp-004d19ff.xdr.gz");
    let txs: Vec<TransactionHistoryEntry> = open("transactions-004d19ff.xdr.gz");
    let certs = archive::certificates(headers, &scp, &txs);
    assert_eq!(certs.len(), 64);
    assert!(certs[..63].iter().all(Result::is_ok));
    assert_eq!(certs[63].as_ref().unwrap_err(), &Error::MissingSuccessor(LAST));
}

#[test]
fn the_public_trust_set_rejects_testnet_ledgers() {
    let public = TrustSet::from_toml(include_str!("../../../trust/public.toml")).unwrap();
    let headers: Vec<LedgerHeaderHistoryEntry> = open("ledger-004d19ff.xdr.gz");
    let cert = archive::certificates(headers, &scp(), &transactions()).remove(0).unwrap();
    assert!(matches!(cert.verify(&public), Err(Error::QuorumNotSatisfied { signers: 0, .. })));
}
