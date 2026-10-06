//! Testnet checkpoint 5052927, certified by SDF's three testnet validators.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]

use externalize_core::xdr::{LedgerHeaderHistoryEntry, ScpHistoryEntry};
use externalize_core::{Error, TrustSet, archive, verify_ancestors};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/testnet");

fn open<T: externalize_core::xdr::ReadXdr>(name: &str) -> Vec<T> {
    archive::read_gz_frames(std::fs::File::open(format!("{DIR}/{name}")).unwrap()).unwrap()
}

#[test]
fn every_testnet_ledger_is_certified_and_chained() {
    let trust = TrustSet::from_toml(include_str!("../../../trust/testnet.toml")).unwrap();
    let headers: Vec<LedgerHeaderHistoryEntry> = open("ledger-004d19ff.xdr.gz");
    let scp: Vec<ScpHistoryEntry> = open("scp-004d19ff.xdr.gz");
    let mut certs = archive::certificates(headers, &scp);
    assert_eq!(certs.len(), 64);
    for c in &certs {
        assert!(c.verify(&trust).unwrap().signers().len() >= 2);
    }
    let newest = certs.pop().unwrap().verify(&trust).unwrap();
    assert_eq!(verify_ancestors(&newest, &certs.into_iter().map(|c| c.header).collect::<Vec<_>>()).unwrap().len(), 63);
}

#[test]
fn the_public_trust_set_rejects_testnet_ledgers() {
    let public = TrustSet::from_toml(include_str!("../../../trust/public.toml")).unwrap();
    let headers: Vec<LedgerHeaderHistoryEntry> = open("ledger-004d19ff.xdr.gz");
    let scp: Vec<ScpHistoryEntry> = open("scp-004d19ff.xdr.gz");
    let cert = archive::certificates(headers, &scp).remove(0);
    assert!(matches!(cert.verify(&public), Err(Error::QuorumNotSatisfied { signers: 0, .. })));
}
