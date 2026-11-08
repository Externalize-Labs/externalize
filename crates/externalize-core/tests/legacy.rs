//! Mainnet ledgers 50000000 and 50000001 (protocol 19): 50000001 has a
//! legacy (pre-generalized) transaction set.
//!
//! The archive's SCP history for that checkpoint holds one trusted signature
//! per ledger, too few for any quorum, so the full certificate is checked with
//! synthetic validators re-signing the genuine values; the legacy set hash is
//! checked against the genuine header.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use ed25519_dalek::{Signer, SigningKey};
use externalize_core::xdr::*;
use externalize_core::{Certificate, Error, Network, TrustSet, archive, inclusion};
use sha2::Digest;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/legacy");
const N: u32 = 50_000_000;

fn open<T: ReadXdr>(name: &str) -> Vec<T> {
    archive::read_gz_frames(std::fs::File::open(format!("{DIR}/{name}")).unwrap()).unwrap()
}

fn headers() -> Vec<LedgerHeaderHistoryEntry> {
    open("ledger-50000000-50000001.xdr.gz")
}

fn next_transactions() -> TransactionHistoryEntry {
    open::<TransactionHistoryEntry>("transactions-50000001.xdr.gz").remove(0)
}

#[test]
fn the_legacy_set_hashes_as_its_header_commits() {
    let h = headers();
    let txs = next_transactions();
    assert_eq!(h[1].header.ledger_version, 19);
    assert!(matches!(txs.ext, TransactionHistoryEntryExt::V0));
    assert!(txs.tx_set.txs.len() > 1);
    let (set_hash, previous) = inclusion::tx_set_hash(&txs).unwrap();
    assert_eq!(set_hash, h[1].header.scp_value.tx_set_hash.0, "stellar-core's legacy contents hash");
    let header_n: [u8; 32] = sha2::Sha256::digest(h[0].header.to_xdr(Limits::none()).unwrap()).into();
    assert_eq!(previous, header_n);
}

fn keys() -> Vec<SigningKey> {
    (1..=3u8).map(|i| SigningKey::from_bytes(&[i; 32])).collect()
}

fn node(k: &SigningKey) -> NodeId {
    NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(k.verifying_key().to_bytes())))
}

fn trust() -> TrustSet {
    let validators: Vec<NodeId> = keys().iter().map(node).collect();
    let q = ScpQuorumSet { threshold: 2, validators: validators.try_into().unwrap(), inner_sets: VecM::default() };
    TrustSet::new(Network::public(), q).unwrap()
}

fn signed(slot: u32, value: &StellarValue) -> ScpHistoryEntry {
    let messages: Vec<ScpEnvelope> = keys()
        .iter()
        .map(|k| {
            let statement = ScpStatement {
                node_id: node(k),
                slot_index: u64::from(slot),
                pledges: ScpStatementPledges::Externalize(ScpStatementExternalize {
                    commit: ScpBallot {
                        counter: 1,
                        value: Value(value.to_xdr(Limits::none()).unwrap().try_into().unwrap()),
                    },
                    n_h: 1,
                    commit_quorum_set_hash: Hash([0; 32]),
                }),
            };
            let payload = externalize_core::scp::signing_payload(&Network::public(), &statement).unwrap();
            ScpEnvelope { statement, signature: Signature(k.sign(&payload).to_bytes().to_vec().try_into().unwrap()) }
        })
        .collect();
    ScpHistoryEntry::V0(ScpHistoryEntryV0 {
        quorum_sets: VecM::default(),
        ledger_messages: LedgerScpMessages { ledger_seq: slot, messages: messages.try_into().unwrap() },
    })
}

/// Ledger 50000000 with its genuine successor; the signatures are synthetic.
fn certificate() -> Certificate {
    let h = headers();
    Certificate {
        scp: signed(N, &h[0].header.scp_value),
        next_scp: signed(N + 1, &h[1].header.scp_value),
        header: h[0].clone(),
        next_transactions: next_transactions(),
    }
}

#[test]
fn a_legacy_transaction_set_certifies_its_previous_ledger() {
    let ledger = certificate().verify(&trust()).unwrap();
    assert_eq!(ledger.sequence(), N);
    assert_eq!(ledger.signers().len(), 3);
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

#[test]
fn a_forged_header_is_not_committed_by_a_legacy_successor() {
    let mut c = certificate();
    c.header.header.tx_set_result_hash = Hash([7; 32]);
    c.header.hash = Hash(sha2::Sha256::digest(c.header.header.to_xdr(Limits::none()).unwrap()).into());
    assert_eq!(c.verify(&trust()).unwrap_err(), Error::HeaderNotCommitted(N));
}
