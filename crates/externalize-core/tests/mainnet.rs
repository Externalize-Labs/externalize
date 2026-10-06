//! Verification against real public-network data: history archive checkpoint
//! 64791359 (ledgers 64791296..=64791359) and two Soroban transactions from
//! its last ledger, fetched from mainnet RPC.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Read;

use externalize_core::archive;
use externalize_core::bundle::{Claim, Hex32, Xdr};
use externalize_core::inclusion::{self, Invocation};
use externalize_core::xdr::*;
use externalize_core::{Bundle, Certificate, Error, Network, TrustSet, verify_ancestors};
use flate2::read::GzDecoder;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mainnet");
const LAST: u32 = 64_791_359;
const TX_4_EVENTS: &str = "9689498be8097cf8b4e0465fff232b8bab486709afcf5aebffdd9ac51f91f873";
const TX_25_EVENTS: &str = "764c39734ec4da0b537f8c5e43b20223274064f84705b18943b1c35512f8da48";

fn trust() -> TrustSet {
    TrustSet::from_toml(include_str!("../../../trust/public.toml")).unwrap()
}

fn gunzip(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    GzDecoder::new(std::fs::File::open(format!("{DIR}/{name}")).unwrap()).read_to_end(&mut out).unwrap();
    out
}

fn frames<T: ReadXdr>(name: &str) -> Vec<T> {
    archive::read_gz_frames(std::fs::File::open(format!("{DIR}/{name}")).unwrap()).unwrap()
}

fn certificates() -> Vec<Certificate> {
    let headers: Vec<LedgerHeaderHistoryEntry> = frames("ledger-03dca33f.xdr.gz");
    let scp: Vec<ScpHistoryEntry> = frames("scp-03dca33f.xdr.gz");
    archive::certificates(headers, &scp)
}

fn last() -> Certificate {
    certificates().pop().unwrap()
}

fn results() -> TransactionHistoryResultEntry {
    TransactionHistoryResultEntry::from_xdr(gunzip("results-64791359.xdr.gz"), Limits::none()).unwrap()
}

fn transactions() -> TransactionHistoryEntry {
    TransactionHistoryEntry::from_xdr(gunzip("transactions-64791359.xdr.gz"), Limits::none()).unwrap()
}

fn invocation(tx: &str) -> Invocation {
    let b64 = std::fs::read_to_string(format!("{DIR}/meta-{}.xdr.b64", &tx[..8])).unwrap();
    let TransactionMeta::V4(m) = TransactionMeta::from_xdr_base64(b64.trim(), Limits::none()).unwrap() else {
        panic!("fixture is not meta v4")
    };
    Invocation {
        return_value: m.soroban_meta.and_then(|s| s.return_value).unwrap_or(ScVal::Void),
        events: m.operations[0].events.to_vec(),
    }
}

fn hash(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

/// Rebuilds a certificate keeping only envelopes accepted by `keep`.
fn with_envelopes(mut c: Certificate, keep: impl FnMut(&ScpEnvelope) -> Option<ScpEnvelope>) -> Certificate {
    let ScpHistoryEntry::V0(e) = &mut c.scp;
    let kept: Vec<ScpEnvelope> = e.ledger_messages.messages.iter().filter_map(keep).collect();
    e.ledger_messages.messages = kept.try_into().unwrap();
    c
}

fn org_of(trust: &TrustSet, env: &ScpEnvelope) -> usize {
    let key = externalize_core::quorum::node_key(&env.statement.node_id);
    trust
        .quorum()
        .inner_sets
        .iter()
        .position(|o| o.validators.iter().any(|v| externalize_core::quorum::node_key(v) == key))
        .unwrap()
}

#[test]
fn every_ledger_in_the_checkpoint_is_certified_by_tier1() {
    let t = trust();
    let certs = certificates();
    assert_eq!(certs.len(), 64);
    for c in &certs {
        let ledger = c.verify(&t).unwrap();
        assert_eq!(ledger.signers().len(), 30, "ledger {}", ledger.sequence());
    }
}

#[test]
fn certified_ledger_vouches_for_its_ancestors() {
    let t = trust();
    let mut certs = certificates();
    let newest = certs.pop().unwrap().verify(&t).unwrap();
    let older: Vec<_> = certs.into_iter().map(|c| c.header).collect();
    let seqs = verify_ancestors(&newest, &older).unwrap();
    assert_eq!(seqs.len(), 63);
    assert_eq!(seqs.first(), Some(&(LAST - 1)));
}

#[test]
fn a_gap_in_the_ancestor_chain_is_rejected() {
    let t = trust();
    let mut certs = certificates();
    let newest = certs.pop().unwrap().verify(&t).unwrap();
    let mut older: Vec<_> = certs.into_iter().map(|c| c.header).collect();
    older.remove(30);
    assert!(matches!(verify_ancestors(&newest, &older), Err(Error::BrokenChain(_))));
}

#[test]
fn seven_of_ten_orgs_is_enough_and_six_is_not() {
    let t = trust();
    let two_per_org = |max_org: usize| {
        let t = t.clone();
        move |env: &ScpEnvelope| {
            let org = org_of(&t, env);
            (org < max_org).then(|| env.clone())
        }
    };
    let c = with_envelopes(last(), two_per_org(7));
    assert!(c.verify(&t).is_ok());

    let c = with_envelopes(last(), two_per_org(6));
    assert_eq!(c.verify(&t).unwrap_err(), Error::QuorumNotSatisfied { ledger: LAST, signers: 18 });
}

#[test]
fn one_validator_per_org_satisfies_no_org() {
    let t = trust();
    let mut seen = std::collections::BTreeSet::new();
    let c = with_envelopes(last(), |env| seen.insert(org_of(&t, env)).then(|| env.clone()));
    assert_eq!(c.verify(&t).unwrap_err(), Error::QuorumNotSatisfied { ledger: LAST, signers: 10 });
}

#[test]
fn forged_signatures_do_not_count() {
    let t = trust();
    let c = with_envelopes(last(), |env| {
        let mut env = env.clone();
        if org_of(&t, &env) >= 4 {
            let mut sig = env.signature.0.to_vec();
            sig[0] ^= 1;
            env.signature = Signature(sig.try_into().unwrap());
        }
        Some(env)
    });
    assert!(matches!(c.verify(&t), Err(Error::QuorumNotSatisfied { signers: 12, .. })));
}

#[test]
fn signatures_are_bound_to_the_network() {
    let public = trust();
    let testnet = TrustSet::new(Network::testnet(), public.quorum().clone()).unwrap();
    assert!(matches!(last().verify(&testnet), Err(Error::QuorumNotSatisfied { signers: 0, .. })));
}

#[test]
fn a_forged_header_is_caught_as_equivocation() {
    let t = trust();
    let mut c = last();
    c.header.header.scp_value.close_time = TimePoint(c.header.header.scp_value.close_time.0 + 1);
    c.header.hash = Hash(sha(&c.header.header.to_xdr(Limits::none()).unwrap()));
    assert!(matches!(c.verify(&t), Err(Error::Equivocation { ledger: LAST, .. })));
}

#[test]
fn a_header_that_does_not_match_its_hash_is_rejected() {
    let mut c = last();
    c.header.header.fee_pool += 1;
    assert_eq!(c.verify(&trust()).unwrap_err(), Error::HeaderHashMismatch { ledger: LAST });
}

#[test]
fn scp_messages_for_another_ledger_are_rejected() {
    let certs = certificates();
    let c = Certificate { header: certs[63].header.clone(), scp: certs[62].scp.clone() };
    assert_eq!(c.verify(&trust()).unwrap_err(), Error::LedgerMismatch { expected: LAST, actual: LAST - 1 });
}

#[test]
fn result_and_transaction_sets_match_the_header() {
    let ledger = last().verify(&trust()).unwrap();
    let r = results();
    let pairs = inclusion::verify_results(ledger.header(), &r).unwrap();
    let txs = inclusion::verify_transactions(&Network::public(), ledger.header(), &transactions()).unwrap();
    assert_eq!(pairs.len(), txs.len());
    assert!(txs.iter().all(|(h, _)| pairs.iter().any(|p| &p.transaction_hash.0 == h)));
}

#[test]
fn a_tampered_result_set_is_rejected() {
    let ledger = last().verify(&trust()).unwrap();
    let mut r = results();
    let mut pairs = r.tx_result_set.results.to_vec();
    pairs[0].result.fee_charged += 1;
    r.tx_result_set.results = pairs.try_into().unwrap();
    assert!(matches!(
        inclusion::verify_results(ledger.header(), &r),
        Err(Error::CommitmentMismatch { what: "result set", .. })
    ));
}

#[test]
fn soroban_events_are_proven_and_tampering_is_caught() {
    let ledger = last().verify(&trust()).unwrap();
    let r = results();
    let pairs = inclusion::verify_results(ledger.header(), &r).unwrap();

    for (tx, n) in [(TX_4_EVENTS, 4), (TX_25_EVENTS, 25)] {
        let pair = inclusion::find_result(pairs, &hash(tx)).unwrap();
        let inv = invocation(tx);
        assert_eq!(inv.events.len(), n);
        inclusion::verify_invocation(pair, 0, &inv).unwrap();

        let mut dropped = inv.clone();
        dropped.events.pop();
        assert!(matches!(inclusion::verify_invocation(pair, 0, &dropped), Err(Error::InvocationMismatch { .. })));

        let mut reordered = inv.clone();
        reordered.events.swap(0, 1);
        assert!(matches!(inclusion::verify_invocation(pair, 0, &reordered), Err(Error::InvocationMismatch { .. })));

        let mut other_return = inv.clone();
        other_return.return_value = ScVal::Bool(true);
        assert!(matches!(inclusion::verify_invocation(pair, 0, &other_return), Err(Error::InvocationMismatch { .. })));

        assert!(matches!(inclusion::verify_invocation(pair, 1, &inv), Err(Error::NotAnInvocation { index: 1, .. })));
    }
}

#[test]
fn unknown_transactions_are_not_found() {
    let ledger = last().verify(&trust()).unwrap();
    let r = results();
    let pairs = inclusion::verify_results(ledger.header(), &r).unwrap();
    assert!(matches!(inclusion::find_result(pairs, &[7; 32]), Err(Error::TransactionNotFound(_))));
}

fn bundle() -> Bundle {
    let c = last();
    let inv = invocation(TX_4_EVENTS);
    Bundle {
        format: externalize_core::bundle::FORMAT.into(),
        network: Network::PUBLIC.into(),
        ledger: Xdr(c.header),
        scp: Xdr(c.scp),
        results: Some(Xdr(results())),
        transactions: None,
        claims: vec![
            Claim::Transaction { tx_hash: Hex32(hash(TX_25_EVENTS)) },
            Claim::Invocation {
                tx_hash: Hex32(hash(TX_4_EVENTS)),
                op_index: 0,
                return_value: Xdr(inv.return_value),
                events: inv.events.into_iter().map(Xdr).collect(),
            },
        ],
    }
}

/// The committed bundle is the cross-language conformance fixture: the Go node
/// must produce it byte for byte. Regenerate with `UPDATE_FIXTURES=1 cargo test`.
#[test]
fn committed_bundle_fixture_is_current_and_verifies() {
    let path = format!("{DIR}/bundle-64791359.json");
    let json = bundle().to_json().unwrap() + "\n";
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &json).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
    assert_eq!(committed, json, "run UPDATE_FIXTURES=1 cargo test to refresh");

    let verified = Bundle::from_json(&committed).unwrap().verify(&trust()).unwrap();
    assert_eq!(verified.ledger.sequence(), LAST);
    assert_eq!(verified.claims.len(), 2);
    assert!(verified.claims.iter().all(|(_, ok)| *ok));
}

#[test]
fn bundles_fail_closed() {
    let t = trust();

    let mut b = bundle();
    b.network = Network::TESTNET.into();
    assert!(matches!(b.verify(&t), Err(Error::NetworkMismatch { .. })));

    let mut b = bundle();
    b.results = None;
    assert_eq!(b.verify(&t).unwrap_err(), Error::MissingData("results"));

    let mut b = bundle();
    b.claims.push(Claim::Transaction { tx_hash: Hex32([9; 32]) });
    assert!(matches!(b.verify(&t), Err(Error::TransactionNotFound(_))));

    let mut b = bundle();
    b.transactions = Some(Xdr(transactions()));
    assert!(b.verify(&t).is_ok(), "a full transaction set strengthens, never weakens");

    let json = bundle().to_json().unwrap().replace(externalize_core::bundle::FORMAT, "externalize/bundle/v0");
    assert!(matches!(Bundle::from_json(&json), Err(Error::Format { .. })));
}

fn sha(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

#[test]
fn oversized_bundles_are_refused_before_any_work() {
    let mut b = bundle();
    let claim = b.claims[0].clone();
    b.claims = vec![claim; externalize_core::bundle::MAX_CLAIMS + 1];
    assert!(matches!(b.verify(&trust()), Err(Error::TooLarge { what: "claims", .. })));
    assert!(matches!(Bundle::from_json(&b.to_json().unwrap()), Err(Error::TooLarge { .. })));
}
