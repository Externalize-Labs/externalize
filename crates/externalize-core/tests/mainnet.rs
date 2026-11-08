//! Verification against real public-network data: history archive checkpoint
//! 64791359 (ledgers 64791296..=64791359) and two Soroban transactions from
//! its last ledger, fetched from mainnet RPC.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Read;

use externalize_core::archive;
use externalize_core::bundle::{Claim, Hex32, Xdr};
use externalize_core::inclusion::{self, Invocation};
use externalize_core::xdr::*;
use externalize_core::{Bundle, Certificate, Error, Network, TrustSet, prove_ancestor, verify_ancestors};
use flate2::read::GzDecoder;
use sha2::Digest;

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

/// SCP messages of the fixture checkpoint and of the next one (64791360..=64791423).
fn scp() -> Vec<ScpHistoryEntry> {
    let mut scp: Vec<ScpHistoryEntry> = frames("scp-03dca33f.xdr.gz");
    scp.extend(frames::<ScpHistoryEntry>("scp-03dca37f.xdr.gz"));
    scp
}

fn scp_for(seq: u32) -> ScpHistoryEntry {
    scp().into_iter().find(|ScpHistoryEntry::V0(e)| e.ledger_messages.ledger_seq == seq).unwrap()
}

/// Ledger 64791360's transaction set, the first of the next checkpoint.
fn next_transactions() -> TransactionHistoryEntry {
    frames::<TransactionHistoryEntry>("transactions-64791360.xdr.gz").remove(0)
}

fn headers() -> Vec<LedgerHeaderHistoryEntry> {
    frames("ledger-03dca33f.xdr.gz")
}

/// The fixture checkpoint's certificates, with the two transaction sets the
/// fixtures carry: those of 64791359 and 64791360.
fn certificates() -> Vec<Result<Certificate, Error>> {
    archive::certificates(headers(), &scp(), &[transactions(), next_transactions()])
}

fn last() -> Certificate {
    certificates().pop().unwrap().unwrap()
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
fn a_ledger_is_certified_through_its_successor_and_only_then() {
    let t = trust();
    let certs = certificates();
    assert_eq!(certs.len(), 64);
    // Only 64791358 and 64791359 have their successor's transaction set in the fixtures.
    for (i, c) in certs.iter().enumerate() {
        let seq = LAST - 63 + i as u32;
        match c {
            Ok(c) => {
                let ledger = c.verify(&t).unwrap();
                assert_eq!(ledger.sequence(), seq);
                assert_eq!(ledger.signers().len(), 30, "ledger {seq}");
                assert!(seq >= LAST - 1);
            }
            Err(e) => {
                assert_eq!(e, &Error::MissingSuccessor(seq));
                assert!(seq < LAST - 1);
            }
        }
    }
}

#[test]
fn certified_ledger_vouches_for_its_ancestors() {
    let t = trust();
    let newest = last().verify(&t).unwrap();
    let mut older = headers();
    older.pop();
    let seqs = verify_ancestors(&newest, &older).unwrap();
    assert_eq!(seqs.len(), 63);
    assert_eq!(seqs.first(), Some(&(LAST - 1)));
}

/// Headers of both fixture checkpoints: 64791232..=64791295 and 64791296..=64791359.
fn two_checkpoints_of_headers() -> Vec<LedgerHeaderHistoryEntry> {
    let mut headers: Vec<LedgerHeaderHistoryEntry> = frames("ledger-03dca2ff.xdr.gz");
    headers.extend(frames::<LedgerHeaderHistoryEntry>("ledger-03dca33f.xdr.gz"));
    headers
}

const IN_PREVIOUS_CHECKPOINT: u32 = 64_791_250;

#[test]
fn a_certified_ledger_proves_one_from_the_previous_checkpoint() {
    let newest = last().verify(&trust()).unwrap();
    let proven = prove_ancestor(&newest, &two_checkpoints_of_headers(), IN_PREVIOUS_CHECKPOINT).unwrap();
    assert_eq!(proven.header.ledger_seq, IN_PREVIOUS_CHECKPOINT);
    // The proven entry's hash is its header's, and the next ledger links to it.
    let hash: [u8; 32] = sha2::Sha256::digest(proven.header.to_xdr(Limits::none()).unwrap()).into();
    assert_eq!(proven.hash.0, hash);
    let next =
        two_checkpoints_of_headers().into_iter().find(|e| e.header.ledger_seq == IN_PREVIOUS_CHECKPOINT + 1).unwrap();
    assert_eq!(next.header.previous_ledger_hash.0, hash);
}

#[test]
fn an_edited_header_breaks_the_chain_even_with_its_hash_recomputed() {
    let newest = last().verify(&trust()).unwrap();
    let mut headers = two_checkpoints_of_headers();
    let forged = headers.iter_mut().find(|e| e.header.ledger_seq == 64_791_300).unwrap();
    forged.header.scp_value.close_time.0 += 1;
    forged.hash = Hash(sha2::Sha256::digest(forged.header.to_xdr(Limits::none()).unwrap()).into());
    // Ledger 64791301 still names the genuine header's hash, so the walk stops there.
    assert_eq!(prove_ancestor(&newest, &headers, IN_PREVIOUS_CHECKPOINT), Err(Error::BrokenChain(64_791_300)));
}

#[test]
fn a_missing_archive_file_is_named_by_its_newest_ledger() {
    let newest = last().verify(&trust()).unwrap();
    let only_newer: Vec<LedgerHeaderHistoryEntry> = frames("ledger-03dca33f.xdr.gz");
    assert_eq!(prove_ancestor(&newest, &only_newer, IN_PREVIOUS_CHECKPOINT), Err(Error::MissingHeader(64_791_295)));
}

#[test]
fn a_ledger_vouches_only_for_its_ancestors() {
    let newest = last().verify(&trust()).unwrap();
    for target in [LAST, LAST + 1] {
        assert_eq!(
            prove_ancestor(&newest, &two_checkpoints_of_headers(), target),
            Err(Error::NotAnAncestor { ledger: target, trusted: LAST })
        );
    }
}

#[test]
fn a_gap_in_the_ancestor_chain_is_rejected() {
    let newest = last().verify(&trust()).unwrap();
    let mut older = headers();
    older.pop();
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
    let c = Certificate { scp: scp_for(LAST - 1), ..last() };
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
        next_scp: Xdr(c.next_scp),
        next_transactions: Xdr(c.next_transactions),
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

    // Both successor fields are required.
    for field in ["next_scp", "next_transactions"] {
        let mut v: serde_json::Value = serde_json::from_str(&bundle().to_json().unwrap()).unwrap();
        v.as_object_mut().unwrap().remove(field);
        let Err(Error::Format { reason, .. }) = Bundle::from_json(&v.to_string()) else { panic!("{field} optional") };
        assert!(reason.contains(field), "{reason}");
    }
}

// --- Forgeries of the parts of a header that slot N's signatures do not cover ---

fn header_hash(h: &LedgerHeader) -> Hash {
    Hash(sha(&h.to_xdr(Limits::none()).unwrap()))
}

/// The attack v1 bundles allowed: rewrite the result set, then recompute
/// `txSetResultHash` and the header hash. `scpValue` is untouched, so slot N's
/// signatures still match.
fn forge_results(b: &mut Bundle, edit: impl FnOnce(&mut Vec<TransactionResultPair>)) {
    let r = &mut b.results.as_mut().unwrap().0;
    let mut pairs = r.tx_result_set.results.to_vec();
    edit(&mut pairs);
    r.tx_result_set.results = pairs.try_into().unwrap();
    let header = &mut b.ledger.0.header;
    header.tx_set_result_hash = Hash(sha(&r.tx_result_set.to_xdr(Limits::none()).unwrap()));
    b.ledger.0.hash = header_hash(header);
    // Self-consistent: the forged results match the forged header.
    inclusion::verify_results(&b.ledger.0.header, r).unwrap();
}

#[test]
fn forged_results_with_recomputed_hashes_are_rejected() {
    let t = trust();

    // A successful transaction reported as failed.
    let mut b = bundle();
    forge_results(&mut b, |pairs| {
        let p = pairs.iter_mut().find(|p| p.transaction_hash.0 == hash(TX_25_EVENTS)).unwrap();
        p.result.result = TransactionResultResult::TxFailed(VecM::default());
    });
    assert_eq!(b.verify(&t).unwrap_err(), Error::HeaderNotCommitted(LAST));

    // A transaction that never happened.
    let mut b = bundle();
    forge_results(&mut b, |pairs| {
        let mut fake = pairs[0].clone();
        fake.transaction_hash = Hash([7; 32]);
        pairs.push(fake);
    });
    b.claims = vec![Claim::Transaction { tx_hash: Hex32([7; 32]) }];
    assert_eq!(b.verify(&t).unwrap_err(), Error::HeaderNotCommitted(LAST));
}

#[test]
fn a_forged_previous_ledger_hash_cannot_prove_a_forged_ancestor() {
    // A fake ledger 64791358, and a 64791359 that links to it.
    let mut fake = headers().into_iter().find(|e| e.header.ledger_seq == LAST - 1).unwrap();
    fake.header.bucket_list_hash = Hash([7; 32]);
    let mut c = last();
    c.header.header.previous_ledger_hash = header_hash(&fake.header);
    c.header.hash = header_hash(&c.header.header);
    // Under v1 this certified, and prove_ancestor then accepted the fake;
    // now the trusted ledger itself is refused.
    assert_eq!(c.verify(&trust()).unwrap_err(), Error::HeaderNotCommitted(LAST));

    let mut b = bundle();
    b.ledger = Xdr(c.header);
    assert_eq!(b.verify(&trust()).unwrap_err(), Error::HeaderNotCommitted(LAST));
}

#[test]
fn a_successor_transaction_set_that_does_not_match_the_externalized_value_is_rejected() {
    let t = trust();

    // Another ledger's genuine set, relabeled.
    let mut other = transactions();
    other.ledger_seq = LAST + 1;
    let c = Certificate { next_transactions: other, ..last() };
    assert_eq!(c.verify(&t).unwrap_err(), Error::SuccessorTxSetMismatch(LAST + 1));

    // One transaction's fee changed.
    let mut c = last();
    let TransactionHistoryEntryExt::V1(GeneralizedTransactionSet::V1(set)) = &mut c.next_transactions.ext else {
        panic!("mainnet runs generalized sets")
    };
    let mut phases = set.phases.to_vec();
    let TransactionPhase::V0(components) = &mut phases[0] else { panic!("classic phase is V0") };
    let mut comps = components.to_vec();
    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = &mut comps[0];
    let mut txs = comp.txs.to_vec();
    let TransactionEnvelope::Tx(tx) = &mut txs[0] else { panic!("first envelope is v1") };
    tx.tx.fee += 1;
    comp.txs = txs.try_into().unwrap();
    *components = comps.try_into().unwrap();
    set.phases = phases.try_into().unwrap();
    assert_eq!(c.verify(&t).unwrap_err(), Error::SuccessorTxSetMismatch(LAST + 1));

    // The right set, but claimed for the wrong ledger.
    let c = Certificate { next_transactions: transactions(), ..last() };
    assert_eq!(c.verify(&t).unwrap_err(), Error::LedgerMismatch { expected: LAST + 1, actual: LAST });
}

#[test]
fn a_successor_transaction_set_naming_another_previous_ledger_is_rejected() {
    let mut c = last();
    let TransactionHistoryEntryExt::V1(GeneralizedTransactionSet::V1(set)) = &mut c.next_transactions.ext else {
        panic!("mainnet runs generalized sets")
    };
    set.previous_ledger_hash = Hash([7; 32]);
    // The set's hash covers previousLedgerHash, so it no longer matches V.
    assert_eq!(c.verify(&trust()).unwrap_err(), Error::SuccessorTxSetMismatch(LAST + 1));
}

#[test]
fn successor_scp_for_the_wrong_slot_is_rejected() {
    let t = trust();
    let c = Certificate { next_scp: scp_for(LAST), ..last() };
    assert_eq!(c.verify(&t).unwrap_err(), Error::LedgerMismatch { expected: LAST + 1, actual: LAST });

    // Relabeled, its envelopes are still for slot N and do not count.
    let mut relabeled = scp_for(LAST);
    let ScpHistoryEntry::V0(e) = &mut relabeled;
    e.ledger_messages.ledger_seq = LAST + 1;
    let c = Certificate { next_scp: relabeled, ..last() };
    assert_eq!(c.verify(&t).unwrap_err(), Error::QuorumNotSatisfied { ledger: LAST + 1, signers: 0 });

    // Slot N+2's genuine messages.
    let c = Certificate { next_scp: scp_for(LAST + 2), ..last() };
    assert_eq!(c.verify(&t).unwrap_err(), Error::LedgerMismatch { expected: LAST + 1, actual: LAST + 2 });
}

#[test]
fn successor_scp_without_a_quorum_is_rejected() {
    let t = trust();
    let mut c = last();
    let ScpHistoryEntry::V0(e) = &mut c.next_scp;
    let kept: Vec<ScpEnvelope> = e.ledger_messages.messages.iter().filter(|m| org_of(&t, m) < 6).cloned().collect();
    e.ledger_messages.messages = kept.try_into().unwrap();
    assert!(matches!(c.verify(&t), Err(Error::QuorumNotSatisfied { ledger, .. }) if ledger == LAST + 1));

    let mut c = last();
    let ScpHistoryEntry::V0(e) = &mut c.next_scp;
    e.ledger_messages.messages = VecM::default();
    assert_eq!(c.verify(&t).unwrap_err(), Error::QuorumNotSatisfied { ledger: LAST + 1, signers: 0 });
}

/// Three validators with known keys, two of which must agree. Real mainnet
/// signatures never equivocate, so equivocation needs keys we hold.
mod synthetic {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub fn keys() -> Vec<SigningKey> {
        (1..=3u8).map(|i| SigningKey::from_bytes(&[i; 32])).collect()
    }

    fn node(k: &SigningKey) -> NodeId {
        NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(k.verifying_key().to_bytes())))
    }

    pub fn trust() -> TrustSet {
        let validators: Vec<NodeId> = keys().iter().map(node).collect();
        let q = ScpQuorumSet { threshold: 2, validators: validators.try_into().unwrap(), inner_sets: VecM::default() };
        TrustSet::new(Network::public(), q).unwrap()
    }

    pub fn externalize(k: &SigningKey, slot: u32, value: &StellarValue) -> ScpEnvelope {
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
    }

    pub fn entry(slot: u32, messages: Vec<ScpEnvelope>) -> ScpHistoryEntry {
        ScpHistoryEntry::V0(ScpHistoryEntryV0 {
            quorum_sets: VecM::default(),
            ledger_messages: LedgerScpMessages { ledger_seq: slot, messages: messages.try_into().unwrap() },
        })
    }

    /// Ledger 64791360's genuine externalized value.
    pub fn next_value() -> StellarValue {
        let ScpHistoryEntry::V0(e) = scp_for(LAST + 1);
        let ScpStatementPledges::Externalize(x) = &e.ledger_messages.messages[0].statement.pledges else { panic!() };
        StellarValue::from_xdr(x.commit.value.0.as_slice(), Limits::none()).unwrap()
    }

    /// The real 64791359 certificate, re-signed by the synthetic validators.
    pub fn certificate(next: [&StellarValue; 3]) -> Certificate {
        let c = last();
        let keys = keys();
        let scp = entry(LAST, keys.iter().map(|k| externalize(k, LAST, &c.header.header.scp_value)).collect());
        let next_scp = entry(LAST + 1, keys.iter().zip(next).map(|(k, v)| externalize(k, LAST + 1, v)).collect());
        Certificate { scp, next_scp, ..c }
    }
}

#[test]
fn synthetic_validators_certify_the_genuine_chain() {
    let v = synthetic::next_value();
    assert_eq!(synthetic::certificate([&v, &v, &v]).verify(&synthetic::trust()).unwrap().signers().len(), 3);
}

#[test]
fn an_equivocating_validator_in_the_successor_scp_is_rejected() {
    let v = synthetic::next_value();
    let mut other = v.clone();
    other.close_time.0 += 1;
    let c = synthetic::certificate([&v, &v, &other]);
    let node = synthetic::keys()[2].verifying_key().to_bytes();
    let node = NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(node))).to_string();
    assert_eq!(c.verify(&synthetic::trust()).unwrap_err(), Error::Equivocation { ledger: LAST + 1, node });
}

#[test]
fn a_successor_whose_consensus_names_another_previous_ledger_is_rejected() {
    // Validators agree on a set that names another previous ledger: the set
    // matches V, but not this header.
    let mut c = last();
    let TransactionHistoryEntryExt::V1(GeneralizedTransactionSet::V1(set)) = &mut c.next_transactions.ext else {
        panic!("mainnet runs generalized sets")
    };
    set.previous_ledger_hash = Hash([7; 32]);
    let mut v = synthetic::next_value();
    v.tx_set_hash = Hash(inclusion::tx_set_hash(&c.next_transactions).unwrap().0);
    let c = Certificate { next_transactions: c.next_transactions, ..synthetic::certificate([&v, &v, &v]) };
    assert_eq!(c.verify(&synthetic::trust()).unwrap_err(), Error::HeaderNotCommitted(LAST));
}

#[test]
fn v1_bundles_are_refused_with_a_reason() {
    // The v1 shape: no successor fields.
    let mut v: serde_json::Value = serde_json::from_str(&bundle().to_json().unwrap()).unwrap();
    let o = v.as_object_mut().unwrap();
    o.remove("next_scp");
    o.remove("next_transactions");
    o.insert("format".into(), externalize_core::bundle::FORMAT_V1.into());
    let err = Bundle::from_json(&v.to_string()).unwrap_err();
    assert_eq!(err, Error::V1Bundle);
    assert!(err.to_string().contains("rebuild it as externalize/bundle/v2"), "{err}");

    // Retagged as v1, even with the successor fields.
    let json =
        bundle().to_json().unwrap().replace(externalize_core::bundle::FORMAT, externalize_core::bundle::FORMAT_V1);
    assert_eq!(Bundle::from_json(&json).unwrap_err(), Error::V1Bundle);

    let mut b = bundle();
    b.format = externalize_core::bundle::FORMAT_V1.into();
    assert_eq!(b.verify(&trust()).unwrap_err(), Error::V1Bundle);
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

#[test]
fn replaying_one_validators_signature_cannot_fake_a_quorum() {
    let t = trust();
    let c = last();
    let ScpHistoryEntry::V0(e) = &c.scp;
    let one = e.ledger_messages.messages[0].clone();
    let forged = with_envelopes(c, |_| Some(one.clone()));
    assert_eq!(forged.verify(&t).unwrap_err(), Error::QuorumNotSatisfied { ledger: LAST, signers: 1 });
}

#[test]
fn untrusted_validators_never_count_even_with_valid_signatures() {
    let t = trust();
    let sdf_only = TrustSet::new(
        Network::public(),
        ScpQuorumSet {
            threshold: 1,
            validators: VecM::default(),
            inner_sets: vec![t.quorum().inner_sets[1].clone()].try_into().unwrap(),
        },
    )
    .unwrap();
    let ledger = last().verify(&sdf_only).unwrap();
    assert_eq!(ledger.signers().len(), 3, "only SDF's three validators are trusted");
}
