//! The JSON verification report, shared by the `externalize` CLI and the
//! WASM package so every front end describes a result the same way.
//!
//! ```json
//! { "verified": true,
//!   "ledger": { "sequence": 64791359, "hash": "…", "close_time": 1758…,
//!               "signers": ["G…"], "orgs": [{ "name": "…", "signed": 3, "validators": 3, "satisfied": true }] },
//!   "claims": [{ "kind": "invocation", "tx_hash": "…", "op_index": 0, "events": 2, "succeeded": true }] }
//! ```
//!
//! A rejection is `{ "verified": false, "error": "…" }`.

use serde_json::{Value, json};
use stellar_xdr::{ContractEvent, ContractEventBody};

use crate::bundle::{Claim, Verified};
use crate::{Error, TrustSet};

/// The report for a verified bundle. With `events`, each invocation claim
/// also lists its proven contract events, decoded.
#[allow(clippy::indexing_slicing, reason = "writing a key into a serde_json object never panics")]
pub fn verified(v: &Verified, trust: &TrustSet, events: bool) -> Value {
    let l = &v.ledger;
    let orgs: Vec<_> = trust
        .org_report(l.signers())
        .into_iter()
        .map(|o| json!({ "name": o.name, "signed": o.signed, "validators": o.validators, "satisfied": o.satisfied }))
        .collect();
    let claims: Vec<_> = v
        .claims
        .iter()
        .map(|(claim, succeeded)| match claim {
            Claim::Transaction { tx_hash } => {
                json!({ "kind": "transaction", "tx_hash": tx_hash.to_string(), "succeeded": succeeded })
            }
            Claim::Invocation { tx_hash, op_index, events: proven, .. } => {
                let mut c = json!({
                    "kind": "invocation", "tx_hash": tx_hash.to_string(), "op_index": op_index,
                    "events": proven.len(), "succeeded": succeeded,
                });
                if events {
                    c["decoded_events"] = proven.iter().map(|e| event(&e.0)).collect();
                }
                c
            }
        })
        .collect();
    json!({
        "verified": true,
        "ledger": {
            "sequence": l.sequence(),
            "hash": hex::encode(l.hash()),
            "close_time": l.close_time(),
            "signers": l.signers().iter().map(ToString::to_string).collect::<Vec<_>>(),
            "orgs": orgs,
        },
        "claims": claims,
    })
}

/// The report for a bundle that did not verify.
pub fn rejected(e: &Error) -> Value {
    json!({ "verified": false, "error": e.to_string() })
}

/// One proven contract event: contract, topics and data as JSON.
pub fn event(e: &ContractEvent) -> Value {
    let ContractEventBody::V0(body) = &e.body;
    json!({
        "contract": e.contract_id.as_ref().map(ToString::to_string),
        "topics": body.topics.iter().map(|t| serde_json::to_value(t).unwrap_or_default()).collect::<Vec<_>>(),
        "data": serde_json::to_value(&body.data).unwrap_or_default(),
    })
}

/// What a bundle claims, **without verifying any of it**: for showing a
/// bundle before (or instead of) checking it. Always `"verified": false`.
pub fn inspect(b: &crate::Bundle) -> Value {
    let h = &b.ledger.0.header;
    let stellar_xdr::ScpHistoryEntry::V0(scp) = &b.scp.0;
    let externalizing = scp
        .ledger_messages
        .messages
        .iter()
        .filter(|m| matches!(m.statement.pledges, stellar_xdr::ScpStatementPledges::Externalize(_)))
        .count();
    let claims: Vec<_> = b
        .claims
        .iter()
        .map(|c| match c {
            Claim::Transaction { tx_hash } => json!({ "kind": "transaction", "tx_hash": tx_hash.to_string() }),
            Claim::Invocation { tx_hash, op_index, events, .. } => json!({
                "kind": "invocation", "tx_hash": tx_hash.to_string(), "op_index": op_index, "events": events.len(),
            }),
        })
        .collect();
    json!({
        "verified": false,
        "network": b.network,
        "ledger": {
            "sequence": h.ledger_seq,
            "close_time": h.scp_value.close_time.0,
            "protocol": h.ledger_version,
        },
        "scp_envelopes": scp.ledger_messages.messages.len(),
        "externalize_envelopes": externalizing,
        "results": b.results.as_ref().map(|r| r.0.tx_result_set.results.len()),
        "transactions_included": b.transactions.is_some(),
        "claims": claims,
    })
}
