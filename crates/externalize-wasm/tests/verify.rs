//! The JavaScript entry point's logic, run natively against the mainnet fixture.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]

use externalize_wasm::verify_to_json;
use serde_json::Value;

const BUNDLE: &str = include_str!("../../externalize-core/tests/fixtures/mainnet/bundle-64791359.json");

fn run(bundle: &str, trust: Option<&str>, events: bool) -> Value {
    serde_json::from_str(&verify_to_json(bundle, trust, events)).unwrap()
}

#[test]
fn verifies_the_mainnet_fixture_with_the_builtin_trust_set() {
    let r = run(BUNDLE, None, true);
    assert_eq!(r["verified"], true, "{r}");
    assert_eq!(r["ledger"]["sequence"], 64_791_359);
    assert_eq!(r["ledger"]["signers"].as_array().unwrap().len(), 30);
    let claims = r["claims"].as_array().unwrap();
    assert!(claims.iter().any(|c| c["kind"] == "invocation" && c["decoded_events"].is_array()));
}

#[test]
fn matches_the_cli_report_shape() {
    // Same keys as `externalize verify --json`, so front ends are interchangeable.
    let r = run(BUNDLE, None, false);
    for key in ["verified", "ledger", "claims"] {
        assert!(r.get(key).is_some(), "missing {key}");
    }
    assert!(r["claims"][0].get("decoded_events").is_none(), "events only on request");
}

#[test]
fn rejections_are_reports_not_errors() {
    let tampered = BUNDLE.replacen("\"ledger\": \"", "\"ledger\": \"AAAA", 1);
    for (bundle, trust) in
        [("not json", None), (tampered.as_str(), None), (BUNDLE, Some(include_str!("../../../trust/testnet.toml")))]
    {
        let r = run(bundle, trust, false);
        assert_eq!(r["verified"], false, "{r}");
        assert!(r["error"].as_str().is_some_and(|e| !e.is_empty()));
    }
}
