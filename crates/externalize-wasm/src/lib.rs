//! The Externalize verifier for JavaScript: wallets and dapps check what an
//! RPC told them against validator signatures, in the browser.
//!
//! ```js
//! import init, { verify } from "externalize-wasm";
//! await init();
//! const report = verify(await (await fetch("/proof.json")).text());
//! if (!report.verified) throw new Error(report.error);
//! console.log(`ledger ${report.ledger.sequence}, ${report.ledger.signers.length} validators`);
//! ```
//!
//! The report has the same shape as `externalize verify --json`.

use externalize_core::{Bundle, TrustSet, report};
use wasm_bindgen::prelude::*;

// TypeScript types for the reports, matching `externalize_core::report`.
#[wasm_bindgen(typescript_custom_section)]
const REPORT_TYPES: &str = r#"
/** How one trusted organization voted on a certified ledger. */
export interface OrgAgreement {
  name: string;
  /** Distinct validators of this org whose EXTERNALIZE signatures verified. */
  signed: number;
  validators: number;
  /** Whether the org's own threshold was met. */
  satisfied: boolean;
}

/** A ledger whose header the trust set's validators signed. */
export interface CertifiedLedger {
  sequence: number;
  /** Ledger hash, lowercase hex. */
  hash: string;
  /** Close time, Unix seconds. */
  close_time: number;
  /** Validators whose signatures verified, as G… strkeys. */
  signers: string[];
  orgs: OrgAgreement[];
}

/** A proven contract event. `topics` and `data` are ScVals in stellar-xdr's JSON form. */
export interface DecodedEvent {
  /** Emitting contract, C… strkey. */
  contract: string | null;
  topics: unknown[];
  data: unknown;
}

/** The transaction was applied in the ledger (`succeeded` false: applied, but failed). */
export interface TransactionClaim {
  kind: "transaction";
  tx_hash: string;
  succeeded: boolean;
}

/** A contract call's return value and events, proven. */
export interface InvocationClaim {
  kind: "invocation";
  tx_hash: string;
  op_index: number;
  /** Number of proven events. */
  events: number;
  succeeded: boolean;
  /** Present when `verify` was called with `events: true`. */
  decoded_events?: DecodedEvent[];
}

export type Claim = TransactionClaim | InvocationClaim;

/** A bundle that verified: the certified ledger and every claim, proven. */
export interface VerifyReport {
  verified: true;
  ledger: CertifiedLedger;
  claims: Claim[];
}

/** An older ledger proven by walking previous-ledger hashes back from a certified one. */
export interface AncestryReport {
  verified: true;
  ledger: { sequence: number; hash: string; close_time: number };
  via: CertifiedLedger;
  links: number;
}

/** A bundle that did not verify. Nothing in it can be relied on. */
export interface Rejection {
  verified: false;
  error: string;
}

/** What `inspect` saw in a bundle. None of it is verified. */
export interface InspectReport {
  verified: false;
  network: string;
  ledger: { sequence: number; close_time: number; protocol: number };
  scp_envelopes: number;
  externalize_envelopes: number;
  /** Transactions in the bundled result set, or null without one. */
  results: number | null;
  transactions_included: boolean;
  claims: InspectClaim[];
}

export type InspectClaim =
  | { kind: "transaction"; tx_hash: string }
  | { kind: "invocation"; tx_hash: string; op_index: number; events: number };
"#;

/// Verifies a proof bundle (JSON text) and returns the report as an object.
///
/// Without `trust_toml`, the built-in trust set for the bundle's network is
/// used (public network tier-1, or testnet). With `events`, invocation claims
/// list their proven contract events, decoded. A bundle that does not verify
/// yields `{ verified: false, error }`; nothing throws.
#[wasm_bindgen(unchecked_return_type = "VerifyReport | Rejection")]
pub fn verify(bundle_json: &str, trust_toml: Option<String>, events: Option<bool>) -> JsValue {
    let report = verify_to_json(bundle_json, trust_toml.as_deref(), events.unwrap_or(false));
    js_sys::JSON::parse(&report).unwrap_or(JsValue::NULL)
}

/// What a bundle claims, without verifying anything (`verified` is always
/// false). Throws if the text is not a bundle at all.
#[wasm_bindgen(unchecked_return_type = "InspectReport")]
pub fn inspect(bundle_json: &str) -> Result<JsValue, JsError> {
    let text = inspect_to_json(bundle_json).map_err(|e| JsError::new(&e))?;
    js_sys::JSON::parse(&text).map_err(|_| JsError::new("could not build the inspection"))
}

/// [`inspect`] as plain Rust, returning JSON text.
pub fn inspect_to_json(bundle_json: &str) -> Result<String, String> {
    Bundle::from_json(bundle_json).map(|b| report::inspect(&b).to_string()).map_err(|e| e.to_string())
}

/// The built-in trust set for a network passphrase, as TOML, if there is one.
#[wasm_bindgen(js_name = builtinTrust)]
pub fn builtin_trust(passphrase: &str) -> Option<String> {
    match passphrase {
        externalize_core::Network::PUBLIC => Some(include_str!("../../../trust/public.toml").to_owned()),
        externalize_core::Network::TESTNET => Some(include_str!("../../../trust/testnet.toml").to_owned()),
        _ => None,
    }
}

/// [`verify`] as plain Rust, returning the report's JSON text.
pub fn verify_to_json(bundle_json: &str, trust_toml: Option<&str>, events: bool) -> String {
    let outcome = Bundle::from_json(bundle_json).and_then(|bundle| {
        let trust = match trust_toml {
            Some(text) => TrustSet::from_toml(text)?,
            None => match TrustSet::builtin(&bundle.network) {
                Some(t) => t?,
                None => {
                    return Ok(serde_json::json!({
                        "verified": false,
                        "error": format!("no built-in trust set for {:?}; pass one", bundle.network),
                    }));
                }
            },
        };
        Ok(match bundle.verify(&trust) {
            Ok(v) => report::verified(&v, &trust, events),
            Err(e) => report::rejected(&e),
        })
    });
    match outcome {
        Ok(v) => v.to_string(),
        Err(e) => report::rejected(&e).to_string(),
    }
}

/// Proves an older `ledger` from a proof bundle and archived `ledger-*.xdr.gz` files.
///
/// `header_files` are the gzipped contents of the archive checkpoint files covering
/// `ledger` up to the bundle's certified ledger. Returns `{ verified: true, ledger, via, links }`
/// or `{ verified: false, error }`; nothing throws.
#[wasm_bindgen(js_name = proveAncestor, unchecked_return_type = "AncestryReport | Rejection")]
pub fn prove_ancestor(
    bundle_json: &str,
    header_files: Vec<js_sys::Uint8Array>,
    ledger: u32,
    trust_toml: Option<String>,
) -> JsValue {
    let files: Vec<Vec<u8>> = header_files.into_iter().map(|a| a.to_vec()).collect();
    let slices: Vec<&[u8]> = files.iter().map(Vec::as_slice).collect();
    let report = prove_ancestor_to_json(bundle_json, &slices, ledger, trust_toml.as_deref());
    js_sys::JSON::parse(&report).unwrap_or(JsValue::NULL)
}

/// [`prove_ancestor`] as plain Rust, returning the report's JSON text.
pub fn prove_ancestor_to_json(
    bundle_json: &str,
    header_files: &[&[u8]],
    ledger: u32,
    trust_toml: Option<&str>,
) -> String {
    let outcome = Bundle::from_json(bundle_json).and_then(|bundle| {
        let trust = match trust_toml {
            Some(text) => TrustSet::from_toml(text)?,
            None => match TrustSet::builtin(&bundle.network) {
                Some(t) => t?,
                None => {
                    return Ok(serde_json::json!({
                        "verified": false,
                        "error": format!("no built-in trust set for {:?}; pass one", bundle.network),
                    }));
                }
            },
        };
        let mut headers = Vec::new();
        for bytes in header_files {
            headers.extend(externalize_core::archive::read_gz_frames(*bytes)?);
        }
        let verified = bundle.verify(&trust)?;
        let proven = externalize_core::prove_ancestor(&verified.ledger, &headers, ledger)?;
        Ok(report::ancestry(&proven, &verified.ledger, &trust))
    });
    match outcome {
        Ok(v) => v.to_string(),
        Err(e) => report::rejected(&e).to_string(),
    }
}
