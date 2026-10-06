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

/// Verifies a proof bundle (JSON text) and returns the report as an object.
///
/// Without `trust_toml`, the built-in trust set for the bundle's network is
/// used (public network tier-1, or testnet). With `events`, invocation claims
/// list their proven contract events, decoded. A bundle that does not verify
/// yields `{ verified: false, error }`; nothing throws.
#[wasm_bindgen]
pub fn verify(bundle_json: &str, trust_toml: Option<String>, events: Option<bool>) -> JsValue {
    let report = verify_to_json(bundle_json, trust_toml.as_deref(), events.unwrap_or(false));
    js_sys::JSON::parse(&report).unwrap_or(JsValue::NULL)
}

/// What a bundle claims, without verifying anything (`verified` is always
/// false). Throws if the text is not a bundle at all.
#[wasm_bindgen]
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
