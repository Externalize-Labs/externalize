//! SCP envelope signatures.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use stellar_xdr::{EnvelopeType, Limits, ScpEnvelope, ScpStatement, WriteXdr};

use crate::quorum::{NodeKey, node_key};
use crate::{Error, Network};

/// Bytes a validator signs: `networkID || ENVELOPE_TYPE_SCP || statement`.
///
/// Matches stellar-core's `HerderImpl::signEnvelope`. Ed25519 signs these bytes
/// directly; there is no pre-hash.
pub fn signing_payload(network: &Network, statement: &ScpStatement) -> Result<Vec<u8>, Error> {
    let mut out = network.id().to_vec();
    out.extend(EnvelopeType::Scp.to_xdr(Limits::none()).map_err(|e| Error::xdr("envelope type", e))?);
    out.extend(statement.to_xdr(Limits::none()).map_err(|e| Error::xdr("SCP statement", e))?);
    Ok(out)
}

/// Returns the signer's key if the envelope's signature is valid on `network`.
///
/// `None` covers every failure (malformed key, wrong length, bad signature):
/// an envelope that does not verify simply does not count.
pub fn verified_signer(network: &Network, envelope: &ScpEnvelope) -> Option<NodeKey> {
    let key = node_key(&envelope.statement.node_id);
    let vk = VerifyingKey::from_bytes(&key).ok()?;
    let sig = Signature::from_slice(envelope.signature.0.as_slice()).ok()?;
    let payload = signing_payload(network, &envelope.statement).ok()?;
    vk.verify(&payload, &sig).ok().map(|()| key)
}

/// Batch-verifies a slice of (envelope, network) pairs and returns the keys
/// of the valid signers, in the same order as the input.
///
/// Uses ed25519-dalek's batch verification: all valid signatures are checked
/// together in a single multi-scalar multiplication, which is faster than
/// verifying them one by one (about 3x for 30 signatures, per the dalek
/// benchmarks).
///
/// **Fail-closed semantics:** if the batch fails, we fall back to per-signature
/// verification to identify which envelopes are valid and which are not —
/// a batch failure is never reported as success.
///
/// Envelopes whose signature is invalid are simply excluded from the result
/// (matching `verified_signer`'s `None` semantics).
pub fn batch_verified_signers(
    network: &Network,
    envelopes: &[ScpEnvelope],
) -> Vec<Option<NodeKey>> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey, batch::Verifier as BatchVerifier};

    // Pre-compute payloads and parse keys/signatures once.
    // Invalid keys or signatures are marked as None up front.
    let mut parsed: Vec<Option<(VerifyingKey, Vec<u8>, Signature)>> = Vec::with_capacity(envelopes.len());
    let mut batch = BatchVerifier::new();

    for env in envelopes {
        let key = node_key(&env.statement.node_id);
        let vk = match VerifyingKey::from_bytes(&key) {
            Ok(vk) => vk,
            Err(_) => {
                parsed.push(None);
                continue;
            }
        };
        let sig = match Signature::from_slice(env.signature.0.as_slice()) {
            Ok(sig) => sig,
            Err(_) => {
                parsed.push(None);
                continue;
            }
        };
        let payload = match signing_payload(network, &env.statement) {
            Ok(p) => p,
            Err(_) => {
                parsed.push(None);
                continue;
            }
        };
        batch.verify(&vk, &payload, &sig);
        parsed.push(Some((vk, payload, sig)));
    }

    // Try batch verification first.
    if batch.verify().is_ok() {
        // Batch passed — all parsed signatures are valid.
        return envelopes
            .iter()
            .enumerate()
            .map(|(i, _)| {
                if parsed[i].is_some() {
                    Some(node_key(&envelopes[i].statement.node_id))
                } else {
                    None
                }
            })
            .collect();
    }

    // Batch failed — fall back to per-signature verification (fail-closed).
    parsed
        .iter()
        .enumerate()
        .map(|(i, p)| match p {
            None => None,
            Some((vk, payload, sig)) => {
                if vk.verify(payload, sig).is_ok() {
                    Some(node_key(&envelopes[i].statement.node_id))
                } else {
                    None
                }
            }
        })
        .collect()
}

