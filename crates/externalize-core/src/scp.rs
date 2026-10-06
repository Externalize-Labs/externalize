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
