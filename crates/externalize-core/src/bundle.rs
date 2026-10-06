//! Self-contained proof bundles.
//!
//! A bundle is JSON whose payloads are base64 XDR, exactly as found in history
//! archives and RPC responses. Whoever produced it is untrusted: everything in
//! it is checked against the verifier's own [`TrustSet`].

use std::marker::PhantomData;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use stellar_xdr::{
    ContractEvent, LedgerHeaderHistoryEntry, Limits, ReadXdr, ScVal, ScpHistoryEntry, TransactionHistoryEntry,
    TransactionHistoryResultEntry, WriteXdr,
};

use crate::certificate::{Certificate, CertifiedLedger};
use crate::inclusion::{self, Invocation};
use crate::{Error, TrustSet};

/// Format tag every bundle carries.
pub const FORMAT: &str = "externalize/bundle/v1";

/// Upper bounds applied when decoding untrusted XDR.
pub const DECODE_LIMITS: Limits = Limits { depth: 512, len: 64 * 1024 * 1024 };

/// A ledger certificate plus the data needed to prove claims against it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    /// Always [`FORMAT`].
    pub format: String,
    /// Network passphrase the bundle claims to describe.
    pub network: String,
    /// `LedgerHeaderHistoryEntry` of the ledger.
    pub ledger: Xdr<LedgerHeaderHistoryEntry>,
    /// `ScpHistoryEntry` recorded for the ledger.
    pub scp: Xdr<ScpHistoryEntry>,
    /// `TransactionHistoryResultEntry`, required by every claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<Xdr<TransactionHistoryResultEntry>>,
    /// `TransactionHistoryEntry`; when present, claimed transactions must be in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transactions: Option<Xdr<TransactionHistoryEntry>>,
    /// Statements about the ledger to prove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Claim>,
}

/// Something the bundle asserts happened in the ledger.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Claim {
    /// The transaction was applied in this ledger (successfully or not).
    Transaction {
        /// Transaction hash, hex.
        tx_hash: Hex32,
    },
    /// Operation `op_index` was a successful contract call with exactly this
    /// return value and these contract events.
    Invocation {
        /// Transaction hash, hex.
        tx_hash: Hex32,
        /// Index of the `InvokeHostFunction` operation.
        op_index: u32,
        /// `ScVal`, base64 XDR.
        return_value: Xdr<ScVal>,
        /// `ContractEvent`s, base64 XDR, in emission order.
        events: Vec<Xdr<ContractEvent>>,
    },
}

/// Outcome of a fully verified bundle.
#[derive(Clone, Debug)]
pub struct Verified {
    /// The certified ledger.
    pub ledger: CertifiedLedger,
    /// Claims that were proven, in bundle order, each with the transaction's success flag.
    pub claims: Vec<(Claim, bool)>,
}

impl Bundle {
    /// Parses a bundle from JSON.
    pub fn from_json(text: &str) -> Result<Self, Error> {
        let b: Self =
            serde_json::from_str(text).map_err(|e| Error::Format { what: "bundle", reason: e.to_string() })?;
        if b.format != FORMAT {
            return Err(Error::Format { what: "bundle", reason: format!("unknown format {:?}", b.format) });
        }
        Ok(b)
    }

    /// Serializes the bundle to pretty JSON.
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Format { what: "bundle", reason: e.to_string() })
    }

    /// Certifies the ledger and proves every claim. Any failure rejects the whole bundle.
    pub fn verify(&self, trust: &TrustSet) -> Result<Verified, Error> {
        if self.network != trust.network().passphrase() {
            return Err(Error::NetworkMismatch {
                expected: trust.network().passphrase().to_owned(),
                actual: self.network.clone(),
            });
        }
        let cert = Certificate { header: self.ledger.0.clone(), scp: self.scp.0.clone() };
        let ledger = cert.verify(trust)?;
        if self.claims.is_empty() {
            return Ok(Verified { ledger, claims: Vec::new() });
        }

        let results = self.results.as_ref().ok_or(Error::MissingData("results"))?;
        let results = inclusion::verify_results(ledger.header(), &results.0)?;
        let applied = match &self.transactions {
            Some(t) => Some(inclusion::verify_transactions(trust.network(), ledger.header(), &t.0)?),
            None => None,
        };

        let mut claims = Vec::with_capacity(self.claims.len());
        for claim in &self.claims {
            let (Claim::Transaction { tx_hash } | Claim::Invocation { tx_hash, .. }) = claim;
            let pair = inclusion::find_result(results, &tx_hash.0)?;
            if let Some(set) = &applied
                && !set.iter().any(|(h, _)| h == &tx_hash.0)
            {
                return Err(Error::TransactionNotFound(tx_hash.to_string()));
            }
            let succeeded = inclusion::successful_operations(pair).is_ok();
            if let Claim::Invocation { op_index, return_value, events, .. } = claim {
                let inv = Invocation {
                    return_value: return_value.0.clone(),
                    events: events.iter().map(|e| e.0.clone()).collect(),
                };
                inclusion::verify_invocation(pair, *op_index, &inv)?;
            }
            claims.push((claim.clone(), succeeded));
        }
        Ok(Verified { ledger, claims })
    }
}

/// An XDR value carried as base64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xdr<T>(pub T);

impl<T: WriteXdr> Serialize for Xdr<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let b64 = self.0.to_xdr_base64(Limits::none()).map_err(serde::ser::Error::custom)?;
        s.serialize_str(&b64)
    }
}

impl<'de, T: ReadXdr> Deserialize<'de> for Xdr<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<T: ReadXdr> serde::de::Visitor<'_> for V<T> {
            type Value = Xdr<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("base64-encoded XDR")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                T::from_xdr_base64(v, DECODE_LIMITS).map(Xdr).map_err(E::custom)
            }
        }
        d.deserialize_str(V(PhantomData))
    }
}

/// A 32-byte hash carried as lowercase hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hex32(pub [u8; 32]);

impl std::fmt::Display for Hex32 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl std::str::FromStr for Hex32 {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = || Error::Format { what: "bundle", reason: format!("not a 32-byte hex hash: {s}") };
        let v = hex::decode(s).map_err(|_| bad())?;
        v.try_into().map(Hex32).map_err(|_| bad())
    }
}

impl Serialize for Hex32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hex32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
