//! Proving that data was committed by a certified ledger.
//!
//! The header commits to its transaction set (`scpValue.txSetHash`) and to its
//! results (`txSetResultHash`). A successful `InvokeHostFunction` result is the
//! SHA-256 of the invocation's return value and contract events, which lets a
//! Soroban event be proven without trusting whoever served it.

use stellar_xdr::{
    ContractEvent, InnerTransactionResultResult, InvokeHostFunctionResult, InvokeHostFunctionSuccessPreImage,
    LedgerHeader, Limits, OperationResult, OperationResultTr, ScVal, TransactionEnvelope, TransactionHistoryEntry,
    TransactionHistoryEntryExt, TransactionHistoryResultEntry, TransactionPhase, TransactionResultPair,
    TransactionResultResult, TxSetComponent, WriteXdr,
};

use crate::{Error, Network, sha256};

/// Checks the result set against the header and returns it for lookups.
pub fn verify_results<'a>(
    header: &LedgerHeader,
    entry: &'a TransactionHistoryResultEntry,
) -> Result<&'a [TransactionResultPair], Error> {
    if entry.ledger_seq != header.ledger_seq {
        return Err(Error::LedgerMismatch { expected: header.ledger_seq, actual: entry.ledger_seq });
    }
    let xdr = entry.tx_result_set.to_xdr(Limits::none()).map_err(|e| Error::xdr("result set", e))?;
    if sha256(xdr) != header.tx_set_result_hash.0 {
        return Err(Error::CommitmentMismatch { ledger: header.ledger_seq, what: "result set" });
    }
    Ok(entry.tx_result_set.results.as_slice())
}

/// Checks the transaction set against the header and returns every envelope with its hash.
///
/// Fee-bump envelopes are hashed as the outer transaction, matching the hash
/// in the result set.
pub fn verify_transactions(
    network: &Network,
    header: &LedgerHeader,
    entry: &TransactionHistoryEntry,
) -> Result<Vec<([u8; 32], TransactionEnvelope)>, Error> {
    let seq = header.ledger_seq;
    if entry.ledger_seq != seq {
        return Err(Error::LedgerMismatch { expected: seq, actual: entry.ledger_seq });
    }
    let TransactionHistoryEntryExt::V1(set) = &entry.ext else {
        return Err(Error::LegacyTransactionSet(seq));
    };
    let xdr = set.to_xdr(Limits::none()).map_err(|e| Error::xdr("transaction set", e))?;
    if sha256(xdr) != header.scp_value.tx_set_hash.0 {
        return Err(Error::CommitmentMismatch { ledger: seq, what: "transaction set" });
    }

    let stellar_xdr::GeneralizedTransactionSet::V1(v1) = set;
    let mut out = Vec::new();
    for phase in v1.phases.iter() {
        let envelopes: Vec<&TransactionEnvelope> = match phase {
            TransactionPhase::V0(components) => {
                components.iter().flat_map(|TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c)| c.txs.iter()).collect()
            }
            TransactionPhase::V1(parallel) => parallel
                .execution_stages
                .iter()
                .flat_map(|stage| stage.0.iter())
                .flat_map(|cluster| cluster.0.iter())
                .collect(),
        };
        for env in envelopes {
            let hash = env.hash(network.id()).map_err(|e| Error::xdr("transaction envelope", e))?;
            out.push((hash, env.clone()));
        }
    }
    Ok(out)
}

/// Finds a transaction's result by hash.
pub fn find_result<'a>(
    results: &'a [TransactionResultPair],
    tx_hash: &[u8; 32],
) -> Result<&'a TransactionResultPair, Error> {
    results.iter().find(|p| &p.transaction_hash.0 == tx_hash).ok_or_else(|| Error::TransactionNotFound(hex(tx_hash)))
}

/// Operation results of a successful transaction (fee-bumped or not).
pub fn successful_operations(pair: &TransactionResultPair) -> Result<&[OperationResult], Error> {
    match &pair.result.result {
        TransactionResultResult::TxSuccess(ops) => Ok(ops.as_slice()),
        TransactionResultResult::TxFeeBumpInnerSuccess(inner) => match &inner.result.result {
            InnerTransactionResultResult::TxSuccess(ops) => Ok(ops.as_slice()),
            _ => Err(Error::TransactionFailed(hex(&pair.transaction_hash.0))),
        },
        _ => Err(Error::TransactionFailed(hex(&pair.transaction_hash.0))),
    }
}

/// The observable outcome of one `InvokeHostFunction` operation.
///
/// Take `return_value` from `sorobanMeta.returnValue` and `events` from the
/// operation's `events` in `TransactionMeta` v4 (or the contract events in
/// earlier meta versions). Diagnostic and transaction-level fee events are
/// not committed and cannot be proven.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// The contract call's return value.
    pub return_value: ScVal,
    /// Contract events emitted by the call, in order.
    pub events: Vec<ContractEvent>,
}

impl Invocation {
    /// SHA-256 of `InvokeHostFunctionSuccessPreImage`, the value stored in the result.
    pub fn commitment(&self) -> Result<[u8; 32], Error> {
        let pre = InvokeHostFunctionSuccessPreImage {
            return_value: self.return_value.clone(),
            events: self.events.clone().try_into().map_err(|e| Error::xdr("contract events", e))?,
        };
        pre.to_xdr(Limits::none()).map(sha256).map_err(|e| Error::xdr("invocation preimage", e))
    }
}

/// Checks that operation `index` of the transaction is a successful contract
/// call whose committed result hash matches `invocation`.
pub fn verify_invocation(pair: &TransactionResultPair, index: u32, invocation: &Invocation) -> Result<(), Error> {
    let tx = hex(&pair.transaction_hash.0);
    let op = successful_operations(pair)?.get(index as usize);
    let Some(OperationResult::OpInner(OperationResultTr::InvokeHostFunction(InvokeHostFunctionResult::Success(h)))) =
        op
    else {
        return Err(Error::NotAnInvocation { tx, index });
    };
    if invocation.commitment()? != h.0 {
        return Err(Error::InvocationMismatch { tx, index });
    }
    Ok(())
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
