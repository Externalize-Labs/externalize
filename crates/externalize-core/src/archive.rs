//! Reading Stellar history archive files.
//!
//! Archives publish one file per category every 64 ledgers (a checkpoint):
//! `ledger/` headers, `scp/` consensus messages, `results/` and
//! `transactions/`. Each file is a gzip of RFC 5531 record-marked XDR.
//! Certifying a ledger takes the `ledger`, `scp` and `transactions` files.

use std::io::Read;

use stellar_xdr::{Frame, LedgerHeaderHistoryEntry, Limited, ReadXdr, ScpHistoryEntry, TransactionHistoryEntry};

use crate::bundle::DECODE_LIMITS;
use crate::{Certificate, Error};

/// Ledgers per checkpoint.
pub const CHECKPOINT_FREQUENCY: u32 = 64;

/// The checkpoint whose files contain ledger `seq`.
pub fn checkpoint(seq: u32) -> u32 {
    (seq / CHECKPOINT_FREQUENCY).saturating_add(1).saturating_mul(CHECKPOINT_FREQUENCY).saturating_sub(1)
}

/// Archive-relative path of a checkpoint file, e.g. `scp/03/dc/a3/scp-03dca33f.xdr.gz`.
pub fn path(category: &str, checkpoint: u32) -> String {
    let h = format!("{checkpoint:08x}");
    let (a, rest) = h.split_at(2);
    let (b, rest) = rest.split_at(2);
    let (c, _) = rest.split_at(2);
    format!("{category}/{a}/{b}/{c}/{category}-{h}.xdr.gz")
}

/// Decodes every record of a decompressed archive stream.
pub fn read_frames<T: ReadXdr>(reader: impl Read) -> Result<Vec<T>, Error> {
    let mut r = Limited::new(reader, DECODE_LIMITS);
    Frame::<T>::read_xdr_iter(&mut r).map(|f| f.map(|f| f.0).map_err(|e| Error::xdr("archive record", e))).collect()
}

/// Decodes every record of a gzipped archive file.
pub fn read_gz_frames<T: ReadXdr>(reader: impl Read) -> Result<Vec<T>, Error> {
    read_frames(flate2::read::GzDecoder::new(reader))
}

/// Pairs each header with its SCP messages and the next ledger's SCP messages
/// and transaction set.
///
/// `scp` and `transactions` may hold several checkpoints' files: a
/// checkpoint's last ledger is certified by the next checkpoint's first.
/// Headers without SCP messages are skipped: there is nothing to certify them
/// with. A header whose successor data is missing is
/// [`Error::MissingSuccessor`], never a certificate.
pub fn certificates(
    headers: Vec<LedgerHeaderHistoryEntry>,
    scp: &[ScpHistoryEntry],
    transactions: &[TransactionHistoryEntry],
) -> Vec<Result<Certificate, Error>> {
    let scp_for = |seq: u32| scp.iter().find(|ScpHistoryEntry::V0(e)| e.ledger_messages.ledger_seq == seq).cloned();
    headers
        .into_iter()
        .filter_map(|header| {
            let seq = header.header.ledger_seq;
            let scp = scp_for(seq)?;
            let next = seq.checked_add(1);
            let next_scp = next.and_then(scp_for);
            let next_transactions = next.and_then(|n| transactions.iter().find(|t| t.ledger_seq == n).cloned());
            Some(match (next_scp, next_transactions) {
                (Some(next_scp), Some(next_transactions)) => {
                    Ok(Certificate { header, scp, next_scp, next_transactions })
                }
                _ => Err(Error::MissingSuccessor(seq)),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoints_and_paths() {
        assert_eq!(checkpoint(1), 63);
        assert_eq!(checkpoint(63), 63);
        assert_eq!(checkpoint(64), 127);
        assert_eq!(checkpoint(64_791_296), 64_791_359);
        assert_eq!(path("scp", 64_791_359), "scp/03/dc/a3/scp-03dca33f.xdr.gz");
    }

    #[test]
    fn truncated_streams_are_errors_not_panics() {
        let r: Result<Vec<ScpHistoryEntry>, _> = read_frames(&[0x80u8, 0, 0, 9, 1, 2][..]);
        assert!(r.is_err());
    }
}
