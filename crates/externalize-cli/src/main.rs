//! `externalize`: verify Stellar ledgers, transactions and Soroban events offline.

use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use externalize_core::bundle::{Claim, Verified};
use externalize_core::xdr::{Frame, Limited, Limits, ReadXdr, ScpHistoryEntry, ScpQuorumSet, ScpStatementPledges};
use externalize_core::{Bundle, Network, TrustSet, quorum};
use serde_json::json;

const PUBLIC_TRUST: &str = include_str!("../../../trust/public.toml");

#[derive(Parser)]
#[command(
    name = "externalize",
    version,
    about = "Verify Stellar ledgers, transactions and Soroban events from validator signatures."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a proof bundle. Exit status: 0 verified, 1 rejected, 2 could not run.
    Verify {
        /// Bundle file (`-` for stdin).
        bundle: PathBuf,
        /// Trust set to verify against. Defaults to the built-in public-network tier-1.
        #[arg(long)]
        trust: Option<PathBuf>,
        /// Print a machine-readable result.
        #[arg(long)]
        json: bool,
    },
    /// Inspect or derive trust sets.
    #[command(subcommand)]
    Trust(TrustCommand),
}

#[derive(Subcommand)]
enum TrustCommand {
    /// Summarize a trust set (the built-in one if no file is given).
    Show {
        /// Trust file.
        file: Option<PathBuf>,
    },
    /// Print, as TOML, the quorum set most validators referenced in an archive `scp-*.xdr.gz` file.
    ///
    /// The output is a starting point: name the orgs and review it before trusting it.
    Derive {
        /// SCP history file from a history archive.
        scp: PathBuf,
        /// Network the archive belongs to (`public`, `testnet` or a passphrase).
        #[arg(long, default_value = "public")]
        network: String,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Verify { bundle, trust, json } => verify(&bundle, trust.as_deref(), json),
        Command::Trust(TrustCommand::Show { file }) => {
            print!("{}", describe(&load_trust(file.as_deref())?));
            Ok(ExitCode::SUCCESS)
        }
        Command::Trust(TrustCommand::Derive { scp, network }) => {
            print!("{}", derive(&scp, &Network::from_name(&network))?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn read_input(path: &Path) -> Result<String, String> {
    if path == Path::new("-") {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(|e| format!("reading stdin: {e}"))?;
        return Ok(s);
    }
    std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

fn load_trust(path: Option<&Path>) -> Result<TrustSet, String> {
    let text = match path {
        Some(p) => read_input(p)?,
        None => PUBLIC_TRUST.to_owned(),
    };
    TrustSet::from_toml(&text).map_err(|e| e.to_string())
}

fn verify(bundle: &Path, trust: Option<&Path>, as_json: bool) -> Result<ExitCode, String> {
    let trust = load_trust(trust)?;
    let outcome = Bundle::from_json(&read_input(bundle)?).and_then(|b| b.verify(&trust));
    match (&outcome, as_json) {
        (Ok(v), true) => println!("{}", report_json(v)),
        (Ok(v), false) => print!("{}", report_text(v)),
        (Err(e), true) => println!("{}", json!({ "verified": false, "error": e.to_string() })),
        (Err(e), false) => eprintln!("REJECTED  {e}"),
    }
    Ok(if outcome.is_ok() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn short(h: &[u8; 32]) -> String {
    hex::encode(h.get(..6).unwrap_or_default())
}

fn report_text(v: &Verified) -> String {
    let l = &v.ledger;
    let mut out = format!(
        "VERIFIED  ledger {}\n  hash      {}\n  closed    {}\n  signers   {} trusted validators\n",
        l.sequence(),
        hex::encode(l.hash()),
        utc(l.close_time()),
        l.signers().len()
    );
    for (claim, succeeded) in &v.claims {
        let status = if *succeeded { "succeeded" } else { "applied, failed" };
        let _ = match claim {
            Claim::Transaction { tx_hash } => writeln!(out, "  tx        {}…  {status}", short(&tx_hash.0)),
            Claim::Invocation { tx_hash, op_index, events, .. } => writeln!(
                out,
                "  call      {}… op {op_index}  return value and {} event(s) proven",
                short(&tx_hash.0),
                events.len()
            ),
        };
    }
    out
}

fn report_json(v: &Verified) -> serde_json::Value {
    let l = &v.ledger;
    let claims: Vec<_> = v
        .claims
        .iter()
        .map(|(claim, succeeded)| match claim {
            Claim::Transaction { tx_hash } => {
                json!({ "kind": "transaction", "tx_hash": tx_hash.to_string(), "succeeded": succeeded })
            }
            Claim::Invocation { tx_hash, op_index, events, .. } => json!({
                "kind": "invocation", "tx_hash": tx_hash.to_string(), "op_index": op_index,
                "events": events.len(), "succeeded": succeeded,
            }),
        })
        .collect();
    json!({
        "verified": true,
        "ledger": {
            "sequence": l.sequence(),
            "hash": hex::encode(l.hash()),
            "close_time": l.close_time(),
            "signers": l.signers().iter().map(ToString::to_string).collect::<Vec<_>>(),
        },
        "claims": claims,
    })
}

fn describe(t: &TrustSet) -> String {
    let q = t.quorum();
    let mut out = format!(
        "network    {}\nthreshold  {} of {}\n",
        t.network().passphrase(),
        q.threshold,
        q.validators.len().saturating_add(q.inner_sets.len())
    );
    for v in q.validators.iter() {
        let _ = writeln!(out, "  validator {v}");
    }
    for (i, inner) in q.inner_sets.iter().enumerate() {
        let fallback = format!("org {}", i.saturating_add(1));
        let name = t.org_name(i).unwrap_or(&fallback);
        let _ = writeln!(out, "  {name:<32} {} of {}", inner.threshold, inner.validators.len());
    }
    out
}

/// Formats unix seconds as an RFC 3339 UTC timestamp (proleptic Gregorian, days-from-civil inverse).
#[allow(clippy::arithmetic_side_effects, reason = "every intermediate is bounded by one 400-year era")]
fn utc(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let rem = secs % 86_400;
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rem / 3_600, rem % 3_600 / 60, rem % 60)
}

fn read_scp(path: &Path) -> Result<Vec<ScpHistoryEntry>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut r = Limited::new(flate2::read::GzDecoder::new(file), Limits::none());
    Frame::<ScpHistoryEntry>::read_xdr_iter(&mut r)
        .map(|f| f.map(|f| f.0).map_err(|e| format!("decoding {}: {e}", path.display())))
        .collect()
}

/// The quorum set referenced by the most EXTERNALIZE statements in the file.
fn dominant_quorum_set(entries: &[ScpHistoryEntry]) -> Result<ScpQuorumSet, String> {
    let mut sets: Vec<([u8; 32], ScpQuorumSet, usize)> = Vec::new();
    for ScpHistoryEntry::V0(e) in entries {
        for q in e.quorum_sets.iter() {
            let h = quorum::hash(q).map_err(|e| e.to_string())?;
            if !sets.iter().any(|(k, _, _)| *k == h) {
                sets.push((h, q.clone(), 0));
            }
        }
    }
    for ScpHistoryEntry::V0(e) in entries {
        for m in e.ledger_messages.messages.iter() {
            if let ScpStatementPledges::Externalize(x) = &m.statement.pledges
                && let Some((_, _, n)) = sets.iter_mut().find(|(k, _, _)| *k == x.commit_quorum_set_hash.0)
            {
                *n = n.saturating_add(1);
            }
        }
    }
    sets.into_iter()
        .max_by_key(|(_, _, n)| *n)
        .filter(|(_, _, n)| *n > 0)
        .map(|(_, q, _)| q)
        .ok_or_else(|| "no EXTERNALIZE statement references a quorum set recorded in the file".to_owned())
}

fn derive(path: &Path, network: &Network) -> Result<String, String> {
    let q = dominant_quorum_set(&read_scp(path)?)?;
    TrustSet::new(network.clone(), q.clone()).map_err(|e| e.to_string())?;
    if q.inner_sets.iter().any(|i| !i.inner_sets.is_empty()) {
        return Err("quorum sets nested deeper than orgs are not expressible in trust files yet".into());
    }

    let net = match network.passphrase() {
        Network::PUBLIC => "public".to_owned(),
        Network::TESTNET => "testnet".to_owned(),
        p => format!("{p:?}"),
    };
    let list = |vs: &[externalize_core::xdr::NodeId]| vs.iter().map(|v| format!("  \"{v}\",\n")).collect::<String>();
    let mut out = format!(
        "# Derived from {}. Name each org and review before trusting.\n\nnetwork = \"{net}\"\nthreshold = {}\n",
        path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
        q.threshold
    );
    if !q.validators.is_empty() {
        let _ = writeln!(out, "validators = [\n{}]", list(&q.validators));
    }
    for (i, inner) in q.inner_sets.iter().enumerate() {
        let _ = write!(
            out,
            "\n[[org]]\nname = \"org-{}\"\nthreshold = {}\nvalidators = [\n{}]\n",
            i.saturating_add(1),
            inner.threshold,
            list(&inner.validators)
        );
    }
    Ok(out)
}
