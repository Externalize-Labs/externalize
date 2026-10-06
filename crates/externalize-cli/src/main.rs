//! `externalize`: verify Stellar ledgers, transactions and Soroban events offline.

use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use externalize_core::bundle::{Claim, Verified};
use externalize_core::xdr::{ReadXdr, ScpHistoryEntry, ScpQuorumSet, ScpStatementPledges};
use externalize_core::{Bundle, Network, TrustSet, archive, quorum, report};

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
        /// Trust set to verify against. Defaults to the built-in set for the bundle's network.
        #[arg(long)]
        trust: Option<PathBuf>,
        /// Print a machine-readable result.
        #[arg(long)]
        json: bool,
        /// Also print every proven contract event, decoded.
        #[arg(long)]
        events: bool,
    },
    /// Show what a bundle claims, without verifying anything.
    Inspect {
        /// Bundle file (`-` for stdin).
        bundle: PathBuf,
        /// Machine-readable output, the same shape the WASM package's `inspect` returns.
        #[arg(long)]
        json: bool,
    },
    /// Certify every ledger in a history archive checkpoint, from its `ledger-*` and `scp-*` files.
    Certify {
        /// `ledger-*.xdr.gz` file.
        #[arg(long)]
        ledger: PathBuf,
        /// `scp-*.xdr.gz` file from the same checkpoint.
        #[arg(long)]
        scp: PathBuf,
        /// Trust set. Defaults to the built-in set for `--network`.
        #[arg(long)]
        trust: Option<PathBuf>,
        /// Network for the built-in trust set (`public` or `testnet`).
        #[arg(long, default_value = "public")]
        network: String,
    },
    /// Inspect or derive trust sets.
    #[command(subcommand)]
    Trust(TrustCommand),
}

#[derive(Subcommand)]
enum TrustCommand {
    /// Summarize a trust set (the built-in one for `--network` if no file is given).
    Show {
        /// Trust file.
        file: Option<PathBuf>,
        /// Network for the built-in trust set (`public` or `testnet`).
        #[arg(long, default_value = "public")]
        network: String,
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
        /// Existing trust file whose org names to reuse for orgs with the same validators.
        #[arg(long)]
        names_from: Option<PathBuf>,
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
        Command::Verify { bundle, trust, json, events } => verify(&bundle, trust.as_deref(), json, events),
        Command::Inspect { bundle, json } => {
            let b = Bundle::from_json(&read_input(&bundle)?).map_err(|e| e.to_string())?;
            if json {
                println!("{}", report::inspect(&b));
            } else {
                print!("{}", inspect(&b));
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Certify { ledger, scp, trust, network } => certify(&ledger, &scp, trust.as_deref(), &network),
        Command::Trust(TrustCommand::Show { file, network }) => {
            print!("{}", describe(&load_trust(file.as_deref(), &network)?));
            Ok(ExitCode::SUCCESS)
        }
        Command::Trust(TrustCommand::Derive { scp, network, names_from }) => {
            let known = match names_from {
                Some(p) => Some(TrustSet::from_toml(&read_input(&p)?).map_err(|e| e.to_string())?),
                None => None,
            };
            print!("{}", derive(&scp, &Network::from_name(&network), known.as_ref())?);
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

/// Loads `path`, or the built-in trust set for `network` when no path is given.
fn load_trust(path: Option<&Path>, network: &str) -> Result<TrustSet, String> {
    let text = match path {
        Some(p) => read_input(p)?,
        None => {
            let passphrase = Network::from_name(network).passphrase().to_owned();
            return TrustSet::builtin(&passphrase)
                .ok_or_else(|| format!("no built-in trust set for {passphrase:?}; pass --trust"))?
                .map_err(|e| e.to_string());
        }
    };
    TrustSet::from_toml(&text).map_err(|e| e.to_string())
}

fn verify(bundle: &Path, trust: Option<&Path>, as_json: bool, events: bool) -> Result<ExitCode, String> {
    let outcome = match Bundle::from_json(&read_input(bundle)?) {
        Ok(b) => {
            let trust = load_trust(trust, &b.network)?;
            b.verify(&trust).map(|v| (v, trust))
        }
        Err(e) => Err(e),
    };
    match (&outcome, as_json) {
        (Ok((v, t)), true) => println!("{}", report::verified(v, t, events)),
        (Ok((v, t)), false) => print!("{}", report_text(v, t, events)),
        (Err(e), true) => println!("{}", report::rejected(e)),
        (Err(e), false) => eprintln!("REJECTED  {e}"),
    }
    Ok(if outcome.is_ok() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn short(h: &[u8; 32]) -> String {
    hex::encode(h.get(..6).unwrap_or_default())
}

/// Describes a bundle's contents. Nothing here is verified.
fn inspect(b: &Bundle) -> String {
    let h = &b.ledger.0.header;
    let externalize_core::xdr::ScpHistoryEntry::V0(scp) = &b.scp.0;
    let externalizing = scp
        .ledger_messages
        .messages
        .iter()
        .filter(|m| matches!(m.statement.pledges, ScpStatementPledges::Externalize(_)))
        .count();
    let mut out = format!(
        "UNVERIFIED bundle for ledger {}
  network   {}
  closed    {}
  protocol  {}
  scp       {} envelopes ({} externalize)
",
        h.ledger_seq,
        b.network,
        utc(h.scp_value.close_time.0),
        h.ledger_version,
        scp.ledger_messages.messages.len(),
        externalizing
    );
    if let Some(r) = &b.results {
        let _ = writeln!(out, "  results   {} transactions", r.0.tx_result_set.results.len());
    }
    if b.transactions.is_some() {
        out.push_str(
            "  txset     included
",
        );
    }
    for claim in &b.claims {
        let _ = match claim {
            Claim::Transaction { tx_hash } => writeln!(out, "  claim     transaction {tx_hash}"),
            Claim::Invocation { tx_hash, op_index, events, .. } => {
                writeln!(out, "  claim     invocation {tx_hash} op {op_index}, {} events", events.len())
            }
        };
    }
    out.push_str(
        "Run `externalize verify` to check any of this.
",
    );
    out
}

#[allow(clippy::indexing_slicing, reason = "reading serde_json::Value by key yields Null, never panics")]
fn report_text(v: &Verified, trust: &TrustSet, show_events: bool) -> String {
    let l = &v.ledger;
    let orgs = trust.org_report(l.signers());
    let agreed: Vec<&str> = orgs.iter().filter(|o| o.satisfied).map(|o| o.name.as_str()).collect();
    let mut out = format!(
        "VERIFIED  ledger {}\n  hash      {}\n  closed    {}\n  signers   {} trusted validators\n",
        l.sequence(),
        hex::encode(l.hash()),
        utc(l.close_time()),
        l.signers().len()
    );
    if !orgs.is_empty() {
        let _ = writeln!(out, "  orgs      {} of {}: {}", agreed.len(), orgs.len(), agreed.join(", "));
    }
    for (claim, succeeded) in &v.claims {
        let status = if *succeeded { "succeeded" } else { "applied, failed" };
        let _ = match claim {
            Claim::Transaction { tx_hash } => writeln!(out, "  tx        {}…  {status}", short(&tx_hash.0)),
            Claim::Invocation { tx_hash, op_index, events, .. } => {
                let r = writeln!(
                    out,
                    "  call      {}… op {op_index}  return value and {} event(s) proven",
                    short(&tx_hash.0),
                    events.len()
                );
                if show_events {
                    for e in events {
                        let j = report::event(&e.0);
                        let _ = writeln!(
                            out,
                            "    event   {}  {}  {}",
                            j["contract"].as_str().unwrap_or("-"),
                            j["topics"],
                            j["data"]
                        );
                    }
                }
                r
            }
        };
    }
    out
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

fn read_gz<T: ReadXdr>(path: &Path) -> Result<Vec<T>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    archive::read_gz_frames(file).map_err(|e| format!("decoding {}: {e}", path.display()))
}

fn read_scp(path: &Path) -> Result<Vec<ScpHistoryEntry>, String> {
    read_gz(path)
}

/// Certifies each ledger of a checkpoint. Exit status 1 if any ledger fails.
fn certify(ledger: &Path, scp: &Path, trust: Option<&Path>, network: &str) -> Result<ExitCode, String> {
    let trust = load_trust(trust, network)?;
    let certs = archive::certificates(read_gz(ledger)?, &read_scp(scp)?);
    if certs.is_empty() {
        return Err("no ledger in the files has SCP messages".into());
    }
    let mut failed = 0usize;
    for cert in &certs {
        let seq = cert.header.header.ledger_seq;
        match cert.verify(&trust) {
            Ok(l) => println!("VERIFIED  ledger {seq}  {}  {} signers", hex::encode(l.hash()), l.signers().len()),
            Err(e) => {
                failed = failed.saturating_add(1);
                println!("REJECTED  ledger {seq}  {e}");
            }
        }
    }
    eprintln!("{} of {} ledgers certified", certs.len().saturating_sub(failed), certs.len());
    Ok(if failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) })
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

/// The name `known` gives an org with exactly these validators, if any.
fn known_name(known: Option<&TrustSet>, validators: &[externalize_core::xdr::NodeId]) -> Option<String> {
    let known = known?;
    let want: std::collections::BTreeSet<[u8; 32]> = validators.iter().map(quorum::node_key).collect();
    known.quorum().inner_sets.iter().enumerate().find_map(|(i, org)| {
        let have: std::collections::BTreeSet<[u8; 32]> = org.validators.iter().map(quorum::node_key).collect();
        (have == want).then(|| known.org_name(i).map(str::to_owned)).flatten()
    })
}

fn derive(path: &Path, network: &Network, known: Option<&TrustSet>) -> Result<String, String> {
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
            "\n[[org]]\nname = \"{}\"\nthreshold = {}\nvalidators = [\n{}]\n",
            known_name(known, &inner.validators).unwrap_or_else(|| format!("org-{}", i.saturating_add(1))),
            inner.threshold,
            list(&inner.validators)
        );
    }
    Ok(out)
}
