//! End-to-end tests of the `externalize` binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use assert_cmd::Command;

const BUNDLE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../externalize-core/tests/fixtures/mainnet/bundle-64791359.json");
const SCP: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../externalize-core/tests/fixtures/mainnet/scp-03dca33f.xdr.gz");

fn cli() -> Command {
    Command::cargo_bin("externalize").unwrap()
}

fn stdout(cmd: &mut Command) -> String {
    String::from_utf8(cmd.output().unwrap().stdout).unwrap()
}

#[test]
fn verifies_a_mainnet_bundle() {
    let out = stdout(cli().args(["verify", BUNDLE]));
    assert!(out.contains("VERIFIED  ledger 64791359"), "{out}");
    assert!(out.contains("closed    2026-10-05T"), "{out}");
    assert!(out.contains("4 event(s) proven"), "{out}");
}

#[test]
fn json_output_is_machine_readable() {
    let out = cli().args(["verify", "--json", BUNDLE]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verified"], true);
    assert_eq!(v["ledger"]["sequence"], 64_791_359);
    assert_eq!(v["ledger"]["signers"].as_array().unwrap().len(), 30);
}

#[test]
fn a_tampered_bundle_exits_one() {
    let tampered = std::fs::read_to_string(BUNDLE).unwrap().replacen("\"op_index\": 0", "\"op_index\": 1", 1);
    let out = cli().args(["verify", "--json", "-"]).write_stdin(tampered).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verified"], false);
}

#[test]
fn unreadable_input_exits_two() {
    cli().args(["verify", "does-not-exist.json"]).assert().code(2);
}

#[test]
fn trust_show_names_orgs() {
    let out = stdout(cli().args(["trust", "show"]));
    assert!(out.contains("threshold  7 of 10"), "{out}");
    assert!(out.contains("Stellar Development Foundation"), "{out}");
}

#[test]
fn derived_trust_set_matches_the_shipped_one() {
    let derived = stdout(cli().args(["trust", "derive", SCP]));
    let dir = std::env::temp_dir().join("externalize-derive-test.toml");
    std::fs::write(&dir, &derived).unwrap();
    let a = stdout(cli().args(["trust", "show", dir.to_str().unwrap()]));
    let b = stdout(cli().args(["trust", "show"]));
    let strip = |s: &str| {
        s.lines().map(|l| l.split_whitespace().rev().take(3).collect::<Vec<_>>().join(" ")).collect::<Vec<_>>()
    };
    assert_eq!(strip(&a), strip(&b), "same thresholds and sizes; only names differ");
}
