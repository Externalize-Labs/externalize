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
    assert!(out.contains("orgs      10 of 10: Blockdaemon, Stellar Development Foundation"), "{out}");
}

#[test]
fn json_output_is_machine_readable() {
    let out = cli().args(["verify", "--json", BUNDLE]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verified"], true);
    assert_eq!(v["ledger"]["sequence"], 64_791_359);
    assert_eq!(v["ledger"]["signers"].as_array().unwrap().len(), 30);
    assert_eq!(v["ledger"]["orgs"].as_array().unwrap().len(), 10);
    assert_eq!(v["ledger"]["orgs"][4]["name"], "MoneyGram");
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

const LEDGER: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../externalize-core/tests/fixtures/mainnet/ledger-03dca33f.xdr.gz");

#[test]
fn certifies_a_whole_mainnet_checkpoint() {
    let out = cli().args(["certify", "--ledger", LEDGER, "--scp", SCP]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.lines().filter(|l| l.starts_with("VERIFIED")).count(), 64, "{s}");
}

#[test]
fn certify_fails_against_the_wrong_trust_set() {
    let dir = std::env::temp_dir().join("externalize-testnet-trust.toml");
    std::fs::write(
        &dir,
        "network = \"testnet\"
threshold = 1
validators = [\"GABMKJM6I25XI4K7U6XWMULOUQIQ27BCTMLS6BYYSOWKTBUXVRJSXHYQ\"]
",
    )
    .unwrap();
    cli().args(["certify", "--ledger", LEDGER, "--scp", SCP, "--trust", dir.to_str().unwrap()]).assert().code(1);
}

const TESTNET: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../externalize-core/tests/fixtures/testnet");

#[test]
fn testnet_has_a_built_in_trust_set() {
    let out = cli()
        .args(["certify", "--network", "testnet"])
        .arg("--ledger")
        .arg(format!("{TESTNET}/ledger-004d19ff.xdr.gz"))
        .arg("--scp")
        .arg(format!("{TESTNET}/scp-004d19ff.xdr.gz"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout(cli().args(["trust", "show", "--network", "testnet"])).contains("Stellar Development Foundation"));
}

#[test]
fn mainnet_signatures_do_not_certify_testnet_trust() {
    cli().args(["certify", "--network", "testnet", "--ledger", LEDGER, "--scp", SCP]).assert().code(1);
}

#[test]
fn proven_events_can_be_decoded() {
    let out = stdout(cli().args(["verify", "--events", BUNDLE]));
    assert_eq!(out.lines().filter(|l| l.trim_start().starts_with("event")).count(), 4, "{out}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout(cli().args(["verify", "--json", "--events", BUNDLE]))).unwrap();
    let events = v["claims"][1]["decoded_events"].as_array().unwrap();
    assert_eq!(events.len(), 4);
    assert!(events[0]["contract"].as_str().unwrap().starts_with('C'));
}

#[test]
fn inspect_describes_without_verifying() {
    let tampered = std::fs::read_to_string(BUNDLE).unwrap().replacen("\"op_index\": 0", "\"op_index\": 1", 1);
    let out = cli().args(["inspect", "-"]).write_stdin(tampered).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("UNVERIFIED bundle for ledger 64791359"), "{s}");
    assert!(s.contains("30 envelopes (30 externalize)") && s.contains("op 1, 4 events"), "{s}");
}

#[test]
fn derive_carries_org_names_forward() {
    let shipped = concat!(env!("CARGO_MANIFEST_DIR"), "/../../trust/public.toml");
    let out = stdout(cli().args(["trust", "derive", SCP, "--names-from", shipped]));
    assert!(out.contains("name = \"LOBSTR\"") && !out.contains("org-"), "{out}");
}
