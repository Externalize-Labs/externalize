// Runs the wasm-bindgen package from Node against the mainnet fixture.
//
//   cargo build --profile wasm -p externalize-wasm --target wasm32-unknown-unknown
//   wasm-bindgen --target nodejs --out-dir pkg target/wasm32-unknown-unknown/wasm/externalize_wasm.wasm
//   node crates/externalize-wasm/tests/node.cjs pkg
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const pkg = require(path.resolve(process.argv[2] || "pkg", "externalize_wasm.js"));
const bundle = fs.readFileSync(
  path.join(__dirname, "../../externalize-core/tests/fixtures/mainnet/bundle-64791359.json"),
  "utf8",
);

const report = pkg.verify(bundle, undefined, true);
assert.equal(report.verified, true, report.error);
assert.equal(report.ledger.sequence, 64791359);
assert.equal(report.ledger.signers.length, 30);
assert.equal(report.ledger.orgs.filter((o) => o.satisfied).length, 10);
assert.ok(report.claims.some((c) => c.kind === "invocation" && c.decoded_events.length > 0));

const tampered = pkg.verify(bundle.replace('"ledger": "', '"ledger": "AAAA'));
assert.equal(tampered.verified, false);
assert.ok(tampered.error.length > 0);

const testnet = pkg.builtinTrust("Test SDF Network ; September 2015");
assert.match(pkg.verify(bundle, testnet).error, /network mismatch/);
assert.equal(pkg.builtinTrust("Standalone Network ; February 2017"), undefined);

const seen = pkg.inspect(bundle);
assert.equal(seen.verified, false);
assert.equal(seen.ledger.sequence, 64791359);
assert.throws(() => pkg.inspect("{}"));

console.log(`ok: ledger ${report.ledger.sequence} verified from JavaScript`);
