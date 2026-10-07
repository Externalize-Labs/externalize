<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="Externalize" height="64">
  </picture>
</p>

<p align="center">
  <b>Don't trust your RPC. Verify that a Stellar ledger, transaction or contract event happened, from the validators' own signatures.</b>
</p>

<p align="center">
  <a href="https://github.com/Externalize-Labs/externalize/actions/workflows/ci.yml"><img src="https://github.com/Externalize-Labs/externalize/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
</p>

---

Every wallet, indexer, bridge and payment facilitator on Stellar believes
whatever its RPC or Horizon server says. Externalize removes that trust. It
checks the SCP `EXTERNALIZE` signatures of the validators you choose (by default
the public network's tier-1, 7 of 10 orgs) and then follows hash commitments
from the certified ledger header down to a single transaction result, or to the
exact return value and events of a Soroban contract call.

```console
$ exnode bundle --rpc https://mainnet.sorobanrpc.com \
    --invocation 764c39734ec4da0b537f8c5e43b20223274064f84705b18943b1c35512f8da48 > proof.json
$ externalize verify proof.json
VERIFIED  ledger 64791359
  hash      8ad992fd014f04876bf3104c079a15d0d53093fc0cad237f86c6991e520b1317
  closed    2026-10-05T23:22:57Z
  signers   30 trusted validators
  orgs      10 of 10: Blockdaemon, Stellar Development Foundation, Obsrvr, Franklin Templeton, MoneyGram, Range, LOBSTR, Creit Tech, PublicNode, YLDS
  call      764c39734ec4… op 0  return value and 25 event(s) proven
```

That is a real mainnet transaction, built from SDF's history archive and a
public RPC, neither of which the verifier trusts.

## What it proves

| Claim | Status |
|---|---|
| Ledger N was externalized by your trust set | ✅ |
| Ledgers older than a certified one (hash chain) | ✅ |
| A transaction was applied, and whether it succeeded | ✅ |
| A transaction's full body | ✅ with `--txset` |
| A Soroban call's return value and contract events | ✅ |
| Events from classic operations, ledger state | ❌ not committed by the header ([why](docs/trust-model.md#what-cannot-be-proven-yet)) |

Verification is fail-closed. Forged headers, signatures from another network, a
quorum one org short, a dropped or reordered event, or a trusted validator
signing a different value all reject the whole bundle. The test suite does
each of these to real mainnet data.

## Quick start

Download a binary for Linux, macOS or Windows from
[Releases](https://github.com/Externalize-Labs/externalize/releases) (each
release lists SHA-256 checksums), or build that release from source:

```sh
cargo install --git https://github.com/Externalize-Labs/externalize --tag v0.1.1 --locked externalize-cli
```

Or try it without installing anything: the
[online verifier](https://externalize-labs.github.io/externalize/) checks a
bundle in your browser.

| Command | What it does |
|---|---|
| `externalize verify proof.json` | Verify a bundle; `--events` decodes every proven contract event, `--json` for machines. Exit 0 verified, 1 rejected, 2 could not run |
| `externalize inspect proof.json` | Show what a bundle claims, without trusting any of it; `--json` for machines |
| `externalize certify --ledger ledger-….xdr.gz --scp scp-….xdr.gz` | Certify all 64 ledgers of a history archive checkpoint |
| `externalize trust show [--network testnet]` | Print a built-in trust set |
| `externalize trust derive scp-….xdr.gz --names-from trust/public.toml` | Rebuild a trust set from what validators actually used |

Built-in trust sets: the public network's tier-1 (7 of 10 orgs, 2 of 3
validators each) and testnet (SDF, 2 of 3). `verify` picks the one matching
the bundle's network; pass `--trust` to use your own.

To build bundles for any recent transaction, run
[`exnode`](https://github.com/Externalize-Labs/externalize-node) (the
untrusted bundle builder, in Go) against a history archive and any Stellar RPC.

## Use it as a library

```rust
use externalize_core::{Bundle, TrustSet};

let trust = TrustSet::from_toml(&std::fs::read_to_string("trust/public.toml")?)?;
let verified = Bundle::from_json(&std::fs::read_to_string("proof.json")?)?.verify(&trust)?;
println!("ledger {} certified by {} validators", verified.ledger.sequence(), verified.ledger.signers().len());
```

Verifying the mainnet fixture bundle (30 signatures and two claims) takes
about 6.6 ms on a laptop; `cargo bench` reproduces it.

The lower-level API (`Certificate`, `inclusion`, `verify_ancestors`,
`archive`) works on raw XDR with no JSON involved.

## Use it from JavaScript

`externalize-wasm` is the same verifier for wallets and dapps, so a page can
check what an RPC told it without trusting the RPC. Releases attach builds for
browsers and Node (666 KB, 212 KB gzipped).

```js
import init, { verify, inspect } from "./externalize_wasm.js";
await init();

const report = verify(bundleJson); // built-in trust set for the bundle's network
if (!report.verified) throw new Error(report.error);
console.log(`ledger ${report.ledger.sequence}, signed by ${report.ledger.signers.length} validators`);
```

`verify(bundle, trustToml?, events?)` returns the same report as
`externalize verify --json`; a bundle that fails is a report with
`verified: false`, never an exception. `inspect(bundle)` shows what a bundle
claims, marked unverified. [`examples/web`](examples/web/index.html) is a page
that verifies a dropped bundle locally; CI runs the package from Node against
the mainnet fixture.

## How it works

```text
 SCP EXTERNALIZE ×N ──signatures──▶ LedgerHeader ──txSetResultHash──▶ TransactionResultSet
  (satisfy trust set)               (scpValue)                         └─ result for tx ─▶ InvokeHostFunction success hash
                                                                                            = SHA-256(return value ‖ events)
```

The full argument, including what you still have to trust, is in
[docs/trust-model.md](docs/trust-model.md). The wire format, for anyone
producing or verifying bundles in another language, is specified in
[docs/bundle-format.md](docs/bundle-format.md).

## Repository layout

| Path | Contents |
|---|---|
| `crates/externalize-core` | Verification library: quorum sets, SCP signatures, certificates, inclusion proofs, bundles |
| `crates/externalize-cli` | The `externalize` binary |
| `crates/externalize-wasm` | The verifier for JavaScript, via wasm-bindgen |
| `examples/web` | A browser page that verifies a bundle locally |
| `trust/` | Public-network and testnet trust sets, derived from archived SCP data |
| `docs/` | Trust model and bundle format specification |
| `crates/externalize-core/tests/fixtures/mainnet` | Real archive checkpoint and RPC data; `bundle-64791359.json` is the conformance fixture `exnode` must reproduce byte for byte |

## Roadmap

1. **Verifier and bundle format.** Done: this repository.
2. **Bundle node.** Done:
   [`externalize-node`](https://github.com/Externalize-Labs/externalize-node).
3. **Wallet package.** Done: `externalize-wasm`, for browsers and Node.
4. **Live collector.** An overlay peer that certifies ledgers before archives publish them.
5. **On-chain verifier.** A Soroban header registry so contracts can act on past events.
6. **ZK wrapper.** Prove a certificate inside a zkVM, so other chains can verify Stellar.

## Contributing

Issues are scoped and labeled for the Stellar Wave program. See
[CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through
[SECURITY.md](SECURITY.md), not public issues.

## License

[Apache-2.0](LICENSE)
