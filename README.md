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

```sh
cargo install --git https://github.com/Externalize-Labs/externalize externalize-cli

# verify the committed mainnet fixture offline
externalize verify crates/externalize-core/tests/fixtures/mainnet/bundle-64791359.json

# inspect the built-in trust set
externalize trust show
```

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

`externalize-core` builds for `wasm32-unknown-unknown`, so the same checks run
in a browser wallet. Verifying the mainnet fixture bundle (30 signatures and
two claims) takes about 6.6 ms on a laptop; `cargo bench` reproduces it. The lower-level API (`Certificate`, `inclusion`,
`verify_ancestors`) works on raw XDR with no JSON involved.

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
| `trust/public.toml` | Public-network tier-1 trust set, derived from archived SCP data |
| `crates/externalize-core/tests/fixtures/mainnet` | Real archive checkpoint and RPC data; `bundle-64791359.json` is the conformance fixture `exnode` must reproduce byte for byte |

## Roadmap

1. **Verifier and bundle format.** Done: this repository.
2. **Bundle node.** Done:
   [`externalize-node`](https://github.com/Externalize-Labs/externalize-node).
3. **Wallet package.** A WASM/npm build so wallets can check RPC answers.
4. **Live collector.** An overlay peer that certifies ledgers before archives publish them.
5. **On-chain verifier.** A Soroban header registry so contracts can act on past events.
6. **ZK wrapper.** Prove a certificate inside a zkVM, so other chains can verify Stellar.

## Contributing

Issues are scoped and labeled for the Stellar Wave program. See
[CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through
[SECURITY.md](SECURITY.md), not public issues.

## License

[Apache-2.0](LICENSE)
