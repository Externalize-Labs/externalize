# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-11-08

### Security

- **Ledger headers were only partly certified.** Affected: v0.1.x to v0.2.0.
  `Certificate::verify` checked that a quorum of trusted validators
  EXTERNALIZEd the header's `scpValue` (transaction set hash, close time,
  upgrades) and that the header hash matched the header. Validators sign
  nothing else in the header, so anyone could rewrite any other field, such as
  `txSetResultHash`, `previousLedgerHash` or the bucket list hash, recompute
  the header hash, and still have it verify. Every claim that depends on
  results was forgeable: whether a transaction was applied and succeeded,
  Soroban return values and events (a forged bundle reported a successful
  transaction as failed, and a bundle without a transaction set was accepted
  for a transaction that never happened). So was ancestry (`prove_ancestor`,
  `externalize ancestry`), which follows `previousLedgerHash`.
- **Fix:** header N is now certified through ledger N+1. A quorum of trusted
  validators must EXTERNALIZE one value V for slot N+1, ledger N+1's
  transaction set must hash to `V.txSetHash` (legacy and generalized sets,
  hashed as stellar-core does), and that set's `previousLedgerHash` must be the
  hash of header N. See `docs/trust-model.md`.

### Changed

- Bundle format `externalize/bundle/v2`, with two required fields:
  `next_scp` (ledger N+1's `ScpHistoryEntry`) and `next_transactions`
  (its `TransactionHistoryEntry`). v1 bundles are refused
  (`Error::V1Bundle`) and must be rebuilt. The conformance fixture is
  regenerated as v2.
- `Certificate` gains `next_scp` and `next_transactions`.
  `archive::certificates` takes the transaction history entries too and
  returns `Error::MissingSuccessor` for a header whose successor data is
  missing.
- `externalize certify` takes `--transactions`, and `--scp` and
  `--transactions` accept the next checkpoint's files as well. Without them a
  checkpoint's last ledger is reported as `NOT CERTIFIED` (exit status 1).
- `externalize ancestry` and `proveAncestor` certify their trusted ledger
  through its successor, carried by the v2 bundle.
- New errors: `MissingSuccessor`, `SuccessorTxSetMismatch`,
  `HeaderNotCommitted`, `V1Bundle`.

## [0.2.0] - 2026-10-28

### Added

- TypeScript types for `externalize-wasm`: `verify` returns
  `VerifyReport | Rejection` and `inspect` an `InspectReport`, with typed
  ledgers, org agreement, claims (narrowed on `kind`) and decoded events,
  instead of `any`.
- `externalize ancestry`: prove a ledger older than a certified one by
  following previous-ledger hashes back through archived `ledger-*` files, as
  text or `--json`. The library side is `prove_ancestor`, which picks the
  needed headers out of whole archive files and names any missing ledger
  (`Error::MissingHeader`). Proving a ledger that is not older is
  `Error::NotAnAncestor`.
- A [browser verifier](https://externalize-labs.github.io/externalize/) on
  GitHub Pages: `externalize-wasm` checks a real mainnet bundle, a tampered
  copy, or a bundle you bring, with nothing sent to a server.
- Prove any mainnet transaction from the browser verifier by its hash (or a
  stellar.expert link). An untrusted exnode builds the bundle and the page
  verifies it. Recent Soroban calls are proven with their return value and
  events, and anything older as an applied transaction. Ledgers not yet in the
  archive are retried until their checkpoint is published. Shareable `#tx=`
  links, and a download of the proof for offline checks.

### Changed

- `stellar-xdr` 30 (from 28), current with protocol 29 on mainnet. Bundles
  built from mainnet ledgers of 2026-10-25 verify unchanged.

## [0.1.1] - 2026-10-07

### Fixed

- Release packaging: only the archives are uploaded, checksummed and attached;
  0.1.0's publish step tripped over the staging folders.

## [0.1.0] - 2026-10-07

### Added

- `externalize-core`: certify ledgers from SCP `EXTERNALIZE` signatures against
  a trust set, fail-closed on equivocation.
- Inclusion proofs for result sets, transaction sets and Soroban invocation
  return values and events.
- Proof bundles (`externalize/bundle/v1`) with a written specification in
  `docs/bundle-format.md`, size limits, and a mainnet conformance fixture.
- History archive reading (`archive` module).
- Trust sets for the public network (tier-1, 7 of 10 orgs) and testnet (SDF,
  2 of 3), with per-org certification reports.
- `externalize` CLI: `verify` (with `--json` and `--events`), `inspect`,
  `certify`, `trust show` and `trust derive` (with `--names-from`).
- Property test showing random corruption never yields a false proof.
- Benchmarks: verifying the mainnet fixture bundle takes about 6.6 ms.
- Release workflow publishing binaries for Linux, macOS and Windows.
- `externalize-wasm`: `verify` and `inspect` for browsers and Node, with the
  built-in trust sets, a size-first build profile (666 KB), a browser example,
  and a CI job that verifies the mainnet fixture from Node. Releases attach
  web and Node packages.
- `report` feature in `externalize-core`: the JSON report and built-in trust
  sets shared by the CLI and the WASM package.
- `externalize inspect --json`.

[Unreleased]: https://github.com/Externalize-Labs/externalize/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Externalize-Labs/externalize/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Externalize-Labs/externalize/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Externalize-Labs/externalize/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Externalize-Labs/externalize/releases/tag/v0.1.0
