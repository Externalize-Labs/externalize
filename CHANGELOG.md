# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Externalize-Labs/externalize/commits/main
