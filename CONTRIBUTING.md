# Contributing

Thanks for helping make Stellar verifiable. This project takes part in the
[Stellar Wave](https://www.drips.network/wave/stellar) program; Wave issues are
labeled with their complexity.

## Setup

```sh
git clone https://github.com/Externalize-Labs/externalize && cd externalize
cargo test --workspace
```

`rust-toolchain.toml` pins the toolchain. The minimum supported Rust version is
1.88.

## Before you open a PR

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs the same commands on Linux, macOS and Windows, checks the MSRV, and
builds `externalize-wasm` and runs it from Node against the mainnet fixture.
To try that locally:

```sh
cargo build -p externalize-wasm --target wasm32-unknown-unknown --profile wasm
wasm-bindgen --target nodejs --out-dir pkg target/wasm32-unknown-unknown/wasm/externalize_wasm.wasm
node crates/externalize-wasm/tests/node.cjs pkg
```

A change to what the verifier reports goes through `externalize_core::report`,
so the CLI's `--json` output and the WASM package stay identical.

## Ground rules

- **Get assigned first.** Comment on the issue and wait for assignment.
- **One issue, one PR.** Link it with `Closes #N`.
- **Tests come with the change.** A verification change needs a test that would
  have failed without it, ideally against the mainnet fixtures.
- **No panics in library code.** `unwrap`, `expect`, `panic!` and unchecked
  indexing are denied by lint; return an `Error` instead.
- **Fail closed.** When in doubt, reject. A verifier that accepts too much is
  worse than none.
- **Keep the tree clean.** Don't commit notes, summaries, PR drafts or backup
  files. CI rejects the common ones.

## Fixtures

`crates/externalize-core/tests/fixtures/mainnet` holds real public-network data:
one archive checkpoint's headers and SCP messages, one ledger's results and
transaction set, and two transactions' meta from RPC. `bundle-64791359.json` is
generated from them:

```sh
UPDATE_FIXTURES=1 cargo test -p externalize-core --test mainnet
```

If you change the bundle format, regenerate it and update the copy in
`externalize-node/testdata` in the same change, so the Go builder and the Rust
verifier keep agreeing byte for byte.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org): `feat(core): …`,
`fix(cli): …`, `docs: …`, `test: …`.
