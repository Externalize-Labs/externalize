# Test fixtures

Real network data, unmodified. Files named by checkpoint (hex) are whole
history archive files. Files named by ledger (decimal) hold that ledger's
records only, copied byte for byte out of the archive file named below; the
ones marked *framed* keep the archive's record marks, so `externalize certify`
and `archive::read_gz_frames` read them like archive files, and the others are
the bare XDR of one entry.

Archives: mainnet `https://history.stellar.org/prd/core-live/core_live_001/`,
testnet `https://history.stellar.org/prd/core-testnet/core_testnet_001/`. A
file `<cat>-<hex>.xdr.gz` lives at `<cat>/<hex[0..2]>/<hex[2..4]>/<hex[4..6]>/`.

## `mainnet/`: checkpoint 64791359 (`03dca33f`)

| File | Source |
|---|---|
| `ledger-03dca2ff.xdr.gz`, `ledger-03dca33f.xdr.gz` | mainnet archive `ledger/03/dc/a2/…`, `ledger/03/dc/a3/…` |
| `scp-03dca33f.xdr.gz` | mainnet archive `scp/03/dc/a3/scp-03dca33f.xdr.gz` |
| `scp-03dca37f.xdr.gz` | mainnet archive `scp/03/dc/a3/scp-03dca37f.xdr.gz` (next checkpoint: ledger 64791360 certifies 64791359) |
| `transactions-64791359.xdr.gz` | ledger 64791359's entry of `transactions/03/dc/a3/transactions-03dca33f.xdr.gz`, bare XDR |
| `transactions-64791360.xdr.gz` | ledger 64791360's entry of `transactions/03/dc/a3/transactions-03dca37f.xdr.gz`, framed |
| `results-64791359.xdr.gz` | ledger 64791359's result entry, bare XDR |
| `meta-*.xdr.b64` | `TransactionMeta` of two Soroban transactions, from mainnet RPC `getTransaction` |
| `bundle-64791359.json` | `externalize/bundle/v2` conformance bundle built from the above; regenerate with `UPDATE_FIXTURES=1 cargo test` |

## `testnet/`: checkpoint 5052927 (`004d19ff`)

| File | Source |
|---|---|
| `ledger-004d19ff.xdr.gz`, `scp-004d19ff.xdr.gz`, `transactions-004d19ff.xdr.gz` | testnet archive, checkpoint `004d19ff` |
| `scp-004d1a3f.xdr.gz` | testnet archive `scp/00/4d/1a/scp-004d1a3f.xdr.gz` |
| `transactions-5052928.xdr.gz` | ledger 5052928's entry of `transactions/00/4d/1a/transactions-004d1a3f.xdr.gz`, framed |

## `legacy/`: mainnet ledger 50000000, protocol 19 (`02faf0bf`)

Ledger 50000001 has a legacy (non-generalized) transaction set.

| File | Source |
|---|---|
| `ledger-50000000.xdr.gz` | ledger 50000000's entry of `ledger/02/fa/f0/ledger-02faf0bf.xdr.gz`, framed |
| `scp-50000000.xdr.gz` | ledgers 50000000 and 50000001's entries of `scp/02/fa/f0/scp-02faf0bf.xdr.gz`, framed |
| `transactions-50000001.xdr.gz` | ledger 50000001's entry of `transactions/02/fa/f0/transactions-02faf0bf.xdr.gz`, framed |
| `trust.toml` | `externalize trust derive scp-02faf0bf.xdr.gz --names-from trust/public.toml`: the quorum set validators used then |
