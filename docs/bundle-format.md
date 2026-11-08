# Bundle format (`externalize/bundle/v2`)

A bundle is a JSON object carrying everything needed to prove facts about one
Stellar ledger. Producers (such as `exnode`) are untrusted: a verifier checks
every field against its own trust set. This page is the contract between
producers and verifiers in any language.

## Encoding rules

- UTF-8 JSON. Unknown top-level or claim fields are an error.
- XDR values are **standard base64** (RFC 4648, with padding) of the canonical
  XDR encoding, exactly as history archives and Stellar RPC produce them.
- Hashes are **lowercase hex**, 64 characters.
- Verifiers must refuse bundles with more than 256 claims, or more than 10,000
  events in one claim.

## Fields

| Field | Type | Required | Content |
|---|---|---|---|
| `format` | string | yes | Always `"externalize/bundle/v2"` |
| `network` | string | yes | Network passphrase, e.g. `"Public Global Stellar Network ; September 2015"` |
| `ledger` | XDR | yes | `LedgerHeaderHistoryEntry` of the ledger (N) |
| `scp` | XDR | yes | `ScpHistoryEntry` recorded for ledger N |
| `next_scp` | XDR | yes | `ScpHistoryEntry` recorded for ledger N+1 |
| `next_transactions` | XDR | yes | `TransactionHistoryEntry` of ledger N+1, from the archive's `transactions-*.xdr.gz` (`ext` v1 carries a generalized set) |
| `results` | XDR | if any claim | `TransactionHistoryResultEntry` of the ledger |
| `transactions` | XDR | no | `TransactionHistoryEntry`; when present, claimed transactions must appear in it |
| `claims` | array | no | Statements to prove; omitted when empty |

Fields are serialized in this order. Ledger N+1 is in the next archive
checkpoint when N is a checkpoint's last ledger (`N % 64 == 63`), so a
bundle for it can be built only once that checkpoint is published.

`externalize/bundle/v1` (no `next_scp`, `next_transactions`) is refused: it
certified only the header's `scpValue`, so every other header field, and
everything proven through it, could be forged. Rebuild such bundles as v2.

### Claims

```json
{ "kind": "transaction", "tx_hash": "<hex>" }
```

The transaction was applied in this ledger. The verifier reports whether it
succeeded.

```json
{
  "kind": "invocation",
  "tx_hash": "<hex>",
  "op_index": 0,
  "return_value": "<XDR ScVal>",
  "events": ["<XDR ContractEvent>", "..."]
}
```

Operation `op_index` of the transaction was a successful `InvokeHostFunction`
whose return value and contract events are exactly these, in this order. Take
them from `TransactionMeta` v4 (`sorobanMeta.returnValue` and
`operations[op_index].events`) or v3 (`sorobanMeta.returnValue`, `.events`).

## Verification algorithm

1. `format` must be `externalize/bundle/v2`, and `network` the trust set's network.
2. **Header.** `ledger.hash` must equal `H = SHA-256(XDR(ledger.header))`.
   Let `N = ledger.header.ledgerSeq`.
3. **Externalized values.** For slot `s` and an `ScpHistoryEntry` `e`:
   `e.ledgerMessages.ledgerSeq` must equal `s`. Consider each envelope whose
   statement is `EXTERNALIZE` for slot `s`, whose Ed25519 signature over
   `networkID ‖ XDR(ENVELOPE_TYPE_SCP) ‖ XDR(statement)` verifies, and whose
   validator is in the trust set. All of them must carry byte-identical
   `commit.value` bytes, or **reject** (equivocation). The validators counted
   (once each) must satisfy the trust set's quorum set.
4. **Ledger N.** Apply 3 to `scp` for slot `N`; the common value must be
   `XDR(ledger.header.scpValue)`.
5. **Ledger N+1.** Apply 3 to `next_scp` for slot `N+1`; decode the common
   value `V` as `StellarValue`.
6. **Successor's set.** `next_transactions.ledgerSeq` must be `N+1`, and the
   hash of its transaction set must equal `V.txSetHash`, computed as
   stellar-core does (`src/herder/TxSetFrame.cpp`):
   - `ext` v1 (generalized): `SHA-256(XDR(GeneralizedTransactionSet))`;
   - `ext` v0 (legacy): `SHA-256(txSet.previousLedgerHash ‖ XDR(tx₀) ‖ XDR(tx₁) ‖ …)`
     over `txSet.txs` in order.
7. **Header committed.** That set's `previousLedgerHash` (`TransactionSetV1`'s
   for generalized sets, `TransactionSet`'s for legacy) must equal `H`. Only
   now is every field of header N certified.
8. **Results.** `SHA-256(XDR(results.txResultSet))` must equal
   `header.txSetResultHash`, and `results.ledgerSeq` the header's sequence.
9. **Transactions** (if present). `SHA-256(XDR(generalizedTxSet))` must equal
   `header.scpValue.txSetHash`. Transaction hashes are computed per envelope
   with the network ID; fee bumps hash as the outer transaction.
10. **Claims.** Each `tx_hash` must appear in the result set (and the
   transaction set, if present). For an invocation, the operation result must
   be `INVOKE_HOST_FUNCTION_SUCCESS(h)` with
   `h = SHA-256(XDR(InvokeHostFunctionSuccessPreImage{return_value, events}))`.

Any failure rejects the whole bundle.

## Conformance

[`crates/externalize-core/tests/fixtures/mainnet/bundle-64791359.json`](../crates/externalize-core/tests/fixtures/mainnet/bundle-64791359.json)
is the reference bundle: a real public-network ledger with one transaction
claim and one invocation claim. A producer is conformant when it emits this
file byte for byte from the same archive and RPC data (the JSON is
pretty-printed with two-space indentation and a trailing newline). A verifier
is conformant when it accepts this file with the public trust set and rejects
every mutation in `tests/mainnet.rs`.
