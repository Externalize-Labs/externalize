# Bundle format (`externalize/bundle/v1`)

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
| `format` | string | yes | Always `"externalize/bundle/v1"` |
| `network` | string | yes | Network passphrase, e.g. `"Public Global Stellar Network ; September 2015"` |
| `ledger` | XDR | yes | `LedgerHeaderHistoryEntry` of the ledger |
| `scp` | XDR | yes | `ScpHistoryEntry` recorded for the same ledger |
| `results` | XDR | if any claim | `TransactionHistoryResultEntry` of the ledger |
| `transactions` | XDR | no | `TransactionHistoryEntry`; when present, claimed transactions must appear in it |
| `claims` | array | no | Statements to prove; omitted when empty |

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

1. `network` must equal the trust set's network.
2. **Header.** `ledger.hash` must equal `SHA-256(XDR(ledger.header))`.
3. **Certificate.** `scp.ledgerMessages.ledgerSeq` must equal the header's
   sequence. For each envelope whose statement is `EXTERNALIZE` for slot
   `ledgerSeq` and whose Ed25519 signature over
   `networkID ‖ XDR(ENVELOPE_TYPE_SCP) ‖ XDR(statement)` verifies, from a
   validator in the trust set:
   - if `commit.value` is not byte-identical to `XDR(header.scpValue)`, **reject**
     (equivocation);
   - otherwise count the validator once.
   The counted validators must satisfy the trust set's quorum set.
4. **Results.** `SHA-256(XDR(results.txResultSet))` must equal
   `header.txSetResultHash`, and `results.ledgerSeq` the header's sequence.
5. **Transactions** (if present). `SHA-256(XDR(generalizedTxSet))` must equal
   `header.scpValue.txSetHash`. Transaction hashes are computed per envelope
   with the network ID; fee bumps hash as the outer transaction.
6. **Claims.** Each `tx_hash` must appear in the result set (and the
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
