# Trust model

Externalize answers one question: **did the validators I trust agree that this
happened?** This page says exactly what that answer is worth.

## What you trust

1. **Your trust set.** A quorum set (`trust/public.toml` by default) naming the
   validators whose signatures count and the thresholds they must meet. This
   is the same configuration a Stellar watcher node uses, and it carries the
   same assumption: if the trust set is compromised or misconfigured, so is
   every answer.
2. **Ed25519 and SHA-256.**
3. **This code.** Small and dependency-light on purpose (see `Cargo.toml`), but
   unaudited. See [SECURITY.md](../SECURITY.md).

## What you do not trust

The archive, the RPC, `exnode`, the network path, and whoever handed you the
bundle. Each of them can withhold data, but none of them can make a false
bundle verify.

## Why a satisfied trust set is enough

Stellar validators sign SCP statements over
`networkID ‖ ENVELOPE_TYPE_SCP ‖ statement`. An `EXTERNALIZE` statement
commits to the ledger's `StellarValue`, which the ledger header repeats as
`scpValue`. When validators that satisfy your trust set have each signed
`EXTERNALIZE` for exactly the header's value, that ledger is the one your
trust set externalized.

Verification is fail-closed:

- A header whose hash does not match its contents is rejected.
- Envelopes with invalid signatures, from untrusted validators, for another
  slot, or carrying non-`EXTERNALIZE` statements do not count.
- **A validly signed `EXTERNALIZE` from a trusted validator for any other value
  is an error (`Equivocation`), never a skip.** A forged header and a misbehaving
  trust set both look like this, and both mean stop.
- Signatures are bound to the network ID, so testnet signatures can never
  certify a mainnet ledger.

## From a ledger to an event

| Claim | Proven by | Committed in |
|---|---|---|
| Ledger N exists | signatures satisfying the trust set | `EXTERNALIZE` statements |
| Older ledgers | `previousLedgerHash` chain | each certified header |
| Transaction applied (success or failure) | `TransactionResultSet` | `txSetResultHash` |
| Transaction body | generalized transaction set | `scpValue.txSetHash` |
| Contract call's return value and events | `InvokeHostFunctionSuccessPreImage` | the operation's success hash |

A certified ledger vouches for its ancestors, never its descendants.

## What cannot be proven (yet)

- **Events from classic operations.** Since protocol 23 classic operations emit
  events, but those live in transaction meta, which no header commits to.
- **Diagnostic events and transaction-level fee events.** Same reason.
- **Ledger state** (balances, contract storage). The bucket list hash commits
  to it, but there is no compact proof format yet.
- **Ledgers not yet in an archive.** Archives publish every 64 ledgers (about
  six minutes). A live overlay collector is on the roadmap.

## Keeping the trust set current

Tier-1 membership changes rarely and publicly. `externalize trust derive`
extracts the quorum set that archive validators actually used, so a change
shows up as a reviewable diff to `trust/public.toml`. Treat that diff like a
dependency upgrade: read it before you merge it.
