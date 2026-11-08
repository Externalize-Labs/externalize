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
commits to the ledger's `StellarValue`: its transaction set hash, close time
and upgrades. The header of ledger N repeats that value as `scpValue`.

### Why ledger N's signatures are not enough

Slot N's signatures cover `scpValue` and nothing else in header N. The
result set hash (`txSetResultHash`), `previousLedgerHash`, the bucket list
hash and every other field are outside them: anyone can rewrite one, recompute
the header hash, and slot N's signatures still match. Versions v0.1.x to v0.2.0
certified headers this way, so results, success flags, Soroban return values
and events, and ancestry were all forgeable.

### How ledger N+1 binds header N

stellar-core builds ledger N+1's transaction set on top of ledger N: the set
carries `previousLedgerHash = SHA-256(XDR(header N))` (`TransactionSet` for
legacy sets, `TransactionSetV1` inside a generalized set), and its hash is
the `txSetHash` validators EXTERNALIZE for slot N+1. So header N is certified
when:

1. validators satisfying your trust set EXTERNALIZE exactly header N's
   `scpValue` for slot N;
2. validators satisfying your trust set EXTERNALIZE one value V for slot N+1;
3. ledger N+1's transaction set hashes to `V.txSetHash`;
4. that set's `previousLedgerHash` is the hash of header N.

Changing any byte of header N changes its hash and breaks 4; changing the set
to match breaks 3; changing V needs the trust set's signatures. A bundle
therefore carries ledger N+1's SCP messages and transaction set
(`next_scp`, `next_transactions`), and `externalize certify` needs the next
checkpoint's files for a checkpoint's last ledger. Without them a ledger is
reported as not certified.

Verification is fail-closed:

- A header whose hash does not match its contents is rejected.
- Envelopes with invalid signatures, from untrusted validators, for another
  slot, or carrying non-`EXTERNALIZE` statements do not count.
- **A validly signed `EXTERNALIZE` from a trusted validator for any other value
  than its peers', in slot N or N+1, is an error (`Equivocation`), never a
  skip.** A forged header and a misbehaving trust set both look like this, and
  both mean stop.
- Signatures are bound to the network ID, so testnet signatures can never
  certify a mainnet ledger.

## From a ledger to an event

| Claim | Proven by | Committed in |
|---|---|---|
| Ledger N's `scpValue` | slot N signatures satisfying the trust set | `EXTERNALIZE` statements for N |
| The rest of header N | slot N+1 signatures, ledger N+1's transaction set | that set's `previousLedgerHash` |
| Older ledgers | `previousLedgerHash` chain | each certified header |
| Transaction applied (success or failure) | `TransactionResultSet` | `txSetResultHash` |
| Transaction body | generalized transaction set | `scpValue.txSetHash` |
| Contract call's return value and events | `InvokeHostFunctionSuccessPreImage` | the operation's success hash |

A certified ledger vouches for its ancestors, never its descendants.
`externalize ancestry` uses this: one certified ledger (certified through its
successor, which the bundle carries) and the archived `ledger-*` files between
them prove any older ledger, one hash link at a time, without that ledger's
own SCP messages.

## What cannot be proven (yet)

- **Events from classic operations.** Since protocol 23 classic operations emit
  events, but those live in transaction meta, which no header commits to.
- **Diagnostic events and transaction-level fee events.** Same reason.
- **Ledger state** (balances, contract storage). The bucket list hash commits
  to it, but there is no compact proof format yet.
- **Ledgers not yet in an archive.** Archives publish every 64 ledgers (about
  six minutes), and a ledger needs its successor, so a checkpoint's last ledger
  waits for the next checkpoint. A live overlay collector is on the roadmap.

## Keeping the trust set current

Tier-1 membership changes rarely and publicly. `externalize trust derive`
extracts the quorum set that archive validators actually used, so a change
shows up as a reviewable diff to `trust/public.toml`. Treat that diff like a
dependency upgrade: read it before you merge it.
