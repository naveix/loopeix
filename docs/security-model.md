# Loopeix Ledger — Integrity & Security Model (V1)

The run ledger (`ledger.jsonl`) is an append-only SHA-256 hash chain. This document states
exactly what that guarantees — and what it does not — so no consumer over-trusts it.

## What the ledger IS

**Tamper-evident** against accidental corruption and naive in-place edits. Each event's
`event_hash` covers the RFC 8785 JSON Canonicalization Scheme (JCS) bytes of every other field
(including `sequence` and `previous_event_hash`); each `previous_event_hash` links to the prior
event. Two independent checks run on read/recovery:

- `validateLedger` — chain **linkage**: strict event shape (unknown keys rejected), a single
  consistent `run_id`, unique `event_id`s, `sequence` 1..n with no gaps, and correct linkage.
- `verifyEventHashes` — **content**: every `event_hash` is recomputed and compared.

`recoverLedger` folds both, plus a dropped partial-final-line and a truncation check, into a
`valid`/`hold` verdict. Any problem yields **HOLD with findings**, never a silent pass.

Detected: single-event content mutation, reorder, insert, delete-middle, sequence gap,
duplicate `event_id`, cross-run splice, injected unknown keys, first-event non-null hash,
partial final line, and (given an expected head sequence) tail truncation.

## What the ledger is NOT (accepted V1 limitations)

The chain is **not tamper-proof**. The sealing algorithm is public and keyless, so a
**write-capable actor** can:

1. **Re-seal a forged chain** — mutate any event, then recompute all hashes and links. Both
   ledger-only checks pass. A previously issued receipt will reject the altered bytes, head, or
   event count, but an actor who also controls the workspace signing key can issue a new receipt.
   (The ledger-only limitation is proven by a test tagged "DOCUMENTED LIMITATION".)
2. **Truncate the tail** — dropping trailing events leaves an internally consistent shorter
   chain. A previously issued receipt detects the changed exact-byte hash, head, and event count;
   without that prior receipt or an expected head sequence, the shorter chain is self-consistent.
3. **Byte-level line tampering** that survives JSON normalization (for example whitespace or a
   duplicate key collapsed by parsing) may evade ledger-only object checks. Deep receipt
   verification hashes the exact serialized ledger bytes and detects any such change relative to
   the signed receipt.

Receipts provide a signed local checkpoint, not an external transparency anchor. They do not stop a
write-capable actor who also controls the signing key from re-sealing and re-signing history.

## V1 mitigations (implemented)

- Strict event schema (`LedgerEvent.strict()`), single-`run_id` + unique-`event_id` binding.
- RFC 8785 canonicalization via `canonicalize@3.0.0` for event hashing and receipt signatures.
- `buildRunManifest` **computes** the ledger hash from the actual events (never trusts a
  caller-supplied value), binds every event to the manifest's `run_id`, and marks
  `blocking_gate_summary.trusted: false` (with zeroed counts) whenever integrity is not `valid`.
- Truncation detection via `recoverLedger({ expectedLastSequence })`.
- ECDSA P-256 receipts bind the exact ledger-byte SHA-256, head event hash, and event count. Deep
  `loopeix verify <receipt> --run-dir <run-dir>` verification checks those bindings plus the full
  chain and content hashes.
- Claims Check receipts are signed (ECDSA P-256 over the RFC 8785 canonical bytes, `src/sign.ts`)
  and `loopeix verify` checks the signature offline. The check uses the public key embedded in
  the receipt, so it proves the receipt was not changed after signing. It does not prove who
  signed: an altered receipt re-signed with a freshly generated key passes. Signer identity
  requires out-of-band key pinning: compare the fingerprint of the embedded public key
  (`loopeix run start` prints it when the key is created) with one obtained from the sender by
  another channel; a `--expected-key` option is planned.

## Remaining work for externally anchored history

Sign the head hash (or each event) with a key the writer holds and the verifier trusts (HMAC
or asymmetric signature), or notarize the head hash to an external append-only sink.
Canonicalization is already RFC 8785 (JCS): `src/hash.ts` delegates to the `canonicalize`
package (keys sorted by Unicode code point, array order preserved, ES6 number serialisation),
and the same canonical bytes are used for ledger event hashes and receipt signature preimages,
so cross-runtime recomputation is possible today. The remaining gap is key trust, not byte form.
Track as an ADR before any "tamper-proof" claim is made in user-facing docs.

## Privacy boundary (unchanged from planning)

Loopeix adds no telemetry and makes no hidden network calls. The current executable path replays an
operator-supplied captured event file and never starts Codex or Claude. Any separate process used by
an operator to create such a capture has its own privacy and network boundary outside Loopeix.
