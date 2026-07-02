# LoopSpec Ledger — Integrity & Security Model (V1)

The run ledger (`ledger.jsonl`) is an append-only SHA-256 hash chain. This document states
exactly what that guarantees — and what it does not — so no consumer over-trusts it.

## What the ledger IS

**Tamper-evident** against accidental corruption and naive in-place edits. Each event's
`event_hash` covers the canonical bytes of every other field (including `sequence` and
`previous_event_hash`); each `previous_event_hash` links to the prior event. Two independent
checks run on read/recovery:

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
   checks pass. (Proven by a test tagged "DOCUMENTED LIMITATION".)
2. **Truncate the tail** — dropping trailing events leaves an internally consistent shorter
   chain. Mitigated only when an expected head sequence is supplied (from a prior manifest).
3. **Byte-level line tampering** that survives JSON normalization (duplicate keys, whitespace)
   — integrity is checked over the parsed/normalized object, not the raw stored bytes.

These require a secret or an external anchor to defeat, which V1 does not implement.

## V1 mitigations (implemented)

- Strict event schema (`LedgerEvent.strict()`), single-`run_id` + unique-`event_id` binding.
- `buildRunManifest` **computes** the ledger hash from the actual events (never trusts a
  caller-supplied value), binds every event to the manifest's `run_id`, and marks
  `blocking_gate_summary.trusted: false` (with zeroed counts) whenever integrity is not `valid`.
- Truncation detection via `recoverLedger({ expectedLastSequence })`.

## Post-V1 (to reach tamper-PROOF)

Sign the head hash (or each event) with a key the writer holds and the verifier trusts (HMAC
or asymmetric signature), or notarize the head hash to an external append-only sink. Pin the
canonicalization to RFC 8785 (JCS) if cross-runtime verification is ever required (today's
canonicalization is `JSON.stringify` over recursively sorted keys — deterministic and
injective over on-disk JSON values, but not a published standard). Track as an ADR before any
"tamper-proof" claim is made in user-facing docs.

## Privacy boundary (unchanged from planning)

LoopSpec adds no telemetry and makes no hidden network calls. Codex CLI and Claude Code CLI
may transmit data under their own settings; that boundary is disclosed before each run.
