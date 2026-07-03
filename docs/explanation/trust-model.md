# Explanation: the trust model

Understanding-oriented. This explains *why* LoopSpec is shaped the way it is — what problem each
layer solves, and, just as importantly, what it deliberately does **not** promise.

## The problem: confidence is not evidence

An AI agent will tell you the fix works, the tests pass, and the refactor is safe — in the same
confident voice whether or not any of that is true. The gap between a claim and its proof is where
trust breaks. LoopSpec's entire design is about closing that gap **or disclosing that it's open**.

Two rules run through everything:

1. **Nothing is verified without independent evidence.** A claim is not true because the model (or a
   human) said so.
2. **What can't be proven is disclosed, not hidden.** Unverified claims and capture gaps are
   first-class output, not omissions.

## The layers

### LoopSpec (authoring)

A LoopSpec is the *intent*: outcome, roles, tasks, tool grants (with risk tiers), gates, and risk
controls, authored in YAML. Validation is two-layer — **structural** (shape/enums, generated from a
Zod schema so the JSON Schema and the runtime checks can't drift) and **relational** (cross-field
invariants a schema can't express, like "no T5 tier without approval"). The strictest control,
`no-t5`, forbids scheduled/recurring/unattended behavior in V1 and is enforced at both layers.

### The run ledger (integrity)

Every run event is appended to a SHA-256 **hash-chained** ledger: each event carries the hash of the
prior one, and its own hash is computed over canonical JSON. Two independent checks — chain linkage
and content-hash recomputation — catch different tampering. Recovery is **fail-closed**: a corrupt
line is quarantined (not silently dropped), the recoverable state is derived from the valid *prefix*
(so a broken run can never report a later `run.completed` as reached), and any problem yields `hold`,
never a silent `valid`.

### Capture adapters (honest normalization)

Codex (`codex exec --json`) and Claude (`--output-format stream-json`) emit different events.
Adapters normalize both into one taxonomy — but they **preserve the difference in what each engine
can observe**. Codex reports command/file/MCP activity as first-class items (full capture); Claude
only infers them from tool-use blocks and hooks (partial capture). LoopSpec records that as a
**capture gap** and never presents Claude's inferred command evidence as if it were as direct as
Codex's. Unknown event types are recorded, never dropped.

### The gate engine (fail-closed safety)

Gates are evaluated conservatively. `no-t5` is injected even if a spec omits it and normalized so a
spec can't weaken it to non-blocking or waivable; any T5 signal (a flag, a T5 tier, an unattended
loop) fails it. Unwaivable gates cannot be waived, and a gate a spec marks non-waivable can't be
waived either. A blocking gate with nothing to verify HOLDs rather than passing.

### The evidence verifier (strong claims need proof)

The verifier resolves each claim's status from its evidence, not from the declared status. A
**strong** claim is `verified` only with present, **independent** evidence (an allowlist — a bare
human note or a self-approval doesn't count) that covers its required evidence types. A claim
declared `verified` that doesn't hold is downgraded to `unverified` with a finding.

*V1 limitation:* the `verified`/`unverified` split is evidence-driven, but `contradicted` is
**declaration-driven** — the verifier trusts a `contradicted` status from the author without checking
evidence (evidence-based contradiction detection is a post-V1 item). `waived` is honored only when a
backing waiver is supplied.

### Reports (truthful by construction)

Every report emits the same sections — verified claims, unverified claims, capture gaps, waivers,
unresolved findings, redaction/retention state, known limitations — even when a section is empty
(shown as an explicit "None," so omission can't be mistaken for absence). The verified section *is*
the verifier's verified set, and the **report-truthfulness gate** HOLDs if a report asserts a claim
the evidence didn't verify. Freeform fields are escaped in both Markdown and HTML so a hostile value
can't corrupt a required disclosure.

### AgentProofProfile (a stricter bar for AI code)

An overlay for AI-authored code: a strong claim needs **executable, passing** evidence (a command
that ran or a test that passed — a file diff proves existence, not that it works), and the
assurance gates must be present, blocking, and non-waivable. It fails closed on miscased strengths,
duplicate-id tricks, and failed/unproven tests.

### Retro → improvement (change without mutation)

A run's retro becomes a `SpecChangeProposal` that creates a **new** version and never edits the one
it came from. Proposals are forward-only and approval-gated: a single safe entry point requires the
proposal to be `approved` and to pass an immutability check (it can't overwrite any existing version)
before a new version is written.

### Redaction (privacy, with an honest backstop)

Before any evidence leaves your machine, redaction scrubs secret-like keys and known secret patterns,
and an **independent** leak-scan re-checks the result — not by replaying the redactor's patterns, but
by walking the structure, flagging any value left under a sensitive key, and catching high-entropy
token-shaped strings the pattern list doesn't recognize. A support bundle is `safe_to_share` only if
that independent scan is clean.

## What LoopSpec does NOT guarantee

Being honest about limits is part of the trust model:

- **Tamper-evident, not tamper-proof.** The ledger detects corruption and naive edits. A
  write-capable actor who knows the (public) sealing algorithm can re-seal a forged or truncated
  chain. Cryptographic signing/anchoring is a post-V1 item. See [security-model](../security-model.md).
- **Redaction is conservative, not complete.** It catches known secret shapes and high-entropy
  tokens; it cannot promise to catch every unknown secret under an innocuous key. Every export is
  scanned and every report states redaction limitations.
- **Local-first concurrency.** The advisory lock that serializes ledger appends targets a single
  machine.
- **Alpha.** Shapes may change before V1.

The point is not that LoopSpec proves everything. It's that it proves what it can, refuses to claim
what it can't, and tells you which is which.
