# Changelog

All notable changes to Loopeix. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
The project is pre-release (alpha); everything below is **Unreleased** until the first tagged version.

## [Unreleased]

### Run-execution layer

- `loopeix run start <spec> --engine <codex|claude>` executes a loop end-to-end (live) or replays a
  captured event file (`--events-file`): validate → run → normalize → seal ledger → gates → truthful
  report + manifest. A failed/timed-out engine seals `run.failed`, never a fake `completed`.
- Engine invocation shells out with an args-array (no shell); Codex uses a `--` terminator so a prompt
  cannot override the read-only sandbox; Claude uses a validated budget cap.
- `report build` / `report open` are now wired to real run directories (rebuild anchors run_state /
  integrity to the sealed ledger, not the sidecar).

### V0.3 Assurance Alpha (S13–S16)

- Dogfood + recovery hardening: corrupt ledger lines are quarantined (never crash); recovery derives
  state from the valid prefix; an advisory file lock (atomic, steal-only-when-stale) serializes appends.
- Retro → improvement engine: a run's retro becomes an immutable, forward-only, approval-gated
  `SpecChangeProposal` that never mutates the current spec.
- AgentProofProfile: a strict overlay for AI code work — strong claims need passing executable evidence;
  assurance gates must be non-waivable.
- Packaging + privacy: conservative redaction with an independent leak-scan; retention classes; a
  redact-then-verify support bundle; reversible install/uninstall docs.

### V0.2 Run Core Alpha (S8–S12)

- Tamper-evident hash-chained run ledger + manifest + fail-closed recovery.
- Codex + Claude capture adapters (one normalized taxonomy; honest per-engine capture gaps).
- Gate engine (fail-closed; `no-t5` injected and un-weakenable; unwaivable gates enforced).
- Evidence verifier (a strong claim needs present, independent evidence; declared-verified is downgraded).
- Local Markdown + static HTML reports; the unwaivable report-truthfulness gate.

### V0.1 Contract Alpha (S5–S7)

- Golden fixtures + test harness.
- Zod schema → generated JSON Schema + independent structural + relational validation.
- oclif CLI skeleton (`doctor`, `init`, `spec validate`, `spec inspect`).

### Security fixes made during review (highlights)

- Closed two T5 authoring bypasses and a gate-engine non-blocking-`no-t5` bypass.
- Closed five secret-leak paths in redaction (Stripe/AWS/JWT/`.env`/high-entropy) + made the leak-scan
  independent of the redactor.
- Closed a cross-process ledger-corruption lock race and a Codex prompt flag-injection sandbox escape.
