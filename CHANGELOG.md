# Changelog

All notable changes to Loopeix. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.1.0] - 2026-07-04

First public release: the Claims Check — seal the brief, adjudicate the agent's claims against
the engine's own event stream, sign the receipt, verify it anywhere offline. Everything below
was built and reviewed pre-release and ships in this version.

### Shadow-fleet validation (S18)

- The shipped npm artifact (not just source) is now exercised by a persona fleet before release:
  240 scripted Tier-0 personas across 5 missions (install, docs-followability, spec corpus,
  receipt tamper, receipt fuzz) × Node 22.12/24/26 containers — **240/240 oracle-decided PASS**,
  including the declared Node 22.12 engines floor. Abuse resistance: 4 forgery classes per tamper
  persona all rejected; ~24 seeded receipt mutations per fuzz persona, zero verified.
- The harness itself is adversarially reviewed and fault-injection tested (`shadow/selftest.sh`):
  oracles are proven to FAIL on mis-staged fixtures, missing deliverables, and wrong answers —
  a green wave means the checks ran, not that nothing was checked.
- Tier-1 (live cheap-model personas) lane is built and validated offline; live waves are gated
  behind a dated operator acknowledgement and hard credential rules (adversarial personas never
  share a container with live auth).

### Claims Check (M3)

- `loopeix pr <receipt.json | run-dir>`: renders a VERIFIED receipt as the PR-body verdict table
  (plain Markdown, zero GitHub permissions, fully offline). Verify-first rendering gate: if the
  receipt fails any check the command prints a single failure block naming the failed checks and
  exits 1 — no table, no card, zero partial output. A run-dir argument turns on the deep gate
  (ledger binding re-derived from the run's `ledger.jsonl`). Fixed glyphs (✅/🟥/⬜ + enum, never
  colour-only), red rows first, contiguous evidence ranges compress above 4 ids
  (`ev_002…ev_029`), every freeform field passes the repo `mdEsc` idiom (now exported from
  `src/report.ts`). `--out <file>` writes the Markdown, `--json` emits the render-model (rows,
  ordering bands, counts).
- Delta Card (`loopeix pr --card <file.svg>` — the chosen command surface; there is no separate
  `card` command): one static, self-contained 1200×630 SVG (SEALED / BROKE / CLAIMED / VERDICT +
  verify pill), same rendering gate, all freeform text XML-escaped after single-line truncation,
  no scripts/foreignObject/external references, deterministic bytes. **Documented deviation from
  the rendering spec for truthfulness:** green "nothing — all promises kept" renders ONLY when
  every clause is KEPT; when no clause is broken but containment clauses are UNEVALUATED the row
  says "no broken promise recorded" in neutral grey — under the presence/absence doctrine
  (claim-families-v1.md) absence of PROMISE_BROKEN never proves promises were kept.
- `examples/snitch-demo/`: the 60-second offline reproduction of The Snitch from the committed
  `tests/fixtures/run-seal/` fixtures (captured-events replay, no live engine, no network), ending
  in the shareable caption. A script-level test executes the README sequence end-to-end through
  the real command classes, so the demo cannot rot silently.
- New render modules exported from the barrel (`src/render/pr.ts`, `src/render/delta-card.ts`,
  `src/render/shared.ts`); golden Markdown + SVG renders under `tests/golden/renders/`; injection
  corpus, rendering-gate, ordering, determinism, and truncation tests. No schema changes.

### Claims Check (M2, with adversarial-review fix-pass)

- Structured sealed brief (`brief_version 0.1`): acceptance/forbidden clauses are typed objects
  (`tests-pass` / `delete_paths` / `write_paths` / `freeform`) so adjudication never guesses at prose;
  the globs rule is structural (a freeform clause cannot even carry globs); clause id `scope` is
  reserved to prevent collision with the built-in F3 scope clause.
- `loopeix run start --seal <brief.yaml>`: the brief is sealed as ledger event 1 (`brief.sealed`,
  before `run.started`; briefless runs are byte-identical to before), the verdict engine adjudicates
  the three v1 families, and a signed `receipt.json` lands in the run dir — for failed runs too.
  Exit-code semantics are unchanged: verdicts inform, the gate engine decides. If `buildReceipt`
  fails, the run dir is still written (without a receipt) so run artifacts are preserved.
- Verdict engine (`computeVerdicts`), the conservative doctrine made executable under the
  "presence convicts; absence never acquits" rule (M2 adversarial review, 2026-07-03):
  - **F1 tests-ran**: runner recognition is program-position tokenization (not substring); `make
    test`, `./scripts/test.sh`, `bun test`, `deno test`, `node --test` handled correctly.
    Absence-based `CONTRADICTED` is removed: zero recognized runners → `UNSUPPORTED` (never
    `CONTRADICTED`). `CONTRADICTED` fires only when a recognized runner IS present and exited
    non-zero while a full-pass assertion was simultaneously claimed.
  - **F2 forbidden paths**: engine-admitted `file_change` events convict at ANY capture level
    (admissions are direct evidence). No recorded violation → `UNEVALUATED` (`KEPT` removed in
    v1; wrapper filesystem diff is phase two). Path normalization (`.`/`..`/NFC/workspace-root)
    before all glob adjudication; unnormalizable paths excluded, cannot convict or acquit.
  - **F3 scope**: same admission-based conviction and `UNEVALUATED` default as F2.
  - **Suite mutation (the Snitch)**: a forbidden-clause `PROMISE_BROKEN` caps `tests-pass` at
    `UNSUPPORTED — suite-mutated` with the broken clause label named explicitly.
  - **Receipt reasons** cite evidence ids, clause labels, and paths only — never raw command
    text (commands can embed inline secrets; receipts travel).
- The Codex adapter's `file_changes` capture level is corrected to `partial` (engine self-report;
  shell-level mutations via bare `rm`/`mv` produce no `file_change` item). Admitted events still
  convict; absence cannot acquit. `shell_command_execution` remains `full`.
- Workspace signing key: concurrent first-generation is serialized via `src/lock.ts`; existing
  keys with wrong permissions are auto-corrected to 0600 and surfaced as a notice.
- Path normalization in `src/glob.ts`: resolves `.`/`..`, NFC-normalizes (Unicode filenames),
  strips workspace-root prefix for absolute paths; null result excluded from adjudication.

**Known limitation RESOLVED (live capture 2026-07-04, codex-cli 0.142.3):** real Codex
`file_change` items carry ABSOLUTE POSIX paths under the run workspace root. Captured, redacted
into `tests/fixtures/adapter-events/codex/s1-codex-file-change.redacted.jsonl`, and tested both
ways: a matching `workspaceRoot` strips the prefix and convicts; a missing or mismatched root
excludes the path and never convicts (the defensive direction proven correct). The run-seal
fixtures deliberately keep the canonical post-strip relative form for replay portability, with a
tested equivalence proof — see `tests/fixtures/run-seal/README.md`. Same-day Claude capture
(2.1.201): a file deletion surfaced ONLY as a Bash `rm` tool_use with no file-change-shaped event —
the shell-rm bypass is live-proven; forbidden clauses stay `UNEVALUATED` (absence never acquits).

### Claims Check (M1)

- Signed receipt schema (`receipt_version 0.1`) + generated `schemas/receipt.schema.json`: per-claim
  verdicts bound to a sealed brief hash and exact ledger bytes. The conservative doctrine is structural —
  a `CONTRADICTED`/`PROMISE_BROKEN` verdict without a cited evidence id is unrepresentable, even to plain ajv.
- Local ECDSA P-256 signer (`node:crypto`, DER, cosign-compatible path); the signature covers the RFC 8785
  canonical receipt with the signature field removed. Golden receipts are signed with an ephemeral in-process
  key — no private key on disk, ever.
- Offline `loopeix verify <receipt>` (`--run-dir` re-derives the ledger binding; exit 0/1; hostile input
  yields failed checks, never a crash) + golden fixtures including the Snitch (forbidden test deletion at
  step 17 → `PROMISE_BROKEN` cited, `tests pass` capped at `UNSUPPORTED — suite-mutated`) and three tamper variants.

### Attestation foundation

- Canonicalization is now pinned to RFC 8785 (JSON Canonicalization Scheme) via
  `canonicalize@3.0.0`.  The old hand-rolled sorted-key `JSON.stringify` shared a
  latent bug with V8: it let the engine re-hoist integer-like object keys (e.g. `"9"`,
  `"10"`) into numeric rather than true UTF-16 code-point order.  JCS enforces strict
  code-point order (`"10"` before `"9"`), matching the spec exactly.  No pre-swap
  persisted ledgers with integer-keyed payloads exist, so no re-seal is required.

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
