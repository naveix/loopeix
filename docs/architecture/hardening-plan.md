# Loopeix Architecture Hardening Plan

> Authored by a Fable 5 architecture pass against the code at commit `a25e7f2` + release-prep, and the
> independent-review findings log. Every weakness below was verified against current source, not
> recalled. Status: **proposed**. The single ordering rule underneath all of it: **make every claim the
> system already renders become true before adding new claims** — verified claims before signatures,
> signatures before real tiers/timestamps get signed, durability before scale.

## Verified current-state facts this plan is built on

1. `src/run/orchestrate.ts` — `evidence: { verified: [], unverified: [], claims: [] }` is hardcoded. A real run never verifies a claim.
2. `src/gates.ts` — `REQUIRED_V1_GATES = ["no-t5"]` only. `checkReportTruthfulness` exists but nothing in `assembleRun`/CLI calls it; `scanForLeaks` is not in the run path either.
3. `src/run/orchestrate.ts` — `risk_tier: "T1"` hardcoded on every ledger event.
4. `src/run/orchestrate.ts` — event timestamps fabricated as `started_at + i seconds`; `NormalizedEvent` carries no timestamp, so the ledger timeline is synthetic.
5. `src/ledger.ts` — hash chain is keyless; re-seal, tail-truncation, and byte-level tampering documented as limits.
6. `src/lock.ts` — hardened but **not imported by any run command**; `run start` writes without a lock. `expectedLastSequence` truncation detection is wired only inside `buildRunManifest`.
7. `src/run/engine.ts` — `spawnSync` (synchronous, whole-stream-then-parse); a crash mid-run persists nothing (ledger assembled in memory, written once at the end).
8. `src/commands/run/start.ts` — `run_id = run_${Date.now().toString(36)}` collides in the same millisecond and is predictable.
9. Spec schema already has what linkage needs: `evaluations[]` (id/type/command/success_condition/required), `tasks[].acceptance_checks`, `tool_grants[]` (risk_tier/scope/requires_approval).
10. Structured-output capture has no fixtures (explicitly deferred).

---

## P0 — Trust closure (make the existing guarantees true end-to-end)

### P0.1 Automatic claim↔evidence linkage (highest-value item)
**Problem.** The whole assurance stack is proven on fixtures but inert in a real run: `verified: []` is hardcoded, so every real report says "None" under Verified claims and `checkReportTruthfulness` is moot.
**Design.** Don't fuzzy-match agent command events to prose checks (agent grades itself). Instead: (1) claims derive from spec `evaluations` (`strong` when `required`); (2) **Loopeix executes the acceptance commands itself** post-engine (`src/run/evaluate.ts`, `spawnSync` args-array, no shell), capturing exit code + redacted output as *independent* `command` evidence + a sealed `evaluation.result` ledger event; (3) agent-stream events stay as *corroborating* evidence only (exact command-string match), never verify alone; (4) wire `verifyEvidence` + `verifyEvaluations` into `assembleRun` and populate the real `EvidenceReport`; (5) **disclose** that `run start` now executes YAML-declared commands (same trust as `make test`) — show the list, `--yes-evaluations`, sandbox posture; `manual-review`/`browser`/`custom` → HOLD "requires human evaluation", never skipped.
**Effort/risk.** M–L. Risk: command execution from spec — mitigated by no-shell + disclosure + already-validated spec.
**Verify.** Golden fixture (one eval passes, one fails) → report shows one verified/one unverified, `all_required_passed=false`, exit 4; adversarial (transcript claims pass, real eval fails) → contradiction; live dogfood produces the first non-empty Verified section.

### P0.2 Wire the three remaining unwaivable gates into the run path
**Problem.** Only `no-t5` is injected; `report-truthfulness`/`evidence-integrity`/`secrets-privacy` are never computed in `assembleRun`. P0.1 un-moots this.
**Design.** A second gate stage after evidence resolution seals three more `gate.result` events before the terminal: **evidence-integrity** (recover + `verifyEventHashes` + head-signature once P0.3); **report-truthfulness** (`checkReportTruthfulness` on the report input pre-render); **secrets-privacy** (`scanForLeaks` over the full report input + every ledger payload *before* `writeRunDir` — any hit → FAIL → `run.held`, quarantined, never written clear). Injection grows `REQUIRED_V1_GATES` to four (the B1-class fix already built). Re-read path: extend `buildReportFromRunDir` to re-derive the verified set + re-run truthfulness, closing its own documented gap.
**Effort/risk.** S–M once P0.1 exists; low (all components exist).
**Verify.** Tamper report-input → HOLD; planted secret → `run.held` + nothing unredacted on disk; non-blocking `report-truthfulness` spec → normalized back to blocking.

### P0.3 Ed25519 detached signature over the ledger head + `loopeix verify`
**Problem.** A write-capable actor can re-seal a forged chain or truncate the tail — the headline limitation.
**Design.** `node:crypto` Ed25519 (no new deps). `loopeix keys init` → PKCS8 key at `~/.loopeix/keys/` (0600); first run auto-generates with a notice, or `--unsigned`. On terminal seal (and per batch after P1.1), sign canonical `{run_id, last_sequence, head_event_hash, signed_at}` → `ledger.head.sig.json` (atomic temp+rename); manifest records `signing.fingerprint`. `loopeix verify <run-dir>` recomputes the head, checks the signature + fingerprint; missing sig on old runs → disclosed finding; present-but-invalid → always HOLD. **Honest framing:** upgrades "tamper-evident" → "tamper-evident + signer-bound", NOT tamper-proof (a same-account attacker reads the key); external anchoring (P3.1) removes the local-key assumption. Update `security-model.md`; don't let the README overclaim (the S17 lesson).
**Effort/risk.** M. Risks: key UX (lost key → verification degrades to today, never worse) + Windows permissions (P2.5).
**Verify.** Re-seal without key → signature fail; tail-truncate + re-sign without key → fail; rotate key, old run still verifies; forged new sig caught by fingerprint mismatch; `verify` exit codes tested.

### P0.4 Raw-byte line verification (cheap normalization-tamper close)
**Problem.** Duplicate-key / whitespace tampering that survives `JSON.parse` is invisible (hashes over the parsed object).
**Design.** In `parseLedgerText`/`recoverLedger`, compare raw line bytes to `JSON.stringify` of the sealed event; mismatch → integrity HOLD. One pass, no format change, skip already-quarantined lines.
**Effort/risk.** S; near-zero (additive detection).
**Verify.** Duplicate-key, inserted-whitespace, reordered-keys adversarial tests all now HOLD.

### P0.5 run_id entropy
**Problem.** Millisecond ids collide under the concurrency P1 introduces, and are predictable.
**Design.** `run_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`.
**Effort/risk.** S. **Verify.** 10k-generation uniqueness; `MachineId` still validates.

---

## P1 — Durability and runtime (a run that survives a crash)

### P1.1 Write-ahead ledger + streaming engine invocation
**Problem.** The whole run is in memory until one `writeRunDir` at the end; `spawnSync` buffers the whole stream. Kill Loopeix mid-run → no evidence anything happened — the inverse of the product promise.
**Design.** Seal `run.started` and `appendFileSync` it **before** spawning. Replace `spawnSync` with async `spawn` + line-buffered JSONL (carry partial-line remainder), normalize incrementally, redact per batch (P0.2), seal + append under `withLock` every N events / T seconds, updating the head signature per batch. Keep `assembleRun` pure by extracting an `IncrementalRun` appender that both the durable path and replay drive (equivalence test: same fixture both drivers → byte-identical ledger apart from timestamps).
**Effort/risk.** L (biggest item). Risks: two-driver drift (replay literally calls the incremental code); fsync (explicit `fsyncSync` per batch or document OS-flush).
**Verify.** `kill -9` mid-stream → valid ledger prefix, honest `hold`, signature verifies over the prefix; replay-equivalence; 500k-line stream without buffer failure; live smoke still clean (operator-approved).

### P1.2 Resume state machine keyed off the ledger's last valid sequence
**Problem.** No resume; `run recover` is read-only. A dead long loop must rerun from scratch.
**Design.** **The ledger IS the state machine** (no lying sidecar — the S12/run-dir lesson). Phase derived from the last valid event. `loopeix run resume <run-dir>`: lock → recover → verify head sig → branch: *mid-engine* → seal `run.recovering`, re-invoke as a **new append-only attempt** (report discloses "resumed, N attempts"; V1 = finish honestly with a fresh attempt, NOT model-context resume); *pre-seal* → re-run evals/gates/report + seal terminal (no engine cost). Feed `manifest.last_ledger_sequence` into `recoverLedger` to activate the existing truncation detector. Resume is operator-invoked → does not weaken `no-t5`.
**Effort/risk.** M–L on top of P1.1. Risk: overclaiming resume — honest "new attempt" framing.
**Verify.** Kill mid-engine → resume completes; truncation → HOLD; resume a terminal run → refuses; double-resume race → lock serializes.

### P1.3 Wire the lock into the run path
**Problem.** `lock.ts` was hardened through a BLOCKING review then never connected; `run start` doesn't lock.
**Design.** `<run-dir>/ledger.lock`; `run start`/`resume`/`report build` take `withLock` around writes; reads stay lock-free (valid-prefix recovery makes torn reads safe).
**Effort/risk.** S. **Verify.** Concurrent same-run `run start` → one proceeds, one fails closed; stale-steal exercised.

### P1.4 Capability / tool-grant enforcement at the engine boundary
**Problem.** `tool_grants` are authoring-time fiction at runtime — `engineCommand` ignores them.
**Design.** (1) Pre-run: derive engine flags from grants (Claude `--allowedTools`/`--disallowedTools`; Codex stays `read-only` — grants only *narrow*, upward needs approval V1 refuses with a finding; `--` preserved). (2) Post-run audit: match each command/tool event against grants; ungranted → blocking finding + event tier escalates (P2.1); capture gaps bound the claim ("audited within capture limits").
**Effort/risk.** M. Risk: Claude flag surface drift — verify against the live `--help` at build time.
**Verify.** Ungranted-tool fixture → finding, exit 4; grants→argv snapshot tests; safety flags proven appended-last non-overridable.

---

## P2 — Fidelity and coverage

- **P2.1 Real per-event risk_tier.** Deterministic classifier: lifecycle→T1, command/file/tool→matched grant tier, unmatched→fail-closed **T3**+finding; `hasT5` gains an event-tier input. Verify with mixed-tier golden fixtures + a fifth T5-vector test.
- **P2.2 Real event timestamps.** Add optional `timestamp` to `NormalizedEvent`; adapters populate from engine events; seal uses adapter ts → wall clock → disclosed synthetic (`clock_source` per event). Sequence stays authoritative. A signed ledger must not assert times that never happened.
- **P2.3 Structured-output capture fixtures.** One operator-approved bounded live capture per engine (`--output-schema`/`--json-schema`), redacted + leak-scanned, mapped to an evidence type P0.1 can use (schema-valid output = strong evidence).
- **P2.4 Redaction corpus expansion.** A leak-corpus dir (one file per secret family incl. Azure/GCP/`age`/`ssh-ed25519`/Vault `hvs.`/`sk-proj-`), each asserted caught by `scanForLeaks` independently of `redact` (the F1 lesson); end-to-end "nothing unredacted under the run dir" test; mutation-test coverage.
- **P2.5 Cross-platform CI matrix.** ubuntu/macos/windows build+unit+replay (no live calls). Fix `linkSync` on network mounts (refuse, don't degrade), Windows `.cmd` resolution (explicit path, never `shell:true`), key-file perms, `join()` vs string paths.
- **P2.6 Pin canonicalization to RFC 8785 (JCS).** So a non-Node verifier can independently re-derive hashes. Version via `manifest.canonicalization`; old ledgers verify under the old scheme. Do before P0.3 signatures proliferate, or version the signed payload. Verify with RFC test vectors + an independent JCS implementation in CI once.

---

## P3 — Scale and polish (demand-driven)

- **P3.1 External anchoring** of the head hash (per-machine append-only anchor log + opt-in `git notes` to the user's remote; RFC 3161 / transparency log opt-in only — network = privacy boundary). Removes the "attacker with your key" window.
- **P3.2 Wire the privacy/support-bundle CLI** (thin post-P0.2); the docs caveats come off only then.
- **P3.3 Evidence-based `contradicted`** (failing execution of the same command → contradicted).
- **P3.4 `gate check` CLI** (S10 follow-on).
- **P3.5 Cross-host locking** (the `host` field exists; build only on real shared-storage need).
- **P3.6 Performance pass** (benchmark a 1M-event ledger; optimize only what it indicts).

## Deliberately staying deferred (and why)

1. **Tamper-proof against a same-privilege local attacker** — impossible in a local-first tool; P0.3+P3.1 shrink the window honestly.
2. **T5 / unattended runs** — a product stance enforced by the most-hardened gate; resume doesn't erode it; revisit only via ADR.
3. **Fuzzy prose-check→transcript linkage** — lets the agent grade itself; P0.1 is strictly stronger.
4. **True mid-conversation engine resume** — neither CLI exposes it reliably; P1.2's honest "new attempt" is what's truthfully claimable.
5. **A daemon/server runtime** — the ledger IS durable state; a runtime only earns complexity if unattended execution becomes a goal (item 2 forbids it).

## Cross-cutting verification discipline

- Every item keeps the loop that caught a BLOCKING issue in eight consecutive sprints: build → independent review → fix → recheck → green tests → operator "ship it".
- Every new guarantee gets an **adversarial** test (the thing it prevents, attempted).
- Every moved limitation updates ALL of: module doc, `security-model.md`, `trust-model.md`, README Limitations, and the report's Known-limitations renderer.
- Live paid calls stay operator-approved, bounded, budget-capped — never from CI/tests.

## Suggested sprint mapping

| Sprint | Items | Why |
|---|---|---|
| S18 | P0.1 + P0.5 | linkage is the product's missing heart |
| S19 | P0.2 + P0.4 | gates live end-to-end; byte-tamper closed |
| S20 | P2.6 → P0.3 + `verify` | pin the canonical form, then sign it |
| S21–S22 | P1.1 + P1.3 | durable streaming runtime under lock |
| S23 | P1.2 + P1.4 | resume; grants become real |
| S24 | P2.1 + P2.2 | tier + timestamp fidelity |
| S25 | P2.3 + P2.4 + P2.5 | coverage + portability |
| P3 | demand-driven | anchoring (P3.1) first |
