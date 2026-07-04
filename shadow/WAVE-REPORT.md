# Shadow-fleet — Tier-0 waves

## S18-B′ scaled wave — 240 personas (2026-07-04)

Substrate: Harbor 0.17.1 (local Docker). Personas: deterministic sampler seed 11, N=240
(docile-install ×80, docs-followability ×40, spec-corpus ×40, adversarial-tamper ×40,
fuzz-receipt ×40; node cells 22.12/24/26). Reproduce:
`node shadow/persona/sample-personas.mjs --n 240 --seed 11 && node shadow/generate/generate-tasks.mjs && bash shadow/prep.sh && bash shadow/run-wave.sh`.

| Metric | Value |
|---|---|
| Trials (oracle-decided) | 240 |
| Pass | **240 / 240 (100%)** |
| Oracle failures | 0 |
| Infra exceptions unrecovered | 0 |
| Infra retries (advisory, from harbor debug log) | 0 reported |
| Gates | SG1 PASS, SG2 PASS (T0 fallback), SG3 PASS, SG4 PASS, SG5 PASS, SG6 MANUAL |
| Wall clock | ~18 min at `--n-concurrent 6`, `--max-retries 2` (hot Docker layer caches) |

Notes: run via `run-wave.sh` (Harbor-native exception retry — Harbor deletes a failed attempt's
trial dir before retrying and never retries oracle reward-0 results, so retries cannot launder
findings). The retry count is advisory (a harbor debug-log line, both job.log and captured
console are grepped); unrecovered exceptions (trial dirs without reward.txt) are the
authoritative infra-failure signal and the curator fails gates on them. Curated verdict verified
by re-running `curate.mjs` in the foreground and reading `findings.json` back from disk
(mtime-checked) after a session tooling incident produced fabricated mid-wave status text —
see the planning repo's S18-B′ notes.

Tier-1 status: lane BUILT and validated offline (selftest runs every T1 reference solution
against its oracle via `-a oracle`, zero engine calls) — no live Tier-1 wave has run yet;
that run is gated on an operator usage-window check (`LOOPEIX_SHADOW_LIVE_OK=<today's date>`).

### Independent review round 2 (2026-07-04) — HOLD → all folded → re-proven

A 3-lane adversarial Workflow review (false-green / harness-code / credential-safety, each
finding independently verified) raised 24 findings; 22 confirmed after verification (2 refuted),
deduplicating to ~17 distinct defects. All fixed in-session; the wave verdict above was
re-derived under the fixed curator with `--expect 240` and stands. Highlights:

- **SG2 pooled-cohort false PASS (P1, reproduced):** curator now gates SG2 on the T1
  docs-followability cohort ONLY and never overrides a dirty Tier-0 docs cohort; per-mission T1
  rates reported separately. Proven by 4 synthetic-job repros.
- **Two answer-key leaks into T1 containers (P1):** labelled `specs/valid|invalid` dirs were
  staged next to `specs-mixed/`, and the docs mission listed self-describing receipt filenames
  ("tampered-verdict"…). prep.sh now stages per-tier bundles (T1 gets ONLY mission inputs +
  anonymised `specs-mixed/` + new content-hash `receipts-mixed/`); leak-free staging asserted.
- **Instruction injection via crafted `--personas` corpus (P1):** generator whitelist-validates
  every corpus string/numeric/enum before interpolation; proven with a hostile corpus (FATAL).
- **Live-wave guard hardening (P1):** non-oracle agents now require a DATED ack
  (`LOOPEIX_SHADOW_LIVE_OK=$(date +%F)`, expires daily), explicit `-p generated-t1*` paths only
  (Tier-0 dirs hold adversarial missions), and a pinned cheap model via `-m`. All four
  rejection paths exercised.
- **selftest could grade a stale job on harbor launch failure (P1):** run_task now checks
  harbor's exit code and grades only a job dir created by that invocation (before/after diff);
  cleanup restores the CANONICAL fleets instead of leaving selftest's tmp fleets staged (P1).
- **Partial-wave floor (P1):** curator `--expect N` (run-wave passes the task-dir count) forces
  all gates FAIL and emits a `short-wave` P1 finding when trials < expected.
- Plus: retry-count robustness (greps job.log AND captured console; advisory label;
  authoritative unrecovered-exception count), wrong-answer fault injection added to selftest,
  EXP-floor >0 asserts, stale-fixture cleanup on re-prep, job-dir before/after detection in
  run-wave, drift-message wording, usage() fix, getans regex-dot escape.
- Accepted risk (documented in CONTRACT §3b): T1 containers keep Harbor's default public
  egress (live adapters need API egress); revisit with agent-host allowlisting before any T2.
- Refuted by verification (for the record): "retry launders timeout findings" (harbor 0.17.1
  excludes agent-timeout exception types from retry by default).

## S18-A′ first full Tier-0 wave — 60 personas

Date: 2026-07-04. Substrate: Harbor (local Docker). Personas: deterministic sampler seed 7, N=60.
Reproduce: `node shadow/persona/sample-personas.mjs --n 60 --seed 7 && node shadow/generate/generate-tasks.mjs && bash shadow/prep.sh && cd shadow && harbor run -a oracle -p generated --n-concurrent 8`.

## Result

| Metric | Value |
|---|---|
| Trials (oracle-decided) | 58 |
| Pass | **58 / 58 (100%)** |
| Oracle failures | 0 |
| Infra exceptions | 2 (Docker bind-mount race, retry-clean — see below) |
| Missions | docile-install ×20, docs-followability ×10, spec-corpus ×10, adversarial-tamper ×10, fuzz-receipt ×10 |
| Node cells | 22.12, 24, 26 (each mission ran on all three) |

### Gates (curator, plan §5)

| Gate | Verdict |
|---|---|
| SG1 install matrix | PASS (docile-install green on all node cells) |
| SG2 docs followability | PASS (good receipts verify, tampered rejected, exit codes match the documented table) |
| SG3 abuse resistance | **PASS** (adversarial-tamper: 4 forgeries/persona all rejected; fuzz-receipt: 0 of ~24 seeded mutations/persona verified) |
| SG4 crash taxonomy | PASS (0 P1 crashes) |
| SG5 spec corpus | PASS (11 invalid specs rejected, 5 valid accepted — on the **packed tarball**, not just source) |
| SG6 distinctness | PASS-with-caveat (corpus: 60 personas, 47 distinct docs-read ratios 0.01–0.99, 11 patience values, 6 archetypes, 10 occupations, 3 node cells; safety invariant holds — **0 adversarial personas at Tier 2**). Caveat: at Tier 0 the oracle runs a fixed per-mission script, so variation is expressed through **mission + env cell + fuzz seed**; the fine-grained docs-read/patience params are latent until Tier 1's LLM personas interpret them. |

## What the fleet caught (during harness development — the point of the spike discipline)

Every candidate "failure" was root-caused against the real CLI before labelling. Three were bugs
in the **harness**, none in Loopeix; catching them is what makes the green trustworthy:

1. **Vacuous forgery (spike):** a `jq` verdict-rewrite targeted a claim already `VERIFIED`, so the
   receipt was byte-identical and `verify` correctly passed — the oracle mis-read it as a
   false-accept. Fixed: flip `VERIFIED→CONTRADICTED` + `atk*_changed` byte-guards.
2. **Bogus fault (`wrong-workspace`):** the docile oracle expected `run start --workspace <nonexistent>`
   to fail; the CLI correctly `mkdir -p`s the workspace and succeeds. Fixed: removed the false-fault
   (operational note: `run start` silently creates arbitrary workspace paths — intended, documented here).
3. **Exit-code capture bug:** `echo "$(basename "$f")=$?"` captured `basename`'s exit (0), not the
   validator's, manufacturing a fake `spec-corpus` P0 "invalid spec accepted". Root-caused: the
   **packed tarball rejects all 11 invalid specs and accepts all 5 valid ones** — Loopeix is correct.
   Fixed: capture `code=$?` before any substitution. This exercised the shipped artifact, which the
   477 unit tests do not.

## Operational finding (real, low severity)

At `--n-concurrent 8` on this 8 GB Docker VM, ~3% of rollouts (2/60) hit a Docker-on-macOS
bind-mount race (`error mounting .../logs/artifacts: no such file or directory`); the container
never starts. Both failed tasks passed on isolated retry. Mitigations for larger waves: cap
concurrency lower (≈6), or wrap the run with a retry of exception-only trials. Not a Loopeix issue.

## Independent review (2026-07-04) — HOLD → fixed → fault-injection proven

Two adversarial reviewers (false-green audit + harness code review, run via workflow) returned a
HOLD with 2 P0 + 6 P1 findings — a class my own self-audit missed: **file-not-found / empty-glob
conditions read as "rejection," so a fully broken Loopeix or mis-staged fixtures could pass a
security mission having tested nothing**, and curate.mjs silently dropped crashed trials so gates
could pass on a partial wave. All fixed:

- `shopt -s nullglob` everywhere; oracles bake hard floors (5 valid / 11 invalid specs, exactly 24
  fuzz mutations) — a mis-staged fixture set now FAILS, not passes.
- Oracles stopped `source`-ing the agent-writable `exits.env` (tier-1/2 code-injection closed);
  fail-closed defaults; machine CODE tokens the curator classifies on.
- docs-followability asserts each fixture existed and that a real "NOT VERIFIED" reason printed;
  curate counts missing-reward trials as **exceptions** that disqualify the gate.
- prep.sh fails loudly on any missing fixture set.

**Proven, not just claimed:** `shadow/selftest.sh` injects each fault and asserts the oracle now
returns reward 0 with the right token (2/2). Clean 12-task wave still 12/12, no regressions.

## Honest scope

Tier 0 only (scripted, deterministic, no LLM, ~free). This wave proves installability on the
engines floor, docs-followability, spec-validation correctness on the shipped artifact, and abuse
resistance (tamper + fuzz). It does **not** measure human trust; persona opinions are not collected
at Tier 0. Tiers 1–2 (cheap-model and real-engine personas) and the retained human loop are later.
