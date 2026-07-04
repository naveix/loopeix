# Shadow-fleet internal contract (frozen)

Every module in `shadow/` implements against these interfaces. Changing a shape here is a
breaking change requiring all three modules to update together. Authored from the live CLI
(2026-07-04): receipt top-level keys are `brief, brief_clauses, capture_gaps, claims, evidence,
ledger_binding, receipt_version, run, signature, summary`; a sealed run dir contains
`receipt.json` + `ledger.jsonl` (+ report files). `loopeix verify <receipt> --run-dir <dir>`
exits 0 = VERIFIED, non-zero = NOT VERIFIED. `loopeix spec validate <file>` exits 0 = valid.

## 1. Persona record (`shadow/persona/personas.jsonl`, one JSON object per line)

```json
{
  "id": "p0007",
  "seed": 7,
  "archetype": "impatient-shipper",
  "identity": { "occupation": "backend engineer", "experience": "senior", "os_pref": "linux" },
  "behaviour": {
    "docs_read_ratio": 0.2,     // 0..1 — fraction of documented steps actually read/followed
    "patience_turns": 3,        // max steps before giving up (T1 turn budget)
    "fault_injection": ["skip-build"],  // subset of {skip-build, wrong-workspace, stale-tarball, none}
    "adversarial": false        // true => routed to the tamper/fuzz lane, never to Tier 2
  },
  "env_cell": { "node": "22.12", "base": "node:22.12-bookworm-slim", "shell": "bash" },
  "mission": "docile-install",  // one of the mission keys in §3
  "tier": 0                     // 0 scripted | 1 cheap-model | 2 real-engine
}
```

Rules: `adversarial:true` ⇒ `tier` = 0 **only** (S18-B′ hardening: Harbor's `claude-code`/`codex`
adapters mount live subscription auth INTO the trial container, so the old "never Tier 2" rule
extends to every live-auth tier — the sampler and generator both fail loudly on violation);
every field required; deterministic given `seed`.

**Tier-0 scope (important, do not overclaim):** at Tier 0 the persona is run by a deterministic
per-mission `solve.sh`, so `docs_read_ratio`, `patience_turns` and `fault_injection` are **carried
metadata only** — they do NOT branch the Tier-0 script. Tier-0 behavioural variation comes from
`mission` + `env_cell` + (for fuzz) `seed`.

**Tier-1 scope (S18-B′):** at Tier 1 the behaviour params are ACTIVE: `docs_read_ratio` selects
the instruction's guidance band (≥0.7 full command steps / 0.3–0.7 command names + `--help`
pointers / <0.3 goal-only), and `patience_turns` is stated as a command budget AND enforced as the
agent timeout in `task.toml` (`clamp(120×patience, 300, 900)` seconds). `fault_injection` remains
`["none"]` at Tier 1 v1. Distinctness claims from these params are measured from action traces
(SG6), not assumed.

## 2. Environment / tier matrix (`shadow/matrix.json`) — read by the generator

```json
{
  "env_cells": [ { "node": "22.12", "base": "node:22.12-bookworm-slim" }, ... ],
  "missions": [ ...manifest of implemented missions... ],
  "archetypes": [ ...each maps an archetype -> mission, tier, behaviour ranges... ]
}
```

The **sampler** reads `env_cells` and `archetypes` (tier and mission come from the archetype; all
archetypes are Tier 0 today). `missions` is a manifest for reference. `tier_mix` is **reserved for
Tier-1/2 sampling and not yet consumed** — it was removed from the shipped matrix to avoid dead
config; re-add it when Tier-1 sampling lands.

## 3. Missions → each compiles to a Harbor task (persona `solve.sh`) + deterministic oracle (`test.sh`)

| mission | persona does | oracle passes iff |
|---|---|---|
| `docile-install` | doctor → run start (snitch replay + seal) → verify → pr | all exits 0; VERIFIED; PROMISE_BROKEN+UNSUPPORTED present; PR row + SVG; receipt+ledger exist |
| `docs-followability` | follows walkthrough L1 (verify committed fixture receipts, good+tampered) | good receipts exit 0, tampered exit 1, exit codes match documented table |
| `adversarial-tamper` | seal honest → forge 4 ways (body flip, ledger edit, truncate, verdict downgrade) | honest verifies; all forgeries rejected; each forgery byte-changed (guard) |
| `spec-corpus` | `spec validate` over valid + invalid spec fixtures | every valid exits 0, every invalid exits non-zero (no false-accept, no false-reject) |
| `fuzz-receipt` | mutate a receipt N times (random byte/field/JSON corruption, seeded) | zero mutation verifies (exit 0); any accept = P0 |

### 3b. Tier-1 missions (live cheap-model personas; docile only — see §1 credential rule)

Run with `harbor run -a claude-code -m <cheap-model>` (or `-a codex`); the agent acts on
`instruction.md`; `solution/solve.sh` is a reference that satisfies the same oracle, so the whole
lane is validated offline with `-a oracle` before any live wave (selftest.sh does this).

| mission (T1) | persona does | deliverable | oracle passes iff |
|---|---|---|---|
| `docile-install` | produce a sealed run in `/app/work` from the fixtures | sealed run artifacts | ≥1 run dir whose `receipt.json` passes an **oracle-run** `loopeix verify` |
| `docs-followability` | judge the 5 receipts in `receipts-mixed/` (content-hash names — the original self-describing filenames are an answer key) | `/app/out/answers.env` (`<file>=VERIFIED\|NOT_VERIFIED`) | every answer matches **oracle-re-derived** truth; exactly 2 of 5 verify (count tripwires: more ⇒ false-accept P0, fewer ⇒ false-reject P0) |
| `spec-corpus` | classify every spec in `specs-mixed/` (content-hash names — directory labels cannot leak the key) | `/app/out/answers.env` (`<file>=valid\|invalid`) | every answer matches oracle-re-derived truth; oracle's own valid-count equals the baked floor (`spec-truth-drift` P0 tripwire) |

**Tier-1 oracle doctrine:** the verifier re-derives ground truth by running the loopeix CLI
itself; agent-written files are graded DELIVERABLES read via `grep` (never sourced, never trusted
as telemetry), missing/malformed = fail-closed. Known scope: the verifier shares the container
with the agent (Harbor design), so a hostile agent could tamper with the CLI or fixtures before
scoring — accepted at Tier 1 because Tier-1 personas are docile-only by the §1 credential rule.

**Tier-1 staging rule (prep.sh):** Tier-1 environments receive ONLY mission inputs — the
tarball, the run-seal fixtures, `specs-mixed/`, `receipts-mixed/`. The labelled `specs/valid/`
+ `specs/invalid/` dirs and the original-named receipts are Tier-0-only: staging them next to
the anonymised sets would hand a live persona the full answer key by hash-matching.

**Persona-corpus trust rule (generate-tasks.mjs):** `--personas` input is untrusted. Every
string field is whitelist-validated (`[A-Za-z0-9 ._:/-]`, ≤64 chars), numerics range-checked,
enums closed — a crafted corpus must not be able to inject instructions into a (live-auth)
Tier-1 container or oracle script.

**Live-wave guards (run-wave.sh):** non-oracle agents require (1) `LOOPEIX_SHADOW_LIVE_OK`
set to TODAY'S date (the usage-window ack expires daily), (2) explicit `-p` paths that are all
under `generated-t1` (never Tier-0 dirs — those hold adversarial missions), (3) an explicit
cheap model via `-m`. Accepted risk v1: Tier-1 containers keep Harbor's default network egress
(`network_mode = "public"`) because the live adapters need API egress; revisit with Harbor's
agent-host allowlisting before any T2 wave.

## 4. Task directory layout the generator emits

Tier 0: `shadow/generated/<persona-id>-<mission>/`. Tier 1: `shadow/generated-t1/<persona-id>-t1-<mission>/`
(separate dir so a Tier-0 wave can never accidentally include live-engine tasks; the `-t1-` name
segment is how the curator assigns tiers). Both dirs are fully gitignored and regenerated
deterministically from a persona corpus (`generate-tasks.mjs --personas <file>` wipes only the
tier dirs present in that corpus).

Standard Harbor task: `task.toml`, `instruction.md`, `environment/Dockerfile`,
`environment/fixtures/` (staged by prep — including `fixtures/specs-mixed/`, the content-hash-named
anonymised spec set for the T1 spec-corpus mission), `solution/solve.sh`, `tests/test.sh`.

## 5. Findings record (`shadow/curate` output: `findings.json` + `findings.md`)

```json
{
  "generated_from_jobs": ["jobs/2026-07-04__10-33-38", "..."],
  "totals": { "trials": 240, "pass": 236, "fail": 4, "exceptions": 0 },
  "by_mission": { "docile-install": { "pass": 120, "fail": 0 }, "...": {} },
  "gates": { "SG1_install": "PASS", "SG3_abuse": "PASS", "...": "..." },
  "findings": [
    {
      "signature": "verify:false-accept:fuzz-receipt",   // dedupe key
      "severity": "P0",
      "count": 1,
      "example_trial": "jobs/.../p0031-fuzz-receipt__xxx",
      "evidence": "oracle stdout line proving it",
      "personas": ["p0031"]
    }
  ]
}
```

Curator dedupes by `signature` (now `token:t<tier>:<mission>`), ranks P0>P1>P2, and maps totals →
the SG1–SG6 gate verdicts from the plan. Tier-0 and Tier-1 cohorts are scored separately
(`by_mission` vs `t1_by_mission`): T0 gates demand zero fails; SG2 uses the plan's Tier-1 measure
(pass rate ≥ 80%) whenever a T1 cohort ran, else falls back to the interim T0 reading.
Severity: false-accept/false-reject/spec-truth-drift on the trust surface = P0; crash/exception/
missing-fixture = P1; T1 persona misses (mission-incomplete/no-answer/wrong-answer) = P2.
