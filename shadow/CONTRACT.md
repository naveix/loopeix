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

Rules: `adversarial:true` ⇒ `tier` ∈ {0,1} (never 2); every field required; deterministic given `seed`.

**Tier-0 scope (important, do not overclaim):** at Tier 0 the persona is run by a deterministic
per-mission `solve.sh`, so `docs_read_ratio`, `patience_turns` and `fault_injection` are **carried
metadata only** — they do NOT branch the Tier-0 script. Tier-0 behavioural variation comes from
`mission` + `env_cell` + (for fuzz) `seed`. The fine-grained params drive **Tier-1 LLM personas**,
which interpret them at runtime. Any coverage claim from these params is a Tier-1 claim.

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

## 4. Task directory layout the generator emits (`shadow/generated/<persona-id>-<mission>/`)

Standard Harbor task: `task.toml`, `instruction.md`, `environment/Dockerfile`,
`environment/fixtures/` (staged by prep), `solution/solve.sh`, `tests/test.sh`.
`environment/loopeix-*.tgz` and `environment/fixtures/` are gitignored (staged by `prep.sh`).

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

Curator dedupes by `signature`, ranks P0>P1>P2, and maps totals → the SG1–SG6 gate verdicts from
the plan. Severity: false-accept/false-reject on the trust surface = P0; crash/exception = P1;
docs-followability miss = P2.
