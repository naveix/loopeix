# Shadow-fleet — S18-A′ first full Tier-0 wave

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
