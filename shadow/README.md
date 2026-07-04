# Loopeix shadow-fleet (S18)

Simulated agent "users" that install and exercise the Loopeix CLI in isolated containers, decided
by deterministic oracles. Substrate: [Harbor](https://github.com/harbor-framework/harbor) (a
persona mission = a Harbor task: instruction + Dockerfile env cell + `tests/test.sh` oracle).
Plan and rationale: `loopeix-specs/docs/sprints/s18-shadow-fleet-plan.md` (decisions D20/D22).

## Run it

```bash
uv tool install harbor          # once; needs a running Docker daemon
./shadow/prep.sh                # build+pack loopeix, stage tarball+fixtures into each task
cd shadow && harbor run -a oracle -p tasks --n-concurrent 2
```

`-a oracle` runs each task's reference persona (`solution/solve.sh`); swap for `-a claude-code` /
`-a codex` (subscription auth) for the Tier 1/2 live personas. `-k N` replicates a task N times —
the scale lever toward hundreds. Results and the packed tarball are gitignored (`jobs/`, `dist/`,
`*.tgz`).

## Spike status (2026-07-04) — GATE MET

| Task | What it proves | Result |
|---|---|---|
| `t0-docile-install` | first-time user: doctor → replay+seal → verify → pr, on the Node 22.12 floor (Linux) | reward 1.0 |
| `t0-adversarial-tamper` | four receipt forgeries (body flip, post-seal ledger edit, truncation, verdict downgrade) all rejected by `loopeix verify`; honest receipt still verifies | reward 1.0 (atk1..4 exit 1) |

Honest spike finding (methodology, not a product bug): a naive `jq` verdict-rewrite was vacuous
because the target claim was already `VERIFIED`, so `verify` correctly passed — the oracle flagged
it as a false-accept until a byte-change guard was added. Tamper oracles must assert the attack
actually changed bytes.

## Tiers (see the plan)

- **T0** scripted, no LLM — deterministic oracles, ~free (these two tasks). Includes the tamper lane.
- **T1** cheap-model Agent SDK personas — local waves of 10–30 concurrent (not 100; 8 GB VM).
- **T2** real `claude`/`codex` sessions — **docile doc-following only**; adversarial personas never
  run here because live credentials sit in the container.
