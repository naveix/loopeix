# Loopeix shadow-fleet (S18)

Simulated agent "users" that install and exercise the Loopeix CLI in isolated containers, decided
by deterministic oracles. Substrate: [Harbor](https://github.com/harbor-framework/harbor) (a
persona mission = a Harbor task: instruction + Dockerfile env cell + `tests/test.sh` oracle).
Plan and rationale: `loopeix-specs/docs/sprints/s18-shadow-fleet-plan.md` (decisions D20/D22).

## Run it (Tier 0 — scripted, free)

```bash
uv tool install harbor                                   # once; needs a running Docker daemon
node shadow/persona/sample-personas.mjs --n 240 --seed 11  # deterministic persona corpus
node shadow/generate/generate-tasks.mjs                  # compile corpus -> shadow/generated/
./shadow/prep.sh                                         # build+pack loopeix, stage tarball+fixtures
bash shadow/run-wave.sh                                  # wave: -n 6, -r 2 (infra retry), auto-curate
```

`run-wave.sh` wraps `harbor run` with the scaled-wave defaults: concurrency 6 (8 GB Docker VM
ceiling), `--max-retries 2` for the ~3% Docker bind-mount race (Harbor retries EXCEPTIONS only and
deletes the failed attempt's dir first — oracle failures are never retried, so findings cannot be
laundered), then reports the infra-retry count and runs the curator. Results and the packed
tarball are gitignored (`jobs/`, `dist/`, `generated*/`, `*.tgz`).

## Tier 1 (live cheap-model personas — operator approval REQUIRED)

Tier-1 personas are run by Harbor's native `claude-code`/`codex` adapters on subscription auth;
the behaviour params (docs band, patience budget) are active. Generate and validate offline first
(`selftest.sh` proves the T1 reference solutions pass their oracles with `-a oracle` — no engine
calls), then, ONLY after the operator has checked the Claude/Codex usage window:

```bash
node shadow/persona/sample-personas.mjs --tiers 1 --n 12 --seed 21 --out shadow/persona/personas-t1.jsonl
node shadow/generate/generate-tasks.mjs --personas shadow/persona/personas-t1.jsonl
./shadow/prep.sh
# claude-code: needs CLAUDE_CODE_OAUTH_TOKEN (from `claude setup-token`) + CLAUDE_FORCE_OAUTH=1
# codex:       needs ~/.codex/auth.json + CODEX_FORCE_AUTH_JSON=1
LOOPEIX_SHADOW_LIVE_OK=$(date +%F) CLAUDE_FORCE_OAUTH=1 CLAUDE_CODE_OAUTH_TOKEN=... \
  bash shadow/run-wave.sh -a claude-code -m claude-haiku-4-5 -p generated-t1 -n 4
```

`run-wave.sh` hard-stops any non-oracle agent unless ALL of: `LOOPEIX_SHADOW_LIVE_OK` equals
TODAY'S date (the usage-window ack expires daily — a stale shell export cannot authorise a wave
weeks later), every `-p` path is under `generated-t1` (Tier-0 dirs hold adversarial missions and
must never see a live-auth agent), and a cheap model is pinned with `-m`. The OAuth token is
mounted into the trial containers, which is why adversarial personas are Tier 0 only (CONTRACT §1).

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

- **T0** scripted, no LLM — deterministic oracles, ~free. Includes the tamper/fuzz lane. The ONLY
  tier where adversarial personas run.
- **T1** cheap-model personas via Harbor's `claude-code`/`codex` adapters (subscription auth,
  model pinned cheap with `-m`) — docile missions only; waves at concurrency ~4 on the 8 GB VM;
  gated on `LOOPEIX_SHADOW_LIVE_OK=1` after an operator usage-window check.
- **T2** real `claude`/`codex` sessions at full model strength — **docile doc-following only**;
  sized from the live usage page before each wave.
