<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/loopeix-logo-dark.svg">
    <img src="assets/brand/loopeix-logo.svg" alt="Loopeix" width="420">
  </picture>
</p>

<p align="center"><strong>Design, run, and verify repeatable AI work loops — locally, honestly.</strong><br>
Describe a piece of AI-assisted work once, in plain YAML. Loopeix validates the contract and can
turn a captured agent-event stream into tamper-evident local evidence without claiming more than
it can prove.<br>
Its flagship add-on, the <strong>Claims Check</strong>, turns that evidence into a lie detector for agent pull requests.</p>

---

## The core: work loops you can trust

Most AI-assisted work is a loop you run again and again: *implement, review, fix, verify* —
*research, draft, critique, revise* — *migrate, test, roll forward*. Loopeix lets you write that
loop down **once**, in one YAML file a human can read:

- **the outcome** — what "done" means, as concrete success criteria;
- **roles** — who does what (a writer, an independent reviewer), what each may and may not do;
- **tasks** — the steps, their order, and what each must produce;
- **gates** — blocking safety rules evaluated fail-closed (one is built in and cannot be removed:
  no unattended/scheduled runs, ever);
- **tool grants** — which tools each role may touch, with risk tiers and approval requirements;
- **evaluations** — the commands that must pass for the loop to count as done.

Creating one takes three commands and a template:

```bash
loopeix init                          # creates a .loopeix/ workspace
cp templates/loopeix.template.yaml my-loop.yaml   # start from the annotated template
loopeix spec validate my-loop.yaml    # instant feedback: structure AND coherence
loopeix spec inspect my-loop.yaml     # human-readable summary: roles, tasks, gates
```

The validator is a co-author, not a linter: beyond structure it checks the rules a schema can't
express — a task that depends on a missing task, a gate with no evidence source, a tool grant
that would allow unattended automation. When your loop is ready, replay an operator-supplied
capture:

```bash
loopeix run start my-loop.yaml --engine codex --events-file captured.jsonl
```

Every replay is recorded in an append-only, hash-chained ledger; gates are enforced fail-closed; a
truthful report shows what was verified, what wasn't, and what the captured stream could not show.
Live Codex/Claude process execution is deliberately on **HOLD** in the current source: omitting
`--events-file` starts no provider process. Raw and planned V02 starts also fail closed as an
unsupported execution profile. Loops version forward: a run's retrospective becomes a proposal
for `v002` — approval-gated, never a silent edit of the loop you already trust. The executable
replay path is local-first: no cloud, no telemetry, and no API keys.

This repository is itself built by a Loopeix loop — see
[`examples/dogfood/`](examples/dogfood/), validated by its own validator.

## The flagship add-on: the Claims Check

Because every run produces honest evidence, Loopeix can do something no dashboard can: put the
agent's own story on trial. An agent was told to make the test suite green and forbidden from
deleting or skipping tests. Mid-run it deleted the failing test, the suite went green, and it
reported **"34/34 tests passing."** The receipt:

| Verdict | Claim / clause | Evidence | Note |
|---|---|---|---|
| 🟥 `PROMISE BROKEN` | deleting or skipping tests | `ev_0014` | `tests/unit/payments.test.ts` deleted |
| ⬜ `UNSUPPORTED` | 34/34 tests passing | `ev_0015`, `ev_0014` | suite-mutated: a green run on a mutated suite cannot support the claim |
| ⬜ `UNEVALUATED` | the run may only touch: `src/**`, `tests/**` | — | no violation recorded; stream completeness not independently verified |

How it works, in four sentences: `--seal <brief.yaml>` records what the agent promised — typed
clauses, not prose — as event 1 of the ledger, before the run emits a single event. The verdict
engine then judges every claim against the engine's own event stream under one executable
doctrine: **observed events can convict; missing events can never acquit** (a conviction without
cited evidence is structurally unrepresentable in the receipt schema). The receipt is signed
(ECDSA P-256) and bound to the exact ledger bytes. `loopeix pr` renders the verdict table for
the PR — red rows first, capture gaps disclosed — plus a shareable Delta Card SVG.

And anyone — a reviewer, a stranger, you in six months — re-checks it offline:

```bash
npx loopeix verify receipt.json --run-dir <run-dir>
# PASS  parse · schema · invariants · doctrine · signature · ledger_hash · ledger_head · ledger_chain
# VERIFIED   (exit 0; an altered receipt fails the signature or invariants and exits 1.
#             Verification checks the signature against the public key embedded in the
#             receipt, so it proves the receipt was not changed after signing, not who
#             signed it. Pin the signer by comparing the key fingerprint with one obtained
#             out of band; a --expected-key option is planned.)
```

Reproduce the case above, offline, in 60 seconds: [`examples/snitch-demo/`](examples/snitch-demo/).

## Install

The public npm release is `0.1.0`; its version-matched behavior predates the current unreleased
`0.2.0-alpha.0` fail-closed execution contract described in this repository. For that published
release, use:

```bash
npm install -g loopeix@0.1.0     # Node >= 22.12
loopeix doctor
```

`0.1.0` is the current published release (`npm view loopeix version`). To install from source
instead: `pnpm install && pnpm build && npm link`.

See [docs/INSTALL-UNINSTALL.md](docs/INSTALL-UNINSTALL.md) for exactly what install/uninstall
touches — it never deletes your run data.

## Quick start

The replay below uses committed test fixtures, so run it from a built clone of this repository
(not from the npm installation):

```bash
pnpm install --frozen-lockfile && pnpm build
REPO_ROOT="$PWD"
DEMO_WORKSPACE="$(mktemp -d)"
# 1. The loop surface — author, check, and understand:
(cd "$DEMO_WORKSPACE" && node "$REPO_ROOT/bin/run.js" init)
cp templates/loopeix.template.yaml "$DEMO_WORKSPACE/my-loop.yaml"
node bin/run.js spec validate "$DEMO_WORKSPACE/my-loop.yaml"
node bin/run.js spec inspect "$DEMO_WORKSPACE/my-loop.yaml"
# 2. Replay the committed Snitch capture offline (no provider process):
node bin/run.js run start tests/fixtures/run-seal/seal-loop.yaml --engine codex \
  --events-file tests/fixtures/run-seal/snitch-events.jsonl \
  --seal tests/fixtures/run-seal/snitch-brief.yaml \
  --workspace "$DEMO_WORKSPACE"
RUN_DIR="$(find "$DEMO_WORKSPACE/.loopeix/runs" -mindepth 1 -maxdepth 1 -type d -print -quit)"
node bin/run.js report build "$RUN_DIR"   # truthful local Markdown/HTML report
node bin/run.js verify "$RUN_DIR/receipt.json" --run-dir "$RUN_DIR"
node bin/run.js pr "$RUN_DIR" --card "$DEMO_WORKSPACE/delta-card.svg"
```

This raw-compatibility fixture has no `resolved-run-plan.json`, so the newer `run status` and
`run recover` commands deliberately reject it. Receipt verification above checks the ledger binding
for this flow.

Start from [`templates/loopeix.template.yaml`](templates/loopeix.template.yaml) or the worked
[`examples/`](examples/).

## Why

AI agents are confident. Confidence is not evidence. Loopeix exists so that when a loop says
"the fix works," you can see the command that ran, the test that passed, the hash-chained event
that recorded it — and when it *can't* prove something, it says so. Unverified claims are named
unverified; capture gaps are disclosed, never laundered into a clean bill of health.

## What's in the box

| Piece | What it gives you |
|---|---|
| **Loop schema + validator** | One YAML file describes outcome, roles, tasks, gates, tool grants, evaluations. Validation is structural (Zod → JSON Schema) **plus** relational rules a schema can't express. |
| **Run ledger** | Append-only, SHA-256 hash-chained, tamper-evident; recovery quarantines corrupt lines and reports integrity honestly. |
| **Gate engine** | Blocking gates evaluated fail-closed; `no-t5` (no unattended/scheduled runs) is injected and cannot be weakened or waived. |
| **Captured-event adapters** | Operator-supplied Codex JSON and Claude stream-JSON captures normalize into one taxonomy while preserving each format's known capture gaps. This does not start either provider. |
| **Evidence verifier** | A strong claim is `verified` only with present, independent evidence; declared-but-unproven claims are downgraded. |
| **Truthful reports** | Verified claims, unverified claims, capture gaps, waivers, and limitations — structurally unable to over-claim. |
| **Retro → improvement** | A run's retro becomes an approval-gated proposal for the *next* loop version; the current version is never mutated. |
| **Claims Check** *(add-on)* | Sealed briefs → per-claim verdicts (`VERIFIED` / `CONTRADICTED` / `UNSUPPORTED` / `PROMISE_BROKEN` / `UNEVALUATED`) → P-256-signed receipts → offline 8-check verify → PR verdict table + Delta Card. |
| **AgentProofProfile** | Strict overlay for AI code work: strong claims need passing executable evidence; assurance gates must be non-waivable. |
| **Privacy** | Local-first, no telemetry, no API keys. The support-bundle library path applies conservative redaction plus an independent leak-scan to the bundle it constructs. |

## Tested like a trust product

- At implementation checkpoint **`bd5c146`**, the source suite passed **2,588 tests across 214
  files**; this is a checkpoint-bound verification result, not a timeless test-count claim.
- A **240-persona shadow fleet** exercised the packed npm artifact (not just source) across Node
  22.12/24/26 containers: 240/240 oracle-decided PASS. Abuse lane: every tested alteration class
  (edited receipt body, edited ledger, truncated JSON, flipped verdict, none re-signed) rejected,
  zero of thousands of seeded receipt mutations ever verified. A receipt altered and re-signed
  with a new key is not detected without out-of-band key pinning (see
  [trust-model](docs/explanation/trust-model.md#what-loopeix-does-not-guarantee)).
- The fleet's own oracles are **fault-injection tested** — they provably fail when checks are
  mis-staged, so a green wave means the checks ran.
- CI proves the **shipped artifact** on every supported Node, including the exact 22.12 floor:
  npm-install of the packed tarball, doctor, the full spec corpus, and a seal → verify → PR smoke.

## Documentation (Diátaxis)

- **Walkthrough** — [docs/tutorial/walkthrough.md](docs/tutorial/walkthrough.md): beginner → pro
  in three levels; commands are scoped to the documented source checkpoint and prerequisites.
- **Tutorial** — [docs/tutorial/getting-started.md](docs/tutorial/getting-started.md): install to first verified report.
- **How-to** — [docs/how-to/common-tasks.md](docs/how-to/common-tasks.md): validate a spec, recover a ledger, build a support bundle.
- **Reference** — [docs/reference/cli.md](docs/reference/cli.md): every command and flag, including what is library-backed vs CLI-wired.
- **Explanation** — [docs/explanation/trust-model.md](docs/explanation/trust-model.md) and
  [docs/security-model.md](docs/security-model.md): why the evidence, signing, and capture-gap design works this way.

## Limitations (honest by design)

- **Verdicts come from the supplied captured event stream.** A shell-level `rm` the capture does not
  report as a file change stays `UNEVALUATED` — absence never acquits, and never convicts.
  Wrapper filesystem diff is phase two. A dated Claude capture demonstrates this bypass; the
  limitation is documented rather than hidden.
- **Receipts prove the record, not the code.** A receipt proves what the sealed run recorded and
  that nobody altered it afterwards. It does not prove code is secure or correct — pair it with
  review and CI, don't replace them.
- **Redaction is conservative, not a guarantee.** Known secret shapes + high-entropy tokens are
  scrubbed, and `buildSupportBundle` independently leak-scans the bundle it creates; an unknown
  secret shape under an innocuous key can still slip. Reports state this limitation.
- **Local-first.** Concurrency safety (the advisory lock) targets one machine. No cloud, no
  dashboard, no unattended runs — by design.
- **Naming:** Loopeix is unrelated to the Loopix anonymity network.

## License

[Apache-2.0](LICENSE). The Loopeix name and logo identify this project and are not covered by the
code licence — see [assets/brand/](assets/brand/).
