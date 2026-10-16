# Getting started

A 10-minute, learning-oriented walkthrough: install Loopeix, create a workspace, author a spec,
replay a committed captured-event fixture, and verify its report and receipt. By the end you will
have completed one offline evidence flow and know where its trust guarantees come from.

> New to the ideas here? Skim [Explanation: the trust model](../explanation/trust-model.md) after
> this — it explains *why* each step exists.

## 1. Prerequisites

- A supported even-major Node.js release: **22.12+, 24, or 26** (`node --version`).
- **pnpm** (`npm install -g pnpm`).

No Codex or Claude installation or credential is required. This walkthrough replays committed,
redacted events; the current source does not start a live provider process.

## 2. Install (from source)

```bash
git clone <this-repo> loopeix && cd loopeix
pnpm install && pnpm build && npm link
```

Confirm the install and that the bundled schema is present:

```bash
loopeix doctor
```

`doctor` checks your Node version, the CLI version, and the bundled JSON Schema. Fix anything it
flags before continuing.

## 3. Create a workspace

```bash
mkdir ../loopeix-demo && cd ../loopeix-demo
loopeix init
```

This creates a `.loopeix/` directory (`workspace.yaml` + `loops/`) **in the current folder** — never
in your home directory. Run data will live here, and uninstalling Loopeix never deletes it (see
[INSTALL-UNINSTALL](../INSTALL-UNINSTALL.md)).

## 4. Author and validate a spec

Copy the starter template and validate it:

```bash
cp ../loopeix/templates/loopeix.template.yaml my-loop.yaml
loopeix spec validate my-loop.yaml
# OK  my-loop.yaml is a valid Loopeix
```

Now **break it on purpose** to see the two-layer validation. Change `risk_tier: "T2"` to `"T5"` and
re-validate:

```bash
loopeix spec validate my-loop.yaml
# INVALID  my-loop.yaml (1 issue):
#   - tool_grants.0.risk_tier: Invalid option: expected one of "T0"|"T1"|"T2"|"T3a"|"T3b"|"T3c"|"T3d"|"T4"
# (exact wording is Zod-version-dependent; the signal is the field path + that T5 was rejected)
```

That error is not a typo check — **T5 (scheduled/unattended behavior) is forbidden in V1**, and the
schema encodes it. Change it back to `T2`.

Validation has two layers: **structural** (shape, enums, generated from Zod → JSON Schema) and
**relational** (cross-field invariants a schema can't express, e.g. "no T5 tier without approval").
Both must pass.

## 5. Inspect it

```bash
loopeix spec inspect my-loop.yaml
# my-loop v001  [evaluator-optimizer]
#   roles: writer, reviewer
#   tasks: do-the-work
#   gates: no-t5*   (* = blocking)
#   max tier without approval: T2
```

`inspect` is the human-readable summary — roles, tasks, and which gates block a run.

## 6. Replay captured evidence and verify the result

The only executable start path in the current source is offline captured-event replay. Run the
repository's clean fixture from the demo workspace:

```bash
loopeix run start ../loopeix/tests/fixtures/run-seal/seal-loop.yaml \
  --engine codex \
  --events-file ../loopeix/tests/fixtures/run-seal/clean-events.jsonl \
  --seal ../loopeix/tests/fixtures/run-seal/clean-brief.yaml \
  --workspace "$PWD"
RUN_DIR="$(find "$PWD/.loopeix/runs" -mindepth 1 -maxdepth 1 -type d -print -quit)"
loopeix report build "$RUN_DIR"
loopeix report open "$RUN_DIR"
loopeix verify "$RUN_DIR/receipt.json" --run-dir "$RUN_DIR"
```

`report open` prints the local HTML path; it does not launch a browser. The final command must print
`VERIFIED`. During replay, events are appended to a hash-chained **ledger**, gates are evaluated,
claims are checked against evidence, and a report is built. A report always has these sections,
even when empty:

- **Verified claims** — exactly the claims the evidence verifier confirmed (a strong claim needs
  present, independent evidence — a file diff alone is not enough).
- **Unverified claims** — declared but not proven; never silently promoted.
- **Capture gaps** — what the engine could not observe directly (disclosed, not hidden).
- **Waivers, unresolved findings, redaction state, known limitations.**

A report **cannot over-claim**: the report-truthfulness gate HOLDs if it asserts a claim the evidence
didn't verify.

This proves the deterministic replay, ledger, report, and offline receipt-verification path. It does
**not** prove live Codex/Claude execution or production-host readiness; those paths remain on HOLD.
`run status` and `run recover` currently require the newer planned-run layout and therefore are not
used for this raw-compatibility fixture.

## Next steps

- [How-to: common tasks](../how-to/common-tasks.md) — validate, recover a ledger, build a report.
- [Reference: CLI](../reference/cli.md) — every command and exit code.
- [Explanation: the trust model](../explanation/trust-model.md) — the design and its honest limits.
