# Getting started

A 10-minute, learning-oriented walkthrough: install LoopSpec, create a workspace, author a spec,
and understand what "valid" and "verified" mean. By the end you'll have validated your first
LoopSpec and know where the trust guarantees come from.

> New to the ideas here? Skim [Explanation: the trust model](../explanation/trust-model.md) after
> this — it explains *why* each step exists.

## 1. Prerequisites

- **Node.js ≥ 22.12** (`node --version`).
- **pnpm** (`npm install -g pnpm`).
- Optionally the **Codex** or **Claude** CLI if you want to capture real runs — LoopSpec uses their
  own login and never handles API keys.

## 2. Install (from source)

```bash
git clone <this-repo> loopspec && cd loopspec
pnpm install && pnpm build && npm link
```

Confirm the install and that the bundled schema is present:

```bash
loopspec doctor
```

`doctor` checks your Node version, the CLI version, and the bundled JSON Schema. Fix anything it
flags before continuing.

## 3. Create a workspace

```bash
mkdir my-project && cd my-project
loopspec init
```

This creates a `.loopspec/` directory (`workspace.yaml` + `loops/`) **in the current folder** — never
in your home directory. Run data will live here, and uninstalling LoopSpec never deletes it (see
[INSTALL-UNINSTALL](../INSTALL-UNINSTALL.md)).

## 4. Author and validate a spec

Copy the starter template and validate it:

```bash
cp templates/loopspec.template.yaml my-loop.yaml   # from your clone (step 2)
# once published to npm: cp "$(npm root -g)/loopspec/templates/loopspec.template.yaml" .
loopspec spec validate my-loop.yaml
# OK  my-loop.yaml is a valid LoopSpec
```

Now **break it on purpose** to see the two-layer validation. Change `risk_tier: "T2"` to `"T5"` and
re-validate:

```bash
loopspec spec validate my-loop.yaml
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
loopspec spec inspect my-loop.yaml
# my-loop v001  [evaluator-optimizer]
#   roles: writer, reviewer
#   tasks: do-the-work
#   gates: no-t5*   (* = blocking)
#   max tier without approval: T2
```

`inspect` is the human-readable summary — roles, tasks, and which gates block a run.

## 6. Understand a report (the payoff)

> **Design preview, not a runnable step in V0.3.** The report *library* is built and tested, but the
> `loopspec report build`/`open` CLI commands are not yet wired (they warn today) — they arrive with
> the run-execution layer. This section explains what a report guarantees so you know what you're
> working toward.

When a loop runs, its events are appended to a hash-chained **ledger**, gates are evaluated, claims
are checked against evidence, and a **report** is built. A report always has these sections, even
when empty:

- **Verified claims** — exactly the claims the evidence verifier confirmed (a strong claim needs
  present, independent evidence — a file diff alone is not enough).
- **Unverified claims** — declared but not proven; never silently promoted.
- **Capture gaps** — what the engine could not observe directly (disclosed, not hidden).
- **Waivers, unresolved findings, redaction state, known limitations.**

A report **cannot over-claim**: the report-truthfulness gate HOLDs if it asserts a claim the evidence
didn't verify.

## Next steps

- [How-to: common tasks](../how-to/common-tasks.md) — validate, recover a ledger, build a report.
- [Reference: CLI](../reference/cli.md) — every command and exit code.
- [Explanation: the trust model](../explanation/trust-model.md) — the design and its honest limits.
