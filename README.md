# Loopeix

**Local-first CLI to design, run, verify, and improve repeatable AI work loops — without claiming
more than it can prove.**

Loopeix turns an AI coding loop (run through the Codex or Claude CLI) into **inspectable local
evidence**: a tamper-evident run ledger, normalized capture across both engines with honest capture
gaps, blocking safety gates, an evidence verifier that refuses to call a strong claim "verified"
without independent proof, and truthful local reports. It is CLI-first, local-first, and holds **no
API keys** — it uses the Codex/Claude CLIs' own authentication.

> **Status: alpha (V0.3).** The schema, validator, run core, gate engine, evidence verifier, report
> builder, retro/improvement engine, AgentProofProfile, and redaction/retention are built **as
> libraries** and independently reviewed. Some **CLI entry points are not yet wired** — `report
> build`/`report open`, `loopeix support bundle`, and `loopeix privacy *` currently warn and do
> nothing; their behavior lives in the library and arrives at the CLI with the run-execution layer.
> Not yet published to npm. See [Limitations](#limitations).

## Why

AI agents are confident. Confidence is not evidence. Loopeix exists so that when a loop says "the
fix works," you can see the command that ran, the test that passed, the hash-chained event that
recorded it, and the gate that would have blocked the run if it hadn't. When it *can't* prove
something, it says so — unverified claims go in an unverified section, and capture gaps are disclosed
rather than hidden.

## Install

```bash
# from source (this repo) — not yet on npm
pnpm install && pnpm build && npm link
loopeix --help
```

See [docs/INSTALL-UNINSTALL.md](docs/INSTALL-UNINSTALL.md) for what install/uninstall does and does
not touch (it never deletes your run data).

## Quick start

```bash
loopeix doctor                          # check Node version, CLI version, bundled schema
loopeix init                            # create a .loopeix/ workspace here
loopeix spec validate my-loop.yaml      # structural + relational validation
loopeix spec inspect my-loop.yaml       # human-readable summary (roles, tasks, gates)
loopeix run status .loopeix/runs/<id>  # recover + report a run's integrity from its ledger (read-only)

# Not yet wired as CLI commands in V0.3 (library-complete; they warn today):
#   loopeix report build/open, loopeix support bundle, loopeix privacy *
# See docs/reference/cli.md for what is runnable now vs library-backed.
```

Start from [`templates/loopeix.template.yaml`](templates/loopeix.template.yaml) or the worked
[`examples/`](examples/).

## What's in the box

| Piece | What it gives you |
|---|---|
| **Schema + validator** | A Loopeix is authored in YAML; validation is structural (Zod → JSON Schema) **plus** relational invariants a schema can't express (e.g. no T5 tier without approval). |
| **Run ledger** | Append-only, SHA-256 hash-chained, tamper-**evident**. Recovery quarantines corrupt lines and reports integrity honestly (never a silent "valid"). |
| **Capture adapters** | Normalize Codex `codex exec --json` and Claude `--output-format stream-json` into one event taxonomy, **preserving each engine's capture gaps** (Codex sees command/file directly; Claude infers them — Loopeix says so). |
| **Gate engine** | Blocking gates evaluated fail-closed. `no-t5` (no scheduled/unattended behavior) is injected and can't be weakened; unwaivable gates can't be waived. |
| **Evidence verifier** | A *strong* claim is `verified` only with present, independent evidence covering its required types. Declared-but-unproven claims are downgraded. |
| **Reports** | Every report shows verified claims, unverified claims, capture gaps, waivers, unresolved findings, redaction state, and known limitations — and can't over-claim. |
| **AgentProofProfile** | A strict overlay for AI code work: strong claims need *executable* (command/test, passing) evidence; assurance gates must be non-waivable. |
| **Retro → improvement** | A run's retro becomes a `SpecChangeProposal` that creates a *new* version and never mutates the current spec; applying it is approval-gated. |
| **Privacy** | Conservative redaction + an independent leak-scan (with a high-entropy backstop) before any support bundle leaves your machine. |

## Documentation (Diátaxis)

- **Tutorial** — [docs/tutorial/getting-started.md](docs/tutorial/getting-started.md): from install to your first verified report.
- **How-to** — [docs/how-to/common-tasks.md](docs/how-to/common-tasks.md): validate a spec, recover a ledger, build a support bundle, propose a change.
- **Reference** — [docs/reference/cli.md](docs/reference/cli.md): every command and flag.
- **Explanation** — [docs/explanation/trust-model.md](docs/explanation/trust-model.md): why the evidence, integrity, and capture-gap design works the way it does.

## Limitations

- **Alpha, not released.** APIs and file shapes may change before V1.
- **Tamper-evident, not tamper-proof.** The ledger detects accidental corruption and naive edits; a
  write-capable actor who knows the (public) sealing algorithm can re-seal a forged chain. Signing is
  a post-V1 item. See [docs/security-model.md](docs/security-model.md).
- **Redaction is conservative but not a guarantee.** It scrubs known secret keys/patterns and
  high-entropy tokens; it cannot promise to catch an unknown secret shape under an innocuous key. Every
  export is leak-scanned and every report states redaction limitations.
- **Local-first.** Concurrency safety (the advisory lock) targets one machine.

## License

TBD before public release.
