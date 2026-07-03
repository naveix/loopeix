# Contributing

Thanks for your interest. LoopSpec is built with an evidence-first discipline — the same one it
enforces — so contributions are expected to prove they work, not assert it.

## Development setup

- **Node.js ≥ 22.12**, **pnpm 11**.

```bash
pnpm install
pnpm build      # tsc, strict, noEmitOnError
pnpm test       # vitest
./bin/run.js --help
```

## Before you open a PR

1. **Build clean** (`pnpm build`) — strict TypeScript, no emit on error.
2. **Tests pass** (`pnpm test`) and your change adds tests for new behavior, including the failure
   paths (fail-closed cases, not just the happy path).
3. **Fixtures stay valid** — `loopspec spec validate` still passes on the golden specs; invalid
   fixtures still fail. CI checks this.
4. **No over-claiming.** If a command or library can't yet do something, say so in the code and docs
   rather than implying it works.

## Design principles (why the code looks the way it does)

- **Two-layer validation.** Structural rules live in the Zod schema (which generates the JSON Schema);
  relational invariants a schema can't express live in a separate pass.
- **Fail closed.** Gates, redaction, recovery, and the assurance profile all default to the safe
  answer on ambiguity or malformed input. A held/failed run must never read as completed.
- **Truthful by construction.** Reports emit every mandatory section (empty → an explicit "None"), the
  verified set *is* the evidence verifier's output, and trust-critical status is anchored to the
  sealed ledger — not to a sidecar file.
- **Independent review.** Non-trivial changes get an independent read (correctness/security) before
  merge; a writer does not self-certify.

See [`docs/explanation/trust-model.md`](docs/explanation/trust-model.md) for the full rationale.

## Commit / PR hygiene

- Small, focused diffs; preserve unrelated changes.
- Explain *why* in the PR, not just *what*.
- Never commit secrets, `.env`, or credentials.
