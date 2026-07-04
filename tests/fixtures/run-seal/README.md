# run-seal fixtures — why `file_change` paths are workspace-RELATIVE here

Real Codex emits **absolute** `file_change` paths, prefixed with the run workspace root
(live capture 2026-07-04, codex-cli 0.142.3 — see
`tests/fixtures/adapter-events/README.md` and the redacted fixture
`adapter-events/codex/s1-codex-file-change.redacted.jsonl`). The fixtures in this directory
deliberately keep **relative** paths (`src/payments.ts`, `tests/unit/payments.test.ts`).
That is an informed decision, not an oversight:

1. **The adapter contract normalizes both shapes.** `src/adapters/codex.ts` carries
   `changes[].path` verbatim; normalization happens downstream in `normalizePath`
   (`src/glob.ts`), which passes relative paths through and strips absolute paths against
   the `workspaceRoot` the CLI supplies (`resolve(flags.workspace)` in
   `src/commands/run/start.ts`, P3a). A relative path is exactly the **canonical
   post-strip form** — the shape every path has by the time glob adjudication runs.

2. **These are replay fixtures and must be workspace-portable.** They are replayed under
   arbitrary `--workspace` roots: the `snitch-demo` README uses `mktemp -d`, and the CLI
   tests use fresh temp dirs. Absolute paths under any committed synthetic root would be
   *excluded* under those mismatched roots (the proven-correct defensive direction — see
   the F5 tests in `tests/unit/verdicts.test.ts`), silently flipping the flagship
   `PROMISE_BROKEN` verdict to `UNEVALUATED`. Relative paths are the only shape that
   replays truthfully under every workspace root, with verdicts identical to a real
   capture replayed in its original workspace.

3. **The equivalence is tested, not assumed.** `tests/unit/run-seal.test.ts` (F5
   path-shape equivalence) absolutizes this snitch fixture under a synthetic root, passes
   the matching `workspaceRoot`, and asserts the verdicts are identical to the committed
   relative fixture. The real ABSOLUTE shape itself is exercised end-to-end by the F5
   tests over the redacted live-capture fixture.

In short: relative here = "already normalized", and the absolute reality is covered by the
real-capture fixture plus tests. Do not "fix" these paths to absolute without also solving
replay portability for the demo and CLI tests.
