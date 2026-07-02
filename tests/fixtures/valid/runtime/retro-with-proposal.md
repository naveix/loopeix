# Retro — run_minimal_bugfix

Loop family: `minimal-bugfix` · Version: `v001` · Run state: completed

## What worked

- The diagnose → verify sequence produced independent evidence (`ev_0001` command, `ev_0002` file hash).
- Both blocking gates (`claim-support`, `no-t5`) passed on evidence, with no waiver.

## What was awkward

- The project check (`npm test`) includes a flaky timing test; it was skipped on CI and recorded as
  an accepted-risk finding (`find_0001`) rather than silently ignored.

## Findings referenced

- `find_0001` — flaky timing test skipped on CI (accepted-risk, low).

## Proposal

This retro creates a `SpecChangeProposal` (`spec-change-proposal-v002.yaml`) that adds an explicit
"known-flaky evaluation" allowance to the loop so the flaky check is declared rather than skipped
ad hoc. The proposal targets a new version `v002` and does not modify `v001`.
