# Sprint S35 — Findings And Closure Record

Verified: 2026-08-12

Execution rule: no commit, push, deployment, S36 work, or visual-architecture
phase without the operator's separate approval.

## Current result

The Phase-0 gaps are implemented. S35 now provides literal V01/V02 dispatch,
frozen V01 replay, strict V02 authoring/compiler/pack contracts, exact replay,
authority-bound positive planning, a durable exact-nine planned-run writer,
pure branded runtime evaluation, versioned control-plane byte ceilings, complete
CLI read-only routing, and a fail-closed V02 start boundary.

The reviewed fixture corpus exists under `tests/fixtures/compat/s35/`, including
the common package oracles, frozen V01 compatibility data, V02 authoring cases,
and nine planned-run members. The mandatory inventory contains 64 files.
Installed-package full smoke and four-artifact verification consume the real
corpus; they do not silently skip missing fixtures.

Graphify is stale and the local-model signature gate is HOLD. In accordance
with the knowledge-operations contract, neither was used as implementation
authority. Local-model routing remains advice-only until S48.

## Important decisions

- V02 planning uses explicit synthetic authority, role, policy, and repository
  observations. Production code does not infer trust facts.
- The enforced byte profile is
  `control-plane-charge-ceilings-v02-s35-1`; it uses conservative canonical-byte
  ceilings, exact plan-derived cardinalities, checked `bigint` arithmetic, and
  actual runtime byte charging. ADR 0009 owns the rationale.
- The V02 fixture generator exercises compile, replay, authority, repository
  observation, and planning, while the independent verifier owns expected
  membership and cross-file invariants.
- V02 execution remains intentionally unavailable in S35. Raw and planned V02
  starts HOLD before execution-side reads or writes.
- The no-checkout runtime CI path has four trust artifacts: product tarball,
  deterministic smoke-harness tar, outer manifest, and a workflow-pinned
  standalone verifier.

## Verification state

The following passed after the final runtime correction:

- typecheck, build, and the full 138-file / 1,477-test Vitest suite;
- deterministic schema generation and unchanged receipt-schema check;
- 64-file mandatory S35 test inventory;
- authoritative secret scan across both repositories;
- V02 fixture inventory and independent verification;
- package creation, installed-product full smoke, deterministic harness build,
  and strict four-artifact verification;
- macOS filesystem durability slice; and
- whitespace/diff checks in both repositories.

The final product tarball has SHA-256
`b06792e730b08305554cd9f935bf4f829ac02e77a118afda16e9a7f018a5ce1e`.
The deterministic runtime-harness tar has SHA-256
`75b09e23d3866c7be870c0ecd3bb330b95dc7d348cc7e7ff112a6fed6f5bff56`,
and the self-hashed outer manifest has SHA-256
`ba0599c5918f0b1a6e66ee1123b77336576712ebc140215ff374627c6ff92d68`.
The hosted Ubuntu/macOS Node matrix is configured but
cannot become executed CI evidence until the operator separately authorizes
commit/push.

## Historical Phase-0 findings

At baseline `13a8906fdd32b005d29c1eb07ee54f55f80c7fc2`, the product had a permissive
version scalar, one shared authoring/runtime family, live-catalog V01 replay,
opaque V02 control fields, no V02 compiler/planner, no bounded control-plane
calculator, and no complete packaged compatibility corpus. Those observations
explain the sprint design but are not current product status.

The hardened pre-RED capture manifest remains historical custody evidence. It
correctly accepts only the clean S34 baseline plus the five capture tools and
must not be weakened. Final S35-D review instead uses the separate integrated-
tree manifest, which binds all relevant modified, deleted, and untracked bytes
in both repositories before the human commit gate.

## Remaining release gate

1. Mint one integrated-tree review manifest outside both repositories.
2. Obtain `SHIP IT` from runtime/schema, evidence/security, CLI/package,
   architecture/status, and authority-governance on that exact digest.
3. Return to the operator for the separate human ship decision.
