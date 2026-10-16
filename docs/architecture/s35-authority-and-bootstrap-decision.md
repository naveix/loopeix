# S35 Authority Fixture And Bootstrap Decision

Status: accepted implementation decision for the current S35 closure review gate

Date: 2026-08-12

## Scope analyzed

- Positive V02 planning inputs implemented in
  `src/run/project-plan-v02.ts` and exercised by the reviewed S35 fixture
  corpus.
- The S35 runtime-artifact bootstrap path implemented by
  `scripts/build-s35-runtime-smoke-harness.mjs`,
  `scripts/verify-s35-build-artifacts.mjs`, and
  `scripts/smoke-packed-package-s35.mjs`.
- The canonical local contract in
  `docs/architecture/s35-contract-closure.md` and the upstream S35/package/CLI
  reference text in `loopeix-specs`.

## Confirmed local evidence

1. Positive planning is implemented and covered by the reviewed fixture and test
   corpus. The current shipped boundary is not "missing planning"; it is that
   V02 execution remains intentionally unavailable after planning. The
   authoritative planned-run path is exercised by the committed fixture set
   under `tests/fixtures/compat/s35/v02/planned-run/` and the S35 planning
   tests.
2. The package smoke/verifier path is materially hardened and the bootstrap
   circularity has been removed by the four-artifact design. Local artifact
   verification now passes with the standalone verifier outside the harness tar,
   workflow-owned verifier pins, deterministic harness construction, and
   installed-package runtime smoke.
3. The reviewed `common/**`, V01 compatibility, and V02 planned-run fixture
   corpus exists in-tree and is consumed by the smoke/verifier path. The smoke
   still fails closed when required reviewed fixture bytes are absent, but the
   corpus itself is no longer a missing-work item.

## External standards summary

These sources shaped the decision below:

- RFC 8785 defines deterministic canonical JSON for repeatable hashing and
  signing: <https://www.rfc-editor.org/info/rfc8785/>
- Git documents that object identity is bound to the object format and exact
  object bytes: <https://git-scm.com/docs/hash-function-transition.html>
- SLSA defines provenance as verifiable information that tracks how an artifact
  was produced: <https://slsa.dev/spec/v1.2/provenance>
- TUF separates trusted roles, hashes, and freshness so one compromised party
  does not implicitly authorize everything else:
  <https://theupdateframework.com/docs/metadata/>
- DSSE is designed to bind payload bytes and payload type while avoiding
  canonicalization confusion in signed envelopes:
  <https://github.com/secure-systems-lab/dsse>
- in-toto layouts require explicit functionary authorization, commands, and
  inspections instead of implicit trust:
  <https://in-toto.io/docs/getting-started/>
- NIST SSDF and related supply-chain guidance emphasize provenance collection
  and automatic verification of hashes or signatures where feasible:
  <https://csrc.nist.gov/projects/ssdf>
  <https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-supply-chain-security-guidance-21>

GitHub Actions and SLSA-specific primary sources narrowed the bootstrap choice:

- GitHub artifact attestations provide signed provenance and are useful only if
  consumers verify them. GitHub also states that attestations are not a
  security guarantee by themselves:
  <https://docs.github.com/en/actions/concepts/security/artifact-attestations>
- GitHub's secure-use guidance says third-party actions and reusable workflows
  should be pinned to a full-length commit SHA, and the same principle applies
  to third-party reusable workflows:
  <https://docs.github.com/en/actions/reference/security/secure-use>
- GitHub documents reusable workflows as the route to shared deterministic build
  logic, and says reusable workflows referenced by SHA are the stable/safe
  option:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations>
- GitHub's SLSA Level 3 guidance says artifact attestations plus a reusable
  workflow improve provenance trust, and verification can require a specific
  signer workflow:
  <https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating>
- GitHub's offline attestation flow still requires separately imported
  attestation bundles and trusted roots; it does not validate the inner member
  inventory of our smoke harness tarball:
  <https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline>
- SLSA says verification requires a preconfigured root of trust, accepted
  builder identities, signature verification, and expectation checks on the
  provenance fields:
  <https://slsa.dev/spec/v1.2/verifying-artifacts>

## Decision 1: use a strictly synthetic authority fixture domain

Expert decision: S35 should unblock positive planning tests with a
**test-only synthetic authority domain**, not with inferred or production-like
authority facts.

Why: this gives us positive contract coverage without teaching the product to
invent trust. That is the smallest change that reduces the highest remaining
risk.

The frozen synthetic fixture domain should follow these rules:

1. All identities are visibly synthetic and non-production.
   Use fixed `s35-fixture-*`, `fixture-*`, or `test://loopeix/s35/...`
   namespaces for role refs, actor refs, repository refs, and fixture bundle
   IDs. Do not reuse live org, user, host, repo, or key names.
2. The fixture bytes are hand-authored and reviewed.
   Production compiler, planner, hash, replay, or serializer code must not
   generate the expected-side oracle files that later validate those same
   paths.
3. The hash preimages are deterministic and closed.
   Use the existing exact hash domains already enforced by the codebase
   (`authority-planning-input-v02`, `repository-base-ref-v02`, repository-state
   domains, and the pack manifest hash) with canonical JSON bytes. The missing
   outer policy digest is frozen below; it is not treated as an existing domain.
4. The repository observation is synthetic but fully specified.
   Freeze one repository root ref, one object format, one base ref, one
   base-ref identity hash, one initial-state bundle, and one
   repository-state hash chain. The object format must agree with the chosen
   object IDs exactly.
5. The policy bundle is fixture authority, not product authority.
   Freeze one reviewed policy bundle whose digest is consumed by
   `resolveImmutableActionApprovalPolicyV02()`. It must contain every one of the
   29 closed action kinds exactly once with the canonical class; a planning-only
   subset would violate the policy schema and weaken the negative matrix.
6. The role assignments are explicit and complete.
   Freeze exactly one assignment for every role in the selected loop. Exactly
   one selected role is the synthetic `operator`; all others are synthetic
   `agent` actors. The human-exception destination resolves to that one operator
   row. No wildcard principals, inferred actors, aliases, or fallback role
   completion are permitted.
7. Time and nonce-like values are deterministic.
   Freeze timestamps, run lineage inputs, and any related IDs that appear in the
   reviewed planned-run corpus so regression diffs are meaningful.
8. Negative controls are first-class fixtures.
   For every positive fixture, ship at least one adjacent failure for each
   critical trust edge: policy digest mismatch, approval hash mismatch, base-ref
   identity mismatch, repository-state mismatch, unsorted forbidden outcomes,
   and role/destination mismatch.

### Resolved production ownership correction

The research pass found one contradiction in the earlier contract: positive
planning required complete role assignments and a pinned repository observation,
but the exact CLI supplied neither. The accepted correction preserves the two
existing V02 flags and assigns each fact to its proper trust owner:

- `AuthorityPlanningInputV02` now carries the complete role assignments. They
  are operator-approved intent, are included in `approval_hash`, and must cover
  every selected-loop role exactly once without actor or stable-identity alias.
- The command captures `RepositoryStateV02` from the pinned workspace and named
  base ref after authority admission. Live Git state is not caller-authored and
  is not added to the approval-hash preimage.

This avoids both unsafe alternatives: inventing actors from the blueprint and
accepting a caller-authored object as a supposedly observed repository state.

### Exact synthetic digest and identity rules

The outer policy digest is the SHA-256 of RFC 8785 canonical JSON for exactly:

```json
{
  "purpose": "action-approval-policy-bundle-v02",
  "registry_version": "<candidate.registry_version>",
  "classifier_registry": "<candidate.classifier_registry>",
  "entries": "<candidate.entries>",
  "human_exception_action_kinds": "<candidate.human_exception_action_kinds>",
  "blocked_action_kinds": "<candidate.blocked_action_kinds>",
  "registry_hash": "<candidate.registry_hash>"
}
```

The angle-bracket strings above denote substitution of the complete typed JSON
value, not a literal string. `policy_digest` is deliberately excluded to avoid a
self-hash cycle. Admission must require equality among the embedded digest, the
host-acknowledged digest, and this independently recomputed digest, after all
inner hashes and the closed taxonomy validate.

Each fixture stable identity hash is the SHA-256 of RFC 8785 canonical JSON for
exactly `{ purpose: "synthetic-stable-actor-identity-v02", fixture_domain:
"test://loopeix/s35/authority/v01", actor_ref, actor_kind }`. This domain exists
only in committed S35 fixture metadata and test admission; it does not create a
production identity provider or authorization mechanism.

The positive planning fixture uses one hermetic synthetic Git observation with
a fixed object format, exact literal object IDs derived from committed fixture
bytes, a named base ref, clean tracked/staged/untracked/submodule components,
and the already-published repository-state hash domains. It never samples the
developer's current checkout. A small independent oracle check may recompute Git
object IDs and canonical hashes, but it must import no production planner,
compiler, serializer, or hash helper.

### Why not DSSE or TUF right now?

Those are useful higher-order trust frameworks, but adopting them in S35 would
expand scope beyond the current shipped verification code. The current runtime
contract verifies exact hashes and closed JSON structures, not envelope
signatures or rotating metadata roles. The expert move here is to freeze
synthetic literals now and leave DSSE/TUF adoption to a later explicit trust
sprint.

## Decision 2: move runtime bootstrap to four trust artifacts

Expert decision: the no-checkout runtime CI path should use **four** immutable
artifacts, not three.

Implementation status: built and verified locally. The workflow now owns the
verifier hash and byte-size literals, builds one Ubuntu artifact, runs the
distinct macOS durability gate, and defines 12 no-checkout runtime cells (2
operating systems x 3 Node.js versions x 2 npm versions). Hosted runtime
evidence remains pending only until the operator authorizes commit/push and the
matrix is executed in GitHub Actions.

Why: a runtime lane cannot safely extract a tarball in order to obtain the code
that tells it whether extracting that tarball is safe.

Required runtime artifact set:

1. Product tarball.
2. Smoke harness tarball.
3. Outer build manifest that binds source commit and both artifact hashes/sizes.
4. Standalone verifier file whose exact SHA-256 and byte size are literals in
   the reviewed workflow definition.

The fourth file is the existing standalone verifier program, copied byte-for-byte
by the build job. It is not archived, and neither its expected digest nor its
expected size comes from the build job or outer manifest. The no-checkout job
checks both against workflow literals using runner-provided hashing/file-size
tools before Node executes it. Any verifier edit therefore requires an explicit,
review-visible workflow pin update.

### Bootstrap option matrix

1. Fourth verifier file with workflow-owned pins.
   This breaks the immediate circularity because the runtime lane can validate
   the smoke harness tar before extraction. It fits the current S35 no-checkout
   and plain-`npm` runtime model, keeps the verifier local to this repository,
   and can be regression-tested with the same deterministic artifact protocol.
   A fourth file whose expected hash comes from the same downloaded manifest
   remains circular and is rejected. Workflow-owned literals make the reviewed
   workflow the bootstrap root. This does **not** by itself prove the source
   commit is safe; it gives the runtime lane a non-circular semantic verifier.
2. Separately pinned reusable workflow or composite action.
   This can also solve bootstrap trust if, and only if, it is governed outside
   the downloaded harness and pinned to a full commit SHA. If it lives in the
   same mutable source repository and evolves with the artifact under test, it
   weakens the independence benefit.
3. GitHub artifact attestations.
   These are additive provenance, not a replacement for the local verifier.
   They can prove where and how the product tarball was built, but they do not
   inspect the smoke harness tar's exact member set, modes, duplicate paths, or
   extraction safety rules.
4. Workflow-inline semantic verifier code.
   Reject for S35. Only the fixed hash/size comparison belongs inline. Archive
   parsing and product-policy logic stays in the dedicated reviewed verifier.
5. Verifier code inside the harness under test.
   Reject for S35. This is the current circularity: the runtime lane would need
   to trust extracted code before it can decide whether extraction was safe.

### Recommended S35 trust-root pattern

Use the **workflow-pinned fourth verifier file now**, and treat GitHub artifact
attestations as a later complementary layer on the product tarball or release
path. If the team later wants stronger organizational separation, promote the
verifier to a separately governed pinned reusable workflow or action in a
follow-on sprint.

Why this is the expert choice for the current scope:

1. It is the smallest change that removes the highest-risk circularity in the
   current runtime-artifact lane.
2. It preserves the current deterministic local verifier semantics instead of
   replacing them with provenance-only checks.
3. It does not require standing up a second governance repository before S35
   can close.

The trust boundary is explicit: the pinned `actions/download-artifact` commit
delivers four opaque files; runner-native hash/size checks authenticate the
verifier; the authenticated verifier validates the other three files before any
harness extraction or product installation. Repository review/branch protection
governs changes to the workflow pins. GitHub attestation can later bind artifact
provenance, but it does not replace these semantic checks.

## What can proceed now

1. Author the reviewed `common/**` and V02 planned-run fixture corpus in this
   synthetic domain.
2. Extend the installed smoke to the full ten-operation matrix once those bytes
   exist.
3. Run the implemented four-artifact CI custody lanes after the fixture corpus
   is complete; do not claim no-checkout runtime verification before they pass.

## What remains blocked after this decision

- S35 still cannot be called complete until the reviewed positive fixture bytes
  actually exist.
- The upstream reference-contract tranche still needs to freeze the same
  literals, otherwise `loopeix-specs` and `loopeix` will drift.
- Whole-system visuals should be drawn from the verified as-built boundary after
  these fixture and bootstrap decisions are implemented, not before.
