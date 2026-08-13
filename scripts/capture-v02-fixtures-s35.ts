import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { compileV02ForTest } from "../src/compiler/compile-v02.js";
import { COMPILE_STORE_SENTINEL_TEXT } from "../src/compiler/compile-store.js";
import { readCompilePackV02 } from "../src/compiler/read-pack-v02.js";
import { replayCompilePackV02 } from "../src/compiler/replay-v02.js";
import { hashCanonical, hashRawBytes } from "../src/hash.js";
import { parseResolvedRunPlanDocument } from "../src/schema/runtime.js";
import { parseLoopeixDocument } from "../src/schema/version-dispatch.js";
import {
  admitAuthorityPlanningInputV02,
  claimApprovedAuthorityRepositoryV02,
} from "../src/run/authority-planning-input-v02.js";
import {
  consumePreparedPlanProjectionV02,
  preflightPlannedRunV02,
  projectPreflightedRunV02,
} from "../src/run/project-plan-v02.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
} from "../src/run/action-classifier-policy-v02.js";
import {
  deriveInvocationRepositoryRootV02,
  observeCleanRepositoryStateV02,
} from "../src/run/repository-observation-v02.js";
import {
  S35_PROJECTION_ORACLES,
  bindingInputForProjectionOracle,
} from "../tests/helpers/s35-projection-oracles.js";

const UTF8 = new TextEncoder();
const FIXTURE_ROOT = resolve("tests/fixtures/compat/s35/v02");
const PLANNED_ROOT = join(FIXTURE_ROOT, "planned-run");
const roots: string[] = [];

function fail(message: string): never {
  throw new Error(`capture-v02-fixtures-s35: ${message}`);
}

function git(root: string, ...args: string[]): string {
  return execFileSync("/usr/bin/git", ["-C", root, ...args], {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
  }).trim();
}

function registerTemp(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  roots.push(root);
  return root;
}

function cleanup(): void {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
}

function cleanRepository(): { root: string; repository_root_ref: string; head: string } {
  const root = registerTemp("loopeix-s35-v02-fixture-repository-");
  git(root, "init", "--initial-branch=main");
  git(root, "config", "user.name", "S35 Fixture");
  git(root, "config", "user.email", "s35@example.invalid");
  writeFileSync(join(root, "README.md"), "fixture\n", { mode: 0o600 });
  git(root, "add", "README.md");
  git(root, "commit", "-m", "fixture");
  const derived = deriveInvocationRepositoryRootV02(root);
  if (!derived.ok) fail(derived.message);
  return { root: derived.canonical_root, repository_root_ref: derived.repository_root_ref, head: git(root, "rev-parse", "HEAD") };
}

function compiledBindingPayload(repositoryRoot: string): Uint8Array {
  const oracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "safe-bugfix");
  if (oracle === undefined) fail("safe-bugfix oracle is unavailable");
  const record = bindingInputForProjectionOracle(oracle) as {
    bindings: Array<{ key: string; value: unknown; approved_by: string } & Record<string, unknown>>;
  };
  for (const binding of record.bindings) {
    if (binding.key === "project.workspace-root") {
      binding.value = { ...(binding.value as Record<string, unknown>), root: repositoryRoot };
    }
    if (binding.key === "project.hard-limits") {
      binding.value = {
        ...(binding.value as Record<string, unknown>),
        max_output_bytes: 6_000_000_000,
        control_plane_output_reserve_bytes: 5_000_000_000,
      };
    }
    if (binding.key === "project.validation") {
      binding.value = (binding.value as Array<Record<string, unknown>>).map((evaluation) => ({
        ...evaluation,
        evaluator_binding: {
          ...(evaluation.evaluator_binding as Record<string, unknown>),
          policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
        },
      }));
    }
  }
  return UTF8.encode(JSON.stringify({
    bindings: record.bindings.map(({ approved_by: _approvedBy, ...binding }) => binding),
  }));
}

async function compileReplayAndAuthority() {
  const repository = cleanRepository();
  const compileWorkspace = registerTemp("loopeix-s35-v02-fixture-compile-");
  const store = join(compileWorkspace, ".loopeix", "compiles");
  mkdirSync(store, { recursive: true });
  writeFileSync(join(store, ".gitignore"), COMPILE_STORE_SENTINEL_TEXT, { mode: 0o600 });
  const compiled = await compileV02ForTest({
    prompt: "Fix the failing parser bug and prove the correction.",
    workspace_root: compileWorkspace,
    binding_payload_bytes: compiledBindingPayload(repository.root),
  }, {
    now: () => 146,
    randomBytes: () => Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]),
  });
  if (!compiled.ok || compiled.pack_ref === null) fail(`expected compiled pack, received ${compiled.reason}`);
  const packRoot = join(store, compiled.pack_ref);
  const read = await readCompilePackV02(packRoot);
  if (!read.ok || read.generated_loop === null) fail("expected a readable generated loop");
  const replayed = replayCompilePackV02(read);
  if (!replayed.ok) fail("expected exact replay");

  const actorByRole = new Map<string, string>();
  for (const control of [...read.generated_loop.gates, ...read.generated_loop.evaluations]) {
    const previous = actorByRole.get(control.evaluator_binding.role_ref);
    if (previous !== undefined && previous !== control.evaluator_binding.evaluator_identity_ref) {
      fail("fixture role has conflicting evaluator identities");
    }
    actorByRole.set(control.evaluator_binding.role_ref, control.evaluator_binding.evaluator_identity_ref);
  }
  const operatorRole = read.generated_loop.roles[0]?.id;
  if (operatorRole === undefined) fail("generated loop has no operator role");
  const roleAssignments = read.generated_loop.roles
    .map(({ id }) => ({
      role_ref: id,
      actor_ref: actorByRole.get(id) ?? `actor_${id.replaceAll("-", "_")}`,
      actor_kind: id === operatorRole ? "operator" as const : "agent" as const,
      stable_identity_hash: hashCanonical({ purpose: "s35-test-actor", role_ref: id }),
    }))
    .sort((left, right) => Buffer.from(left.role_ref).compare(Buffer.from(right.role_ref)));
  const operator = roleAssignments.find(({ role_ref }) => role_ref === operatorRole);
  if (operator === undefined) fail("operator role assignment is missing");

  const baseRef = {
    kind: "git-ref" as const,
    canonical_ref_name: "refs/heads/main",
    object_id: { algorithm: "sha1" as const, value: repository.head },
    identity_hash: "",
  };
  baseRef.identity_hash = hashCanonical({
    purpose: "repository-base-ref-v02",
    repository_root_ref: repository.repository_root_ref,
    object_format: "sha1",
    kind: baseRef.kind,
    canonical_ref_name: baseRef.canonical_ref_name,
    object_id: baseRef.object_id,
  });
  const authorityInput = {
    schema_version: "0.2" as const,
    authority_planning_input_id: "authority_plan_positive_01",
    compile_pack_manifest_hash: hashRawBytes(readFileSync(join(packRoot, "pack-manifest.json"))),
    forbidden_outcomes: ["data loss"],
    delegation_mode: "none" as const,
    role_assignments: roleAssignments,
    human_exception_destination: {
      operator_role_ref: operator.role_ref,
      operator_actor_ref: operator.actor_ref,
      operator_stable_identity_hash: operator.stable_identity_hash,
    },
    repository: {
      repository_root_ref: repository.repository_root_ref,
      object_format: "sha1" as const,
      base_ref: baseRef,
      transition_mode: "linear-settled-writes" as const,
    },
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    approval_hash: "",
  };
  authorityInput.approval_hash = hashCanonical({
    purpose: "authority-planning-input-v02",
    schema_version: authorityInput.schema_version,
    authority_planning_input_id: authorityInput.authority_planning_input_id,
    compile_pack_manifest_hash: authorityInput.compile_pack_manifest_hash,
    forbidden_outcomes: authorityInput.forbidden_outcomes,
    delegation_mode: authorityInput.delegation_mode,
    role_assignments: authorityInput.role_assignments,
    human_exception_destination: authorityInput.human_exception_destination,
    repository: authorityInput.repository,
    policy_digest: authorityInput.policy_digest,
  });
  const admitted = admitAuthorityPlanningInputV02(
    UTF8.encode(JSON.stringify(authorityInput)),
    authorityInput.approval_hash,
  );
  if (!admitted.ok) fail(admitted.message);
  const claimed = claimApprovedAuthorityRepositoryV02(admitted.approved);
  if (claimed === null) fail("expected a claimable repository binding");
  const observed = observeCleanRepositoryStateV02(repository.root, claimed);
  if (!observed.ok) fail(observed.message);

  return {
    packRoot,
    replay: replayed.replay,
    authority: admitted.approved,
    observation: observed.observation,
    repositoryRoot: repository.root,
  };
}

function invalidAuthoring(validBytes: Uint8Array): Uint8Array {
  const parsed = parseYaml(Buffer.from(validBytes).toString("utf8"));
  if (typeof parsed !== "object" || parsed === null) fail("valid authoring YAML did not parse");
  const invalid = structuredClone(parsed) as Record<string, unknown>;
  const limitPolicy = invalid.limit_policy;
  if (typeof limitPolicy !== "object" || limitPolicy === null) fail("valid authoring has no limit_policy");
  (limitPolicy as Record<string, unknown>).max_tool_calls = "thirty-two";
  const text = stringifyYaml(invalid, {
    lineWidth: 0,
    minContentWidth: 0,
    singleQuote: false,
  }).replace(/\r\n/g, "\n");
  return UTF8.encode(text.endsWith("\n") ? text : `${text}\n`);
}

async function main(): Promise<void> {
  const { packRoot, replay, authority, observation, repositoryRoot } = await compileReplayAndAuthority();
  const preflight = preflightPlannedRunV02(
    replay,
    authority,
    observation,
    { engine: "codex", workspace_root: repositoryRoot },
  );
  if (!preflight.ok) fail(`planner preflight failed: ${preflight.reason}`);

  const milliseconds = Date.parse("2026-08-12T12:34:56Z");
  const planToken = `${milliseconds.toString(36)}_0102030405060708`;
  const projected = projectPreflightedRunV02(preflight.preflight, {
    plan_token: planToken,
    run_id: `run_${planToken}`,
    created_at: "2026-08-12T12:34:56Z",
  });
  if (!projected.ok) fail(`planner projection failed: ${projected.reason}`);
  const prepared = consumePreparedPlanProjectionV02(projected.prepared);
  if (prepared === null) fail("prepared planner snapshot was unavailable");
  const generatedLoop = prepared.members.find(({ name }) => name === "generated.loop.yaml");
  const resolvedRunPlan = prepared.members.find(({ name }) => name === "resolved-run-plan.json");
  if (generatedLoop === undefined) fail("prepared planner snapshot has no generated.loop.yaml");
  if (resolvedRunPlan === undefined) fail("prepared planner snapshot has no resolved-run-plan.json");

  const validAuthoringBytes = generatedLoop.bytes;
  const invalidAuthoringBytes = invalidAuthoring(validAuthoringBytes);
  const validParsed = parseLoopeixDocument(parseYaml(Buffer.from(validAuthoringBytes).toString("utf8")));
  const invalidParsed = parseLoopeixDocument(parseYaml(Buffer.from(invalidAuthoringBytes).toString("utf8")));
  const planParsed = parseResolvedRunPlanDocument(JSON.parse(Buffer.from(resolvedRunPlan.bytes).toString("utf8")));
  if (!validParsed.ok || validParsed.schema_version !== "0.2") fail("generated valid authoring did not validate as V02");
  if (invalidParsed.ok || invalidParsed.schema_version !== "0.2" || invalidParsed.reason !== "INVALID_AUTHORING_DOCUMENT") {
    fail("generated invalid authoring did not fail as a V02 INVALID_AUTHORING_DOCUMENT");
  }
  if (!planParsed.ok || planParsed.schema_version !== "0.2" || planParsed.execution_profile !== "bounded-v02") {
    fail("generated resolved run plan did not parse as bounded V02");
  }

  mkdirSync(FIXTURE_ROOT, { recursive: true });
  rmSync(join(FIXTURE_ROOT, "authoring-valid.loop.yaml"), { force: true });
  rmSync(join(FIXTURE_ROOT, "authoring-invalid.loop.yaml"), { force: true });
  rmSync(PLANNED_ROOT, { recursive: true, force: true });
  mkdirSync(PLANNED_ROOT, { recursive: true });
  writeFileSync(join(FIXTURE_ROOT, "authoring-valid.loop.yaml"), Buffer.from(validAuthoringBytes), { mode: 0o600, flag: "wx" });
  writeFileSync(join(FIXTURE_ROOT, "authoring-invalid.loop.yaml"), Buffer.from(invalidAuthoringBytes), { mode: 0o600, flag: "wx" });
  for (const member of prepared.members) {
    writeFileSync(join(PLANNED_ROOT, member.name), Buffer.from(member.bytes), { mode: 0o600, flag: "wx" });
  }
  void packRoot;
}

main()
  .then(() => cleanup())
  .catch((error: unknown) => {
    cleanup();
    throw error;
  });
