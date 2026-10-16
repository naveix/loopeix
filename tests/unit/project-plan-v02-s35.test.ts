import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

// The production calculator intentionally remains HOLD while the independent
// runtime-schema byte-bound audit is unresolved. This focused test isolates the
// planner projection seam; production still requires a real calculator PASS.
vi.mock("../../src/compiler/control-plane-budget-v02.js", () => ({
  deriveControlPlaneBudgetV02: () => ({
    ok: true,
    value: {
      required_control_plane_output_bytes: 1_000_000,
      k_non_clock_primary_event_max: 1,
      clock_event_max: 1,
      terminal_event_reservation_max: 8,
      event_families: [],
      file_families: [],
    },
  }),
}));

import { compileV02ForTest } from "../../src/compiler/compile-v02.js";
import { COMPILE_STORE_SENTINEL_TEXT } from "../../src/compiler/compile-store.js";
import { readCompilePackV02 } from "../../src/compiler/read-pack-v02.js";
import { replayCompilePackV02 } from "../../src/compiler/replay-v02.js";
import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import { ResolvedRunPlanV02 } from "../../src/schema/runtime.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import {
  admitAuthorityPlanningInputV02,
  claimApprovedAuthorityRepositoryV02,
} from "../../src/run/authority-planning-input-v02.js";
import {
  consumePreparedPlanProjectionV02,
  preflightPlannedRunV02,
  projectPreflightedRunV02,
} from "../../src/run/project-plan-v02.js";
import {
  deriveInvocationRepositoryRootV02,
  observeCleanRepositoryStateV02,
} from "../../src/run/repository-observation-v02.js";
import {
  S35_PROJECTION_ORACLES,
  bindingInputForProjectionOracle,
} from "../helpers/s35-projection-oracles.js";

const UTF8 = new TextEncoder();
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function git(root: string, ...args: string[]): string {
  return execFileSync("/usr/bin/git", ["-C", root, ...args], {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
  }).trim();
}

function cleanRepository(): { root: string; repository_root_ref: string; head: string } {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s35-plan-repository-"));
  roots.push(root);
  git(root, "init", "--initial-branch=main");
  git(root, "config", "user.name", "S35 Fixture");
  git(root, "config", "user.email", "s35@example.invalid");
  writeFileSync(join(root, "README.md"), "fixture\n");
  git(root, "add", "README.md");
  git(root, "commit", "-m", "fixture");
  const derived = deriveInvocationRepositoryRootV02(root);
  if (!derived.ok) throw new Error(derived.message);
  return { root, repository_root_ref: derived.repository_root_ref, head: git(root, "rev-parse", "HEAD") };
}

function compiledBindingPayload(repositoryRoot: string): Uint8Array {
  const oracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "safe-bugfix")!;
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

async function genuineInputs() {
  const repository = cleanRepository();
  const compileWorkspace = mkdtempSync(join(tmpdir(), "loopeix-s35-plan-compile-"));
  roots.push(compileWorkspace);
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
  if (!compiled.ok) throw new Error(`compile failed: ${compiled.reason}`);
  const packRoot = join(store, compiled.pack_ref);
  const read = await readCompilePackV02(packRoot);
  if (!read.ok || read.generated_loop === null) throw new Error("expected genuine compiled read");
  const replayed = replayCompilePackV02(read);
  if (!replayed.ok) throw new Error("expected genuine exact replay");

  const actorByRole = new Map<string, string>();
  for (const control of [...read.generated_loop.gates, ...read.generated_loop.evaluations]) {
    const previous = actorByRole.get(control.evaluator_binding.role_ref);
    if (previous !== undefined && previous !== control.evaluator_binding.evaluator_identity_ref) {
      throw new Error("fixture role has conflicting evaluator identities");
    }
    actorByRole.set(control.evaluator_binding.role_ref, control.evaluator_binding.evaluator_identity_ref);
  }
  const operatorRole = read.generated_loop.roles[0]!.id;
  const roleAssignments = read.generated_loop.roles
    .map(({ id }) => ({
      role_ref: id,
      actor_ref: actorByRole.get(id) ?? `actor_${id.replaceAll("-", "_")}`,
      actor_kind: id === operatorRole ? "operator" as const : "agent" as const,
      stable_identity_hash: hashCanonical({ purpose: "s35-test-actor", role_ref: id }),
    }))
    .sort((left, right) => Buffer.from(left.role_ref).compare(Buffer.from(right.role_ref)));
  const operator = roleAssignments.find(({ role_ref }) => role_ref === operatorRole)!;
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
  if (!admitted.ok) throw new Error(admitted.message);
  const claimed = claimApprovedAuthorityRepositoryV02(admitted.approved);
  if (claimed === null) throw new Error("expected genuine repository claim");
  const observed = observeCleanRepositoryStateV02(repository.root, claimed);
  if (!observed.ok) throw new Error(observed.message);
  return {
    replay: replayed.replay,
    authority: admitted.approved,
    observation: observed.observation,
    repositoryRoot: repository.root,
  };
}

describe("S35 pure positive V02 planner projection", () => {
  it("projects a strict resolved plan and exact writer-ready nine-member payload", async () => {
    const input = await genuineInputs();
    const preflight = preflightPlannedRunV02(
      input.replay,
      input.authority,
      input.observation,
      { engine: "codex", workspace_root: input.repositoryRoot },
    );
    expect(preflight.ok, preflight.ok ? undefined : preflight.reason).toBe(true);
    if (!preflight.ok) return;
    const milliseconds = Date.parse("2026-08-12T12:34:56Z");
    const planToken = `${milliseconds.toString(36)}_0102030405060708`;
    const result = projectPreflightedRunV02(preflight.preflight, {
      plan_token: planToken,
      run_id: `run_${planToken}`,
      created_at: "2026-08-12T12:34:56Z",
    });

    expect(result.ok, result.ok ? undefined : result.reason).toBe(true);
    if (!result.ok) return;
    expect(result.disposition).toBe("prepared");
    expect(Object.hasOwn(result, "resolved_run_plan_hash")).toBe(false);
    const snapshot = consumePreparedPlanProjectionV02(result.prepared);
    expect(snapshot).not.toBeNull();
    if (snapshot === null) return;
    expect(ResolvedRunPlanV02.safeParse(snapshot.resolved_run_plan).success).toBe(true);
    expect(snapshot.members.map(({ name }) => name)).toEqual([
      "work-item.json", "binding-input.json", "intake-record.json", "catalog-resolution.json",
      "compilation-record.json", "compile-pack-manifest.json", "generated.loop.yaml",
      "intake-brief.json", "resolved-run-plan.json",
    ]);
    expect(Buffer.from(snapshot.members.at(-1)!.bytes).toString("utf8").endsWith("\n")).toBe(true);
    expect(snapshot.output_descriptor).toMatchObject({
      kind: "plan",
      schema_version: "0.2",
      run_id: `run_${planToken}`,
      loop_family: snapshot.resolved_run_plan.loop_family,
      output_budget_bytes: 33_554_432,
    });
    expect(consumePreparedPlanProjectionV02(result.prepared)).toBeNull();

    expect(projectPreflightedRunV02(preflight.preflight, {
      plan_token: planToken,
      run_id: `run_${planToken}`,
      created_at: "2026-08-12T12:34:56Z",
    })).toMatchObject({ ok: false, reason: "INVALID_V02_PROJECTION" });

    for (let attempt = 2; attempt <= 16; attempt += 1) {
      const entropy = attempt.toString(16).padStart(16, "0");
      const retryToken = `${milliseconds.toString(36)}_${entropy}`;
      const retry = projectPreflightedRunV02(preflight.preflight, {
        plan_token: retryToken,
        run_id: `run_${retryToken}`,
        created_at: "2026-08-12T12:34:56Z",
      });
      expect(retry.ok).toBe(true);
      if (retry.ok) expect(consumePreparedPlanProjectionV02(retry.prepared)).not.toBeNull();
    }
    const exhaustedToken = `${milliseconds.toString(36)}_0000000000000011`;
    expect(projectPreflightedRunV02(preflight.preflight, {
      plan_token: exhaustedToken,
      run_id: `run_${exhaustedToken}`,
      created_at: "2026-08-12T12:34:56Z",
    })).toMatchObject({ ok: false, reason: "INVALID_V02_PROJECTION" });
  });
});
