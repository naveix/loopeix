import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import {
  captureRuntimeProfileRegistryV03,
  deriveRuntimeExecutionPolicyForRegisteredAdapterV03,
} from "../../src/schema/runtime-plan-v03.js";
import {
  HashRuntimeInputV03,
  HashRuntimeRecoveryPolicyV03,
} from "../../src/schema/runtime-v04.js";
import {
  inspectRuntimePlanV03,
  isValidatedRuntimePlanV03,
  projectRuntimePlanV03,
} from "../../src/run/project-plan-v03.js";

const INVALID_POLICY = "INVALID_V03_RUNTIME_EXECUTION_POLICY" as const;
const CAPTURED_REGISTRY = captureRuntimeProfileRegistryV03();

function loadPlanV02(): ResolvedRunPlanV02Value {
  return ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
    "utf8",
  )));
}

describe("S41-A strict V03 runtime-plan derivation", () => {
  it("derives the exact checked Codex policy and V04 control-byte vector", () => {
    expect(deriveRuntimeExecutionPolicyForRegisteredAdapterV03(loadPlanV02())).toEqual({
      ok: true,
      value: {
        runtime_execution_policy: {
          profile_id: "runtime-execution-controls-v04-s41-1",
          charge_profile_id: "control-plane-charge-ceilings-v04-s41-1",
          max_process_runtime_ms: 30_000,
          max_execution_attempts: 17,
          run_owner_acquisition_max: 17,
          task_owner_acquisition_max: 4,
          integrator_acquisition_max: 17,
          owner_lease_duration_ms: 30_000,
          heartbeat_interval_ms: 10_000,
          run_heartbeat_event_max: 102,
          task_heartbeat_event_max: 12,
          integrator_heartbeat_event_max: 102,
          run_owner_release_max: 17,
          task_owner_release_max: 4,
          integrator_release_max: 17,
          max_compaction_events: 4,
          max_summary_records: 4,
          max_summary_content_bytes: 65_536,
        },
        required_control_plane_output_bytes: 1_591_738_368,
      },
    });
  });

  it("maps the exact parsed adapter engine through the closed release registry", () => {
    expect(deriveRuntimeExecutionPolicyForRegisteredAdapterV03(loadPlanV02())).toMatchObject({
      ok: true,
      value: {
        runtime_execution_policy: {
          max_process_runtime_ms: 30_000,
          max_execution_attempts: 17,
        },
        required_control_plane_output_bytes: 1_591_738_368,
      },
    });
  });

  it("admits only the exact closed Claude tuple", () => {
    const input = loadPlanV02();
    input.adapter_plan.engine = "claude_code_cli";
    input.adapter_plan.command = "claude -p --output-format stream-json --include-hook-events";

    const result = projectRuntimePlanV03(input, CAPTURED_REGISTRY);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.runtime_execution_policy.max_process_runtime_ms).toBe(30_000);
    expect(result.value.adapter_plan).toEqual(input.adapter_plan);
  });

  it.each([
    ["command suffix", "codex exec --json --dangerously-bypass-approvals-and-sandbox", "codex_cli"],
    ["cross-paired command", "claude -p --output-format stream-json --include-hook-events", "codex_cli"],
    ["command whitespace", "codex exec --json ", "codex_cli"],
  ] as const)("fails closed for %s", (_case, command, engine) => {
    const input = loadPlanV02();
    input.adapter_plan.command = command;
    input.adapter_plan.engine = engine;
    expect(projectRuntimePlanV03(input, CAPTURED_REGISTRY)).toEqual({
      ok: false,
      reason: INVALID_POLICY,
    });
  });

  it("rejects a structurally forged capture registry", () => {
    expect(projectRuntimePlanV03(loadPlanV02(), {
      registry_id: "s41-captured-runtime-profile-registry-v01",
    } as typeof CAPTURED_REGISTRY)).toEqual({ ok: false, reason: INVALID_POLICY });
  });

  it("fails closed when checked policy arithmetic overflows", () => {
    const input = loadPlanV02();
    const overflow = structuredClone(input);
    for (const rule of overflow.retry_policy.rules) rule.max_task_executions = Number.MAX_SAFE_INTEGER;

    expect(deriveRuntimeExecutionPolicyForRegisteredAdapterV03(overflow)).toEqual({
      ok: false,
      reason: INVALID_POLICY,
    });
  });

  it.each([
    ["lease duration below two milliseconds", (plan: ResolvedRunPlanV02Value) => {
      plan.limit_policy.max_elapsed_ms = 1;
    }],
    ["zero work-output headroom", (plan: ResolvedRunPlanV02Value) => {
      plan.limit_policy.max_output_bytes = plan.limit_policy.control_plane_output_reserve_bytes
        + (plan.recovery_policy.reserve.max_output_bytes ?? 0);
    }],
    ["heartbeat cardinality overflow", (plan: ResolvedRunPlanV02Value) => {
      plan.limit_policy.max_elapsed_ms = Number.MAX_SAFE_INTEGER;
    }],
    ["insufficient control reserve", (plan: ResolvedRunPlanV02Value) => {
      plan.limit_policy.control_plane_output_reserve_bytes = plan.required_control_plane_output_bytes;
    }],
    ["command case drift", (plan: ResolvedRunPlanV02Value) => {
      plan.adapter_plan.command = "Codex exec --json";
    }],
  ] as const)("fails closed for %s", (_case, mutate) => {
    const input = loadPlanV02();
    mutate(input);
    expect(projectRuntimePlanV03(input, CAPTURED_REGISTRY)).toEqual({
      ok: false,
      reason: INVALID_POLICY,
    });
  });

  it("projects an immutable strict V03 clone with the exact derived recovery hash fields", () => {
    const input = loadPlanV02();
    const before = structuredClone(input);
    const result = projectRuntimePlanV03(input, CAPTURED_REGISTRY);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(input).toEqual(before);
    expect(result.value).not.toBe(input);
    expect(result.value.schema_version).toBe("0.3");
    expect(result.value.execution_profile).toBe("bounded-v04");
    expect(result.value.runtime_input_hash).toBe(HashRuntimeInputV03(before));
    expect(result.value.runtime_recovery_policy_hash).toBe(HashRuntimeRecoveryPolicyV03(before));
    expect(Object.keys(result.value).sort()).toEqual([
      ...Object.keys(before),
      "runtime_input_hash",
      "runtime_recovery_policy_hash",
      "runtime_execution_policy",
    ].sort());
    expect(Object.keys(result.value.runtime_execution_policy).sort()).toEqual([
      "charge_profile_id",
      "heartbeat_interval_ms",
      "integrator_acquisition_max",
      "integrator_heartbeat_event_max",
      "integrator_release_max",
      "max_compaction_events",
      "max_execution_attempts",
      "max_process_runtime_ms",
      "max_summary_content_bytes",
      "max_summary_records",
      "owner_lease_duration_ms",
      "profile_id",
      "run_heartbeat_event_max",
      "run_owner_acquisition_max",
      "run_owner_release_max",
      "task_heartbeat_event_max",
      "task_owner_acquisition_max",
      "task_owner_release_max",
    ]);
    expect(Object.isFrozen(result.value)).toBe(true);
    expect(Object.isFrozen(result.value.adapter_plan)).toBe(true);
    expect(Object.isFrozen(result.value.tasks)).toBe(true);
    expect(Object.isFrozen(result.value.tasks[0])).toBe(true);
    expect(Object.isFrozen(result.value.runtime_execution_policy)).toBe(true);
    expect(() => {
      (result.value.adapter_plan as { command: string }).command = "mutated";
    }).toThrow(TypeError);
    expect(() => {
      (result.value.tasks as unknown as Array<unknown>).push({});
    }).toThrow(TypeError);
  });

  it("uses the frozen exact input and recovery-policy hash preimages", () => {
    const plan = loadPlanV02();
    expect(HashRuntimeInputV03(plan)).toBe(hashCanonical({
      purpose: "runtime-input-v03",
      schema_version: "0.3",
      compile_pack_manifest_hash: plan.compile_pack_manifest_hash,
      work_item_id: plan.work_item_id,
      intake_brief_id: plan.intake_brief_id,
      tasks: plan.tasks,
      context_snapshot: plan.context_snapshot,
    }));
    expect(HashRuntimeRecoveryPolicyV03(plan)).toBe(hashCanonical({
      purpose: "runtime-recovery-policy-v03",
      schema_version: "0.3",
      trigger: plan.trigger,
      goal: plan.goal,
      progress: plan.progress,
      stop_policy: plan.stop_policy,
      limit_policy: plan.limit_policy,
      retry_policy: plan.retry_policy,
      recovery_policy: plan.recovery_policy,
      side_effects: plan.side_effects,
      compensations: plan.compensations,
      runtime_record_limits: plan.runtime_record_limits,
      assurance_profile: plan.assurance_profile,
      risk_controls: plan.risk_controls,
      tool_grants: plan.tool_grants,
      workspace_boundary: plan.workspace_boundary,
      adapter_plan: plan.adapter_plan,
      gates: plan.gates,
      evaluations: plan.evaluations,
    }));
  });

  it.each(["runtime_input_hash", "runtime_recovery_policy_hash"] as const)(
    "rejects a caller mutation of %s",
    (field) => {
      const projected = projectRuntimePlanV03(loadPlanV02(), CAPTURED_REGISTRY);
      if (!projected.ok) throw new Error(projected.reason);
      const mutated = structuredClone(projected.value);
      mutated[field] = `sha256:${"0".repeat(64)}`;
      expect(inspectRuntimePlanV03(new TextEncoder().encode(JSON.stringify(mutated))))
        .toEqual({ ok: false, reason: "RUNTIME_PLAN_SCHEMA_INVALID" });
    },
  );

  it("leaves the frozen V02 parser and input bytes semantically unchanged", () => {
    const input = loadPlanV02();
    const encodedBefore = JSON.stringify(input);
    const projected = projectRuntimePlanV03(input, CAPTURED_REGISTRY);

    expect(projected.ok).toBe(true);
    expect(ResolvedRunPlanV02.safeParse(input).success).toBe(true);
    expect(JSON.stringify(input)).toBe(encodedBefore);
    if (!projected.ok) return;
    expect(ResolvedRunPlanV02.safeParse(projected.value).success).toBe(false);
  });

  it("rejects unknown and V02-invalid inputs with the stable policy failure", () => {
    const input = loadPlanV02();
    const invalid = { ...input, unexpected: true };
    expect(projectRuntimePlanV03(invalid, CAPTURED_REGISTRY)).toEqual({
      ok: false,
      reason: INVALID_POLICY,
    });
  });

  it("captures exact strict V03 plan bytes behind an unforgeable runtime brand", () => {
    const projected = projectRuntimePlanV03(loadPlanV02(), CAPTURED_REGISTRY);
    if (!projected.ok) throw new Error(projected.reason);
    const source = new TextEncoder().encode(`${JSON.stringify(projected.value, null, 2)}\n`);
    const inspected = inspectRuntimePlanV03(source);
    expect(inspected).toMatchObject({
      ok: true,
      validated_plan: {
        run_id: projected.value.run_id,
        plan_hash: hashRawBytes(source),
        byte_length: source.byteLength,
        plan: projected.value,
      },
    });
    if (!inspected.ok) return;
    expect(isValidatedRuntimePlanV03(inspected.validated_plan)).toBe(true);
    expect(isValidatedRuntimePlanV03({ ...inspected.validated_plan })).toBe(false);
    expect(Object.isFrozen(inspected.validated_plan)).toBe(true);
    expect(Object.isFrozen(inspected.validated_plan.plan)).toBe(true);
    source.fill(0);
    expect(inspected.validated_plan.plan.schema_version).toBe("0.3");
  });

  it("fails closed for forged, duplicate-key, V02, shared, and oversized plan bytes", () => {
    const projected = projectRuntimePlanV03(loadPlanV02(), CAPTURED_REGISTRY);
    if (!projected.ok) throw new Error(projected.reason);
    expect(inspectRuntimePlanV03(new TextEncoder().encode('{"schema_version":"0.3","schema_version":"0.3"}')))
      .toEqual({ ok: false, reason: "RUNTIME_PLAN_SYNTAX_INVALID" });
    expect(inspectRuntimePlanV03(new TextEncoder().encode(JSON.stringify(loadPlanV02()))))
      .toEqual({ ok: false, reason: "RUNTIME_PLAN_SCHEMA_INVALID" });
    expect(inspectRuntimePlanV03(new Uint8Array(4_194_305)))
      .toEqual({ ok: false, reason: "RUNTIME_PLAN_INPUT_INVALID" });
    expect(inspectRuntimePlanV03({})).toEqual({ ok: false, reason: "RUNTIME_PLAN_INPUT_INVALID" });
    if (typeof SharedArrayBuffer !== "undefined") {
      expect(inspectRuntimePlanV03(new Uint8Array(new SharedArrayBuffer(8))))
        .toEqual({ ok: false, reason: "RUNTIME_PLAN_INPUT_INVALID" });
    }
  });
});
