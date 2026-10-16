import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { deriveControlPlaneBudgetV02 } from "../../src/compiler/control-plane-budget-v02.js";
import { RuntimeEventTypesV03, RuntimeEventV03 } from "../../src/schema/runtime-v03.js";
import {
  HashRuntimeInputV03,
  HashRuntimeRecoveryPolicyV03,
  ResolvedRunPlanV03,
  RuntimeEventTypesV04,
  RuntimeEventV04,
  RuntimeExecutionPolicyV03,
  RuntimeSchemaInventoryV04,
  type ResolvedRunPlanV03Value,
  type RuntimeEventV04Value,
  type RuntimeExecutionPolicyV03Value,
} from "../../src/schema/runtime-v04.js";

type Assert<T extends true> = T;
type IsAssignable<T, U> = T extends U ? true : false;
type _S41TypeContract = [
  Assert<IsAssignable<ResolvedRunPlanV03Value["schema_version"], "0.3">>,
  Assert<IsAssignable<ResolvedRunPlanV03Value["execution_profile"], "bounded-v04">>,
  Assert<IsAssignable<RuntimeExecutionPolicyV03Value["profile_id"], "runtime-execution-controls-v04-s41-1">>,
  Assert<IsAssignable<RuntimeEventV04Value["schema_version"], "0.4">>,
];

const H = (character: string) => `sha256:${character.repeat(64)}`;
const ref = (ledger_sequence: number, character = `${ledger_sequence % 10}`) => ({
  ledger_sequence,
  event_hash: H(character),
});

const runtimeInventoryV04 = {
  resolved_run_plan: "0.3",
  ledger_event: "0.4",
  run_manifest: "0.4",
  artifact_manifest: "0.2",
  redaction_derivative: "0.2",
  human_authorization_proof: "0.2",
  authority_envelope: "0.2",
  agency_recommendation: "0.2",
  authority_revocation: "0.2",
  task_result: "0.2",
  manual_observation: "0.2",
  export_decision: "0.2",
  evidence_item: "0.2",
  gate_result: "0.2",
  evaluation_result: "0.2",
  claim: "0.2",
  finding: "0.2",
  waiver: "0.2",
  gate_waiver_authority: "0.2",
  summary_artifact: "0.1",
} as const;

const NEW_TYPES = [
  "task.execution-non-entry-acknowledged",
  "control.pause-requested",
  "recovery.resume-requested",
  "execution.attempt-started",
  "ownership.lease-acquired",
  "ownership.lease-heartbeat-recorded",
  "ownership.lease-released",
  "run.compaction-recorded",
] as const;
const EXPECTED_RESOLVED_RUN_PLAN_V03_KEYS = [
  ...Object.keys(loadPlanV02()),
  "runtime_input_hash",
  "runtime_recovery_policy_hash",
  "runtime_execution_policy",
].sort();

const envelope = {
  schema_version: "0.4",
  event_id: "event_s41_1",
  run_id: "run_s41_1",
  sequence: 12,
  recorded_at: "2026-08-26T20:41:00Z",
  risk_tier: "T1",
  related_ids: [],
  previous_event_hash: H("1"),
  event_hash: H("2"),
} as const;

function checkedAdd(left: number, right: number): number {
  const value = left + right;
  if (!Number.isSafeInteger(value)) throw new TypeError("safe integer overflow");
  return value;
}

function checkedSum(values: readonly number[]): number {
  let total = 0;
  for (const value of values) total = checkedAdd(total, value);
  return total;
}

function checkedMultiply(left: number, right: number): number {
  const value = left * right;
  if (!Number.isSafeInteger(value)) throw new TypeError("safe integer overflow");
  return value;
}

function checkedSubtract(left: number, right: number): number {
  const value = left - right;
  if (!Number.isSafeInteger(value)) throw new TypeError("safe integer overflow");
  return value;
}

function checkedCeilDiv(left: number, right: number): number {
  return Math.ceil(left / right);
}

function loadPlanV02(): Record<string, unknown> {
  return JSON.parse(
    readFileSync(
      join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
      "utf8",
    ),
  ) as Record<string, unknown>;
}

function deriveRuntimeExecutionPolicy(plan: Record<string, unknown>) {
  const typedPlan = plan as {
    tasks: Array<{ id: string }>;
    retry_policy: { rules: Array<{ task_ref: string; max_task_executions: number }> };
    compensations: Array<unknown>;
    limit_policy: {
      max_loop_attempts: number;
      max_elapsed_ms: number;
      max_output_bytes: number;
      control_plane_output_reserve_bytes: number;
    };
    recovery_policy: {
      reserve: { max_output_bytes: number };
    };
  };

  const retryMaxByTask = new Map<string, number>();
  for (const task of typedPlan.tasks) retryMaxByTask.set(task.id, 0);
  for (const rule of typedPlan.retry_policy.rules) {
    retryMaxByTask.set(rule.task_ref, Math.max(retryMaxByTask.get(rule.task_ref) ?? 0, rule.max_task_executions));
  }

  let actionAttempts = 0;
  for (const task of typedPlan.tasks) actionAttempts = checkedAdd(actionAttempts, retryMaxByTask.get(task.id) ?? 0);
  const compensationCount = typedPlan.compensations.length;
  const loopAttemptLimit = typedPlan.limit_policy.max_loop_attempts;
  const executionAttemptLimit = checkedSum([
    checkedMultiply(2, actionAttempts),
    checkedMultiply(2, compensationCount),
    9,
  ]);
  const maxProcessRuntimeMs = Math.min(typedPlan.limit_policy.max_elapsed_ms, 30_000);
  const ownerLeaseDurationMs = Math.min(maxProcessRuntimeMs, 30_000);
  const heartbeatIntervalMs = Math.max(1, Math.floor(ownerLeaseDurationMs / 3));
  const runHeartbeatWindows = checkedCeilDiv(typedPlan.limit_policy.max_elapsed_ms, heartbeatIntervalMs);
  const taskHeartbeatWindows = checkedCeilDiv(maxProcessRuntimeMs, heartbeatIntervalMs);
  const runHeartbeatEventMax = checkedMultiply(executionAttemptLimit, runHeartbeatWindows);
  const taskHeartbeatEventMax = checkedMultiply(actionAttempts, taskHeartbeatWindows);
  const integratorHeartbeatEventMax = checkedMultiply(executionAttemptLimit, runHeartbeatWindows);
  const outputBudgetAfterControlReserve = checkedSubtract(
    typedPlan.limit_policy.max_output_bytes,
    typedPlan.limit_policy.control_plane_output_reserve_bytes,
  );
  const summaryContentBudget = checkedSubtract(
    outputBudgetAfterControlReserve,
    typedPlan.recovery_policy.reserve.max_output_bytes,
  );
  if (summaryContentBudget <= 0) throw new TypeError("summary budget must stay positive");

  return {
    profile_id: "runtime-execution-controls-v04-s41-1",
    charge_profile_id: "control-plane-charge-ceilings-v04-s41-1",
    max_process_runtime_ms: maxProcessRuntimeMs,
    max_execution_attempts: executionAttemptLimit,
    run_owner_acquisition_max: executionAttemptLimit,
    task_owner_acquisition_max: actionAttempts,
    integrator_acquisition_max: executionAttemptLimit,
    owner_lease_duration_ms: ownerLeaseDurationMs,
    heartbeat_interval_ms: heartbeatIntervalMs,
    run_heartbeat_event_max: runHeartbeatEventMax,
    task_heartbeat_event_max: taskHeartbeatEventMax,
    integrator_heartbeat_event_max: integratorHeartbeatEventMax,
    run_owner_release_max: executionAttemptLimit,
    task_owner_release_max: actionAttempts,
    integrator_release_max: executionAttemptLimit,
    max_compaction_events: loopAttemptLimit,
    max_summary_records: loopAttemptLimit,
    max_summary_content_bytes: Math.min(65_536, summaryContentBudget),
  } as const;
}

function deriveRequiredControlBytes(
  plan: Record<string, unknown>,
  policy: ReturnType<typeof deriveRuntimeExecutionPolicy>,
): number {
  const typedPlan = plan as {
    compensations: Array<unknown>;
    limit_policy: { max_elapsed_ms: number; max_loop_attempts: number };
  };
  const v02Budget = deriveControlPlaneBudgetV02(plan as Parameters<typeof deriveControlPlaneBudgetV02>[0]);
  if (!v02Budget.ok) throw new TypeError(v02Budget.message);
  const actionAttempts = policy.task_owner_acquisition_max;
  const executionAttemptLimit = policy.max_execution_attempts;
  const runHeartbeatWindows = checkedCeilDiv(
    typedPlan.limit_policy.max_elapsed_ms,
    policy.heartbeat_interval_ms,
  );
  const taskHeartbeatWindows = checkedCeilDiv(policy.max_process_runtime_ms, policy.heartbeat_interval_ms);
  const doubledExecutionAttemptLimit = checkedMultiply(2, executionAttemptLimit);
  const subordinateAcquisitions = checkedSum([actionAttempts, executionAttemptLimit]);
  const heartbeats = checkedSum([
    checkedMultiply(doubledExecutionAttemptLimit, runHeartbeatWindows),
    checkedMultiply(actionAttempts, taskHeartbeatWindows),
  ]);
  const releases = checkedSum([actionAttempts, doubledExecutionAttemptLimit]);
  const addedNonClockEvents = checkedSum([
    executionAttemptLimit - 1,
    executionAttemptLimit,
    subordinateAcquisitions,
    heartbeats,
    releases,
    executionAttemptLimit,
    typedPlan.limit_policy.max_loop_attempts,
  ]);
  const addedClockEvents = checkedSum([
    executionAttemptLimit - 1,
    executionAttemptLimit,
    subordinateAcquisitions,
    heartbeats,
    releases,
    executionAttemptLimit,
  ]);

  return checkedSum([
    v02Budget.value.required_control_plane_output_bytes,
    checkedMultiply(checkedSum([addedNonClockEvents, addedClockEvents]), 131_072),
    checkedMultiply(typedPlan.limit_policy.max_loop_attempts, 262_144),
  ]);
}

function resolvedRunPlanV03Fixture() {
  const base = loadPlanV02();
  const runtimeExecutionPolicy = deriveRuntimeExecutionPolicy(base);
  return {
    ...base,
    schema_version: "0.3",
    execution_profile: "bounded-v04",
    runtime_input_hash: HashRuntimeInputV03(base as never),
    runtime_recovery_policy_hash: HashRuntimeRecoveryPolicyV03(base as never),
    required_control_plane_output_bytes: deriveRequiredControlBytes(base, runtimeExecutionPolicy),
    runtime_execution_policy: runtimeExecutionPolicy,
  };
}

function mutatedLoopAttemptOverflowFixture() {
  const base = loadPlanV02();
  const mutated = {
    ...base,
    limit_policy: {
      ...(base.limit_policy as Record<string, unknown>),
      max_loop_attempts: 20_000_000_000,
      max_output_bytes: Number.MAX_SAFE_INTEGER,
      control_plane_output_reserve_bytes: Number.MAX_SAFE_INTEGER - 2_048,
    },
    recovery_policy: {
      ...(base.recovery_policy as Record<string, unknown>),
      reserve: {
        ...((base.recovery_policy as { reserve: Record<string, unknown> }).reserve),
        max_output_bytes: 1_024,
      },
    },
  };
  return {
    ...mutated,
    schema_version: "0.3",
    execution_profile: "bounded-v04",
    required_control_plane_output_bytes: 1,
    runtime_input_hash: HashRuntimeInputV03(mutated as never),
    runtime_recovery_policy_hash: HashRuntimeRecoveryPolicyV03(mutated as never),
    runtime_execution_policy: deriveRuntimeExecutionPolicy(mutated),
  };
}

describe("S41-A V04 runtime schema contract", () => {
  it("closes the inventory at exactly 20 keys and the event family at exactly 59 members", () => {
    expect(RuntimeSchemaInventoryV04.parse(runtimeInventoryV04)).toEqual(runtimeInventoryV04);
    expect(RuntimeSchemaInventoryV04.safeParse({ ...runtimeInventoryV04, extra: true }).success).toBe(false);
    expect(RuntimeSchemaInventoryV04.safeParse({ ...runtimeInventoryV04, summary_artifact: undefined }).success).toBe(false);

    expect(RuntimeEventTypesV04).toEqual([...RuntimeEventTypesV03, ...NEW_TYPES]);
    expect(RuntimeEventTypesV04).toHaveLength(59);
    expect(new Set(RuntimeEventTypesV04)).toHaveLength(59);
  });

  const newEventFixtures = [
    {
      event_type: "task.execution-non-entry-acknowledged",
      source: "adapter",
      authority_ref: null,
      payload: {
        action_id: "action_s41_1",
        task_ref: "diagnose-root-cause",
        admission_ref: ref(4),
        attempt_event_ref: ref(3),
        adapter_invocation_id: "adapter_invocation_s41_1",
        adapter_ref: "adapter-runner",
        adapter_version_hash: H("4"),
        fence_epoch: 3,
        host_identity_hash: H("5"),
        boot_id_hash: H("6"),
        unit_name_hash: H("7"),
        cgroup_path_hash: H("8"),
        acknowledgement_observation_hash: H("9"),
      },
    },
    {
      event_type: "control.pause-requested",
      source: "operator",
      authority_ref: "auth_pause_1",
      payload: {
        request_id: "request_pause_1",
        requested_by: "operator",
        reason_code: "operator-request",
        attempt_event_ref: ref(7),
        run_owner_lease_ref: ref(8),
        request_clock_ref: ref(9),
        fence_epoch: 2,
      },
    },
    {
      event_type: "recovery.resume-requested",
      source: "operator",
      authority_ref: "auth_resume_1",
      payload: {
        request_id: "request_resume_1",
        mode: "ordinary",
        resume_nonce_hash: H("3"),
        previous_attempt_event_ref: ref(6),
        source_boundary_sequence: 11,
        source_boundary_head_hash: H("4"),
        source_manifest_hash: H("5"),
        repository_state_hash: H("a"),
        plan_hash: H("6"),
        input_hash: H("7"),
        recovery_policy_hash: H("8"),
        authority_envelope_hash: H("9"),
        request_clock_ref: ref(10),
        target_action_admission_ref: null,
        compensation_phase_event_ref: null,
      },
    },
    {
      event_type: "execution.attempt-started",
      source: "kernel",
      authority_ref: null,
      payload: {
        attempt_id: "attempt_s41_1",
        attempt_ordinal: 2,
        mode: "ordinary",
        previous_attempt_event_ref: ref(6),
        resume_request_event_ref: ref(7),
        resume_nonce_hash: H("3"),
        source_boundary_sequence: 11,
        source_boundary_head_hash: H("4"),
        source_manifest_hash: H("5"),
        repository_state_hash: H("a"),
        plan_hash: H("6"),
        input_hash: H("7"),
        recovery_policy_hash: H("8"),
        authority_envelope_hash: H("9"),
        run_owner_lease_id: "lease_owner_s41_1",
        issued_clock_ref: ref(10),
        deadline_elapsed_ms: 900,
        boot_id_hash: H("a"),
        monotonic_clock_id: "clock_mono_s41_1",
        previous_fence_epoch: 2,
        fence_epoch: 3,
      },
    },
    {
      event_type: "ownership.lease-acquired",
      source: "policy-enforcement-point",
      authority_ref: "auth_owner_1",
      payload: {
        owner_lease_id: "lease_task_s41_1",
        scope: "task",
        scope_ref: "diagnose-root-cause",
        parent_run_owner_lease_id: "lease_owner_s41_1",
        attempt_event_ref: ref(7),
        issued_clock_ref: ref(10),
        deadline_elapsed_ms: 900,
        boot_id_hash: H("a"),
        monotonic_clock_id: "clock_mono_s41_1",
        fence_epoch: 3,
        heartbeat_limit: 15,
      },
    },
    {
      event_type: "ownership.lease-heartbeat-recorded",
      source: "kernel",
      authority_ref: null,
      payload: {
        owner_lease_event_ref: ref(8),
        heartbeat_ordinal: 2,
        observation_clock_ref: ref(11),
        previous_deadline_elapsed_ms: 600,
        deadline_elapsed_ms: 900,
        boot_id_hash: H("a"),
        monotonic_clock_id: "clock_mono_s41_1",
        fence_epoch: 3,
      },
    },
    {
      event_type: "ownership.lease-released",
      source: "kernel",
      authority_ref: null,
      payload: {
        owner_lease_event_ref: ref(8),
        release_clock_ref: ref(12),
        reason: "superseded",
        fence_epoch: 3,
      },
    },
    {
      event_type: "run.compaction-recorded",
      source: "kernel",
      authority_ref: null,
      payload: {
        summary_id: "summary_s41_1",
        summary_record_path: "summaries/records/summary_s41_1.json",
        summary_record_hash: H("b"),
        summary_content_path: "summaries/content/summary_s41_1.bin",
        summary_content_hash: H("c"),
        summary_size_bytes: 4096,
        attempt_event_ref: ref(7),
        integrator_lease_event_ref: ref(9),
        source_first_event_ref: ref(3),
        source_last_event_ref: ref(12),
        source_prefix_sequence: 12,
        source_prefix_head_hash: H("d"),
        pre_context_hash: H("e"),
        post_context_hash: H("f"),
      },
    },
  ] as const;

  it.each(newEventFixtures)("accepts the exact new V04 event contract for $event_type", (event) => {
    expect(RuntimeEventV04.safeParse({ ...envelope, ...event }).success).toBe(true);
    expect(RuntimeEventV03.safeParse({ ...envelope, ...event }).success).toBe(false);
  });

  it.each(newEventFixtures)("rejects source, authority, missing-key, and extra-key mutations for $event_type", (event) => {
    const valid = { ...envelope, ...event };
    const wrongSource = event.source === "kernel" ? "operator" : "kernel";
    const wrongAuthority = event.authority_ref === null ? "auth_unexpected" : null;
    const payload = structuredClone(event.payload) as Record<string, unknown>;
    const firstKey = Object.keys(payload)[0];
    expect(firstKey).toBeDefined();
    if (firstKey === undefined) return;
    delete payload[firstKey];

    expect(RuntimeEventV04.safeParse({ ...valid, source: wrongSource }).success).toBe(false);
    expect(RuntimeEventV04.safeParse({ ...valid, authority_ref: wrongAuthority }).success).toBe(false);
    expect(RuntimeEventV04.safeParse({ ...valid, payload }).success).toBe(false);
    expect(RuntimeEventV04.safeParse({
      ...valid,
      payload: { ...event.payload, unexpected: true },
    }).success).toBe(false);
  });

  it("rejects compaction path mismatches for both record and content members", () => {
    const base = {
      ...envelope,
      source: "kernel",
      authority_ref: null,
      event_type: "run.compaction-recorded",
      payload: {
        summary_id: "summary_s41_1",
        summary_record_path: "summaries/records/summary_s41_1.json",
        summary_record_hash: H("b"),
        summary_content_path: "summaries/content/summary_s41_1.bin",
        summary_content_hash: H("c"),
        summary_size_bytes: 4096,
        attempt_event_ref: ref(7),
        integrator_lease_event_ref: ref(9),
        source_first_event_ref: ref(3),
        source_last_event_ref: ref(12),
        source_prefix_sequence: 12,
        source_prefix_head_hash: H("d"),
        pre_context_hash: H("e"),
        post_context_hash: H("f"),
      },
    } as const;

    expect(RuntimeEventV04.safeParse(base).success).toBe(true);
    expect(RuntimeEventV04.safeParse({
      ...base,
      payload: { ...base.payload, summary_record_path: "summaries/records/not-the-summary.json" },
    }).success).toBe(false);
    expect(RuntimeEventV04.safeParse({
      ...base,
      payload: { ...base.payload, summary_content_path: "summaries/content/not-the-summary.bin" },
    }).success).toBe(false);
  });

  it("strengthens pause, reconciliation, effect, and limit events without widening V03", () => {
    const paused = {
      ...envelope,
      source: "operator",
      authority_ref: "auth_pause_1",
      event_type: "run.paused",
      payload: {
        requested_by: "operator",
        reason_code: "operator-request",
        request_event_ref: ref(9),
        attempt_event_ref: ref(7),
        quiescent_boundary_sequence: 11,
        quiescent_boundary_head_hash: H("3"),
        previous_fence_epoch: 2,
        fence_epoch: 3,
        invalidated_owner_lease_refs: [ref(8)],
      },
    } as const;
    expect(RuntimeEventV04.safeParse(paused).success).toBe(true);
    expect(RuntimeEventV04.safeParse({
      ...paused,
      payload: { ...paused.payload, invalidated_owner_lease_refs: [] },
    }).success).toBe(false);
    expect(RuntimeEventV03.safeParse(paused).success).toBe(false);

    const provenNonStart = {
      ...envelope,
      source: "integrity",
      authority_ref: null,
      event_type: "task.action-outcome-reconciled",
      payload: {
        action_id: "action_s41_1",
        task_ref: "diagnose-root-cause",
        admission_ref: ref(4),
        reconciliation_status: "proven-non-start",
        attempt_event_ref: ref(7),
        adapter_invocation_id: "adapter_invocation_s41_1",
        adapter_ref: "adapter-runner",
        adapter_version_hash: H("4"),
        non_entry_ack_event_ref: ref(5),
        process_cannot_continue_ref: ref(6),
        fence_epoch: 3,
      },
    } as const;
    expect(RuntimeEventV04.safeParse(provenNonStart).success).toBe(true);
    expect(RuntimeEventV04.safeParse({
      ...provenNonStart,
      payload: { ...provenNonStart.payload, reconciliation_status: "outcome-remains-unknown" },
    }).success).toBe(false);

    const reconciledNotCommitted = {
      ...envelope,
      source: "integrity",
      authority_ref: null,
      event_type: "effect.outcome",
      payload: {
        task_ref: "diagnose-root-cause",
        effect_ref: "effect-none",
        action_id: "action_s41_1",
        outcome: "not-committed",
        evidence_refs: [ref(6)],
        reconciliation_event_ref: ref(6),
      },
    } as const;
    expect(RuntimeEventV04.safeParse(reconciledNotCommitted).success).toBe(true);
    expect(RuntimeEventV04.safeParse({
      ...reconciledNotCommitted,
      payload: { ...reconciledNotCommitted.payload, evidence_refs: [ref(5), ref(6)] },
    }).success).toBe(false);

    const blocked = {
      ...envelope,
      source: "policy-enforcement-point",
      authority_ref: "auth_owner_1",
      event_type: "limit.admission-blocked",
      payload: {
        request_id: "request_limit_s41_1",
        task_ref: "diagnose-root-cause",
        phase: "work",
        compensation_ref: null,
        request_kind: "process-start",
        request_hash: H("8"),
        violations: [{
          limit_ref: "max-workers",
          consumed: 1,
          requested: 1,
          ceiling: 1,
        }],
      },
    } as const;
    expect(RuntimeEventV04.safeParse(blocked).success).toBe(true);
    expect(RuntimeEventV03.safeParse(blocked).success).toBe(false);
  });

  it("derives the exact runtime execution policy and control-byte replacement from the V02 plan", () => {
    const fixture = resolvedRunPlanV03Fixture();

    expect(ResolvedRunPlanV03.safeParse(fixture).success).toBe(true);
    expect(ResolvedRunPlanV03.safeParse({
      ...fixture,
      required_control_plane_output_bytes: fixture.required_control_plane_output_bytes - 1,
    }).success).toBe(false);
    expect(ResolvedRunPlanV03.safeParse({
      ...fixture,
      runtime_execution_policy: {
        ...fixture.runtime_execution_policy,
        heartbeat_interval_ms: fixture.runtime_execution_policy.owner_lease_duration_ms,
      },
    }).success).toBe(false);
    expect(RuntimeExecutionPolicyV03.safeParse({
      ...fixture.runtime_execution_policy,
      owner_lease_duration_ms: 1,
    }).success).toBe(false);
    expect(RuntimeExecutionPolicyV03.safeParse({
      ...fixture.runtime_execution_policy,
      max_summary_content_bytes: 65_537,
    }).success).toBe(false);
  });

  it("accepts only the two exact release-registered adapter capture tuples", () => {
    const codex = resolvedRunPlanV03Fixture();
    expect(ResolvedRunPlanV03.safeParse(codex).success).toBe(true);

    const claudeBase = {
      ...loadPlanV02(),
      adapter_plan: {
        ...loadPlanV02().adapter_plan,
        engine: "claude_code_cli",
        command: "claude -p --output-format stream-json --include-hook-events",
      },
    };
    const claudePolicy = deriveRuntimeExecutionPolicy(claudeBase);
    const claude = {
      ...claudeBase,
      schema_version: "0.3",
      execution_profile: "bounded-v04",
      runtime_input_hash: HashRuntimeInputV03(claudeBase as never),
      runtime_recovery_policy_hash: HashRuntimeRecoveryPolicyV03(claudeBase as never),
      required_control_plane_output_bytes: deriveRequiredControlBytes(claudeBase, claudePolicy),
      runtime_execution_policy: claudePolicy,
    };
    expect(ResolvedRunPlanV03.safeParse(claude).success).toBe(true);

    for (const adapterPlan of [
      { ...codex.adapter_plan, command: "codex exec --json --extra" },
      { ...codex.adapter_plan, command: claude.adapter_plan.command },
      { ...claude.adapter_plan, command: codex.adapter_plan.command },
    ]) {
      expect(ResolvedRunPlanV03.safeParse({ ...codex, adapter_plan: adapterPlan }).success).toBe(false);
    }
  });

  it("rejects overflowed V04 control-byte derivation instead of coercing arithmetic", () => {
    const fixture = mutatedLoopAttemptOverflowFixture();

    const parsed = ResolvedRunPlanV03.safeParse(fixture);
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((issue) => issue.message === "INVALID_V03_RUNTIME_EXECUTION_POLICY")).toBe(true);
    }
  });

  it("keeps the exact V03 top-level key set and rejects a mutated inherited V02 invariant", () => {
    const fixture = resolvedRunPlanV03Fixture();

    expect(Object.keys(fixture).sort()).toEqual(EXPECTED_RESOLVED_RUN_PLAN_V03_KEYS);
    expect(ResolvedRunPlanV03.safeParse({
      ...fixture,
      authority_subject: {
        ...fixture.authority_subject,
        mission: {
          ...fixture.authority_subject.mission,
          objective: "mutated objective",
        },
      },
    }).success).toBe(false);
  });
});
