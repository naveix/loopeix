import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  evaluateRuntimeLimitAccountingV04,
  projectRuntimeLimitCountersAtPrefixV04,
  projectRuntimeLimitCountersV04,
  scheduleRuntimeRetryV04,
} from "../../src/run/runtime-limit-accounting-v04.js";
import {
  inspectRuntimePlanV03,
  projectRuntimePlanV03,
  type ValidatedRuntimePlanV03,
} from "../../src/run/project-plan-v03.js";
import {
  buildRunManifestV04,
  inspectRunManifestV04,
  type ValidatedRunManifestV04,
} from "../../src/run/runtime-manifest-v04.js";
import type { ValidatedRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import type { ResolvedRunPlanV03Value } from "../../src/schema/runtime-v04.js";

const REGISTRY = captureRuntimeProfileRegistryV03();
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const H = (character: string) => `sha256:${character.repeat(64)}`;
const UTF8 = new TextEncoder();

function loadPlanV02(): ResolvedRunPlanV02Value {
  return ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
    "utf8",
  )));
}

function planV03(options: Readonly<{
  recovery?: Readonly<{ elapsed: number; tools: number; output: number; tokens?: number; cost?: number }>;
  tokens?: number;
  cost?: number;
}> = {}): ResolvedRunPlanV03Value {
  const source = loadPlanV02();
  if (options.tokens !== undefined) source.limit_policy.max_tokens = options.tokens;
  if (options.cost !== undefined) {
    source.limit_policy.max_cost_minor_units = options.cost;
    source.limit_policy.cost_currency = "GBP";
  }
  if (options.recovery !== undefined) {
    source.recovery_policy.reserve.max_elapsed_ms = options.recovery.elapsed;
    source.recovery_policy.reserve.max_tool_calls = options.recovery.tools;
    source.recovery_policy.reserve.max_output_bytes = options.recovery.output;
    source.recovery_policy.reserve.max_tokens = options.recovery.tokens ?? null;
    source.recovery_policy.reserve.max_cost_minor_units = options.recovery.cost ?? null;
  }
  const result = projectRuntimePlanV03(source, REGISTRY);
  if (!result.ok) throw new Error(result.reason);
  return result.value;
}

function accountingInput(plan: ResolvedRunPlanV03Value, phase: "work" | "compensation" = "work") {
  return {
    plan,
    phase,
    consumed: {
      loop_attempts: 1,
      execution_attempts: 2,
      task_executions: Object.fromEntries(plan.tasks.map((task) => [task.id, 0])),
      elapsed_ms: 1_000,
      tool_calls: 3,
      action_output_bytes: 5_000,
      control_output_bytes: 7_000,
      token_count: 0,
      cost_minor_units: 0,
      active_workers: 0,
    },
    requested: {
      task_ref: plan.tasks[0]!.id,
      loop_attempts: 0,
      execution_attempts: 0,
      task_executions: 0,
      elapsed_ms: 0,
      tool_calls: 0,
      action_output_bytes: 0,
      control_output_bytes: 0,
      token_count: 0,
      cost_minor_units: 0,
      workers: 0,
      process_runtime_ms: 0,
    },
  } as const;
}

type EventRow = Record<string, unknown>;
type GenuineProjectionInput = Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
}>;

function validatedPlanV03(mutator?: (plan: ResolvedRunPlanV02Value) => void): ValidatedRuntimePlanV03 {
  const source = loadPlanV02();
  mutator?.(source);
  const projected = projectRuntimePlanV03(source, REGISTRY);
  if (!projected.ok) throw new Error(projected.reason);
  const inspected = inspectRuntimePlanV03(UTF8.encode(JSON.stringify(projected.value)));
  if (!inspected.ok) throw new Error(inspected.reason);
  return inspected.validated_plan;
}

function appendEvent(
  events: EventRow[],
  runId: string,
  eventType: string,
  source: string,
  authorityRef: string | null,
  payload: EventRow,
): EventRow {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_limit_projection_s41_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-26T20:00:${String(sequence).padStart(2, "0")}Z`,
    event_type: eventType,
    source: source,
    authority_ref: authorityRef,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: (events.at(-1)?.event_hash as string | undefined) ?? null,
    payload,
  };
  const row = { ...preimage, event_hash: hashCanonical(preimage) };
  events.push(row);
  return row;
}

function eventRef(row: EventRow) {
  return { ledger_sequence: row.sequence as number, event_hash: row.event_hash as string };
}

function ledgerEventRef(
  ledger: ValidatedRuntimeLedgerV04,
  eventType: string,
  ordinal = 1,
) {
  let seen = 0;
  for (const event of ledger.events) {
    if (event.event_type !== eventType) continue;
    seen += 1;
    if (seen === ordinal) return { ledger_sequence: event.sequence, event_hash: event.event_hash };
  }
  throw new Error(`missing event ${eventType}#${ordinal}`);
}

function projectionEvents(validatedPlan: ValidatedRuntimePlanV03): EventRow[] {
  const { plan } = validatedPlan;
  const events: EventRow[] = [];
  appendEvent(events, plan.run_id, "run.initialized", "kernel", null, {
    plan_hash: validatedPlan.plan_hash,
    initial_fence_epoch: 0,
    runtime_schema_versions: {
      resolved_run_plan: "0.3", ledger_event: "0.4", run_manifest: "0.4",
      artifact_manifest: "0.2", redaction_derivative: "0.2", human_authorization_proof: "0.2",
      authority_envelope: "0.2", agency_recommendation: "0.2", authority_revocation: "0.2",
      task_result: "0.2", manual_observation: "0.2", export_decision: "0.2",
      evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2", claim: "0.2",
      finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2", summary_artifact: "0.1",
    },
  });
  const started = appendEvent(events, plan.run_id, "run.started", "kernel", null, { executor_profile_hash: H("1") });
  const clock = appendEvent(events, plan.run_id, "run.clock-observed", "kernel", null, {
    clock_id: "clock_limit_projection_s41", observed_at: "2026-08-26T20:00:02Z", elapsed_ms: 250,
    reason: "run-owner-acquisition", task_ref: null, failure_ordinal: null,
    use_ref: "run_owner_limit_projection_s41", attempt_ref: null, owner_lease_ref: null,
    boot_id_hash: H("2"), monotonic_clock_id: "monotonic_limit_projection_s41",
  });
  appendEvent(events, plan.run_id, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_limit_projection_s41", attempt_ordinal: 1, mode: "ordinary",
    previous_attempt_event_ref: null, resume_request_event_ref: null, resume_nonce_hash: null,
    source_boundary_sequence: 2, source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("3"),
    repository_state_hash: plan.authority_subject.repository.initial_state.repository_state_hash,
    plan_hash: validatedPlan.plan_hash, input_hash: H("4"),
    recovery_policy_hash: H("5"), authority_envelope_hash: H("6"),
    run_owner_lease_id: "run_owner_limit_projection_s41", issued_clock_ref: eventRef(clock),
    deadline_elapsed_ms: 30_000, boot_id_hash: H("2"), monotonic_clock_id: "monotonic_limit_projection_s41",
    previous_fence_epoch: 0, fence_epoch: 0,
  });
  return events;
}

const proposalBindings = {
  action_proposal_id: "proposal_limit_projection_s41", action_proposal_hash: H("7"),
  action_actor_ref: "actor_limit_projection_s41", action_actor_stable_identity_hash: H("7"),
  on_behalf_of_chain_hash: H("7"), repository_root_ref: "repository_limit_projection_s41",
  repository_base_ref_identity_hash: H("7"), repository_pre_state_hash: H("7"),
  authorized_change_set_hash: H("7"), normalized_dispatch_hash: H("7"), action_scope_hash: H("7"),
  action_class: "task", classifier_input_hash: H("7"), classifier_registry_hash: H("7"),
  classifier_rule_hash: H("7"), data_flow_hash: H("7"),
} as const;

function appendAdmission(
  events: EventRow[],
  validatedPlan: ValidatedRuntimePlanV03,
  ordinal: number,
  taskExecutionsAfter: number,
  actionOutputBytesAfter = 5,
): EventRow {
  const attempt = events.find((row) => row.event_type === "execution.attempt-started")!;
  return appendEvent(events, validatedPlan.run_id, "task.action-admitted", "policy-enforcement-point", "authority_limit_projection_s41", {
    action_id: `action_limit_projection_s41_${ordinal}`,
    task_ref: validatedPlan.plan.tasks[0]!.id,
    lease_id: `action_lease_limit_projection_s41_${ordinal}`,
    lease_event_ref: eventRef(attempt), admission_clock_ref: eventRef(attempt), ...proposalBindings,
    action_proposal_id: `proposal_limit_projection_s41_${ordinal}`,
    policy_action_kind: "network-read", action_approval_class: "agency", execution_ordinal: ordinal,
    retry_of_failure_ordinal: null, fence_epoch: 0,
    side_effect_refs: ["effect-limit-projection-s41"], waiver_gate_use_checks: [],
    task_executions_after: taskExecutionsAfter, action_output_bytes_after: actionOutputBytesAfter,
    attempt_event_ref: eventRef(attempt), parent_run_owner_lease_id: "run_owner_limit_projection_s41",
    logical_operation_idempotency_key: H("8"), resolved_operation_input_hash: H("9"),
    recovery_policy_hash: H("5"), process_runtime_ceiling_ms: 30_000,
  });
}

function appendTerminalCounters(
  events: EventRow[],
  validatedPlan: ValidatedRuntimePlanV03,
  admission: EventRow,
): void {
  const attempt = events.find((row) => row.event_type === "execution.attempt-started")!;
  for (const ordinal of [1, 2]) {
    appendEvent(events, validatedPlan.run_id, "tool.call-admitted", "policy-enforcement-point", "authority_limit_projection_s41", {
      tool_call_id: `tool_call_limit_projection_s41_${ordinal}`,
      action_id: admission.payload && (admission.payload as EventRow).action_id,
      task_ref: validatedPlan.plan.tasks[0]!.id, tool_grant_ref: validatedPlan.plan.tool_grants[0]!.id,
      fence_epoch: 0, tool_calls_after: ordinal,
    });
  }
  appendEvent(events, validatedPlan.run_id, "task.execution-completed", "adapter", null, {
    action_id: (admission.payload as EventRow).action_id, task_ref: validatedPlan.plan.tasks[0]!.id,
    admission_ref: eventRef(admission), result_id: "result_limit_projection_s41",
    result_path: "records/task-results/result_limit_projection_s41.json", result_hash: H("a"),
    output_bytes: 5, tool_calls: 2, token_count: 10,
    observed_cost: { capture: "captured", cost_minor_units: 7, cost_currency: "GBP", cost_minor_units_after: 7 },
    action_output_bytes_after: 5, tool_calls_after: 2, token_count_after: 10,
    attempt_event_ref: eventRef(attempt), process_runtime_ms: 100,
    loop_attempts_after: 1, task_executions_after: 1, workers_after: 1,
  });
}

function genuineProjectionInput(options: Readonly<{
  mutateEvents?: (events: EventRow[], plan: ValidatedRuntimePlanV03) => void;
  summaryRecord?: Readonly<{ present: boolean; matching: boolean; extra: boolean }>;
}> = {}): GenuineProjectionInput {
  const validatedPlan = validatedPlanV03();
  const events = projectionEvents(validatedPlan);
  options.mutateEvents?.(events, validatedPlan);
  const capturedFiles: Array<{ path: string; family: "primary" | "record"; required: boolean; mode: 384; bytes: Uint8Array }> = [];
  if (options.summaryRecord !== undefined) {
    const recordBytes = UTF8.encode("summary-record-bytes");
    if (!options.summaryRecord.extra) {
      const attempt = events.find((row) => row.event_type === "execution.attempt-started")!;
      appendEvent(events, validatedPlan.run_id, "run.compaction-recorded", "kernel", null, {
        summary_id: "summary_limit_projection_s41",
        summary_record_path: "summaries/records/summary_limit_projection_s41.json",
        summary_record_hash: options.summaryRecord.matching ? hashRawBytes(recordBytes) : H("b"),
        summary_content_path: "summaries/content/summary_limit_projection_s41.bin",
        summary_content_hash: H("c"), summary_size_bytes: 11,
        attempt_event_ref: eventRef(attempt), integrator_lease_event_ref: eventRef(attempt),
        source_first_event_ref: eventRef(events[0]!), source_last_event_ref: eventRef(events.at(-1)!),
        source_prefix_sequence: events.at(-1)!.sequence, source_prefix_head_hash: events.at(-1)!.event_hash,
        pre_context_hash: H("d"), post_context_hash: H("e"),
      });
    }
    if (options.summaryRecord.present) {
      capturedFiles.push({
        path: options.summaryRecord.extra
          ? "summaries/records/summary_extra_projection_s41.json"
          : "summaries/records/summary_limit_projection_s41.json",
        family: "record", required: true, mode: 384, bytes: recordBytes,
      });
    }
  }
  const ledgerBytes = UTF8.encode(`${events.map((row) => JSON.stringify(row)).join("\n")}\n`);
  capturedFiles.unshift({ path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes });
  const built = buildRunManifestV04({ ledger_bytes: ledgerBytes, created_at: "2026-08-26T20:10:00Z", captured_files: capturedFiles });
  if (!built.ok) throw new Error(built.reason);
  const inspected = inspectRunManifestV04({ manifest_bytes: built.bytes, ledger_bytes: ledgerBytes, captured_files: capturedFiles });
  if (!inspected.ok) throw new Error(inspected.reason);
  return { validated_plan: validatedPlan, ledger: inspected.ledger, manifest: inspected.validated_manifest };
}

describe("S41-B branded durable counter projection", () => {
  it("derives complete immutable zero-based counters from exact durable facts", () => {
    const input = genuineProjectionInput();
    const result = projectRuntimeLimitCountersV04(input);
    expect(result).toMatchObject({
      ok: true,
      value: {
        loop_attempts: 0,
        execution_attempts: 1,
        elapsed_ms: 250,
        tool_calls: 0,
        action_output_bytes: 0,
        control_output_bytes: input.ledger.ledger_byte_length,
        token_count: 0,
        cost_minor_units: 0,
        active_workers: 0,
      },
    });
    if (!result.ok) return;
    expect(Object.keys(result.value.task_executions).sort()).toEqual(
      input.validated_plan.plan.tasks.map(({ id }) => id).sort(),
    );
    expect(Object.values(result.value.task_executions).every((count) => count === 0)).toBe(true);
    expect(Object.isFrozen(result.value)).toBe(true);
    expect(Object.isFrozen(result.value.task_executions)).toBe(true);
  });

  it("counts crash-in-flight work, cumulative terminal facts, summary content, and exact control bytes", () => {
    const input = genuineProjectionInput({
      mutateEvents(events, plan) {
        const admission = appendAdmission(events, plan, 1, 1);
        appendTerminalCounters(events, plan, admission);
      },
      summaryRecord: { present: true, matching: true, extra: false },
    });
    const recordRow = input.manifest.file_inventory.find(({ path }) => path === "summaries/records/summary_limit_projection_s41.json")!;
    const result = projectRuntimeLimitCountersV04(input);
    expect(result).toMatchObject({
      ok: true,
      value: {
        loop_attempts: 1,
        execution_attempts: 1,
        elapsed_ms: 250,
        tool_calls: 2,
        action_output_bytes: 16,
        control_output_bytes: input.ledger.ledger_byte_length + recordRow.size_bytes!,
        token_count: 10,
        cost_minor_units: 7,
        active_workers: 1,
        task_executions: { [input.validated_plan.plan.tasks[0]!.id]: 1 },
      },
    });
  });

  it("requires genuine matching plan, ledger, and manifest brands with exact raw plan identity", () => {
    const input = genuineProjectionInput();
    expect(projectRuntimeLimitCountersV04({ ...input, validated_plan: { ...input.validated_plan } })).toEqual({
      ok: false, reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
    });
    expect(projectRuntimeLimitCountersV04({ ...input, ledger: { ...input.ledger } })).toEqual({
      ok: false, reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
    });
    expect(projectRuntimeLimitCountersV04({ ...input, manifest: { ...input.manifest } })).toEqual({
      ok: false, reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
    });
    const driftedPlan = validatedPlanV03((plan) => { plan.created_at = "2026-08-26T19:59:59Z"; });
    expect(projectRuntimeLimitCountersV04({ ...input, validated_plan: driftedPlan })).toEqual({
      ok: false, reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
    });
  });

  it("rejects missing, extra, or hash-mismatched committed summary record rows", () => {
    for (const summaryRecord of [
      { present: false, matching: true, extra: false },
      { present: true, matching: true, extra: true },
      { present: true, matching: false, extra: false },
    ] as const) {
      const input = genuineProjectionInput({ summaryRecord });
      expect(projectRuntimeLimitCountersV04(input)).toEqual({
        ok: false, reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
      });
    }
  });

  it("rejects contradictory cumulative task execution history in a genuinely validated ledger", () => {
    const input = genuineProjectionInput({
      mutateEvents(events, plan) {
        appendAdmission(events, plan, 1, 1);
        appendAdmission(events, plan, 2, 1);
      },
    });
    expect(projectRuntimeLimitCountersV04(input)).toEqual({
      ok: false, reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
    });
  });

  it("projects an exact inclusive prefix without comparing against the later ledger head", () => {
    const input = genuineProjectionInput({
      mutateEvents(events, plan) {
        const admission = appendAdmission(events, plan, 1, 1);
        appendTerminalCounters(events, plan, admission);
      },
      summaryRecord: { present: true, matching: true, extra: false },
    });

    const result = projectRuntimeLimitCountersAtPrefixV04({
      ...input,
      prefix_event_ref: ledgerEventRef(input.ledger, "task.action-admitted"),
    });

    expect(result).toMatchObject({
      ok: true,
      value: {
        loop_attempts: 0,
        execution_attempts: 1,
        elapsed_ms: 250,
        tool_calls: 0,
        action_output_bytes: 5,
        control_output_bytes: input.ledger.line_byte_lengths
          .slice(0, ledgerEventRef(input.ledger, "task.action-admitted").ledger_sequence)
          .reduce((total, length) => total + length, 0),
        token_count: 0,
        cost_minor_units: 0,
        active_workers: 1,
        task_executions: { [input.validated_plan.plan.tasks[0]!.id]: 1 },
      },
    });
  });

  it("excludes and then includes compaction record bytes and summary content exactly at the compaction prefix", () => {
    const input = genuineProjectionInput({
      mutateEvents(events, plan) {
        const admission = appendAdmission(events, plan, 1, 1);
        appendTerminalCounters(events, plan, admission);
      },
      summaryRecord: { present: true, matching: true, extra: false },
    });
    const terminalRef = ledgerEventRef(input.ledger, "task.execution-completed");
    const compactionRef = ledgerEventRef(input.ledger, "run.compaction-recorded");
    const recordRow = input.manifest.file_inventory.find(({ path }) => path === "summaries/records/summary_limit_projection_s41.json")!;

    expect(projectRuntimeLimitCountersAtPrefixV04({
      ...input,
      prefix_event_ref: terminalRef,
    })).toMatchObject({
      ok: true,
      value: {
        action_output_bytes: 5,
        control_output_bytes: input.ledger.line_byte_lengths
          .slice(0, terminalRef.ledger_sequence)
          .reduce((total, length) => total + length, 0),
      },
    });

    expect(projectRuntimeLimitCountersAtPrefixV04({
      ...input,
      prefix_event_ref: compactionRef,
    })).toMatchObject({
      ok: true,
      value: {
        action_output_bytes: 16,
        control_output_bytes: input.ledger.line_byte_lengths
          .slice(0, compactionRef.ledger_sequence)
          .reduce((total, length) => total + length, 0) + recordRow.size_bytes!,
      },
    });
  });

  it("fails closed on forged prefix refs and non-exact top-level prefix input", () => {
    const input = genuineProjectionInput({
      mutateEvents(events, plan) {
        const admission = appendAdmission(events, plan, 1, 1);
        appendTerminalCounters(events, plan, admission);
      },
      summaryRecord: { present: true, matching: true, extra: false },
    });
    const forgedRef = ledgerEventRef(input.ledger, "task.execution-completed");

    expect(projectRuntimeLimitCountersAtPrefixV04({
      ...input,
      prefix_event_ref: { ...forgedRef, event_hash: HASH_B },
    })).toEqual({
      ok: false, reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
    });
    expect(projectRuntimeLimitCountersAtPrefixV04({
      ...input,
      prefix_event_ref: { ledger_sequence: input.ledger.events.length + 1, event_hash: forgedRef.event_hash },
    })).toEqual({
      ok: false, reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
    });
    expect(projectRuntimeLimitCountersAtPrefixV04({
      ...input,
      prefix_event_ref: { ...forgedRef, extra: true },
    })).toEqual({
      ok: false, reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
    });
    expect(projectRuntimeLimitCountersAtPrefixV04({
      ...input,
      prefix_event_ref: forgedRef,
      extra: true,
    })).toEqual({
      ok: false, reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
    });
  });

  it("matches the whole-ledger projector when the prefix points at the exact head", () => {
    const input = genuineProjectionInput({
      mutateEvents(events, plan) {
        const admission = appendAdmission(events, plan, 1, 1);
        appendTerminalCounters(events, plan, admission);
      },
      summaryRecord: { present: true, matching: true, extra: false },
    });
    const headRef = eventRef(input.ledger.events.at(-1)!);
    const full = projectRuntimeLimitCountersV04(input);
    const prefix = projectRuntimeLimitCountersAtPrefixV04({
      ...input,
      prefix_event_ref: headRef,
    });

    expect(prefix).toEqual(full);
  });
});

describe("S41-B pure global limit accounting", () => {
  it("keeps run-global attempt and per-task execution totals across recovery attempts", () => {
    const input = structuredClone(accountingInput(planV03()));
    input.consumed.execution_attempts = 2;
    input.consumed.task_executions[input.requested.task_ref] = 0;
    input.requested.execution_attempts = 1;
    input.requested.task_executions = 1;

    const result = evaluateRuntimeLimitAccountingV04(input);
    expect(result).toMatchObject({
      ok: true,
      value: {
        admitted: true,
        prospective: { execution_attempts: 3, requested_task_executions: 1 },
      },
    });
  });

  it("preserves recovery and control output reserves for work, then unlocks only recovery reserve", () => {
    const plan = planV03({ recovery: { elapsed: 500, tools: 2, output: 1_000 } });
    const work = structuredClone(accountingInput(plan));
    const workCeiling = plan.limit_policy.max_output_bytes
      - plan.limit_policy.control_plane_output_reserve_bytes
      - plan.recovery_policy.reserve.max_output_bytes;
    work.consumed.action_output_bytes = workCeiling - 1;
    work.requested.action_output_bytes = 1;
    expect(evaluateRuntimeLimitAccountingV04(work)).toMatchObject({
      ok: true,
      value: { admitted: true, ceilings: { action_output_bytes: workCeiling } },
    });
    work.requested.action_output_bytes = 2;
    expect(evaluateRuntimeLimitAccountingV04(work)).toMatchObject({
      ok: true,
      value: { admitted: false, violations: [{ limit_ref: "max-output-bytes" }] },
    });

    const compensation = structuredClone(accountingInput(plan, "compensation"));
    compensation.consumed.action_output_bytes = workCeiling;
    compensation.requested.action_output_bytes = 1_000;
    expect(evaluateRuntimeLimitAccountingV04(compensation)).toMatchObject({
      ok: true,
      value: {
        admitted: true,
        ceilings: {
          action_output_bytes: plan.limit_policy.max_output_bytes
            - plan.limit_policy.control_plane_output_reserve_bytes,
        },
      },
    });
  });

  it("enforces the separate control bucket, process runtime, worker, elapsed, tool, token, and cost ceilings", () => {
    const plan = planV03({
      tokens: 100,
      cost: 100,
      recovery: { elapsed: 500, tools: 2, output: 1_000, tokens: 10, cost: 10 },
    });
    const input = structuredClone(accountingInput(plan));
    input.consumed.elapsed_ms = plan.limit_policy.max_elapsed_ms - 500;
    input.consumed.tool_calls = plan.limit_policy.max_tool_calls - 2;
    input.consumed.control_output_bytes = plan.limit_policy.control_plane_output_reserve_bytes;
    input.consumed.token_count = 90;
    input.consumed.cost_minor_units = 90;
    input.requested.elapsed_ms = 1;
    input.requested.tool_calls = 1;
    input.requested.control_output_bytes = 1;
    input.requested.token_count = 1;
    input.requested.cost_minor_units = 1;
    input.requested.workers = 2;
    input.requested.process_runtime_ms = plan.runtime_execution_policy.max_process_runtime_ms + 1;

    const result = evaluateRuntimeLimitAccountingV04(input);
    expect(result).toMatchObject({
      ok: true,
      value: {
        admitted: false,
        violations: [
          { limit_ref: "max-cost" },
          { limit_ref: "max-elapsed-ms" },
          { limit_ref: "max-output-bytes" },
          { limit_ref: "max-process-runtime" },
          { limit_ref: "max-tokens" },
          { limit_ref: "max-tool-calls" },
          { limit_ref: "max-workers" },
        ],
      },
    });
  });

  it("uses the retry-policy maximum for the requested task and fails closed on unsafe arithmetic", () => {
    const plan = planV03();
    const atTaskCeiling = structuredClone(accountingInput(plan));
    atTaskCeiling.consumed.task_executions[atTaskCeiling.requested.task_ref] = 1;
    atTaskCeiling.requested.task_executions = 1;
    expect(evaluateRuntimeLimitAccountingV04(atTaskCeiling)).toMatchObject({
      ok: true,
      value: { admitted: false, requested_task_executions_exhausted: true },
    });

    const overflow = structuredClone(accountingInput(plan));
    overflow.consumed.action_output_bytes = Number.MAX_SAFE_INTEGER;
    overflow.requested.action_output_bytes = 1;
    expect(evaluateRuntimeLimitAccountingV04(overflow)).toEqual({
      ok: false,
      reason: "INVALID_RUNTIME_LIMIT_ACCOUNTING",
    });
  });

  it("admits a request landing exactly at a ceiling while reporting zero future headroom", () => {
    const plan = planV03();
    const input = structuredClone(accountingInput(plan));
    input.consumed.execution_attempts = plan.runtime_execution_policy.max_execution_attempts - 1;
    input.requested.execution_attempts = 1;
    input.consumed.action_output_bytes = plan.limit_policy.max_output_bytes
      - plan.limit_policy.control_plane_output_reserve_bytes - 1;
    input.requested.action_output_bytes = 1;

    const result = evaluateRuntimeLimitAccountingV04(input);
    expect(result).toMatchObject({
      ok: true,
      value: {
        admitted: true,
        execution_attempts_exhausted: true,
        exhausted_limit_refs: ["max-output-bytes"],
        remaining: { execution_attempts: 0, action_output_bytes: 0 },
      },
    });
    if (!result.ok) return;
    expect(Object.isFrozen(result.value)).toBe(true);
    expect(Object.isFrozen(result.value.remaining)).toBe(true);
    expect(result.value.violations.every(({ limit_ref }) => [
      "max-loop-attempts", "max-elapsed-ms", "max-tool-calls", "max-output-bytes",
      "max-tokens", "max-cost", "max-process-runtime", "max-workers",
    ].includes(limit_ref))).toBe(true);
  });
});

describe("S41-B replay-stable retry jitter", () => {
  it.each([
    [{
      run_id: "run_s41_retry",
      task_ref: "task_s41_retry",
      failure_event_ref: { ledger_sequence: 17, event_hash: HASH_A },
      failure_ordinal: 2,
      rule: { retryable: true, backoff: "exponential", base_delay_ms: 50, max_delay_ms: 1_000 },
    }, "sha256:d492cdc9c0cf077aafa5680a52f177f3630a7594d094c831e24168dba282cf3c", 100, 20, -18, 82],
    [{
      run_id: "run_s41_retry",
      task_ref: "task_s41_retry",
      failure_event_ref: { ledger_sequence: 18, event_hash: HASH_B },
      failure_ordinal: 3,
      rule: { retryable: true, backoff: "fixed", base_delay_ms: 250, max_delay_ms: 250 },
    }, "sha256:863cd9687589f0fe1ce35f16981c5e023cde18e0c89251b1a0cc120b50473a95", 250, 50, -7, 243],
    [{
      run_id: "run_s41_other",
      task_ref: "task_s41_retry",
      failure_event_ref: { ledger_sequence: 4, event_hash: HASH_C },
      failure_ordinal: 1,
      rule: { retryable: true, backoff: "exponential", base_delay_ms: 1, max_delay_ms: 10 },
    }, "sha256:eb48fc8f92d35045fc9ab9cf747bedaecd7f8ddc5d9d4a880b5fbc73b23612ae", 1, 0, 0, 1],
  ] as const)("matches frozen vector %#", (input, digest, deterministic, window, jitter, scheduled) => {
    expect(scheduleRuntimeRetryV04(input)).toEqual({
      ok: true,
      value: {
        identity_hash: digest,
        deterministic_backoff_ms: deterministic,
        jitter_window_ms: window,
        signed_jitter_ms: jitter,
        scheduled_delay_ms: scheduled,
      },
    });
  });

  it("returns exact zero delay for non-retryable and none rules, and rejects invalid fixed rules", () => {
    const base = {
      run_id: "run_s41_retry",
      task_ref: "task_s41_retry",
      failure_event_ref: { ledger_sequence: 17, event_hash: HASH_A },
      failure_ordinal: 2,
    } as const;
    expect(scheduleRuntimeRetryV04({
      ...base,
      rule: { retryable: false, backoff: "none", base_delay_ms: 0, max_delay_ms: 0 },
    })).toMatchObject({
      ok: true,
      value: { deterministic_backoff_ms: 0, jitter_window_ms: 0, signed_jitter_ms: 0, scheduled_delay_ms: 0 },
    });
    expect(scheduleRuntimeRetryV04({
      ...base,
      rule: { retryable: true, backoff: "fixed", base_delay_ms: 10, max_delay_ms: 11 },
    })).toEqual({ ok: false, reason: "INVALID_RUNTIME_RETRY_SCHEDULE" });
    expect(scheduleRuntimeRetryV04({
      ...base,
      task_ref: "diagnose-root-cause",
      rule: { retryable: false, backoff: "none", base_delay_ms: 0, max_delay_ms: 0 },
    })).toMatchObject({ ok: true, value: { scheduled_delay_ms: 0 } });
    expect(scheduleRuntimeRetryV04({
      ...base,
      task_ref: "Not canonical",
      rule: { retryable: false, backoff: "none", base_delay_ms: 0, max_delay_ms: 0 },
    })).toEqual({ ok: false, reason: "INVALID_RUNTIME_RETRY_SCHEDULE" });
  });
});
