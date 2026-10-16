import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import { inspectRuntimePlanV03, projectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import { deriveProgressV02ForRuntime } from "../../src/run/progress-evaluator.js";
import { inspectRuntimeLedgerV04, type ValidatedRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import { buildRunManifestV04, inspectRunManifestV04, type ValidatedRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import { projectRuntimeStatusV04 } from "../../src/run/runtime-status-v04.js";
import { evaluateRuntimeLimitAccountingV04 } from "../../src/run/runtime-limit-accounting-v04.js";
import { inspectRuntimeSummaryV04, SUMMARY_INVALIDATION_RULES_V04 } from "../../src/run/runtime-summary-v04.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";

const REGISTRY = captureRuntimeProfileRegistryV03();
const UTF8 = new TextEncoder();
const H = (character: string) => `sha256:${character.repeat(64)}`;
const INVENTORY = {
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
const PROPOSAL_BINDINGS = {
  action_proposal_id: "proposal_status_s41_1",
  action_proposal_hash: H("a"),
  action_actor_ref: "actor_status_s41_1",
  action_actor_stable_identity_hash: H("a"),
  on_behalf_of_chain_hash: H("a"),
  repository_root_ref: "repository_status_s41_1",
  repository_base_ref_identity_hash: H("a"),
  repository_pre_state_hash: H("a"),
  authorized_change_set_hash: H("a"),
  normalized_dispatch_hash: H("a"),
  action_scope_hash: H("a"),
  action_class: "task",
  classifier_input_hash: H("a"),
  classifier_registry_hash: H("a"),
  classifier_rule_hash: H("a"),
  data_flow_hash: H("a"),
} as const;

function loadPlanV02(): ResolvedRunPlanV02Value {
  return ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
    "utf8",
  )));
}

function validatedPlan(mutator?: (plan: ResolvedRunPlanV02Value) => void) {
  const plan = loadPlanV02();
  mutator?.(plan);
  const projected = projectRuntimePlanV03(plan, REGISTRY);
  if (!projected.ok) throw new Error(projected.reason);
  const inspected = inspectRuntimePlanV03(UTF8.encode(JSON.stringify(projected.value)));
  if (!inspected.ok) throw new Error(inspected.reason);
  return inspected.validated_plan;
}

function ref(event: RuntimeEventV04Value) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function append(
  events: RuntimeEventV04Value[],
  runId: string,
  eventType: RuntimeEventV04Value["event_type"],
  source: RuntimeEventV04Value["source"],
  authorityRef: string | null,
  payload: unknown,
) {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_status_s41_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T12:00:${String(sequence).padStart(2, "0")}Z`,
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null,
    payload,
  };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

function actionAdmission(events: RuntimeEventV04Value[], plan = validatedPlan()) {
  const attempt = events.findLast((event) => event.event_type === "execution.attempt-started");
  if (attempt === undefined) throw new Error("missing attempt");
  return append(events, plan.run_id, "task.action-admitted", "policy-enforcement-point", "authority_status_s41", {
    action_id: "action_status_s41_1",
    task_ref: plan.plan.tasks[0]!.id,
    lease_id: "action_lease_status_s41_1",
    lease_event_ref: ref(attempt),
    admission_clock_ref: ref(attempt),
    ...PROPOSAL_BINDINGS,
    policy_action_kind: "network-read",
    action_approval_class: "agency",
    execution_ordinal: 1,
    retry_of_failure_ordinal: null,
    fence_epoch: attempt.payload.fence_epoch,
    side_effect_refs: ["effect-status-s41"],
    waiver_gate_use_checks: [],
    task_executions_after: 1,
    action_output_bytes_after: 0,
    attempt_event_ref: ref(attempt),
    parent_run_owner_lease_id: attempt.payload.run_owner_lease_id,
    logical_operation_idempotency_key: H("b"),
    resolved_operation_input_hash: H("c"),
    recovery_policy_hash: attempt.payload.recovery_policy_hash,
    process_runtime_ceiling_ms: plan.plan.runtime_execution_policy.max_process_runtime_ms,
  });
}

function manifestFor(
  ledgerBytes: Uint8Array,
  capturedFiles: readonly Readonly<{
    path: string;
    family: "primary" | "record" | "projection";
    required: boolean;
    mode: 384 | null;
    bytes: Uint8Array | null;
  }>[],
) {
  const built = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-30T12:01:00Z",
    captured_files: capturedFiles,
  });
  if (!built.ok) throw new Error(built.reason);
  const inspected = inspectRunManifestV04({
    manifest_bytes: built.bytes,
    ledger_bytes: ledgerBytes,
    captured_files: capturedFiles,
  });
  if (!inspected.ok) throw new Error(inspected.reason);
  return inspected;
}

type BaseScenarioOptions = Readonly<{
  mutatePlan?: (plan: ResolvedRunPlanV02Value) => void;
  ownerStatus?: "current" | "proven-stale" | "absent" | "ambiguous";
  addPendingResume?: boolean;
  addTerminalSeal?: boolean;
  addQuarantine?: boolean;
  addOutcomeUnknown?: boolean;
  addCompensationPhase?: boolean;
  addProgressPlateau?: boolean;
  highElapsedMs?: number;
}>;

function buildBaseScenario(options: BaseScenarioOptions = {}) {
  const plan = validatedPlan(options.mutatePlan);
  const events: RuntimeEventV04Value[] = [];
  append(events, plan.run_id, "run.initialized", "kernel", null, {
    plan_hash: plan.plan_hash,
    initial_fence_epoch: 0,
    runtime_schema_versions: INVENTORY,
  });
  const started = append(events, plan.run_id, "run.started", "kernel", null, {
    executor_profile_hash: H("1"),
  });
  const ownerClock = append(events, plan.run_id, "run.clock-observed", "kernel", null, {
    clock_id: "clock_run_owner_status_s41",
    observed_at: "2026-08-30T12:00:02Z",
    elapsed_ms: 1,
    reason: "run-owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: "run_owner_status_s41_1",
    attempt_ref: null,
    owner_lease_ref: null,
    boot_id_hash: H("1"),
    monotonic_clock_id: "monotonic_status_s41_1",
  });
  const attempt = append(events, plan.run_id, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_status_s41_1",
    attempt_ordinal: 1,
    mode: "ordinary",
    previous_attempt_event_ref: null,
    resume_request_event_ref: null,
    resume_nonce_hash: null,
    source_boundary_sequence: started.sequence,
    source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("2"),
    repository_state_hash: plan.plan.authority_subject.repository.initial_state.repository_state_hash,
    plan_hash: plan.plan_hash,
    input_hash: plan.plan.runtime_input_hash,
    recovery_policy_hash: plan.plan.runtime_recovery_policy_hash,
    authority_envelope_hash: H("5"),
    run_owner_lease_id: "run_owner_status_s41_1",
    issued_clock_ref: ref(ownerClock),
    deadline_elapsed_ms: 1_000,
    boot_id_hash: H("1"),
    monotonic_clock_id: "monotonic_status_s41_1",
    previous_fence_epoch: 0,
    fence_epoch: 0,
  });

  if (options.highElapsedMs !== undefined) {
    append(events, plan.run_id, "run.clock-observed", "kernel", null, {
      clock_id: "clock_elapsed_status_s41",
      observed_at: "2026-08-30T12:00:03Z",
      elapsed_ms: options.highElapsedMs,
      reason: "stale-owner-check",
      task_ref: null,
      failure_ordinal: null,
      use_ref: "run_owner_status_s41_1",
      attempt_ref: ref(attempt),
      owner_lease_ref: ref(attempt),
      boot_id_hash: H("1"),
      monotonic_clock_id: "monotonic_status_s41_1",
    });
  }

  let admission: RuntimeEventV04Value | null = null;
  if (options.addOutcomeUnknown) {
    admission = actionAdmission(events, plan);
    append(events, plan.run_id, "task.action-outcome-unknown", "adapter", null, {
      action_id: admission.payload.action_id,
      task_ref: admission.payload.task_ref,
      admission_ref: ref(admission),
      detection_reason: "process-status-unavailable",
      observation_ref: ref(ownerClock),
      evidence_refs: [ref(ownerClock)],
    });
  }

  if (options.addProgressPlateau) {
    const attemptRef = ref(attempt);
    for (let ordinal = 1; ordinal <= 3; ordinal += 1) {
      const observation = append(events, plan.run_id, "task.progress-observed", "evaluator", null, {
        observation_ref: plan.plan.progress.observations[0]!.id,
        task_ref: null,
        pending_attempt_ordinal: ordinal,
        sample: {
          status: "source-present",
          sample_ref: {
            record_kind: "evaluation-result",
            record_id: `evaluation_status_s41_${ordinal}`,
            record_event_ref: attemptRef,
          },
          sample_hash: H("6"),
          value_status: "parseable",
          sample_value: false,
        },
      });
      append(events, plan.run_id, "loop.attempt-completed", "kernel", null, {
        attempt_ordinal: ordinal,
        previous_attempt_event_ref: null,
        prefix_sequence: observation.sequence,
        prefix_head_hash: observation.event_hash,
        work_action_refs: [],
        progress_observation_refs: [ref(observation)],
      });
    }
  }

  let compensationPhase: RuntimeEventV04Value | null = null;
  if (options.addCompensationPhase) {
    const freeze = append(events, plan.run_id, "run.terminal-freeze-entered", "evaluator", null, {
      revision: 1,
      candidate: "failed",
      candidate_evidence_refs: [ref(attempt)],
      fence_epoch: 0,
    });
    compensationPhase = append(events, plan.run_id, "run.compensation-phase-entered", "evaluator", null, {
      request_revision: 1,
      request_event_hash: freeze.event_hash,
      pending_terminal: "failed",
      compensation_refs: ["compensation-status-s41"],
      freeze_event_hash: freeze.event_hash,
    });
  }

  if (options.addPendingResume) {
    const requestClock = append(events, plan.run_id, "run.clock-observed", "kernel", null, {
      clock_id: "clock_resume_status_s41",
      observed_at: "2026-08-30T12:00:04Z",
      elapsed_ms: 400,
      reason: "recovery-request",
      task_ref: null,
      failure_ordinal: null,
      use_ref: "request_status_s41_1",
      attempt_ref: ref(attempt),
      owner_lease_ref: ref(attempt),
      boot_id_hash: null,
      monotonic_clock_id: null,
    });
    append(events, plan.run_id, "recovery.resume-requested", "operator", "authority_resume_status_s41", {
      request_id: "request_status_s41_1",
      mode: compensationPhase === null ? "ordinary" : "compensation-continuation",
      resume_nonce_hash: H("7"),
      previous_attempt_event_ref: ref(attempt),
      source_boundary_sequence: requestClock.sequence,
      source_boundary_head_hash: requestClock.event_hash,
      source_manifest_hash: H("8"),
      repository_state_hash: plan.plan.authority_subject.repository.initial_state.repository_state_hash,
      plan_hash: plan.plan_hash,
      input_hash: plan.plan.runtime_input_hash,
      recovery_policy_hash: plan.plan.runtime_recovery_policy_hash,
      authority_envelope_hash: H("5"),
      request_clock_ref: ref(requestClock),
      target_action_admission_ref: null,
      compensation_phase_event_ref: compensationPhase === null ? null : ref(compensationPhase),
    });
  }

  if (options.addQuarantine) {
    const rejected = append(events, plan.run_id, "integrity.observation-rejected", "integrity", null, {
      reason_code: "capture-gap",
      observation_hash: H("9"),
      adapter_invocation_id: "adapter_status_s41",
      claimed_action_id: null,
    });
    append(events, plan.run_id, "run.quarantined", "integrity", null, {
      reason_code: "capture-gap",
      evidence_refs: [ref(rejected)],
    });
  }

  if (options.addTerminalSeal) {
    const freeze = append(events, plan.run_id, "run.terminal-freeze-entered", "evaluator", null, {
      revision: 1,
      candidate: "completed",
      candidate_evidence_refs: [ref(attempt)],
      fence_epoch: 0,
    });
    append(events, plan.run_id, "run.terminal-sealed", "evaluator", null, {
      outcome: "completed",
      pre_seal_ledger_sequence: freeze.sequence,
      pre_seal_ledger_head_hash: freeze.event_hash,
      pre_seal_snapshot_hash: H("d"),
      previous_fence_epoch: 0,
      fence_epoch: 1,
    });
  }

  const ledgerBytes = UTF8.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const inspectedLedger = inspectRuntimeLedgerV04(ledgerBytes);
  if (!inspectedLedger.ok) throw new Error(`${inspectedLedger.reason}: ${JSON.stringify(inspectedLedger.issues)}`);
  const inspectedManifest = manifestFor(ledgerBytes, [
    { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes },
  ]);
  const ownerStatus = options.ownerStatus === "current"
    ? { status: "current" as const, owner_lease_event_ref: ref(attempt), evidence_refs: [ref(ownerClock)] }
    : options.ownerStatus === "absent"
      ? { status: "absent" as const, evidence_refs: [] as const }
      : options.ownerStatus === "ambiguous"
        ? { status: "ambiguous" as const, ambiguous_reason: "heartbeat-at-deadline" as const, owner_lease_event_ref: ref(attempt), evidence_refs: [ref(ownerClock)] }
        : { status: "proven-stale" as const, stale_reason: "same-domain-deadline-reached" as const, owner_lease_event_ref: ref(attempt), evidence_refs: [ref(ownerClock)] };
  return {
    plan,
    ledger: inspectedManifest.ledger,
    manifest: inspectedManifest.validated_manifest,
    ownerStatus,
  };
}

function buildSummaryScenario(appendLaterEvent: boolean | "sealed" | "quarantined") {
  const plan = validatedPlan();
  const events: RuntimeEventV04Value[] = [];
  append(events, plan.run_id, "run.initialized", "kernel", null, {
    plan_hash: plan.plan_hash,
    initial_fence_epoch: 0,
    runtime_schema_versions: INVENTORY,
  });
  const started = append(events, plan.run_id, "run.started", "kernel", null, { executor_profile_hash: H("1") });
  const ownerClock = append(events, plan.run_id, "run.clock-observed", "kernel", null, {
    clock_id: "clock_run_owner_summary_status_s41",
    observed_at: "2026-08-30T12:00:02Z",
    elapsed_ms: 1,
    reason: "run-owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: "run_owner_summary_status_s41_1",
    attempt_ref: null,
    owner_lease_ref: null,
    boot_id_hash: H("1"),
    monotonic_clock_id: "mono_summary_status_s41_1",
  });
  const attempt = append(events, plan.run_id, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_summary_status_s41_1",
    attempt_ordinal: 1,
    mode: "ordinary",
    previous_attempt_event_ref: null,
    resume_request_event_ref: null,
    resume_nonce_hash: null,
    source_boundary_sequence: started.sequence,
    source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("2"),
    repository_state_hash: plan.plan.authority_subject.repository.initial_state.repository_state_hash,
    plan_hash: plan.plan_hash,
    input_hash: plan.plan.runtime_input_hash,
    recovery_policy_hash: plan.plan.runtime_recovery_policy_hash,
    authority_envelope_hash: H("5"),
    run_owner_lease_id: "run_owner_summary_status_s41_1",
    issued_clock_ref: ref(ownerClock),
    deadline_elapsed_ms: 1_000,
    boot_id_hash: H("1"),
    monotonic_clock_id: "mono_summary_status_s41_1",
    previous_fence_epoch: 0,
    fence_epoch: 0,
  });
  const integratorClock = append(events, plan.run_id, "run.clock-observed", "kernel", null, {
    clock_id: "clock_integrator_summary_status_s41",
    observed_at: "2026-08-30T12:00:03Z",
    elapsed_ms: 10,
    reason: "owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: "integrator_summary_status_s41_1",
    attempt_ref: ref(attempt),
    owner_lease_ref: ref(attempt),
    boot_id_hash: H("1"),
    monotonic_clock_id: "mono_summary_status_s41_1",
  });
  const integrator = append(events, plan.run_id, "ownership.lease-acquired", "policy-enforcement-point", "authority_summary_status_s41", {
    owner_lease_id: "integrator_summary_status_s41_1",
    scope: "integrator",
    scope_ref: "summary_status_s41_1",
    parent_run_owner_lease_id: "run_owner_summary_status_s41_1",
    attempt_event_ref: ref(attempt),
    issued_clock_ref: ref(integratorClock),
    deadline_elapsed_ms: 999,
    boot_id_hash: H("1"),
    monotonic_clock_id: "mono_summary_status_s41_1",
    fence_epoch: 0,
    heartbeat_limit: 2,
  });
  const sourceLedgerBytes = UTF8.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const accounting = evaluateRuntimeLimitAccountingV04({
    plan: plan.plan,
    phase: "work",
    consumed: {
      loop_attempts: 0,
      execution_attempts: 1,
      task_executions: Object.fromEntries(plan.plan.tasks.map((task) => [task.id, 0])),
      elapsed_ms: 10,
      tool_calls: 0,
      action_output_bytes: 0,
      control_output_bytes: sourceLedgerBytes.byteLength,
      token_count: 0,
      cost_minor_units: 0,
      active_workers: 0,
    },
    requested: {
      task_ref: null,
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
  });
  if (!accounting.ok) throw new Error(accounting.reason);
  const contentBytes = new Uint8Array(16).fill(120);
  const preimage = {
    schema_version: "0.1",
    summary_id: "summary_status_s41_1",
    run_id: plan.run_id,
    attempt_id: attempt.payload.attempt_id,
    plan_hash: plan.plan_hash,
    input_hash: attempt.payload.input_hash,
    recovery_policy_hash: attempt.payload.recovery_policy_hash,
    authority_envelope_hash: attempt.payload.authority_envelope_hash,
    producer_ref: ref(integrator),
    source_first_event_ref: ref(events[0]!),
    source_last_event_ref: ref(integrator),
    source_prefix_sequence: integrator.sequence,
    source_prefix_head_hash: integrator.event_hash,
    lossiness_class: "lossless",
    retained_budget_state: {
      remaining_elapsed_ms: accounting.value.remaining.elapsed_ms,
      remaining_tool_calls: accounting.value.remaining.tool_calls,
      remaining_action_output_bytes: accounting.value.remaining.action_output_bytes,
      remaining_control_output_bytes: accounting.value.remaining.control_output_bytes,
      remaining_tokens: accounting.value.remaining.token_count,
      remaining_cost_minor_units: accounting.value.remaining.cost_minor_units,
      remaining_workers: accounting.value.remaining.workers,
    },
    retained_counter_state: {
      loop_attempts_after: 0,
      execution_attempts_after: 1,
      per_task_executions_after: plan.plan.tasks.map((task) => task.id).sort().map((task_ref) => ({
        task_ref,
        task_executions_after: 0,
      })),
      action_output_bytes_after: 0,
      control_output_bytes_after: sourceLedgerBytes.byteLength,
      tool_calls_after: 0,
      tokens_after: 0,
      cost_minor_units_after: 0,
      active_workers_after: 0,
    },
    fence_epoch: 0,
    resume_boundary: {
      source_boundary_sequence: started.sequence,
      source_boundary_head_hash: started.event_hash,
      source_manifest_hash: H("2"),
      attempt_event_ref: ref(attempt),
      fence_epoch: 0,
    },
    invalidation_rules: SUMMARY_INVALIDATION_RULES_V04,
    content_path: "summaries/content/summary_status_s41_1.bin",
    content_hash: hashRawBytes(contentBytes),
    content_size_bytes: contentBytes.byteLength,
  };
  const record = { ...preimage, record_hash: hashCanonical(preimage) };
  const recordBytes = UTF8.encode(JSON.stringify(record));
  const preContextHash = hashCanonical({
    purpose: "runtime-context-root-v01",
    schema_version: "0.1",
    run_id: plan.run_id,
    plan_hash: plan.plan_hash,
    runtime_input_hash: plan.plan.runtime_input_hash,
    context_snapshot: plan.plan.context_snapshot,
  });
  const postContextHash = hashCanonical({
    purpose: "runtime-context-compaction-v01",
    schema_version: "0.1",
    run_id: plan.run_id,
    plan_hash: plan.plan_hash,
    pre_context_hash: preContextHash,
    summary_id: record.summary_id,
    summary_record_hash: hashRawBytes(recordBytes),
    summary_content_hash: record.content_hash,
    source_first_event_ref: record.source_first_event_ref,
    source_last_event_ref: record.source_last_event_ref,
    source_prefix_sequence: record.source_prefix_sequence,
    source_prefix_head_hash: record.source_prefix_head_hash,
  });
  const compaction = append(events, plan.run_id, "run.compaction-recorded", "kernel", null, {
    summary_id: record.summary_id,
    summary_record_path: `summaries/records/${record.summary_id}.json`,
    summary_record_hash: hashRawBytes(recordBytes),
    summary_content_path: record.content_path,
    summary_content_hash: record.content_hash,
    summary_size_bytes: record.content_size_bytes,
    attempt_event_ref: ref(attempt),
    integrator_lease_event_ref: ref(integrator),
    source_first_event_ref: record.source_first_event_ref,
    source_last_event_ref: record.source_last_event_ref,
    source_prefix_sequence: record.source_prefix_sequence,
    source_prefix_head_hash: record.source_prefix_head_hash,
    pre_context_hash: preContextHash,
    post_context_hash: postContextHash,
  });
  if (appendLaterEvent === true) {
    append(events, plan.run_id, "run.clock-observed", "kernel", null, {
      clock_id: "clock_summary_status_s41_later",
      observed_at: "2026-08-30T12:00:04Z",
      elapsed_ms: 11,
      reason: "owner-heartbeat",
      task_ref: null,
      failure_ordinal: null,
      use_ref: "integrator_summary_status_s41_1",
      attempt_ref: ref(attempt),
      owner_lease_ref: ref(integrator),
      boot_id_hash: H("1"),
      monotonic_clock_id: "mono_summary_status_s41_1",
    });
  }
  if (appendLaterEvent === "sealed") {
    const freeze = append(events, plan.run_id, "run.terminal-freeze-entered", "evaluator", null, {
      revision: 1,
      candidate: "failed",
      candidate_evidence_refs: [ref(compaction)],
      fence_epoch: 0,
    });
    append(events, plan.run_id, "run.terminal-sealed", "evaluator", null, {
      outcome: "failed",
      pre_seal_ledger_sequence: freeze.sequence,
      pre_seal_ledger_head_hash: freeze.event_hash,
      pre_seal_snapshot_hash: H("8"),
      previous_fence_epoch: 0,
      fence_epoch: 1,
    });
  }
  if (appendLaterEvent === "quarantined") {
    const rejected = append(events, plan.run_id, "integrity.observation-rejected", "integrity", null, {
      reason_code: "capture-gap",
      observation_hash: H("9"),
      adapter_invocation_id: "adapter_summary_status_s41",
      claimed_action_id: null,
    });
    append(events, plan.run_id, "run.quarantined", "integrity", null, {
      reason_code: "capture-gap",
      evidence_refs: [ref(rejected)],
    });
  }
  const ledgerBytes = UTF8.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const inspectedLedger = inspectRuntimeLedgerV04(ledgerBytes);
  if (!inspectedLedger.ok) throw new Error(inspectedLedger.reason);
  const inspectedManifest = manifestFor(ledgerBytes, [
    { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes },
    { path: "summaries/content/summary_status_s41_1.bin", family: "record", required: true, mode: 384, bytes: contentBytes },
    { path: "summaries/records/summary_status_s41_1.json", family: "record", required: true, mode: 384, bytes: recordBytes },
  ]);
  const inspectedSummary = inspectRuntimeSummaryV04({
    ledger: inspectedManifest.ledger,
    manifest: inspectedManifest.validated_manifest,
    compaction_event_ref: ref(compaction),
  });
  if (!inspectedSummary.ok) throw new Error(inspectedSummary.reason);
  return {
    plan,
    ledger: inspectedManifest.ledger,
    manifest: inspectedManifest.validated_manifest,
    summary: inspectedSummary.inspected_summary,
    ownerStatus: { status: "proven-stale" as const, stale_reason: "same-domain-deadline-reached" as const, owner_lease_event_ref: ref(attempt), evidence_refs: [ref(ownerClock)] },
  };
}

describe("S41-D projectRuntimeStatusV04", () => {
  it("projects the normal recovery-ready status truthfully and freezes the output", () => {
    const scenario = buildBaseScenario({ ownerStatus: "proven-stale" });
    const result = projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: null,
    });
    expect(result).toMatchObject({ ok: true });
    if (!result.ok) return;
    expect(result.status.run).toMatchObject({ state: "running", phase: "work" });
    expect(result.status.attempt).toMatchObject({ current_attempt_ordinal: 1 });
    expect(result.status.attempt.history).toHaveLength(1);
    expect(result.status.summary).toEqual({ status: "absent" });
    expect(result.status.next_action).toMatchObject({ disposition: "resume", mode: "ordinary", reason_code: "eligible" });
    expect(Object.isFrozen(result.status)).toBe(true);
    expect(Object.isFrozen(result.status.attempt.history)).toBe(true);
    expect(Object.isFrozen(result.status.limits.counters)).toBe(true);
  });

  it("reports the sealed terminal state and refuses further recovery", () => {
    const scenario = buildBaseScenario({ ownerStatus: "proven-stale", addTerminalSeal: true });
    const result = projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: null,
    });
    expect(result).toMatchObject({
      ok: true,
      status: {
        run: { state: "sealed", terminal: { sealed: true, outcome: "completed" } },
        next_action: { disposition: "hold", reason_code: "run-terminal-sealed" },
      },
    });
  });

  it("reports quarantine truth and stops with the stable quarantine hold reason", () => {
    const scenario = buildBaseScenario({ ownerStatus: "proven-stale", addQuarantine: true });
    const result = projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: null,
    });
    expect(result).toMatchObject({
      ok: true,
      status: {
        run: { state: "quarantined" },
        next_action: { disposition: "hold", reason_code: "run-quarantined" },
      },
    });
  });

  it("recognizes a durable pending resume request and surfaces the exact next action", () => {
    const scenario = buildBaseScenario({ ownerStatus: "proven-stale", addPendingResume: true });
    const result = projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: null,
    });
    expect(result).toMatchObject({
      ok: true,
      status: {
        next_action: { disposition: "resume-pending", reason_code: "pending-resume-request-valid", mode: "ordinary" },
      },
    });
  });

  it("separates in-flight from outcome-unknown actions and holds until reconciliation proof acquisition is authorized", () => {
    const scenario = buildBaseScenario({ ownerStatus: "proven-stale", addOutcomeUnknown: true });
    const result = projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: null,
    });
    expect(result).toMatchObject({ ok: true });
    if (!result.ok) return;
    expect(result.status.actions.in_flight_action_refs).toHaveLength(1);
    expect(result.status.actions.outcome_unknown_action_refs).toHaveLength(1);
    expect(result.status.next_action).toMatchObject({
      disposition: "hold",
      reason_code: "reconciliation-proof-not-authorized",
      target_action_admission_ref: result.status.actions.outcome_unknown_action_refs[0]!.admission_ref,
    });
  });

  it("reports exhausted reserve-aware limits and surfaces the matching recovery hold reason", () => {
    const scenario = buildBaseScenario({
      ownerStatus: "proven-stale",
      mutatePlan: (plan) => { plan.limit_policy.max_elapsed_ms = 200; },
      highElapsedMs: 300,
    });
    const result = projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: null,
    });
    expect(result).toMatchObject({ ok: true });
    if (!result.ok) return;
    expect(result.status.limits.exhausted_limit_refs).toContain("max-elapsed-ms");
    expect(result.status.next_action).toMatchObject({ disposition: "hold", reason_code: "elapsed-budget-exhausted" });
  });

  it("fails closed on summary drift and reports the stable invalidation reason", () => {
    const scenario = buildSummaryScenario(true);
    const result = projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: scenario.summary,
    });
    expect(result).toMatchObject({
      ok: true,
      status: {
        summary: { status: "invalid", reason: "source-head-mismatch" },
        next_action: { disposition: "hold", reason_code: "source-head-mismatch" },
      },
    });
  });

  it("reports a genuine current-head summary as valid", () => {
    const scenario = buildSummaryScenario(false);
    const result = projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: scenario.summary,
    });
    expect(result).toMatchObject({
      ok: true,
      status: { summary: { status: "valid" } },
    });
  });

  it.each([
    ["sealed", "run-terminal-sealed"],
    ["quarantined", "run-quarantined"],
  ] as const)("keeps %s truth ahead of an invalid summary diagnostic", (terminalState, reasonCode) => {
    const scenario = buildSummaryScenario(terminalState);
    const result = projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: scenario.summary,
    });
    expect(result).toMatchObject({
      ok: true,
      status: {
        summary: { status: "invalid", reason: "source-head-mismatch" },
        next_action: { disposition: "hold", reason_code: reasonCode },
      },
    });
  });

  it("composes the existing V02 progress derivation and flags a plateau honestly", () => {
    const scenario = buildBaseScenario({ ownerStatus: "proven-stale", addProgressPlateau: true });
    const direct = deriveProgressV02ForRuntime({
      run_id: scenario.ledger.run_id,
      plan_hash: scenario.ledger.plan_hash,
      plan: scenario.plan.plan,
      ledger_sequence: scenario.ledger.sequence,
      ledger_head_hash: scenario.ledger.head_hash,
      completed_loop_attempts: 3,
      observations: scenario.ledger.events.filter((event) => event.event_type === "task.progress-observed"),
      events: scenario.ledger.events,
    } as Parameters<typeof deriveProgressV02ForRuntime>[0]);
    const result = projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: null,
    });
    expect(direct).toMatchObject({ ok: true });
    expect(result).toMatchObject({ ok: true });
    if (!direct.ok || !result.ok) return;
    expect(result.status.progress.evaluation).toEqual(direct.value);
    expect(result.status.progress).toMatchObject({
      stalled: true,
      stalled_observation_refs: ["project-progress"],
    });
  });

  it("rejects forged brands and mismatched ledger-manifest pairs", () => {
    const scenario = buildBaseScenario({ ownerStatus: "proven-stale" });
    expect(projectRuntimeStatusV04({
      validated_plan: { ...scenario.plan },
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      owner_status: scenario.ownerStatus,
      summary: null,
    })).toEqual({ ok: false, reason: "INVALID_RUNTIME_STATUS_INPUT" });

    const other = buildBaseScenario({ ownerStatus: "proven-stale", addTerminalSeal: true });
    expect(projectRuntimeStatusV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: other.manifest,
      owner_status: scenario.ownerStatus,
      summary: null,
    })).toEqual({ ok: false, reason: "INVALID_RUNTIME_STATUS_INPUT" });
  });
});
