import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { inspectRuntimePlanV03, projectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import {
  buildRunManifestV04,
  inspectRunManifestV04,
} from "../../src/run/runtime-manifest-v04.js";
import { inspectRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import {
  planRuntimeRecoveryV04,
  projectRuntimeRecoveryAdviceV04,
  validatePendingRuntimeRecoveryV04,
} from "../../src/run/runtime-recovery-v04.js";
import {
  ResolvedRunPlanV02,
  type ResolvedRunPlanV02Value,
} from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";

const REGISTRY = captureRuntimeProfileRegistryV03();
const E = new TextEncoder();
const H = (c: string) => `sha256:${c.repeat(64)}`;
const inventory = {
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
const proposalBindings = {
  action_proposal_id: "proposal_s41_1",
  action_proposal_hash: H("a"),
  action_actor_ref: "actor_s41_1",
  action_actor_stable_identity_hash: H("a"),
  on_behalf_of_chain_hash: H("a"),
  repository_root_ref: "repository_s41_1",
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

function validatedPlan() {
  const projected = projectRuntimePlanV03(loadPlanV02(), REGISTRY);
  if (!projected.ok) throw new Error(projected.reason);
  const bytes = E.encode(`${JSON.stringify(projected.value, null, 2)}\n`);
  const inspected = inspectRuntimePlanV03(bytes);
  if (!inspected.ok) throw new Error(inspected.reason);
  return inspected.validated_plan;
}

function ref(event: RuntimeEventV04Value) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function append(
  events: RuntimeEventV04Value[],
  runId: string,
  event_type: RuntimeEventV04Value["event_type"],
  source: RuntimeEventV04Value["source"],
  authority_ref: string | null,
  payload: unknown,
) {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_recovery_s41_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T10:00:${String(sequence).padStart(2, "0")}Z`,
    event_type,
    source,
    authority_ref,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null,
    payload,
  };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

type ScenarioOptions = Readonly<{
  planHash?: string;
  inputHash?: string;
  recoveryPolicyHash?: string;
  addUnresolvedAction?: boolean;
  addCompensationPhase?: boolean;
  seal?: boolean;
  quarantine?: boolean;
  pause?: boolean;
  pendingResume?: boolean;
}>;

function buildScenario(options: ScenarioOptions = {}) {
  const plan = validatedPlan();
  const runId = plan.run_id;
  const events: RuntimeEventV04Value[] = [];
  const planHash = options.planHash ?? plan.plan_hash;
  const inputHash = options.inputHash ?? plan.plan.runtime_input_hash;
  const policyHash = options.recoveryPolicyHash ?? plan.plan.runtime_recovery_policy_hash;
  const authorityHash = H("f");

  append(events, runId, "run.initialized", "kernel", null, {
    plan_hash: planHash,
    initial_fence_epoch: 0,
    runtime_schema_versions: inventory,
  });
  const started = append(events, runId, "run.started", "kernel", null, {
    executor_profile_hash: H("b"),
  });
  const runOwnerClock = append(events, runId, "run.clock-observed", "kernel", null, {
    clock_id: "clock_run_owner_recovery_s41",
    observed_at: "2026-08-30T10:00:02Z",
    elapsed_ms: 1,
    reason: "run-owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: "run_owner_recovery_s41_1",
    attempt_ref: null,
    owner_lease_ref: null,
    boot_id_hash: H("1"),
    monotonic_clock_id: "clock_recovery_s41_1",
  });
  const attempt = append(events, runId, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_recovery_s41_1",
    attempt_ordinal: 1,
    mode: "ordinary",
    previous_attempt_event_ref: null,
    resume_request_event_ref: null,
    resume_nonce_hash: null,
    source_boundary_sequence: started.sequence,
    source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("c"),
    plan_hash: planHash,
    input_hash: inputHash,
    recovery_policy_hash: policyHash,
    authority_envelope_hash: authorityHash,
    repository_state_hash: plan.plan.authority_subject.repository.initial_state.repository_state_hash,
    run_owner_lease_id: "run_owner_recovery_s41_1",
    issued_clock_ref: ref(runOwnerClock),
    deadline_elapsed_ms: 1_000,
    boot_id_hash: H("1"),
    monotonic_clock_id: "clock_recovery_s41_1",
    previous_fence_epoch: 0,
    fence_epoch: 0,
  });

  let unresolvedAction: RuntimeEventV04Value | null = null;
  if (options.addUnresolvedAction) {
    unresolvedAction = append(events, runId, "task.action-admitted", "policy-enforcement-point", "authority_s41", {
      action_id: "action_recovery_s41_1",
      task_ref: plan.plan.tasks[0]!.id,
      lease_id: "action_lease_recovery_s41_1",
      lease_event_ref: ref(attempt),
      admission_clock_ref: ref(runOwnerClock),
      ...proposalBindings,
      policy_action_kind: "network-read",
      action_approval_class: "agency",
      execution_ordinal: 1,
      retry_of_failure_ordinal: null,
      fence_epoch: 0,
      side_effect_refs: ["effect-s41"],
      waiver_gate_use_checks: [],
      task_executions_after: 1,
      action_output_bytes_after: 0,
      attempt_event_ref: ref(attempt),
      parent_run_owner_lease_id: attempt.payload.run_owner_lease_id,
      logical_operation_idempotency_key: H("2"),
      resolved_operation_input_hash: H("3"),
      recovery_policy_hash: policyHash,
      process_runtime_ceiling_ms: plan.plan.runtime_execution_policy.max_process_runtime_ms,
    });
  }

  let compensationPhase: RuntimeEventV04Value | null = null;
  if (options.addCompensationPhase) {
    const freeze = append(events, runId, "run.terminal-freeze-entered", "evaluator", null, {
      revision: 1,
      candidate: "failed",
      candidate_evidence_refs: [ref(attempt)],
      fence_epoch: 0,
    });
    compensationPhase = append(events, runId, "run.compensation-phase-entered", "evaluator", null, {
      request_revision: 1,
      request_event_hash: freeze.event_hash,
      pending_terminal: "failed",
      compensation_refs: ["compensation-s41"],
      freeze_event_hash: freeze.event_hash,
    });
  }

  let paused: RuntimeEventV04Value | null = null;
  let pendingResume: RuntimeEventV04Value | null = null;
  if (options.pause) {
    const pauseClock = append(events, runId, "run.clock-observed", "kernel", null, {
      clock_id: "clock_pause_recovery_s41",
      observed_at: "2026-08-30T10:00:03Z",
      elapsed_ms: 300,
      reason: "pause-request",
      task_ref: null,
      failure_ordinal: null,
      use_ref: "pause_recovery_s41_1",
      attempt_ref: ref(attempt),
      owner_lease_ref: ref(attempt),
      boot_id_hash: null,
      monotonic_clock_id: null,
    });
    const pauseRequest = append(events, runId, "control.pause-requested", "operator", "authority_pause_s41", {
      request_id: "pause_recovery_s41_1",
      requested_by: "operator",
      reason_code: "operator-request",
      attempt_event_ref: ref(attempt),
      run_owner_lease_ref: ref(attempt),
      request_clock_ref: ref(pauseClock),
      fence_epoch: 0,
    });
    append(events, runId, "run.fence-advanced", "policy-enforcement-point", "authority_pause_s41", {
      previous_fence_epoch: 0,
      fence_epoch: 1,
      reason: "pause-request",
      evidence_refs: [ref(pauseRequest)],
      attempt_ref: ref(attempt),
      owner_lease_refs: [ref(attempt)],
    });
    paused = append(events, runId, "run.paused", "operator", "authority_pause_s41", {
      requested_by: "operator",
      reason_code: "operator-request",
      request_event_ref: ref(pauseRequest),
      attempt_event_ref: ref(attempt),
      quiescent_boundary_sequence: events.at(-1)!.sequence,
      quiescent_boundary_head_hash: events.at(-1)!.event_hash,
      previous_fence_epoch: 0,
      fence_epoch: 1,
      invalidated_owner_lease_refs: [ref(attempt)],
    });
  }
  if (options.pendingResume) {
    const boundary = paused ?? attempt;
    const resumeClock = append(events, runId, "run.clock-observed", "kernel", null, {
      clock_id: "clock_resume_recovery_s41",
      observed_at: "2026-08-30T10:00:04Z",
      elapsed_ms: 350,
      reason: "recovery-request",
      task_ref: null,
      failure_ordinal: null,
      use_ref: "resume_recovery_s41_1",
      attempt_ref: ref(attempt),
      owner_lease_ref: ref(attempt),
      boot_id_hash: null,
      monotonic_clock_id: null,
    });
    append(events, runId, "run.clock-observed", "kernel", null, {
      clock_id: "clock_resume_run_owner_recovery_s41",
      observed_at: "2026-08-30T10:00:05Z",
      elapsed_ms: 351,
      reason: "run-owner-acquisition",
      task_ref: null,
      failure_ordinal: null,
      use_ref: "run_owner_recovery_s41_2",
      attempt_ref: null,
      owner_lease_ref: null,
      boot_id_hash: H("2"),
      monotonic_clock_id: "clock_recovery_s41_2",
    });
    pendingResume = append(events, runId, "recovery.resume-requested", "operator", "authority_resume_s41", {
      request_id: "resume_recovery_s41_1",
      mode: "ordinary",
      resume_nonce_hash: H("7"),
      previous_attempt_event_ref: ref(attempt),
      source_boundary_sequence: boundary.sequence,
      source_boundary_head_hash: boundary.event_hash,
      source_manifest_hash: H("8"),
      plan_hash: planHash,
      input_hash: inputHash,
      recovery_policy_hash: policyHash,
      authority_envelope_hash: authorityHash,
      repository_state_hash: plan.plan.authority_subject.repository.initial_state.repository_state_hash,
      request_clock_ref: ref(resumeClock),
      target_action_admission_ref: null,
      compensation_phase_event_ref: null,
    });
  }

  if (options.quarantine) {
    const rejected = append(events, runId, "integrity.observation-rejected", "integrity", null, {
      reason_code: "ledger-history-invalid",
      finding: "quarantine-needed",
      evidence_refs: [ref(attempt)],
    });
    append(events, runId, "run.quarantined", "integrity", null, {
      reason_code: "ledger-history-invalid",
      evidence_refs: [ref(rejected)],
    });
  }

  if (options.seal) {
    const freeze = append(events, runId, "run.terminal-freeze-entered", "evaluator", null, {
      revision: 1,
      candidate: "failed",
      candidate_evidence_refs: [ref(attempt)],
      fence_epoch: events.some((event) => event.event_type === "run.paused") ? 1 : 0,
    });
    append(events, runId, "run.terminal-sealed", "evaluator", null, {
      outcome: "failed",
      pre_seal_ledger_sequence: freeze.sequence,
      pre_seal_ledger_head_hash: freeze.event_hash,
      pre_seal_snapshot_hash: H("9"),
      previous_fence_epoch: events.some((event) => event.event_type === "run.paused") ? 1 : 0,
      fence_epoch: events.some((event) => event.event_type === "run.paused") ? 2 : 1,
    });
  }

  const ledgerBytes = E.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const ledgerCheck = inspectRuntimeLedgerV04(ledgerBytes);
  if (!ledgerCheck.ok) throw new Error(`${ledgerCheck.reason}: ${JSON.stringify(ledgerCheck.issues)}`);
  const files = [{ path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes }] as const;
  const built = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-30T10:01:00Z",
    captured_files: files,
  });
  if (!built.ok) throw new Error(built.reason);
  const admitted = inspectRunManifestV04({
    manifest_bytes: built.bytes,
    ledger_bytes: ledgerBytes,
    captured_files: files,
  });
  if (!admitted.ok) throw new Error(admitted.reason);
  return {
    plan,
    ledger: admitted.ledger,
    manifest: admitted.validated_manifest,
    attempt,
    unresolvedAction,
    compensationPhase,
    paused,
    pendingResume,
  };
}

describe("S41-B pure recovery decisions", () => {
  it("refuses recovery when the current attempt input hash drifts from the validated V03 plan", () => {
    const scenario = buildScenario({ inputHash: H("d") });
    const attempt = scenario.ledger.events.find((event) => event.event_type === "execution.attempt-started");
    if (attempt === undefined) throw new Error("missing attempt");

    expect(projectRuntimeRecoveryAdviceV04({
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      plan: scenario.plan,
      owner_status: { status: "proven-stale", stale_reason: "same-domain-deadline-reached", owner_lease_event_ref: ref(attempt), evidence_refs: [ref(attempt)] },
      request: {
        request_id: "request_s41",
        requested_mode: "ordinary",
        resume_nonce_hash: H("6"),
        authority_envelope_hash: H("f"),
        target_action_admission_ref: null,
        compensation_phase_event_ref: null,
      },
      summary: null,
    })).toEqual({
      ok: true,
      decision: { disposition: "refused", precedence: 5, reason_code: "input-hash-drift" },
    });
  });

  it("refuses recovery when the current attempt recovery policy hash drifts from the validated V03 plan", () => {
    const scenario = buildScenario({ recoveryPolicyHash: H("e") });
    const attempt = scenario.ledger.events.find((event) => event.event_type === "execution.attempt-started");
    if (attempt === undefined) throw new Error("missing attempt");

    expect(projectRuntimeRecoveryAdviceV04({
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      plan: scenario.plan,
      owner_status: { status: "proven-stale", stale_reason: "same-domain-deadline-reached", owner_lease_event_ref: ref(attempt), evidence_refs: [ref(attempt)] },
      request: {
        request_id: "request_s41",
        requested_mode: "ordinary",
        resume_nonce_hash: H("6"),
        authority_envelope_hash: H("f"),
        target_action_admission_ref: null,
        compensation_phase_event_ref: null,
      },
      summary: null,
    })).toEqual({
      ok: true,
      decision: { disposition: "refused", precedence: 5, reason_code: "recovery-policy-hash-drift" },
    });
  });

  it("fails closed for unbranded or cross-lineage recovery inputs", () => {
    const base = buildScenario();
    expect(planRuntimeRecoveryV04({
      ledger: base.ledger,
      manifest: base.manifest,
      plan: base.plan,
      owner_status: { status: "absent", evidence_refs: [] },
      request: { request_id: "resume_raw_unauthorized", requested_mode: "ordinary", resume_nonce_hash: H("6"), authority_envelope_hash: H("f"), target_action_admission_ref: null, compensation_phase_event_ref: null },
      summary: null,
    })).toEqual({ ok: false, reason: "INVALID_RUNTIME_RECOVERY_INPUT" });

    expect(projectRuntimeRecoveryAdviceV04({
      ledger: { ...base.ledger },
      manifest: base.manifest,
      plan: base.plan,
      owner_status: { status: "proven-stale", stale_reason: "same-domain-deadline-reached", owner_lease_event_ref: ref(base.attempt), evidence_refs: [ref(base.attempt)] },
      request: { request_id: "resume_recovery_s41_2", requested_mode: "ordinary", resume_nonce_hash: H("6"), authority_envelope_hash: H("f"), target_action_admission_ref: null, compensation_phase_event_ref: null },
      summary: null,
    })).toEqual({ ok: false, reason: "INVALID_RUNTIME_RECOVERY_INPUT" });

    const driftedPlan = buildScenario({ planHash: H("0") });
    expect(projectRuntimeRecoveryAdviceV04({
      ledger: driftedPlan.ledger,
      manifest: driftedPlan.manifest,
      plan: base.plan,
      owner_status: { status: "proven-stale", stale_reason: "same-domain-deadline-reached", owner_lease_event_ref: ref(driftedPlan.attempt), evidence_refs: [ref(driftedPlan.attempt)] },
      request: { request_id: "resume_recovery_s41_2", requested_mode: "ordinary", resume_nonce_hash: H("6"), authority_envelope_hash: H("f"), target_action_admission_ref: null, compensation_phase_event_ref: null },
      summary: null,
    })).toEqual({ ok: false, reason: "INVALID_RUNTIME_RECOVERY_INPUT" });
  });

  it("refuses a sealed source before lower-precedence conditions", () => {
    const sealed = buildScenario({ seal: true });
    expect(projectRuntimeRecoveryAdviceV04({
      ledger: sealed.ledger,
      manifest: sealed.manifest,
      plan: sealed.plan,
      owner_status: { status: "current", owner_lease_event_ref: ref(sealed.attempt), evidence_refs: [ref(sealed.attempt)] },
      request: { request_id: "resume_recovery_s41_2", requested_mode: "ordinary", resume_nonce_hash: H("6"), authority_envelope_hash: H("f"), target_action_admission_ref: null, compensation_phase_event_ref: null },
      summary: null,
    })).toEqual({
      ok: true,
      decision: { disposition: "refused", precedence: 2, reason_code: "run-terminal-sealed" },
    });
  });

  it("refuses a current owner and routes unresolved work only into exact reconciliation", () => {
    const active = buildScenario();
    expect(projectRuntimeRecoveryAdviceV04({
      ledger: active.ledger,
      manifest: active.manifest,
      plan: active.plan,
      owner_status: { status: "current", owner_lease_event_ref: ref(active.attempt), evidence_refs: [ref(active.attempt)] },
      request: { request_id: "resume_recovery_s41_2", requested_mode: "ordinary", resume_nonce_hash: H("6"), authority_envelope_hash: H("f"), target_action_admission_ref: null, compensation_phase_event_ref: null },
      summary: null,
    })).toEqual({
      ok: true,
      decision: { disposition: "refused", precedence: 4, reason_code: "owner-current" },
    });

    const unresolved = buildScenario({ addUnresolvedAction: true });
    expect(projectRuntimeRecoveryAdviceV04({
      ledger: unresolved.ledger,
      manifest: unresolved.manifest,
      plan: unresolved.plan,
      owner_status: { status: "proven-stale", stale_reason: "same-domain-deadline-reached", owner_lease_event_ref: ref(unresolved.attempt), evidence_refs: [ref(unresolved.attempt)] },
      request: { request_id: "resume_recovery_s41_2", requested_mode: "ordinary", resume_nonce_hash: H("6"), authority_envelope_hash: H("f"), target_action_admission_ref: null, compensation_phase_event_ref: null },
      summary: null,
    })).toEqual({
      ok: true,
      decision: { disposition: "refused", precedence: 7, reason_code: "ordinary-blocked-by-unresolved-action" },
    });

    expect(projectRuntimeRecoveryAdviceV04({
      ledger: unresolved.ledger,
      manifest: unresolved.manifest,
      plan: unresolved.plan,
      owner_status: { status: "proven-stale", stale_reason: "same-domain-deadline-reached", owner_lease_event_ref: ref(unresolved.attempt), evidence_refs: [ref(unresolved.attempt)] },
      request: {
        request_id: "resume_recovery_s41_3",
        requested_mode: "reconciliation-only",
        resume_nonce_hash: H("5"),
        authority_envelope_hash: H("f"),
        target_action_admission_ref: ref(unresolved.unresolvedAction!),
        compensation_phase_event_ref: null,
      },
      summary: null,
    })).toEqual({
      ok: true,
      decision: {
        disposition: "refused",
        precedence: 7,
        reason_code: "reconciliation-proof-not-authorized",
      },
    });
  });

  it("requires the exact compensation boundary and projects the exact next request", () => {
    const scenario = buildScenario({ addCompensationPhase: true, pause: true });
    expect(projectRuntimeRecoveryAdviceV04({
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      plan: scenario.plan,
      owner_status: { status: "absent", evidence_refs: [] },
      request: {
        request_id: "resume_recovery_s41_4",
        requested_mode: "compensation-continuation",
        resume_nonce_hash: H("4"),
        authority_envelope_hash: H("f"),
        target_action_admission_ref: null,
        compensation_phase_event_ref: ref(scenario.attempt),
      },
      summary: null,
    })).toEqual({
      ok: true,
      decision: { disposition: "refused", precedence: 7, reason_code: "compensation-boundary-mismatch" },
    });

    expect(projectRuntimeRecoveryAdviceV04({
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      plan: scenario.plan,
      owner_status: { status: "absent", evidence_refs: [] },
      request: {
        request_id: "resume_recovery_s41_5",
        requested_mode: "compensation-continuation",
        resume_nonce_hash: H("3"),
        authority_envelope_hash: H("f"),
        target_action_admission_ref: null,
        compensation_phase_event_ref: ref(scenario.compensationPhase!),
      },
      summary: null,
    })).toMatchObject({
      ok: true,
      decision: {
        disposition: "eligible",
        mode: "compensation-continuation",
        next_attempt_ordinal: 2,
        next_fence_epoch: 2,
        resume_boundary: {
          source_boundary_sequence: scenario.paused!.sequence,
          source_boundary_head_hash: scenario.paused!.event_hash,
          attempt_event_ref: ref(scenario.attempt),
          fence_epoch: 1,
        },
      },
    });
  });

  it("blocks compensation continuation while an admitted action remains unresolved", () => {
    const scenario = buildScenario({ addUnresolvedAction: true, addCompensationPhase: true });
    expect(projectRuntimeRecoveryAdviceV04({
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      plan: scenario.plan,
      owner_status: {
        status: "proven-stale",
        stale_reason: "same-domain-deadline-reached",
        owner_lease_event_ref: ref(scenario.attempt),
        evidence_refs: [ref(scenario.attempt)],
      },
      request: {
        request_id: "resume_recovery_s41_unresolved_compensation",
        requested_mode: "compensation-continuation",
        resume_nonce_hash: H("2"),
        authority_envelope_hash: H("f"),
        target_action_admission_ref: null,
        compensation_phase_event_ref: ref(scenario.compensationPhase!),
      },
      summary: null,
    })).toEqual({
      ok: true,
      decision: {
        disposition: "refused",
        precedence: 7,
        reason_code: "compensation-blocked-by-unresolved-action",
      },
    });
  });

  it("revalidates the exact durable pending request before attempt start", () => {
    const scenario = buildScenario({ pendingResume: true });
    expect(validatePendingRuntimeRecoveryV04({
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      plan: scenario.plan,
      owner_status: { status: "absent", evidence_refs: [] },
      pending_request_event_ref: ref(scenario.pendingResume!),
      summary: null,
    })).toMatchObject({
      ok: true,
      decision: {
        disposition: "eligible",
        mode: "ordinary",
        next_attempt_ordinal: 2,
        next_fence_epoch: 1,
        request_projection: {
          request_id: "resume_recovery_s41_1",
          previous_attempt_event_ref: ref(scenario.attempt),
        },
      },
    });

    expect(validatePendingRuntimeRecoveryV04({
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      plan: scenario.plan,
      owner_status: { status: "absent", evidence_refs: [] },
      pending_request_event_ref: ref(scenario.attempt),
      summary: null,
    })).toEqual({
      ok: true,
      decision: { disposition: "refused", precedence: 4, reason_code: "double-resume" },
    });
  });
});
