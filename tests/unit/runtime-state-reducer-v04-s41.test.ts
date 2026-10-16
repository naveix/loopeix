import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  reduceRuntimeEventPrefixV04,
  type RuntimeStateV04,
} from "../../src/run/runtime-state-reducer-v04.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;

const inventory = {
  resolved_run_plan: "0.3", ledger_event: "0.4", run_manifest: "0.4",
  artifact_manifest: "0.2", redaction_derivative: "0.2", human_authorization_proof: "0.2",
  authority_envelope: "0.2", agency_recommendation: "0.2", authority_revocation: "0.2",
  task_result: "0.2", manual_observation: "0.2", export_decision: "0.2",
  evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2", claim: "0.2",
  finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2", summary_artifact: "0.1",
} as const;

type Source = RuntimeEventV04Value["source"];

function ref(event: RuntimeEventV04Value) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function append(
  events: RuntimeEventV04Value[],
  event_type: RuntimeEventV04Value["event_type"],
  source: Source,
  authority_ref: string | null,
  payload: unknown,
): RuntimeEventV04Value {
  const sequence = events.length + 1;
  const previous = events.at(-1);
  const event = RuntimeEventV04.parse({
    schema_version: "0.4",
    event_id: `event_s41_reducer_${sequence}`,
    run_id: "run_s41_reducer",
    sequence,
    recorded_at: `2026-08-26T21:00:${String(sequence).padStart(2, "0")}Z`,
    event_type,
    source,
    authority_ref,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: previous?.event_hash ?? null,
    event_hash: H(sequence.toString(36)),
    payload,
  });
  events.push(event);
  return event;
}

function initialized(): RuntimeEventV04Value[] {
  const events: RuntimeEventV04Value[] = [];
  append(events, "run.initialized", "kernel", null, {
    plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: inventory,
  });
  return events;
}

function started(): { events: RuntimeEventV04Value[]; start: RuntimeEventV04Value } {
  const events = initialized();
  const start = append(events, "run.started", "kernel", null, { executor_profile_hash: H("b") });
  return { events, start };
}

function attemptPayload(
  startOrBoundary: RuntimeEventV04Value,
  previousAttempt: RuntimeEventV04Value | null,
  request: RuntimeEventV04Value | null,
  ordinal: number,
  previousFence: number,
) {
  const recovery = request?.event_type === "recovery.resume-requested" ? request : null;
  return {
    attempt_id: `attempt_s41_${ordinal}`,
    attempt_ordinal: ordinal,
    mode: recovery?.payload.mode ?? "ordinary",
    previous_attempt_event_ref: previousAttempt === null ? null : ref(previousAttempt),
    resume_request_event_ref: recovery === null ? null : ref(recovery),
    resume_nonce_hash: recovery?.payload.resume_nonce_hash ?? null,
    source_boundary_sequence: recovery?.payload.source_boundary_sequence ?? startOrBoundary.sequence,
    source_boundary_head_hash: recovery?.payload.source_boundary_head_hash ?? startOrBoundary.event_hash,
    source_manifest_hash: recovery?.payload.source_manifest_hash ?? H("c"),
    repository_state_hash: recovery?.payload.repository_state_hash ?? H("1"),
    plan_hash: recovery?.payload.plan_hash ?? H("a"),
    input_hash: recovery?.payload.input_hash ?? H("d"),
    recovery_policy_hash: recovery?.payload.recovery_policy_hash ?? H("e"),
    authority_envelope_hash: recovery?.payload.authority_envelope_hash ?? H("f"),
    run_owner_lease_id: `run_owner_s41_${ordinal}`,
    issued_clock_ref: ref(startOrBoundary),
    deadline_elapsed_ms: 1_000 + ordinal,
    boot_id_hash: H("9"),
    monotonic_clock_id: "monotonic_s41_1",
    previous_fence_epoch: previousFence,
    fence_epoch: ordinal === 1 ? 0 : previousFence + 1,
  };
}

function active(): {
  events: RuntimeEventV04Value[];
  start: RuntimeEventV04Value;
  attempt: RuntimeEventV04Value;
} {
  const { events, start } = started();
  const attempt = append(events, "execution.attempt-started", "kernel", null, attemptPayload(start, null, null, 1, 0));
  return { events, start, attempt };
}

function acquireTaskLease(events: RuntimeEventV04Value[], attempt: RuntimeEventV04Value) {
  if (attempt.event_type !== "execution.attempt-started") throw new TypeError("expected attempt event");
  const clock = append(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_owner_acquire_s41", observed_at: "2026-08-26T21:00:03Z", elapsed_ms: 100,
    reason: "owner-acquisition", task_ref: null, failure_ordinal: null, use_ref: "task_owner_s41_1",
    attempt_ref: ref(attempt), owner_lease_ref: ref(attempt), boot_id_hash: attempt.payload.boot_id_hash,
    monotonic_clock_id: attempt.payload.monotonic_clock_id,
  });
  return append(events, "ownership.lease-acquired", "policy-enforcement-point", "authority_s41", {
    owner_lease_id: "task_owner_s41_1",
    scope: "task",
    scope_ref: "task-s41",
    parent_run_owner_lease_id: attempt.payload.run_owner_lease_id,
    attempt_event_ref: ref(attempt),
    issued_clock_ref: ref(clock),
    deadline_elapsed_ms: attempt.payload.deadline_elapsed_ms - 1,
    boot_id_hash: attempt.payload.boot_id_hash,
    monotonic_clock_id: attempt.payload.monotonic_clock_id,
    fence_epoch: attempt.payload.fence_epoch,
    heartbeat_limit: 3,
  });
}

function requestPause(events: RuntimeEventV04Value[], attempt: RuntimeEventV04Value) {
  if (attempt.event_type !== "execution.attempt-started") throw new TypeError("expected attempt event");
  const clock = append(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_pause_s41", observed_at: "2026-08-26T21:00:04Z", elapsed_ms: 200,
    reason: "pause-request", task_ref: null, failure_ordinal: null, use_ref: "pause_s41_1",
    attempt_ref: ref(attempt), owner_lease_ref: ref(attempt), boot_id_hash: null, monotonic_clock_id: null,
  });
  return append(events, "control.pause-requested", "operator", "authority_pause_s41", {
    request_id: "pause_s41_1", requested_by: "operator", reason_code: "operator-request",
    attempt_event_ref: ref(attempt), run_owner_lease_ref: ref(attempt), request_clock_ref: ref(clock),
    fence_epoch: attempt.payload.fence_epoch,
  });
}

function pause(events: RuntimeEventV04Value[], attempt: RuntimeEventV04Value) {
  const request = requestPause(events, attempt);
  const activeRefs = [ref(attempt)];
  append(events, "run.fence-advanced", "policy-enforcement-point", "authority_pause_s41", {
    previous_fence_epoch: 0, fence_epoch: 1, reason: "pause-request",
    evidence_refs: [ref(request)], attempt_ref: ref(attempt), owner_lease_refs: activeRefs,
  });
  return append(events, "run.paused", "operator", "authority_pause_s41", {
    requested_by: "operator", reason_code: "operator-request", request_event_ref: ref(request),
    attempt_event_ref: ref(attempt), quiescent_boundary_sequence: events.at(-1)!.sequence,
    quiescent_boundary_head_hash: events.at(-1)!.event_hash,
    previous_fence_epoch: 0, fence_epoch: 1, invalidated_owner_lease_refs: activeRefs,
  });
}

function requestResume(
  events: RuntimeEventV04Value[],
  previousAttempt: RuntimeEventV04Value,
  boundary: RuntimeEventV04Value,
  mode: "ordinary" | "reconciliation-only" | "compensation-continuation" = "ordinary",
) {
  const clock = append(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_resume_s41", observed_at: "2026-08-26T21:00:07Z", elapsed_ms: 300,
    reason: "recovery-request", task_ref: null, failure_ordinal: null, use_ref: "resume_s41_1",
    attempt_ref: ref(previousAttempt), owner_lease_ref: ref(previousAttempt), boot_id_hash: null, monotonic_clock_id: null,
  });
  return append(events, "recovery.resume-requested", "operator", "authority_resume_s41", {
    request_id: "resume_s41_1", mode, resume_nonce_hash: H("7"),
    previous_attempt_event_ref: ref(previousAttempt), source_boundary_sequence: boundary.sequence,
    source_boundary_head_hash: boundary.event_hash, source_manifest_hash: H("8"), repository_state_hash: H("1"), plan_hash: H("a"),
    input_hash: H("d"), recovery_policy_hash: H("e"), authority_envelope_hash: H("f"),
    request_clock_ref: ref(clock),
    target_action_admission_ref: mode === "reconciliation-only" ? ref(previousAttempt) : null,
    compensation_phase_event_ref: mode === "compensation-continuation" ? ref(boundary) : null,
  });
}

function recovered(mode: "reconciliation-only" | "compensation-continuation") {
  const { events, attempt } = active();
  const boundary = pause(events, attempt);
  const request = requestResume(events, attempt, boundary, mode);
  const recoveredAttempt = append(events, "execution.attempt-started", "kernel", null,
    attemptPayload(boundary, attempt, request, 2, 1));
  return { events, attempt: recoveredAttempt };
}

const proposalBindings = {
  action_proposal_id: "proposal_s41_1", action_proposal_hash: H("a"), action_actor_ref: "actor_s41_1",
  action_actor_stable_identity_hash: H("a"), on_behalf_of_chain_hash: H("a"),
  repository_root_ref: "repository_s41_1", repository_base_ref_identity_hash: H("a"),
  repository_pre_state_hash: H("a"), authorized_change_set_hash: H("a"), normalized_dispatch_hash: H("a"),
  action_scope_hash: H("a"), action_class: "task", classifier_input_hash: H("a"),
  classifier_registry_hash: H("a"), classifier_rule_hash: H("a"), data_flow_hash: H("a"),
} as const;

const executionBindings = {
  action_proposal_id: proposalBindings.action_proposal_id,
  action_proposal_hash: proposalBindings.action_proposal_hash,
  action_actor_ref: proposalBindings.action_actor_ref,
  action_actor_stable_identity_hash: proposalBindings.action_actor_stable_identity_hash,
  on_behalf_of_chain_hash: proposalBindings.on_behalf_of_chain_hash,
  repository_root_ref: proposalBindings.repository_root_ref,
  repository_base_ref_identity_hash: proposalBindings.repository_base_ref_identity_hash,
  repository_pre_state_hash: proposalBindings.repository_pre_state_hash,
  authorized_change_set_hash: proposalBindings.authorized_change_set_hash,
  normalized_dispatch_hash: proposalBindings.normalized_dispatch_hash,
} as const;

function admitAction(
  events: RuntimeEventV04Value[],
  attempt: RuntimeEventV04Value,
  leaseEvent: RuntimeEventV04Value = attempt,
) {
  if (attempt.event_type !== "execution.attempt-started") throw new TypeError("expected attempt event");
  return append(events, "task.action-admitted", "policy-enforcement-point", "authority_s41", {
    action_id: "action_s41_1", task_ref: "task-s41", lease_id: "action_lease_s41_1",
    lease_event_ref: ref(leaseEvent), admission_clock_ref: ref(attempt), ...proposalBindings,
    policy_action_kind: "network-read", action_approval_class: "agency", execution_ordinal: 1,
    retry_of_failure_ordinal: null, fence_epoch: attempt.payload.fence_epoch,
    side_effect_refs: ["effect-s41"], waiver_gate_use_checks: [], task_executions_after: 1,
    action_output_bytes_after: 0, attempt_event_ref: ref(attempt),
    parent_run_owner_lease_id: attempt.payload.run_owner_lease_id,
    logical_operation_idempotency_key: H("2"), resolved_operation_input_hash: H("3"),
    recovery_policy_hash: H("e"), process_runtime_ceiling_ms: 30_000,
  });
}

function appendNonEntryProof(
  events: RuntimeEventV04Value[],
  attempt: RuntimeEventV04Value,
  admission: RuntimeEventV04Value,
) {
  const acknowledgement = append(events, "task.execution-non-entry-acknowledged", "adapter", null, {
    action_id: "action_s41_1", task_ref: "task-s41", admission_ref: ref(admission),
    attempt_event_ref: ref(attempt), adapter_invocation_id: "invocation_s41_non_entry",
    adapter_ref: "adapter-s41", adapter_version_hash: H("1"), fence_epoch: 0,
    host_identity_hash: H("2"), boot_id_hash: H("3"), unit_name_hash: H("4"),
    cgroup_path_hash: H("5"), acknowledgement_observation_hash: H("6"),
  });
  const termination = append(events, "process.termination-attempted", "adapter", null, {
    trigger: "reconciliation", trigger_event_ref: ref(acknowledgement), action_admission_event_ref: ref(admission),
    adapter_invocation_id: "invocation_s41_non_entry", host_identity_hash: H("2"), boot_id_hash: H("3"),
    unit_name_hash: H("4"), cgroup_path_hash: H("5"), termination_request_hash: H("7"),
    termination_observation_hash: H("8"), observed_outcome: "terminated",
  });
  return append(events, "task.action-outcome-reconciled", "integrity", null, {
    action_id: "action_s41_1", task_ref: "task-s41", admission_ref: ref(admission),
    reconciliation_status: "proven-non-start", attempt_event_ref: ref(attempt),
    adapter_invocation_id: "invocation_s41_non_entry", adapter_ref: "adapter-s41",
    adapter_version_hash: H("1"), non_entry_ack_event_ref: ref(acknowledgement),
    process_cannot_continue_ref: ref(termination), fence_epoch: 0,
  });
}

function appendNonEntrySettlement(events: RuntimeEventV04Value[], reconciliation: RuntimeEventV04Value) {
  const effect = append(events, "effect.outcome", "integrity", null, {
    task_ref: "task-s41", effect_ref: "effect-s41", action_id: "action_s41_1",
    outcome: "not-committed", evidence_refs: [ref(reconciliation)], reconciliation_event_ref: ref(reconciliation),
  });
  const head = { algorithm: "sha1", value: "a".repeat(40) } as const;
  const repositoryStateFields = {
    repository_root_ref: "repository_s41_1", base_ref_identity_hash: H("a"), head, merge_base: head,
    head_state_hash: H("a"), tracked_diff_hash: H("a"), staged_diff_hash: H("a"),
    untracked_content_hash: H("a"), submodule_state_hash: H("a"),
  };
  const repositoryStateHash = hashCanonical({ purpose: "repository-state-v02", ...repositoryStateFields });
  const observedFields = {
    repository_root_ref: "repository_s41_1", base_ref_identity_hash: H("a"),
    repository_pre_state_hash: H("a"), repository_post_state_hash: repositoryStateHash,
    head_before: head, head_after: head, changes: [],
  };
  const observedChangeSetHash = hashCanonical({ purpose: "observed-repository-change-set-v02", ...observedFields });
  append(events, "task.action-settled", "kernel", null, {
    action_id: "action_s41_1", task_ref: "task-s41", terminal_event_ref: ref(reconciliation),
    action_proposal_id: "proposal_s41_1", action_proposal_hash: H("a"), action_actor_ref: "actor_s41_1",
    action_actor_stable_identity_hash: H("a"), on_behalf_of_chain_hash: H("a"),
    repository_root_ref: "repository_s41_1", repository_base_ref_identity_hash: H("a"),
    repository_pre_state_hash: H("a"), authorized_change_set_hash: H("a"), normalized_dispatch_hash: H("a"),
    policy_action_kind: "network-read", action_approval_class: "agency",
    repository_post_state: { ...repositoryStateFields, repository_state_hash: repositoryStateHash },
    repository_post_state_hash: repositoryStateHash,
    observed_change_set: { ...observedFields, observed_change_set_hash: observedChangeSetHash },
    observed_change_set_hash: observedChangeSetHash, repository_transition_status: "authorized-change",
    effect_outcomes: [{ effect_ref: "effect-s41", outcome: "not-committed", outcome_event_ref: ref(effect) }],
  });
}

function success(events: readonly RuntimeEventV04Value[]): RuntimeStateV04 {
  const result = reduceRuntimeEventPrefixV04(events);
  expect(result.ok).toBe(true);
  if (!result.ok) throw new TypeError(result.message);
  return result.state;
}

describe("S41-A V04 pure runtime state reducer", () => {
  it("derives the initial attempt and immutable active run-owner truth", () => {
    const { events, attempt } = active();
    const state = success(events);
    expect(state).toMatchObject({
      state: "running", started: true, current_attempt_ordinal: 1,
      current_fence_epoch: 0, pending_resume_request: null,
      active_run_owner: { owner_lease_id: "run_owner_s41_1", lease_event_ref: ref(attempt), active: true, released: false },
    });
    expect(Object.isFrozen(state)).toBe(true);
    expect(Object.isFrozen(state.active_run_owner)).toBe(true);
  });

  it("keeps a committed recovery request as non-work-admitting pending intent", () => {
    const { events, attempt } = active();
    const boundary = pause(events, attempt);
    const request = requestResume(events, attempt, boundary);
    const pending = success(events);
    expect(pending.pending_resume_request).toMatchObject({ request_id: "resume_s41_1", event_ref: ref(request) });

    acquireTaskLease(events, attempt);
    expect(reduceRuntimeEventPrefixV04(events)).toMatchObject({ ok: false, message: expect.stringContaining("pending recovery request") });
  });

  it("consumes one exact request and nonce for the next ordinal and fence", () => {
    const { events, attempt } = active();
    const boundary = pause(events, attempt);
    const request = requestResume(events, attempt, boundary);
    const recovered = append(events, "execution.attempt-started", "kernel", null,
      attemptPayload(boundary, attempt, request, 2, 1));
    const state = success(events);
    expect(state).toMatchObject({
      state: "running", current_attempt_ordinal: 2, current_attempt_event_ref: ref(recovered),
      current_attempt_mode: "ordinary",
      current_fence_epoch: 2, pending_resume_request: null,
      consumed_resume_request_ids: ["resume_s41_1"], consumed_resume_nonce_hashes: [H("7")],
    });
  });

  it("exposes the current attempt mode and fail-closes reconciliation-only work", () => {
    const allowed = recovered("reconciliation-only");
    append(allowed.events, "run.clock-observed", "kernel", null, {
      clock_id: "clock_reconcile_s41", observed_at: "2026-08-26T21:01:00Z", elapsed_ms: 400,
      reason: "terminal-use", task_ref: null, failure_ordinal: null, use_ref: "reconcile_s41_1",
      attempt_ref: null, owner_lease_ref: null,
      boot_id_hash: null, monotonic_clock_id: null,
    });
    append(allowed.events, "compensation.settled", "evaluator", null, {
      compensation_ref: "compensation-s41", status: "unable", unable_reason: "unknown-action-outcome",
      evidence_refs: [ref(allowed.events.at(-1)!)],
    });
    expect(success(allowed.events).current_attempt_mode).toBe("reconciliation-only");

    const work = recovered("reconciliation-only");
    admitAction(work.events, work.attempt);
    expect(reduceRuntimeEventPrefixV04(work.events)).toMatchObject({
      ok: false,
      message: expect.stringContaining("reconciliation-only"),
    });

    const activeCompensation = recovered("reconciliation-only");
    append(activeCompensation.events, "compensation.settled", "evaluator", null, {
      compensation_ref: "compensation-s41", status: "compensated", unable_reason: null,
      evidence_refs: [ref(activeCompensation.attempt)],
    });
    expect(reduceRuntimeEventPrefixV04(activeCompensation.events)).toMatchObject({
      ok: false,
      message: expect.stringContaining("reconciliation-only"),
    });
  });

  it("permits compensation settlement but rejects ordinary loop work in compensation-continuation", () => {
    const allowed = recovered("compensation-continuation");
    if (allowed.attempt.event_type !== "execution.attempt-started") throw new TypeError("expected attempt event");
    const compensationLease = append(allowed.events, "lease.issued", "policy-enforcement-point", "authority_s41", {
      lease_id: "compensation_lease_s41", task_ref: "task-s41", phase: "compensation",
      compensation_ref: "compensation-s41", ...proposalBindings,
      authority_envelope_ref: ref(allowed.attempt), policy_decision_ref: ref(allowed.attempt),
      policy_action_kind: "network-read", action_approval_class: "agency",
      fence_epoch: allowed.attempt.payload.fence_epoch,
      issued_at: "2026-08-26T21:01:00Z", expires_at: "2026-08-26T21:02:00Z", waiver_gate_refs: [],
      attempt_event_ref: ref(allowed.attempt), parent_run_owner_lease_id: allowed.attempt.payload.run_owner_lease_id,
      logical_operation_idempotency_key: H("2"), resolved_operation_input_hash: H("3"),
      recovery_policy_hash: H("e"), process_runtime_ceiling_ms: 30_000,
    });
    admitAction(allowed.events, allowed.attempt, compensationLease);
    append(allowed.events, "compensation.settled", "evaluator", null, {
      compensation_ref: "compensation-s41", status: "compensated", unable_reason: null,
      evidence_refs: [ref(allowed.attempt)],
    });
    expect(success(allowed.events).current_attempt_mode).toBe("compensation-continuation");

    const ordinary = recovered("compensation-continuation");
    append(ordinary.events, "loop.attempt-completed", "kernel", null, {
      attempt_ordinal: 1, previous_attempt_event_ref: null,
      prefix_sequence: ordinary.attempt.sequence, prefix_head_hash: ordinary.attempt.event_hash,
      work_action_refs: [], progress_observation_refs: [],
    });
    expect(reduceRuntimeEventPrefixV04(ordinary.events)).toMatchObject({
      ok: false,
      message: expect.stringContaining("compensation-continuation"),
    });
  });

  it("rejects skipped ordinals, wrong prior attempts, reused requests, and reused nonces", () => {
    const { events, attempt } = active();
    const boundary = pause(events, attempt);
    const request = requestResume(events, attempt, boundary);
    const bad = attemptPayload(boundary, attempt, request, 3, 1);
    append(events, "execution.attempt-started", "kernel", null, { ...bad, attempt_ordinal: 3 });
    expect(reduceRuntimeEventPrefixV04(events)).toMatchObject({ ok: false, message: expect.stringContaining("ordinal") });
  });

  it("binds subordinate leases to the active attempt, parent, fence, domain, and deadline", () => {
    const { events, attempt } = active();
    const lease = acquireTaskLease(events, attempt);
    const clock = append(events, "run.clock-observed", "kernel", null, {
      clock_id: "clock_owner_heartbeat_s41", observed_at: "2026-08-26T21:00:05Z", elapsed_ms: 999,
      reason: "owner-heartbeat", task_ref: null, failure_ordinal: null, use_ref: "task_owner_s41_1",
      attempt_ref: ref(attempt), owner_lease_ref: ref(lease), boot_id_hash: H("9"), monotonic_clock_id: "monotonic_s41_1",
    });
    append(events, "ownership.lease-heartbeat-recorded", "kernel", null, {
      owner_lease_event_ref: ref(lease), heartbeat_ordinal: 1, observation_clock_ref: ref(clock),
      previous_deadline_elapsed_ms: 1_000, deadline_elapsed_ms: 1_001,
      boot_id_hash: H("9"), monotonic_clock_id: "monotonic_s41_1", fence_epoch: 0,
    });
    const state = success(events);
    expect(state.subordinate_owner_leases).toEqual([
      expect.objectContaining({ owner_lease_id: "task_owner_s41_1", heartbeat_ordinal: 1, deadline_elapsed_ms: 1_001 }),
    ]);

    const duplicate = [...events];
    acquireTaskLease(duplicate, attempt);
    expect(reduceRuntimeEventPrefixV04(duplicate)).toMatchObject({ ok: false, message: expect.stringContaining("unique") });
  });

  it("rejects stale or superseded lease heartbeats and duplicate releases", () => {
    const { events, attempt } = active();
    const lease = acquireTaskLease(events, attempt);
    const releaseClock = append(events, "run.clock-observed", "kernel", null, {
      clock_id: "clock_owner_release_s41", observed_at: "2026-08-26T21:00:05Z", elapsed_ms: 500,
      reason: "owner-release", task_ref: null, failure_ordinal: null, use_ref: "task_owner_s41_1",
      attempt_ref: ref(attempt), owner_lease_ref: ref(lease), boot_id_hash: H("9"), monotonic_clock_id: "monotonic_s41_1",
    });
    append(events, "ownership.lease-released", "kernel", null, {
      owner_lease_event_ref: ref(lease), release_clock_ref: ref(releaseClock), reason: "completed", fence_epoch: 0,
    });
    const heartbeatClock = append(events, "run.clock-observed", "kernel", null, {
      clock_id: "clock_owner_heartbeat_after_release_s41", observed_at: "2026-08-26T21:00:06Z", elapsed_ms: 700,
      reason: "owner-heartbeat", task_ref: null, failure_ordinal: null, use_ref: "task_owner_s41_1",
      attempt_ref: ref(attempt), owner_lease_ref: ref(lease), boot_id_hash: H("9"), monotonic_clock_id: "monotonic_s41_1",
    });
    append(events, "ownership.lease-heartbeat-recorded", "kernel", null, {
      owner_lease_event_ref: ref(lease), heartbeat_ordinal: 1, observation_clock_ref: ref(heartbeatClock),
      previous_deadline_elapsed_ms: 1_000, deadline_elapsed_ms: 1_001,
      boot_id_hash: H("9"), monotonic_clock_id: "monotonic_s41_1", fence_epoch: 0,
    });
    expect(reduceRuntimeEventPrefixV04(events)).toMatchObject({ ok: false, message: expect.stringContaining("active") });
  });

  it("refuses pause and seal while an admitted action remains in flight", () => {
    const pauseCase = active();
    admitAction(pauseCase.events, pauseCase.attempt);
    requestPause(pauseCase.events, pauseCase.attempt);
    expect(reduceRuntimeEventPrefixV04(pauseCase.events)).toMatchObject({ ok: true });
    append(pauseCase.events, "run.fence-advanced", "policy-enforcement-point", "authority_pause_s41", {
      previous_fence_epoch: 0, fence_epoch: 1, reason: "pause-request", evidence_refs: [],
      attempt_ref: ref(pauseCase.attempt), owner_lease_refs: [ref(pauseCase.attempt)],
    });
    append(pauseCase.events, "run.paused", "operator", "authority_pause_s41", {
      requested_by: "operator", reason_code: "operator-request", request_event_ref: ref(pauseCase.events.at(-2)!),
      attempt_event_ref: ref(pauseCase.attempt), quiescent_boundary_sequence: pauseCase.events.at(-1)!.sequence,
      quiescent_boundary_head_hash: pauseCase.events.at(-1)!.event_hash, previous_fence_epoch: 0, fence_epoch: 1,
      invalidated_owner_lease_refs: [ref(pauseCase.attempt)],
    });
    expect(reduceRuntimeEventPrefixV04(pauseCase.events)).toMatchObject({ ok: false, message: expect.stringContaining("quiescent") });

    const sealCase = active();
    const admission = admitAction(sealCase.events, sealCase.attempt);
    append(sealCase.events, "run.terminal-freeze-entered", "evaluator", null, {
      revision: 1, candidate: "held", candidate_evidence_refs: [ref(admission)], fence_epoch: 0,
    });
    append(sealCase.events, "run.terminal-sealed", "evaluator", null, {
      outcome: "held", pre_seal_ledger_sequence: sealCase.events.at(-1)!.sequence,
      pre_seal_ledger_head_hash: sealCase.events.at(-1)!.event_hash, pre_seal_snapshot_hash: H("6"),
      previous_fence_epoch: 0, fence_epoch: 1,
    });
    expect(reduceRuntimeEventPrefixV04(sealCase.events)).toMatchObject({ ok: false, message: expect.stringContaining("in-flight") });
  });

  it("settles proven non-start only after exact non-entry, termination, and integrity non-commit facts", () => {
    const exact = active();
    const admission = admitAction(exact.events, exact.attempt);
    const reconciliation = appendNonEntryProof(exact.events, exact.attempt, admission);
    appendNonEntrySettlement(exact.events, reconciliation);
    expect(success(exact.events).in_flight_action_ids).toEqual([]);

    const contradicted = active();
    const contradictedAdmission = admitAction(contradicted.events, contradicted.attempt);
    append(contradicted.events, "task.execution-started", "adapter", null, {
      action_id: "action_s41_1", task_ref: "task-s41", admission_ref: ref(contradictedAdmission),
      adapter_invocation_id: "invocation_s41_non_entry", ...executionBindings,
      policy_action_kind: "network-read", action_approval_class: "agency",
    });
    appendNonEntryProof(contradicted.events, contradicted.attempt, contradictedAdmission);
    expect(reduceRuntimeEventPrefixV04(contradicted.events)).toMatchObject({
      ok: false, message: expect.stringContaining("contradict"),
    });
  });

  it("requires exact quarantine adjacency and preserves quarantine state", () => {
    const { events } = active();
    append(events, "integrity.observation-rejected", "integrity", null, {
      reason_code: "capture-gap", observation_hash: H("4"), adapter_invocation_id: "adapter_s41_1", claimed_action_id: null,
    });
    append(events, "run.clock-observed", "kernel", null, {
      clock_id: "clock_s41_1", observed_at: "2026-08-26T21:01:00Z", elapsed_ms: 1,
      reason: "terminal-use", task_ref: null, failure_ordinal: null, use_ref: "terminal_s41_1",
      attempt_ref: null, owner_lease_ref: null, boot_id_hash: null, monotonic_clock_id: null,
    });
    expect(reduceRuntimeEventPrefixV04(events)).toMatchObject({ ok: false, message: expect.stringContaining("immediately") });
  });

  it("makes terminal freeze sticky, advances the seal fence once, and rejects post-seal events", () => {
    const { events, attempt } = active();
    append(events, "run.terminal-freeze-entered", "evaluator", null, {
      revision: 1, candidate: "completed", candidate_evidence_refs: [ref(attempt)], fence_epoch: 0,
    });
    append(events, "run.terminal-sealed", "evaluator", null, {
      outcome: "completed", pre_seal_ledger_sequence: events.at(-1)!.sequence,
      pre_seal_ledger_head_hash: events.at(-1)!.event_hash, pre_seal_snapshot_hash: H("6"),
      previous_fence_epoch: 0, fence_epoch: 1,
    });
    expect(success(events)).toMatchObject({ state: "sealed", terminal_freeze_entered: true, terminal_sealed: true, current_fence_epoch: 1 });
    append(events, "run.clock-observed", "kernel", null, {
      clock_id: "clock_s41_2", observed_at: "2026-08-26T21:02:00Z", elapsed_ms: 2,
      reason: "terminal-use", task_ref: null, failure_ordinal: null, use_ref: "terminal_s41_2",
      attempt_ref: null, owner_lease_ref: null, boot_id_hash: null, monotonic_clock_id: null,
    });
    expect(reduceRuntimeEventPrefixV04(events)).toMatchObject({ ok: false, message: "No event may follow a terminal seal." });
  });
});
