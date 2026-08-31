import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { inspectRuntimePlanV03, projectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import { inspectRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import { buildRunManifestV04, inspectRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import { projectRuntimeRecoveryAdviceV04 } from "../../src/run/runtime-recovery-v04.js";
import { reduceRuntimeEventPrefixV04 } from "../../src/run/runtime-state-reducer-v04.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import {
  RuntimeEventTypesV04,
  RuntimeEventV04,
  type RuntimeEventV04Value,
} from "../../src/schema/runtime-v04.js";

const UTF8 = new TextEncoder();
const REGISTRY = captureRuntimeProfileRegistryV03();
const H = (character: string) => `sha256:${character.repeat(64)}`;
const RUN_ID = "run_s41_race_matrix";
const INVENTORY = {
  resolved_run_plan: "0.3", ledger_event: "0.4", run_manifest: "0.4",
  artifact_manifest: "0.2", redaction_derivative: "0.2", human_authorization_proof: "0.2",
  authority_envelope: "0.2", agency_recommendation: "0.2", authority_revocation: "0.2",
  task_result: "0.2", manual_observation: "0.2", export_decision: "0.2",
  evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2", claim: "0.2",
  finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2", summary_artifact: "0.1",
} as const;
const PROPOSAL = {
  action_proposal_id: "proposal_s41_race", action_proposal_hash: H("a"), action_actor_ref: "actor_s41_race",
  action_actor_stable_identity_hash: H("a"), on_behalf_of_chain_hash: H("a"),
  repository_root_ref: "repository_s41_race", repository_base_ref_identity_hash: H("a"),
  repository_pre_state_hash: H("a"), authorized_change_set_hash: H("a"), normalized_dispatch_hash: H("a"),
  action_scope_hash: H("a"), action_class: "task", classifier_input_hash: H("a"),
  classifier_registry_hash: H("a"), classifier_rule_hash: H("a"), data_flow_hash: H("a"),
} as const;

function ref(event: RuntimeEventV04Value) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function append(
  events: RuntimeEventV04Value[],
  eventType: RuntimeEventV04Value["event_type"],
  source: RuntimeEventV04Value["source"],
  authorityRef: string | null,
  payload: unknown,
  runId = RUN_ID,
) {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4", event_id: `event_s41_race_${sequence}`, run_id: runId, sequence,
    recorded_at: `2026-08-30T18:00:${String(sequence).padStart(2, "0")}Z`, event_type: eventType,
    source, authority_ref: authorityRef, risk_tier: "T1", related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null, payload,
  };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

function activePrefix() {
  const events: RuntimeEventV04Value[] = [];
  append(events, "run.initialized", "kernel", null, {
    plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: INVENTORY,
  });
  const started = append(events, "run.started", "kernel", null, { executor_profile_hash: H("b") });
  const clock = append(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_s41_race_owner", observed_at: "2026-08-30T18:00:02Z", elapsed_ms: 1,
    reason: "run-owner-acquisition", task_ref: null, failure_ordinal: null,
    use_ref: "run_owner_s41_race", attempt_ref: null, owner_lease_ref: null,
    boot_id_hash: H("1"), monotonic_clock_id: "mono_s41_race",
  });
  const attempt = append(events, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_s41_race_1", attempt_ordinal: 1, mode: "ordinary",
    previous_attempt_event_ref: null, resume_request_event_ref: null, resume_nonce_hash: null,
    source_boundary_sequence: started.sequence, source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("c"), repository_state_hash: H("a"), plan_hash: H("a"), input_hash: H("d"),
    recovery_policy_hash: H("e"), authority_envelope_hash: H("f"),
    run_owner_lease_id: "run_owner_s41_race", issued_clock_ref: ref(clock), deadline_elapsed_ms: 1_000,
    boot_id_hash: H("1"), monotonic_clock_id: "mono_s41_race", previous_fence_epoch: 0, fence_epoch: 0,
  });
  return { events, attempt };
}

function admit(
  events: RuntimeEventV04Value[],
  attempt: RuntimeEventV04Value,
  runId = RUN_ID,
  taskRef = "task-s41-race",
) {
  return append(events, "task.action-admitted", "policy-enforcement-point", "authority_s41_race", {
    action_id: "action_s41_race", task_ref: taskRef, lease_id: "action_lease_s41_race",
    lease_event_ref: ref(attempt), admission_clock_ref: ref(attempt), ...PROPOSAL,
    policy_action_kind: "network-read", action_approval_class: "agency", execution_ordinal: 1,
    retry_of_failure_ordinal: null, fence_epoch: 0, side_effect_refs: ["effect-s41-race"],
    waiver_gate_use_checks: [], task_executions_after: 1, action_output_bytes_after: 0,
    attempt_event_ref: ref(attempt), parent_run_owner_lease_id: "run_owner_s41_race",
    logical_operation_idempotency_key: H("2"), resolved_operation_input_hash: H("3"),
    recovery_policy_hash: H("e"), process_runtime_ceiling_ms: 30_000,
  }, runId);
}

function marker(events: RuntimeEventV04Value[], name: string, elapsedMs: number) {
  return append(events, "run.clock-observed", "kernel", null, {
    clock_id: `clock_${name}`, observed_at: "2026-08-30T18:00:20Z", elapsed_ms: elapsedMs,
    reason: "terminal-use", task_ref: null, failure_ordinal: null, use_ref: `use_${name}`,
    attempt_ref: null, owner_lease_ref: null, boot_id_hash: null, monotonic_clock_id: null,
  });
}

function requestResume(events: RuntimeEventV04Value[], attempt: RuntimeEventV04Value, id: string, nonce: string) {
  const boundary = events.at(-1)!;
  const clock = append(events, "run.clock-observed", "kernel", null, {
    clock_id: `clock_${id}`, observed_at: "2026-08-30T18:00:21Z", elapsed_ms: 21,
    reason: "recovery-request", task_ref: null, failure_ordinal: null, use_ref: id,
    attempt_ref: ref(attempt), owner_lease_ref: ref(attempt), boot_id_hash: null, monotonic_clock_id: null,
  });
  return append(events, "recovery.resume-requested", "operator", "authority_s41_race", {
    request_id: id, mode: "ordinary", resume_nonce_hash: nonce,
    previous_attempt_event_ref: ref(attempt), source_boundary_sequence: boundary.sequence,
    source_boundary_head_hash: boundary.event_hash, source_manifest_hash: H("c"), plan_hash: H("a"),
    repository_state_hash: H("a"),
    input_hash: H("d"), recovery_policy_hash: H("e"), authority_envelope_hash: H("f"),
    request_clock_ref: ref(clock), target_action_admission_ref: null, compensation_phase_event_ref: null,
  });
}

function requestPause(events: RuntimeEventV04Value[], attempt: RuntimeEventV04Value) {
  const clock = append(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_pause_s41_race", observed_at: "2026-08-30T18:00:22Z", elapsed_ms: 22,
    reason: "pause-request", task_ref: null, failure_ordinal: null, use_ref: "pause_s41_race",
    attempt_ref: ref(attempt), owner_lease_ref: ref(attempt), boot_id_hash: null, monotonic_clock_id: null,
  });
  return append(events, "control.pause-requested", "operator", "authority_s41_race", {
    request_id: "pause_s41_race", requested_by: "operator", reason_code: "operator-request",
    attempt_event_ref: ref(attempt), run_owner_lease_ref: ref(attempt), request_clock_ref: ref(clock), fence_epoch: 0,
  });
}

function reduced(events: readonly RuntimeEventV04Value[]) {
  const result = reduceRuntimeEventPrefixV04(events);
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.message);
  return result.state;
}

function loadPlanV02(): ResolvedRunPlanV02Value {
  return ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"), "utf8",
  )));
}

function brandedRecoveryInput(addUnresolvedAction = false) {
  const projected = projectRuntimePlanV03(loadPlanV02(), REGISTRY);
  if (!projected.ok) throw new Error(projected.reason);
  const inspectedPlan = inspectRuntimePlanV03(UTF8.encode(JSON.stringify(projected.value)));
  if (!inspectedPlan.ok) throw new Error(inspectedPlan.reason);
  const plan = inspectedPlan.validated_plan;
  const events: RuntimeEventV04Value[] = [];
  append(events, "run.initialized", "kernel", null, {
    plan_hash: plan.plan_hash, initial_fence_epoch: 0, runtime_schema_versions: INVENTORY,
  }, plan.run_id);
  const started = append(events, "run.started", "kernel", null, { executor_profile_hash: H("b") }, plan.run_id);
  const clock = append(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_s41_race_branded", observed_at: "2026-08-30T18:00:02Z", elapsed_ms: 1,
    reason: "run-owner-acquisition", task_ref: null, failure_ordinal: null, use_ref: "run_owner_s41_race",
    attempt_ref: null, owner_lease_ref: null, boot_id_hash: H("1"), monotonic_clock_id: "mono_s41_race",
  }, plan.run_id);
  const attempt = append(events, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_s41_race_1", attempt_ordinal: 1, mode: "ordinary",
    previous_attempt_event_ref: null, resume_request_event_ref: null, resume_nonce_hash: null,
    source_boundary_sequence: started.sequence, source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("c"),
    repository_state_hash: plan.plan.authority_subject.repository.initial_state.repository_state_hash,
    plan_hash: plan.plan_hash, input_hash: plan.plan.runtime_input_hash,
    recovery_policy_hash: plan.plan.runtime_recovery_policy_hash, authority_envelope_hash: H("f"), run_owner_lease_id: "run_owner_s41_race",
    issued_clock_ref: ref(clock), deadline_elapsed_ms: 1_000, boot_id_hash: H("1"),
    monotonic_clock_id: "mono_s41_race", previous_fence_epoch: 0, fence_epoch: 0,
  }, plan.run_id);
  const admission = addUnresolvedAction ? admit(events, attempt, plan.run_id, plan.plan.tasks[0]!.id) : null;
  const ledgerBytes = UTF8.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const inspectedLedger = inspectRuntimeLedgerV04(ledgerBytes);
  if (!inspectedLedger.ok) throw new Error(inspectedLedger.reason);
  const files = [{ path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes }] as const;
  const built = buildRunManifestV04({ ledger_bytes: ledgerBytes, created_at: "2026-08-30T18:01:00Z", captured_files: files });
  if (!built.ok) throw new Error(built.reason);
  const manifest = inspectRunManifestV04({ manifest_bytes: built.bytes, ledger_bytes: ledgerBytes, captured_files: files });
  if (!manifest.ok) throw new Error(manifest.reason);
  return { plan, ledger: manifest.ledger, manifest: manifest.validated_manifest, attempt, admission };
}

describe("S41-E crash and race matrix at implemented durable boundaries", () => {
  it("crash before admission leaves no admitted or in-flight action", () => {
    const { events } = activePrefix();
    expect(reduced(events).in_flight_action_ids).toEqual([]);
  });

  it.each([
    "after admission/before spawn",
    "mid-engine",
    "mid-verifier",
    "before request/phase",
    "during settlement",
    "before seal",
  ])("crash %s preserves the admitted action as unresolved until exact settlement", (boundary) => {
    const { events, attempt } = activePrefix();
    admit(events, attempt);
    marker(events, boundary.replaceAll(/[^a-z]+/g, "_"), 20);
    expect(reduced(events).in_flight_action_ids).toEqual(["action_s41_race"]);
  });

  it("ordinary recovery refuses an admitted-but-unsettled action using genuine inspected brands", () => {
    const input = brandedRecoveryInput(true);
    const result = projectRuntimeRecoveryAdviceV04({
      ledger: input.ledger, manifest: input.manifest, plan: input.plan,
      owner_status: { status: "proven-stale", stale_reason: "same-domain-deadline-reached", owner_lease_event_ref: ref(input.attempt), evidence_refs: [ref(input.attempt)] },
      request: { request_id: "resume_s41_race", requested_mode: "ordinary", resume_nonce_hash: H("7"), authority_envelope_hash: H("f"), target_action_admission_ref: null, compensation_phase_event_ref: null },
      summary: null,
    });
    expect(result).toMatchObject({ ok: true, decision: { disposition: "refused", reason_code: "ordinary-blocked-by-unresolved-action" } });
  });

  it("true concurrent/double resume admits one pending request and rejects the second", () => {
    const { events, attempt } = activePrefix();
    requestResume(events, attempt, "resume_s41_race_1", H("7"));
    requestResume(events, attempt, "resume_s41_race_2", H("8"));
    expect(reduceRuntimeEventPrefixV04(events)).toMatchObject({
      ok: false, message: "A recovery request requires one current attempt and no pending recovery request.",
    });
  });

  it("resume-versus-pause ordering never admits work while the resume request is pending", () => {
    const { events, attempt } = activePrefix();
    requestResume(events, attempt, "resume_s41_race_1", H("7"));
    requestPause(events, attempt);
    expect(reduced(events).pending_resume_request?.request_id).toBe("resume_s41_race_1");
    admit(events, attempt);
    expect(reduceRuntimeEventPrefixV04(events)).toMatchObject({
      ok: false, message: expect.stringContaining("recovery request remains pending"),
    });
  });

  it.each([
    ["revoke", "authority.grant-revoked"],
    ["abort", "control.abort-requested"],
    ["freeze", "run.terminal-freeze-entered"],
    ["seal", "run.terminal-sealed"],
  ] as const)("resume-versus-%s is ordered by the append-only prefix and cannot create a second attempt", (_name, eventType) => {
    const { events, attempt } = activePrefix();
    requestResume(events, attempt, "resume_s41_race_1", H("7"));
    if (eventType === "authority.grant-revoked") {
      append(events, eventType, "operator", "operator_s41_race", {
        revocation_id: "revocation_s41_race", record_path: "authority/revocation_s41_race.json", record_hash: H("a"),
        run_id: RUN_ID, plan_hash: H("a"), target: { kind: "authority-envelope", target_ref: { record_kind: "authority-envelope", record_id: "envelope_s41_race", record_event_ref: ref(events[0]!) }, target_scope_hash: H("a") },
        previous_revocation_epoch: 0, revocation_epoch: 1, effective_prefix_ref: ref(events.at(-1)!),
        reason_code: "operator-revoked", evidence_refs: [{ record_kind: "human-authorization", record_id: "auth_s41_race", record_event_ref: ref(events[0]!) }],
        revoker_kind: "operator", revoker_identity_ref: "operator_s41_race", revoker_stable_identity_hash: H("a"),
        revoker_authentication_context_hash: H("a"), policy_digest: H("a"), revoked_at: "2026-08-30T18:00:22Z",
        signer_key_ref: "key_s41_race", statement_hash: H("a"),
      });
    } else if (eventType === "control.abort-requested") {
      append(events, eventType, "operator", "operator_s41_race", {
        request_id: "abort_s41_race", requested_by: "operator", reason_code: "operator-requested",
        policy_decision_ref: null, evidence_refs: [ref(events.at(-1)!)],
      });
    } else if (eventType === "run.terminal-freeze-entered") {
      append(events, eventType, "evaluator", null, { revision: 1, candidate: "held", candidate_evidence_refs: [ref(events.at(-1)!)], fence_epoch: 0 });
    } else {
      append(events, "run.terminal-freeze-entered", "evaluator", null, { revision: 1, candidate: "held", candidate_evidence_refs: [ref(events.at(-1)!)], fence_epoch: 0 });
      append(events, eventType, "evaluator", null, {
        outcome: "held", pre_seal_ledger_sequence: events.at(-1)!.sequence,
        pre_seal_ledger_head_hash: events.at(-1)!.event_hash, pre_seal_snapshot_hash: H("9"),
        previous_fence_epoch: 0, fence_epoch: 1,
      });
    }
    const state = reduced(events);
    expect(state.current_attempt_ordinal).toBe(1);
    expect(state.pending_resume_request?.request_id).toBe("resume_s41_race_1");
    if (eventType === "run.terminal-sealed") expect(state.terminal_sealed).toBe(true);
  });

  it.each([
    ["stale-owner", { status: "proven-stale", stale_reason: "same-domain-deadline-reached" }, "eligible"],
    ["heartbeat-at-deadline", { status: "ambiguous", ambiguous_reason: "heartbeat-at-deadline" }, "owner-ambiguous"],
  ] as const)("%s requires explicit owner evidence and never infers staleness from silence", (_name, status, expected) => {
    const input = brandedRecoveryInput();
    const decision = projectRuntimeRecoveryAdviceV04({
      ledger: input.ledger, manifest: input.manifest, plan: input.plan,
      owner_status: { ...status, owner_lease_event_ref: ref(input.attempt), evidence_refs: [ref(input.attempt)] },
      request: { request_id: "resume_s41_race", requested_mode: "ordinary", resume_nonce_hash: H("7"), authority_envelope_hash: H("f"), target_action_admission_ref: null, compensation_phase_event_ref: null },
      summary: null,
    });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(expected === "eligible" ? decision.decision.disposition : (decision.decision as { reason_code?: string }).reason_code).toBe(expected);
  });

  it("consumed-but-untracked and pre-issued post-seal leases fail closed at the closed event/reducer boundary", () => {
    expect(RuntimeEventTypesV04).not.toContain("lease.consumed");
    expect(RuntimeEventTypesV04).not.toContain("authority.grant-consumed");

    const { events, attempt } = activePrefix();
    append(events, "run.terminal-freeze-entered", "evaluator", null, {
      revision: 1, candidate: "held", candidate_evidence_refs: [ref(attempt)], fence_epoch: 0,
    });
    append(events, "run.terminal-sealed", "evaluator", null, {
      outcome: "held", pre_seal_ledger_sequence: events.at(-1)!.sequence,
      pre_seal_ledger_head_hash: events.at(-1)!.event_hash, pre_seal_snapshot_hash: H("9"),
      previous_fence_epoch: 0, fence_epoch: 1,
    });
    admit(events, attempt);
    expect(reduceRuntimeEventPrefixV04(events)).toMatchObject({ ok: false, message: "No event may follow a terminal seal." });
  });

  it("expired lease remains an explicit admission-time kernel gap rather than a schema claim", () => {
    const historicalLease = {
      schema_version: "0.4", event_id: "event_s41_expired_lease", run_id: RUN_ID, sequence: 5,
      recorded_at: "2026-08-30T18:01:00Z", event_type: "lease.issued",
      source: "policy-enforcement-point", authority_ref: "authority_s41_race", risk_tier: "T1",
      related_ids: [], previous_event_hash: H("1"), event_hash: H("2"),
      payload: {
        lease_id: "lease_expired_s41_race", task_ref: "task-s41-race", phase: "work", compensation_ref: null,
        ...PROPOSAL, policy_action_kind: "planning", action_approval_class: "automatic",
        authority_envelope_ref: { ledger_sequence: 2, event_hash: H("2") },
        policy_decision_ref: { ledger_sequence: 3, event_hash: H("3") }, fence_epoch: 0,
        issued_at: "2026-08-30T18:00:00Z", expires_at: "2026-08-30T18:00:30Z", waiver_gate_refs: [],
        attempt_event_ref: { ledger_sequence: 4, event_hash: H("4") },
        parent_run_owner_lease_id: "run_owner_s41_race", logical_operation_idempotency_key: H("5"),
        resolved_operation_input_hash: H("6"), recovery_policy_hash: H("e"), process_runtime_ceiling_ms: 30_000,
      },
    } as const;
    expect(RuntimeEventV04.safeParse(historicalLease).success).toBe(true);
    expect(RuntimeEventV04.safeParse({
      ...historicalLease,
      payload: { ...historicalLease.payload, issued_at: historicalLease.payload.expires_at },
    }).success).toBe(false);
  });

  it("missing/lost/forged non-start proof and outcome unknown remain distinguishable and fail closed", () => {
    const base = {
      schema_version: "0.4", event_id: "event_s41_non_start", run_id: RUN_ID, sequence: 9,
      recorded_at: "2026-08-30T18:00:30Z", source: "integrity", authority_ref: null,
      risk_tier: "T1", related_ids: [], previous_event_hash: H("1"), event_hash: H("2"),
      event_type: "task.action-outcome-reconciled",
      payload: {
        action_id: "action_s41_race", task_ref: "task-s41-race", admission_ref: { ledger_sequence: 5, event_hash: H("5") },
        reconciliation_status: "proven-non-start", attempt_event_ref: { ledger_sequence: 4, event_hash: H("4") },
        adapter_invocation_id: "adapter_invocation_s41_race", adapter_ref: "adapter-s41-race",
        adapter_version_hash: H("6"), non_entry_ack_event_ref: { ledger_sequence: 6, event_hash: H("6") },
        process_cannot_continue_ref: { ledger_sequence: 7, event_hash: H("7") }, fence_epoch: 0,
      },
    } as const;
    expect(RuntimeEventV04.safeParse(base).success).toBe(true);
    for (const missing of ["non_entry_ack_event_ref", "process_cannot_continue_ref"] as const) {
      const payload = { ...base.payload } as Record<string, unknown>;
      delete payload[missing];
      expect(RuntimeEventV04.safeParse({ ...base, payload }).success).toBe(false);
    }
    expect(RuntimeEventV04.safeParse({
      ...base, payload: { ...base.payload, non_entry_ack_event_ref: { ledger_sequence: 0, event_hash: H("f") } },
    }).success).toBe(false);

    const unknown = {
      ...base, event_id: "event_s41_unknown", event_type: "effect.outcome",
      payload: { task_ref: "task-s41-race", effect_ref: "effect-s41-race", action_id: "action_s41_race", outcome: "unknown", evidence_refs: [{ ledger_sequence: 8, event_hash: H("8") }], reconciliation_event_ref: null },
    } as const;
    expect(RuntimeEventV04.safeParse(unknown).success).toBe(true);
    expect(RuntimeEventV04.safeParse({ ...unknown, source: "adapter" }).success).toBe(false);
    expect(RuntimeEventV04.safeParse({ ...unknown, payload: { ...unknown.payload, reconciliation_event_ref: { ledger_sequence: 8, event_hash: H("8") } } }).success).toBe(false);
  });
});
