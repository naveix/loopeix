import { z } from "zod";

import { canonicalize, hashRawBytes } from "../hash.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";
import {
  ActionProposalV02,
  AuthorityEnvelopeRecordedEventV02,
  PolicyDecisionRecordedEventV02,
  ResolvedRunPlanV02,
  type RuntimeEventV02Value,
} from "../schema/runtime.js";
import { Hash } from "../schema/scalars.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import {
  revalidateSimulatedAuthorityLeaseV02,
  simulateAuthorityDecisionV02,
} from "./action-classifier-policy-v02.js";
import {
  AuthorityEnvelopeV02,
  AgencyRecommendationRecordV02,
  AuthorityRevocationRecordV02,
  admitRuntimeRecordsV02,
  inspectCapturedAuthorityTrustBoundaryV02,
  isCapturedAuthorityTrustContextV02,
  verifyAdmittedAuthorityTrustRecordsV02,
  type CapturedAuthorityTrustContextForS36V02,
} from "./runtime-record-admission-v02.js";
import {
  appendRuntimeEventV03,
  createRuntimeEventDraftV03,
  inspectRuntimeWriteSessionV03ForAdmission,
  poisonRuntimeWriteSessionV03ForAdmission,
  verifyRuntimeWriteSessionAdmissionReadbackV03,
  type RuntimeWriteSessionV03,
} from "./runtime-write-session-v03.js";

declare const dispatchPermitBrandV01: unique symbol;

export type DispatchPermitV01 = Readonly<{ [dispatchPermitBrandV01]: never }>;

export type RuntimeActionAdmissionRequestV03 = Readonly<{
  action_proposal_id: string;
  policy_decision_id: string;
  normalized_dispatch_hash: string;
  expected_fence_epoch: number;
}>;

export type AdmitRuntimeActionV03Error =
  | "RUNTIME_WRITE_SESSION_INVALID"
  | "RUNTIME_WRITE_SESSION_POISONED"
  | "RUN_QUARANTINED"
  | "RUN_TERMINAL"
  | "CANONICAL_AUTHORITY_RECORDS_INVALID"
  | "SIMULATION_REVALIDATION_FAILED"
  | "AUTHORITY_STALE_OR_REVOKED"
  | "REPOSITORY_OR_DISPATCH_DRIFT"
  | "LIMIT_ADMISSION_BLOCKED"
  | "LEASE_ISSUANCE_NOT_COMMITTED"
  | "ACTION_ADMISSION_NOT_COMMITTED"
  | "RUNTIME_IO_OUTCOME_UNKNOWN"
  | "COMMITTED_READBACK_INVALID";

export type AdmitRuntimeActionV03Result =
  | Readonly<{
      ok: true;
      permit: DispatchPermitV01;
      lease_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
      admission_clock_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
      action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
      committed_manifest_hash: string;
    }>
  | Readonly<{ ok: false; error: AdmitRuntimeActionV03Error }>;

const RuntimeActionAdmissionRequest = z.object({
  action_proposal_id: MachineIdV02,
  policy_decision_id: MachineIdV02,
  normalized_dispatch_hash: Hash,
  expected_fence_epoch: z.number().int().nonnegative().refine(Number.isSafeInteger),
}).strict();

const RuntimeActionAdmissionContext = z.object({
  authority_trust_context: z.custom<CapturedAuthorityTrustContextForS36V02>(isCapturedAuthorityTrustContextV02),
  repository_pre_state_hash: Hash,
  normalized_dispatch_hash: Hash,
  observed_at: z.string().check(z.iso.datetime()),
  elapsed_ms: z.number().int().nonnegative().refine(Number.isSafeInteger),
  reviewer_view_hash: Hash,
  enforcement: z.object({
    available: z.boolean(),
    information_flow_allowed: z.boolean(),
    gates_passed: z.boolean(),
    immediate_revalidation_passed: z.boolean(),
  }).strict(),
  condition_results: z.array(z.object({ condition_hash: Hash, satisfied: z.boolean() }).strict()),
  lease_id: MachineIdV02,
  clock_id: MachineIdV02,
  action_id: MachineIdV02,
}).strict();

type LedgerRef = Readonly<{ ledger_sequence: number; event_hash: string }>;
type RecordValue = Record<string, unknown>;

type PermitState = {
  session: RuntimeWriteSessionV03;
  action_admission_event_ref: LedgerRef;
  normalized_dispatch_hash: string;
  broker: object | null;
  used: boolean;
};

export type ConsumeDispatchPermitV01Result = Readonly<{
  ok: true;
  action_admission_event_ref: LedgerRef;
}> | Readonly<{
  ok: false;
  error: "DISPATCH_PERMIT_INVALID" | "DISPATCH_PERMIT_SESSION_MISMATCH"
    | "DISPATCH_BINDING_MISMATCH" | "DISPATCH_PERMIT_ALREADY_USED";
}>;

const permits = new WeakMap<DispatchPermitV01, PermitState>();

/** Package-private B4 seam: pins the first broker by identity and consumes the permit exactly once. */
export function consumeDispatchPermitV01(
  permit: DispatchPermitV01,
  session: RuntimeWriteSessionV03,
  broker: object,
  normalizedDispatchHash: string,
): ConsumeDispatchPermitV01Result {
  const state = permits.get(permit);
  if (state === undefined) return Object.freeze({ ok: false, error: "DISPATCH_PERMIT_INVALID" });
  if (state.session !== session) return Object.freeze({ ok: false, error: "DISPATCH_PERMIT_SESSION_MISMATCH" });
  if (state.normalized_dispatch_hash !== normalizedDispatchHash
    || (state.broker !== null && state.broker !== broker)) {
    return Object.freeze({ ok: false, error: "DISPATCH_BINDING_MISMATCH" });
  }
  if (state.used) return Object.freeze({ ok: false, error: "DISPATCH_PERMIT_ALREADY_USED" });
  state.broker = broker;
  state.used = true;
  return Object.freeze({ ok: true, action_admission_event_ref: state.action_admission_event_ref });
}

function eventRef(event: { sequence: number; event_hash: string }): LedgerRef {
  return Object.freeze({ ledger_sequence: event.sequence, event_hash: event.event_hash });
}

function eventAtRef(events: readonly RuntimeEventV02Value[], ref: LedgerRef): RuntimeEventV02Value | undefined {
  return events.find((event) => event.sequence === ref.ledger_sequence && event.event_hash === ref.event_hash);
}

function recordAtPath(records: ReadonlyMap<string, unknown>, path: unknown): RecordValue | null {
  const value = typeof path === "string" ? records.get(path) : undefined;
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as RecordValue : null;
}

function simulationProjectionMatches(simulation: RecordValue, decision: RecordValue): boolean {
  const pairs = [
    ["decision", "decision"], ["decision_disposition", "decision_disposition"],
    ["reason_codes", "reason_codes"], ["quorum_requirement_hash", "quorum_requirement_hash"],
    ["recommendation_event_refs", "recommendation_event_refs"], ["condition_hashes", "condition_hashes"],
    ["failed_condition_hashes", "failed_condition_hashes"],
  ] as const;
  return pairs.every(([left, right]) => canonicalize(simulation[left]) === canonicalize(decision[right]));
}

function prospectiveLimitsPass(
  plan: z.infer<typeof ResolvedRunPlanV02>,
  proposal: z.infer<typeof ActionProposalV02>,
  events: readonly RuntimeEventV02Value[],
  elapsedMs: number,
): boolean {
  const scope = proposal.action_scope.bounded_constraints;
  const delta = proposal.budget_delta;
  const taskAdmissions = events.filter((event) => event.event_type === "task.action-admitted");
  const decisions = events.filter((event) => event.event_type === "policy.decision-recorded"
    && (event.payload as RecordValue).action_proposal_id === proposal.action_proposal_id);
  const taskExecutions = taskAdmissions.filter((event) => (event.payload as RecordValue).task_ref === proposal.task_ref);
  const completed = events.filter((event) => event.event_type === "task.execution-completed" || event.event_type === "task.execution-failed");
  const cumulative = (rows: readonly RuntimeEventV02Value[], field: string): number | null => {
    let current = 0;
    for (const row of rows) {
      const candidate = (row.payload as RecordValue)[field];
      if (candidate === undefined) continue;
      if (typeof candidate !== "number" || !Number.isSafeInteger(candidate) || candidate < current) return null;
      current = candidate;
    }
    return current;
  };
  const toolCalls = cumulative(events.filter((event) => event.event_type === "tool.call-admitted"
    || event.event_type === "task.execution-completed" || event.event_type === "task.execution-failed"), "tool_calls_after");
  const outputBytes = cumulative(events.filter((event) => event.event_type === "artifact.write-admitted"
    || event.event_type === "task.execution-completed" || event.event_type === "task.execution-failed"), "action_output_bytes_after");
  const tokens = cumulative(completed, "token_count_after");
  const costRows = completed.map((event) => (event.payload as RecordValue).observed_cost as RecordValue | undefined);
  const costCaptureRequired = plan.limit_policy.max_cost_minor_units !== null || scope.cost.capture === "required";
  if (costCaptureRequired && (scope.cost.capture !== "required" || delta.cost.capture !== "required"
    || plan.limit_policy.cost_currency !== scope.cost.cost_currency
    || delta.cost.cost_currency !== scope.cost.cost_currency)) return false;
  let cost = 0;
  for (const observed of costRows) {
    if (!costCaptureRequired) continue;
    if (observed?.capture !== "captured" || observed.cost_currency !== scope.cost.cost_currency
      || typeof observed.cost_minor_units_after !== "number"
      || !Number.isSafeInteger(observed.cost_minor_units_after)
      || observed.cost_minor_units_after < cost) return false;
    cost = observed.cost_minor_units_after;
  }
  const inFlight = new Set<string>();
  for (const event of events) {
    const payload = event.payload as RecordValue;
    if (event.event_type === "task.execution-started") inFlight.add(String(payload.action_id));
    if (["task.execution-completed", "task.execution-failed", "task.action-outcome-unknown", "task.action-outcome-reconciled"].includes(event.event_type)) {
      inFlight.delete(String(payload.action_id));
    }
  }
  const safeAdd = (left: number, right: number): number | null => Number.isSafeInteger(left + right) ? left + right : null;
  if (toolCalls === null || outputBytes === null || tokens === null) return false;
  const nextTools = safeAdd(toolCalls, delta.tool_calls);
  const nextOutput = safeAdd(outputBytes, delta.output_bytes);
  const nextTokens = safeAdd(tokens, delta.tokens);
  const deltaCost = delta.cost.capture === "required" ? delta.cost.cost_minor_units : 0;
  const nextCost = safeAdd(cost, deltaCost);
  const retryCeiling = Math.max(0, ...plan.retry_policy.rules
    .filter((rule) => rule.task_ref === proposal.task_ref)
    .map((rule) => rule.max_task_executions));
  return taskAdmissions.length < scope.max_actions
    && decisions.length <= scope.max_decisions
    && taskAdmissions.length < plan.limit_policy.max_loop_attempts
    && taskExecutions.length < scope.max_attempts
    && taskExecutions.length < retryCeiling
    && inFlight.size < Math.min(plan.limit_policy.max_workers, scope.max_workers)
    && elapsedMs <= plan.limit_policy.max_elapsed_ms && elapsedMs <= scope.max_elapsed_ms
    && nextTools !== null && nextTools <= plan.limit_policy.max_tool_calls && nextTools <= scope.max_tool_calls
    && nextOutput !== null && nextOutput <= plan.limit_policy.max_output_bytes && nextOutput <= scope.max_output_bytes
    && nextTokens !== null && (plan.limit_policy.max_tokens === null || nextTokens <= plan.limit_policy.max_tokens)
    && nextCost !== null && (plan.limit_policy.max_cost_minor_units === null || nextCost <= plan.limit_policy.max_cost_minor_units)
    && (scope.cost.capture === "not-applicable" || nextCost <= scope.cost.max_cost_minor_units);
}

/** Test-only projection for exhaustive counter-history mutation coverage. */
export const inspectProspectiveRuntimeActionLimitsV03ForTest = prospectiveLimitsPass;

function proposalSideEffectsMatchPlan(
  plan: z.infer<typeof ResolvedRunPlanV02>,
  proposal: z.infer<typeof ActionProposalV02>,
): boolean {
  const declared = new Map(plan.side_effects
    .filter((row) => row.task_id === proposal.task_ref)
    .flatMap((row) => row.effects.map((effect) => [effect.effect_id, effect] as const)));
  const constraints = proposal.action_scope.side_effect_constraints;
  return proposal.side_effect_refs.length > 0 && proposal.side_effect_refs.every((ref) => {
    const effect = ref.task_ref === proposal.task_ref ? declared.get(ref.effect_ref) : undefined;
    return effect !== undefined
      && constraints.allowed_effect_classes.includes(effect.effect_class)
      && constraints.allowed_effect_refs.some((allowed) => allowed.task_ref === ref.task_ref
        && allowed.effect_ref === ref.effect_ref)
      && (!constraints.require_inspectable || effect.inspectable)
      && (!constraints.require_reversible || effect.reversible)
      && (!constraints.require_idempotency_key || effect.idempotency === "required")
      && (!constraints.require_compensation || effect.compensation_ref !== null);
  });
}

function copiedProposalBindings(proposal: z.infer<typeof ActionProposalV02>) {
  return {
    action_proposal_id: proposal.action_proposal_id,
    action_proposal_hash: proposal.action_proposal_hash,
    action_actor_ref: proposal.action_actor_ref,
    action_actor_stable_identity_hash: proposal.action_actor_stable_identity_hash,
    on_behalf_of_chain_hash: proposal.on_behalf_of_chain_hash,
    repository_root_ref: proposal.repository_root_ref,
    repository_base_ref_identity_hash: proposal.repository_base_ref_identity_hash,
    repository_pre_state_hash: proposal.repository_pre_state_hash,
    authorized_change_set_hash: proposal.authorized_change_set_hash,
    normalized_dispatch_hash: proposal.normalized_dispatch_hash,
    action_scope_hash: proposal.action_scope_hash,
    action_class: proposal.action_class,
    classifier_input_hash: proposal.classification_binding.classifier_input_hash,
    classifier_registry_hash: proposal.classification_binding.classifier_registry_hash,
    classifier_rule_hash: proposal.classification_binding.classifier_rule_hash,
    data_flow_hash: proposal.data_flow.data_flow_hash,
    policy_action_kind: proposal.policy_action_kind,
    action_approval_class: proposal.action_approval_class,
  };
}

function mapSessionError(error: string): AdmitRuntimeActionV03Error {
  if (error === "RUNTIME_WRITE_SESSION_POISONED") return "RUNTIME_WRITE_SESSION_POISONED";
  if (error === "RUN_QUARANTINED") return "RUN_QUARANTINED";
  if (error === "RUN_TERMINAL") return "RUN_TERMINAL";
  return "RUNTIME_WRITE_SESSION_INVALID";
}

/** Package-private S40-B admission boundary; never exported from the package root. */
export async function admitRuntimeActionV03(
  session: RuntimeWriteSessionV03,
  requestInput: unknown,
): Promise<AdmitRuntimeActionV03Result> {
  const request = RuntimeActionAdmissionRequest.safeParse(requestInput);
  if (!request.success) {
    return Object.freeze({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });
  }
  const inspected = await inspectRuntimeWriteSessionV03ForAdmission(session);
  if (!inspected.ok) return Object.freeze({ ok: false, error: mapSessionError(inspected.error) });
  const { snapshot } = inspected;
  const context = RuntimeActionAdmissionContext.safeParse(snapshot.admission_context);
  const decodedPlan = decodeStructuredDocumentV02(snapshot.plan_capture.bytes, "json");
  const parsedPlan = decodedPlan.ok ? ResolvedRunPlanV02.safeParse(decodedPlan.value) : null;
  if (!context.success || parsedPlan === null || !parsedPlan.success
    || snapshot.plan_capture.path !== "resolved-run-plan.json"
    || snapshot.plan_capture.raw_hash !== hashRawBytes(snapshot.plan_capture.bytes)
    || snapshot.plan_capture.raw_hash !== snapshot.plan_hash
    || parsedPlan.data.run_id !== snapshot.run_id) {
    return Object.freeze({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });
  }
  if (snapshot.envelopes.some((envelope) => envelope.recorded_at !== context.data.observed_at)) {
    return Object.freeze({ ok: false, error: "REPOSITORY_OR_DISPATCH_DRIFT" });
  }

  const v02Events = snapshot.events as unknown as readonly RuntimeEventV02Value[];
  const recordBytes = new Map(snapshot.record_captures.map((capture) => [capture.path, capture.bytes]));
  const recordHashes = new Map(snapshot.record_captures.map((capture) => [capture.path, capture.raw_hash]));
  const admitted = admitRuntimeRecordsV02({
    events: v02Events, run_id: snapshot.run_id, plan_hash: snapshot.plan_hash,
    record_bytes_by_path: recordBytes, raw_hash_by_path: recordHashes,
  });
  if (!admitted.ok || !verifyAdmittedAuthorityTrustRecordsV02(
    context.data.authority_trust_context, admitted.value.records_by_path, v02Events,
  ).ok) return Object.freeze({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });

  const decisionEvents = snapshot.events.filter((event) => event.event_type === "policy.decision-recorded"
    && (event.payload as RecordValue).policy_decision_id === request.data.policy_decision_id);
  const parsedDecision = decisionEvents.length === 1 ? PolicyDecisionRecordedEventV02.safeParse({
    ...decisionEvents[0], schema_version: "0.2",
  }) : null;
  if (parsedDecision === null || !parsedDecision.success) {
    return Object.freeze({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });
  }
  const decision = parsedDecision.data.payload;
  const proposal = ActionProposalV02.safeParse(decision.action_proposal);
  if (!proposal.success || proposal.data.action_proposal_id !== request.data.action_proposal_id
    || proposal.data.normalized_dispatch_hash !== request.data.normalized_dispatch_hash
    || decision.decision !== "allow" || decision.decision_disposition !== "lease-eligible") {
    return Object.freeze({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });
  }
  const envelopeEventRaw = eventAtRef(v02Events, decision.authority_envelope_ref.record_event_ref);
  const envelopeEvent = envelopeEventRaw === undefined ? null : AuthorityEnvelopeRecordedEventV02.safeParse({
    ...envelopeEventRaw, schema_version: "0.2",
  });
  const envelopeRecord = envelopeEvent?.success
    ? recordAtPath(admitted.value.records_by_path, envelopeEvent.data.payload.record_path)
    : null;
  const envelope = AuthorityEnvelopeV02.safeParse(envelopeRecord);
  if (!envelope.success || envelope.data.authority_envelope_id !== decision.authority_envelope_ref.record_id
    || envelope.data.run_id !== snapshot.run_id || envelope.data.plan_hash !== snapshot.plan_hash) {
    return Object.freeze({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });
  }

  const boundary = inspectCapturedAuthorityTrustBoundaryV02(context.data.authority_trust_context);
  const observed = Date.parse(context.data.observed_at);
  const currentEpoch = boundary?.authority_epochs.find((row) => row.authenticated_principal_ref === envelope.data.issuer.principal_ref)?.revocation_epoch;
  const revoked = snapshot.events.some((event) => event.event_type === "authority.grant-revoked"
    && AuthorityRevocationRecordV02.safeParse(recordAtPath(
      admitted.value.records_by_path, (event.payload as RecordValue).record_path,
    )).data?.target.target_ref.record_id === envelope.data.authority_envelope_id);
  if (boundary === null || boundary.observed_at !== context.data.observed_at
    || boundary.policy_digest !== decision.policy_digest || currentEpoch !== envelope.data.revocation_epoch
    || decision.revocation_epoch !== envelope.data.revocation_epoch || revoked
    || observed < Date.parse(envelope.data.issued_at) || observed >= Date.parse(envelope.data.expires_at)
    || observed < Date.parse(decision.issued_at) || observed >= Date.parse(decision.expires_at)) {
    return Object.freeze({ ok: false, error: "AUTHORITY_STALE_OR_REVOKED" });
  }

  if (snapshot.current_fence_epoch !== request.data.expected_fence_epoch
    || proposal.data.repository_pre_state_hash !== context.data.repository_pre_state_hash
    || proposal.data.normalized_dispatch_hash !== context.data.normalized_dispatch_hash) {
    return Object.freeze({ ok: false, error: "REPOSITORY_OR_DISPATCH_DRIFT" });
  }

  const recommendations = decision.recommendation_event_refs.map((ref) => {
    const event = eventAtRef(v02Events, ref);
    const record = event?.event_type === "approval.recommendation-recorded"
      ? recordAtPath(admitted.value.records_by_path, (event.payload as RecordValue).record_path)
      : null;
    const parsed = AgencyRecommendationRecordV02.safeParse(record);
    return parsed.success ? {
      event_ref: ref,
      action_proposal_hash: parsed.data.action_proposal_hash,
      reviewer_view_hash: context.data.reviewer_view_hash,
      reviewed_through_ref: parsed.data.reviewed_through_ref,
      quorum_requirement_hash: parsed.data.quorum_requirement_hash,
      evaluator_role_ref: parsed.data.evaluator_role_ref,
      evaluator_stable_identity_hash: parsed.data.evaluator_stable_identity_hash,
      decision: parsed.data.decision,
      conditions: parsed.data.conditions,
      evidence_refs: parsed.data.evidence_refs,
      evidence_independence_keys: parsed.data.evidence_independence_keys,
      issued_at: parsed.data.issued_at,
      expires_at: parsed.data.expires_at,
    } : null;
  });
  if (recommendations.some((row) => row === null)) {
    return Object.freeze({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });
  }
  const simulationInput = {
    proposal: {
      action_proposal_id: proposal.data.action_proposal_id,
      action_proposal_hash: proposal.data.action_proposal_hash,
      action_class: proposal.data.action_class,
      policy_action_kind: proposal.data.policy_action_kind,
      action_approval_class: proposal.data.action_approval_class,
      policy_digest: decision.policy_digest,
      action_scope_hash: proposal.data.action_scope_hash,
      normalized_dispatch_hash: proposal.data.normalized_dispatch_hash,
      repository_pre_state_hash: proposal.data.repository_pre_state_hash,
      classifier_rule_hash: proposal.data.classification_binding.classifier_rule_hash,
      data_flow_hash: proposal.data.data_flow.data_flow_hash,
      effective_risk_tier: proposal.data.effective_risk_tier,
    },
    reviewer_view_hash: context.data.reviewer_view_hash,
    reviewed_through_ref: decision.reviewed_through_ref,
    recommendations,
    authority: { envelope_verified: true, contained: true, proof_fresh: true, revocation_epoch_current: true },
    enforcement: context.data.enforcement,
    condition_results: context.data.condition_results,
    issued_at: decision.issued_at,
    expires_at: decision.expires_at,
    fence_epoch: snapshot.current_fence_epoch,
  };
  const simulation = simulateAuthorityDecisionV02(simulationInput);
  if (!simulation.ok || simulation.value.simulated_lease === null
    || !simulationProjectionMatches(simulation.value as unknown as RecordValue, decision as unknown as RecordValue)
    || !revalidateSimulatedAuthorityLeaseV02(simulation.value.simulated_lease, simulationInput).ok) {
    return Object.freeze({ ok: false, error: "SIMULATION_REVALIDATION_FAILED" });
  }
  if (!proposalSideEffectsMatchPlan(parsedPlan.data, proposal.data)
    || !prospectiveLimitsPass(parsedPlan.data, proposal.data, v02Events, context.data.elapsed_ms)) {
    return Object.freeze({ ok: false, error: "LIMIT_ADMISSION_BLOCKED" });
  }
  const lastPriorAdmission = Math.max(-1, ...snapshot.events
    .map((event, index) => event.event_type === "task.action-admitted"
      && (event.payload as RecordValue).task_ref === proposal.data.task_ref ? index : -1));
  const unresolvedRetry = snapshot.events.slice(lastPriorAdmission + 1).some((event) => event.event_type === "task.execution-failed"
    && (event.payload as RecordValue).task_ref === proposal.data.task_ref);
  const waiverBranchPresent = snapshot.events.some((event) => event.event_type === "authority.waiver-recorded");
  if (unresolvedRetry || waiverBranchPresent) {
    return Object.freeze({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });
  }

  const bindings = copiedProposalBindings(proposal.data);
  const authorityRef = parsedDecision.data.authority_ref;
  const leaseDraft = createRuntimeEventDraftV03({
    event_type: "lease.issued", source: "policy-enforcement-point", authority_ref: authorityRef,
    risk_tier: proposal.data.effective_risk_tier, related_ids: [],
    payload: {
      lease_id: context.data.lease_id, task_ref: proposal.data.task_ref, phase: proposal.data.phase,
      compensation_ref: proposal.data.compensation_ref, ...bindings,
      authority_envelope_ref: decision.authority_envelope_ref.record_event_ref,
      policy_decision_ref: eventRef(parsedDecision.data), fence_epoch: snapshot.current_fence_epoch,
      issued_at: context.data.observed_at, expires_at: decision.expires_at, waiver_gate_refs: [],
    },
  });
  if (leaseDraft === null) return Object.freeze({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });
  const lease = await appendRuntimeEventV03(session, leaseDraft);
  if (!lease.ok) {
    if (lease.classification === "OUTCOME_UNKNOWN") {
      await poisonRuntimeWriteSessionV03ForAdmission(session);
      return Object.freeze({ ok: false, error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
    }
    return Object.freeze({ ok: false, error: "LEASE_ISSUANCE_NOT_COMMITTED" });
  }
  const clockDraft = createRuntimeEventDraftV03({
    event_type: "run.clock-observed", source: "kernel", authority_ref: null,
    risk_tier: proposal.data.effective_risk_tier, related_ids: [],
    payload: {
      clock_id: context.data.clock_id, observed_at: context.data.observed_at, elapsed_ms: context.data.elapsed_ms,
      reason: "action-admission", task_ref: proposal.data.task_ref, failure_ordinal: null, use_ref: context.data.action_id,
    },
  });
  if (clockDraft === null) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: "ACTION_ADMISSION_NOT_COMMITTED" });
  }
  const clock = await appendRuntimeEventV03(session, clockDraft);
  if (!clock.ok) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: clock.classification === "OUTCOME_UNKNOWN"
      ? "RUNTIME_IO_OUTCOME_UNKNOWN" : "ACTION_ADMISSION_NOT_COMMITTED" });
  }
  const priorTaskAdmissions = snapshot.events.filter((event) => event.event_type === "task.action-admitted"
    && (event.payload as RecordValue).task_ref === proposal.data.task_ref).length;
  const currentOutputBytes = Math.max(0, ...snapshot.events
    .filter((event) => event.event_type === "artifact.write-admitted"
      || event.event_type === "task.execution-completed" || event.event_type === "task.execution-failed")
    .map((event) => Number((event.payload as RecordValue).action_output_bytes_after ?? 0)));
  const nextOrdinal = priorTaskAdmissions + 1;
  const nextOutputBytes = currentOutputBytes + proposal.data.budget_delta.output_bytes;
  if (!Number.isSafeInteger(nextOrdinal) || !Number.isSafeInteger(nextOutputBytes)) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: "LIMIT_ADMISSION_BLOCKED" });
  }
  const admissionDraft = createRuntimeEventDraftV03({
    event_type: "task.action-admitted", source: "policy-enforcement-point", authority_ref: authorityRef,
    risk_tier: proposal.data.effective_risk_tier, related_ids: [],
    payload: {
      action_id: context.data.action_id, task_ref: proposal.data.task_ref, lease_id: context.data.lease_id,
      lease_event_ref: lease.event_ref, admission_clock_ref: clock.event_ref, ...bindings,
      execution_ordinal: nextOrdinal, retry_of_failure_ordinal: null,
      fence_epoch: snapshot.current_fence_epoch,
      side_effect_refs: proposal.data.side_effect_refs.map((row) => row.effect_ref), waiver_gate_use_checks: [],
      task_executions_after: nextOrdinal,
      action_output_bytes_after: nextOutputBytes,
    },
  });
  if (admissionDraft === null) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: "ACTION_ADMISSION_NOT_COMMITTED" });
  }
  const admission = await appendRuntimeEventV03(session, admissionDraft);
  if (!admission.ok) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: admission.classification === "OUTCOME_UNKNOWN"
      ? "RUNTIME_IO_OUTCOME_UNKNOWN" : "ACTION_ADMISSION_NOT_COMMITTED" });
  }
  const readback = await verifyRuntimeWriteSessionAdmissionReadbackV03(session, {
    lease_event_ref: lease.event_ref, admission_clock_ref: clock.event_ref,
    action_admission_event_ref: admission.event_ref, manifest_hash: admission.manifest_hash,
  });
  if (!readback.ok) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: "COMMITTED_READBACK_INVALID" });
  }
  const permit = Object.freeze({}) as DispatchPermitV01;
  permits.set(permit, {
    session, action_admission_event_ref: admission.event_ref,
    normalized_dispatch_hash: proposal.data.normalized_dispatch_hash, broker: null, used: false,
  });
  return Object.freeze({
    ok: true, permit, lease_event_ref: lease.event_ref, admission_clock_ref: clock.event_ref,
    action_admission_event_ref: admission.event_ref, committed_manifest_hash: readback.readback.manifest_hash,
  });
}
