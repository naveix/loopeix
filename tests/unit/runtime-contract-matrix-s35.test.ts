import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import * as runtime from "../../src/schema/runtime.js";

type RuntimeModule = Record<string, unknown> & {
  RuntimeEventTypesV02: readonly string[];
  RuntimeEventV02: ZodType;
};

type SchemaDef = {
  type: string;
  shape?: Record<string, ZodType>;
  innerType?: ZodType;
  element?: ZodType;
  items?: readonly ZodType[];
  options?: readonly ZodType[];
  entries?: Record<string, string>;
  values?: readonly unknown[];
  in?: ZodType;
  valueType?: ZodType;
};

type ContractRow = {
  eventType: string;
  constructorName: string;
  source: string;
  authority: string | null;
};

const schemas = runtime as unknown as RuntimeModule;
const HASH = `sha256:${"a".repeat(64)}`;
const ISO = "2026-08-10T12:00:00Z";
const STRING_CANDIDATES = [HASH, "a".repeat(40), ISO, "records/item.json", "application/json", "principal_1", "item-a", "x"];

function schemaDef(schema: ZodType): SchemaDef {
  return (schema as unknown as { def: SchemaDef }).def;
}

function synthesize(schema: ZodType): unknown {
  const def = schemaDef(schema);
  switch (def.type) {
    case "object":
      return Object.fromEntries(Object.entries(def.shape ?? {}).map(([key, child]) => [key, synthesize(child)]));
    case "array": {
      const empty: unknown[] = [];
      if (schema.safeParse(empty).success) return empty;
      return [synthesize(def.element!)];
    }
    case "tuple":
      return (def.items ?? []).map(synthesize);
    case "union":
      return synthesize((def.options ?? [])[0]!);
    case "nullable":
      return null;
    case "optional":
      return undefined;
    case "literal":
      return (def.values ?? [])[0];
    case "enum":
      return Object.values(def.entries ?? {})[0];
    case "string":
      return STRING_CANDIDATES.find((candidate) => schema.safeParse(candidate).success) ?? "x";
    case "number":
      return [1, 0, 2].find((candidate) => schema.safeParse(candidate).success) ?? 1;
    case "boolean":
      return true;
    case "null":
      return null;
    case "record":
      return {};
    case "pipe":
      return synthesize(def.in!);
    case "transform":
      return {};
    default:
      throw new Error(`unsupported Zod fixture node: ${def.type}`);
  }
}

const CONTRACT_ROWS = [
  ["run.initialized", "RunInitializedEventV02", "kernel", null],
  ["run.clock-observed", "RunClockObservedEventV02", "kernel", null],
  ["run.fence-advanced", "RunFenceAdvancedEventV02", "policy-enforcement-point", "principal_1"],
  ["control.abort-requested", "ControlAbortRequestedEventV02", "operator", "principal_1"],
  ["gate.result-required", "GateResultRequiredEventV02", "kernel", null],
  ["gate.result-recorded", "GateResultRecordedEventV02", "evaluator", null],
  ["evaluation.result-required", "EvaluationResultRequiredEventV02", "kernel", null],
  ["evaluation.result-recorded", "EvaluationResultRecordedEventV02", "evaluator", null],
  ["authority.human-authorization-recorded", "AuthorityHumanAuthorizationRecordedEventV02", "operator", "principal_1"],
  ["authority.envelope-recorded", "AuthorityEnvelopeRecordedEventV02", "policy-enforcement-point", "principal_1"],
  ["approval.recommendation-recorded", "ApprovalRecommendationRecordedEventV02", "evaluator", null],
  ["policy.decision-recorded", "PolicyDecisionRecordedEventV02", "policy-enforcement-point", "principal_1"],
  ["authority.waiver-recorded", "AuthorityWaiverRecordedEventV02", "operator", "principal_1"],
  ["authority.grant-revoked", "AuthorityGrantRevokedEventV02", "operator", "principal_1"],
  ["evidence.recorded", "EvidenceRecordedEventV02", "kernel", null],
  ["observation.manual-recorded", "ObservationManualRecordedEventV02", "operator", "principal_1"],
  ["claim.recorded", "ClaimRecordedEventV02", "kernel", null],
  ["finding.recorded", "FindingRecordedEventV02", "evaluator", null],
  ["waiver.recorded", "WaiverRecordedEventV02", "operator", "principal_1"],
  ["lease.issued", "LeaseIssuedEventV02", "policy-enforcement-point", "principal_1"],
  ["task.action-admitted", "TaskActionAdmittedEventV02", "policy-enforcement-point", "principal_1"],
  ["tool.call-admitted", "ToolCallAdmittedEventV02", "policy-enforcement-point", "principal_1"],
  ["artifact.write-admitted", "ArtifactWriteAdmittedEventV02", "policy-enforcement-point", "principal_1"],
  ["limit.admission-blocked", "LimitAdmissionBlockedEventV02", "policy-enforcement-point", "principal_1"],
  ["task.execution-started", "TaskExecutionStartedEventV02", "adapter", null],
  ["task.execution-completed", "TaskExecutionCompletedEventV02", "adapter", null],
  ["task.progress-fact-recorded", "TaskProgressFactRecordedEventV02", "adapter", null],
  ["task.execution-failed", "TaskExecutionFailedEventV02", "adapter", null],
  ["task.action-outcome-unknown", "TaskActionOutcomeUnknownEventV02", "adapter", null],
  ["task.action-outcome-reconciled", "TaskActionOutcomeReconciledEventV02", "integrity", null],
  ["artifact.recorded", "ArtifactRecordedEventV02", "kernel", null],
  ["record.redaction-derivative-recorded", "RecordRedactionDerivativeRecordedEventV02", "kernel", null],
  ["record.custody-state-recorded", "RecordCustodyStateRecordedEventV02", "kernel", null],
  ["record.export-decision-recorded", "RecordExportDecisionRecordedEventV02", "evaluator", null],
  ["effect.outcome", "EffectOutcomeEventV02", "adapter", null],
  ["task.action-settled", "TaskActionSettledEventV02", "kernel", null],
  ["loop.attempt-completed", "LoopAttemptCompletedEventV02", "kernel", null],
  ["task.progress-observed", "TaskProgressObservedEventV02", "evaluator", null],
  ["run.terminal-freeze-entered", "RunTerminalFreezeEnteredEventV02", "evaluator", null],
  ["run.terminal-freeze-revised", "RunTerminalFreezeRevisedEventV02", "evaluator", null],
  ["run.compensation-requested", "RunCompensationRequestedEventV02", "evaluator", null],
  ["run.compensation-request-revised", "RunCompensationRequestRevisedEventV02", "evaluator", null],
  ["run.compensation-phase-entered", "RunCompensationPhaseEnteredEventV02", "evaluator", null],
  ["run.compensation-candidate-escalated", "RunCompensationCandidateEscalatedEventV02", "evaluator", null],
  ["compensation.settled", "CompensationSettledEventV02", "evaluator", null],
  ["run.terminal-sealed", "RunTerminalSealedEventV02", "evaluator", null],
] satisfies readonly (readonly [string, string, string, string | null])[];

const rows: ContractRow[] = CONTRACT_ROWS.map(([eventType, constructorName, source, authority]) => ({
  eventType,
  constructorName,
  source,
  authority,
}));

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("expected fixture object");
  return value as Record<string, unknown>;
}

function ledgerRef(sequence: number): Record<string, unknown> {
  return { ledger_sequence: sequence, event_hash: HASH };
}

function terminalStates(): Record<string, unknown>[] {
  return [
    { state: "completed", condition_mode: "all", conditions: [{ source: "success-criterion", ref: "criterion-main", outcome: "satisfied" }], priority: 100 },
    { state: "held", condition_mode: "any", conditions: [{ source: "gate", ref: "gate-a", outcome: "hold" }], priority: 300 },
    { state: "blocked", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "contention", outcome: "observed" }], priority: 200 },
    { state: "failed", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "invalid-input", outcome: "observed" }], priority: 600 },
    { state: "stalled", condition_mode: "any", conditions: [{ source: "progress", ref: "progress-main", outcome: "stalled" }], priority: 400 },
    { state: "exhausted", condition_mode: "any", conditions: [{ source: "limit", ref: "max-loop-attempts", outcome: "reached" }], priority: 500 },
    { state: "aborted", condition_mode: "any", conditions: [{ source: "control", ref: "abort-requested", outcome: "present" }], priority: 700 },
  ];
}

function normalizeAuthorityScope(scope: Record<string, unknown>): void {
  const subject = object(scope.authority_subject);
  const mission = object(subject.mission);
  mission.terminal_states = terminalStates();
  const repository = object(subject.repository);
  const baseRef = object(repository.base_ref);
  object(baseRef.object_id).value = "a".repeat(40);
  const initialState = object(repository.initial_state);
  object(initialState.head).value = "a".repeat(40);
  object(initialState.merge_base).value = "a".repeat(40);
}

function normalizeFixture(row: ContractRow, event: Record<string, unknown>): void {
  const payload = object(event.payload);
  switch (row.eventType) {
    case "run.clock-observed":
      Object.assign(payload, { reason: "action-admission", task_ref: "task-main", failure_ordinal: null, use_ref: "action_1" });
      break;
    case "run.fence-advanced":
      Object.assign(payload, { previous_fence_epoch: 0, fence_epoch: 1 });
      break;
    case "authority.human-authorization-recorded":
      Object.assign(payload, { run_id: event.run_id, authenticated_principal_ref: row.authority, issued_at: ISO, expires_at: "2026-08-10T12:05:00Z" });
      break;
    case "authority.envelope-recorded":
      Object.assign(payload, { run_id: event.run_id, issuer_principal_ref: row.authority, subject_ref: "agent_1", issued_at: ISO, expires_at: "2026-08-10T12:05:00Z" });
      break;
    case "approval.recommendation-recorded":
      Object.assign(payload, {
        run_id: event.run_id, phase: "work", compensation_ref: null, decision: "allow", condition_hashes: [],
        evidence_refs: [{ record_kind: "evidence", record_id: "evidence_1", record_event_ref: ledgerRef(1) }],
        evaluator_actor_ref: "evaluator_1", evaluator_stable_identity_hash: `sha256:${"b".repeat(64)}`,
        issued_at: ISO, expires_at: "2026-08-10T12:05:00Z",
      });
      (payload.reason_codes as Record<string, unknown>[]).forEach((reason) => { reason.policy_digest = payload.policy_digest; });
      break;
    case "policy.decision-recorded": {
      Object.assign(payload, { run_id: event.run_id, phase: "work", compensation_ref: null, issued_at: ISO, expires_at: "2026-08-10T12:05:00Z" });
      const proposal = object(payload.action_proposal);
      Object.assign(proposal, {
        run_id: payload.run_id, plan_hash: payload.plan_hash, task_ref: payload.task_ref, phase: payload.phase,
        compensation_ref: null, policy_action_kind: "planning", action_approval_class: "automatic",
      });
      const changeSet = object(proposal.authorized_change_set);
      object(changeSet.expected_pre_head).value = "a".repeat(40);
      object(changeSet.required_post_head).value = "a".repeat(40);
      Object.assign(changeSet, { transition_mode: "read-only", mode: "no-change", changes: [] });
      const scope = object(proposal.action_scope);
      normalizeAuthorityScope(scope);
      const flow = object(proposal.data_flow);
      flow.data_flow_hash = hashCanonical({
        purpose: "action-data-flow-v02", readable_classifications: flow.readable_classifications,
        exportable_classifications: flow.exportable_classifications, sink_refs: flow.sink_refs,
        data_access_mode: flow.data_access_mode,
      });
      proposal.on_behalf_of_chain_hash = hashCanonical({ purpose: "action-on-behalf-of-chain-v02", on_behalf_of_chain: proposal.on_behalf_of_chain });
      proposal.authorized_change_set_hash = hashCanonical({ purpose: "authorized-repository-change-set-v02", ...changeSet });
      proposal.normalized_dispatch_hash = hashCanonical({ purpose: "normalized-action-dispatch-v02", ...object(proposal.normalized_dispatch) });
      proposal.action_scope_hash = hashCanonical(scope);
      const { action_proposal_hash: _ignored, ...proposalPreimage } = proposal;
      proposal.action_proposal_hash = hashCanonical({ purpose: "action-proposal-v02", ...proposalPreimage });
      Object.assign(payload, {
        action_proposal_id: proposal.action_proposal_id, action_proposal_hash: proposal.action_proposal_hash,
        action_actor_ref: proposal.action_actor_ref, action_actor_stable_identity_hash: proposal.action_actor_stable_identity_hash,
        on_behalf_of_chain_hash: proposal.on_behalf_of_chain_hash, repository_root_ref: proposal.repository_root_ref,
        repository_base_ref_identity_hash: proposal.repository_base_ref_identity_hash,
        repository_pre_state_hash: proposal.repository_pre_state_hash, authorized_change_set_hash: proposal.authorized_change_set_hash,
        normalized_dispatch_hash: proposal.normalized_dispatch_hash, action_scope_hash: proposal.action_scope_hash,
        action_class: proposal.action_class, classifier_input_hash: object(proposal.classification_binding).classifier_input_hash,
        classifier_registry_hash: object(proposal.classification_binding).classifier_registry_hash,
        classifier_rule_hash: object(proposal.classification_binding).classifier_rule_hash,
        data_flow_hash: flow.data_flow_hash, policy_action_kind: "planning", action_approval_class: "automatic",
        quorum_requirement_hash: null, recommendation_event_refs: [], condition_hashes: [], failed_condition_hashes: [],
        decision: "allow", decision_disposition: "lease-eligible", evidence_refs: [],
      });
      (payload.reason_codes as Record<string, unknown>[]).forEach((reason) => { reason.policy_digest = payload.policy_digest; });
      break;
    }
    case "authority.waiver-recorded": {
      Object.assign(payload, { run_id: event.run_id, issuer_principal_ref: row.authority, issued_at: ISO, expires_at: "2026-08-10T12:05:00Z", allowed_gate_refs: ["gate-a"], max_risk_tier: "T2" });
      payload.approval_evidence_refs = [{ record_kind: "human-authorization", record_id: "authorization_1", record_event_ref: ledgerRef(1) }];
      const scope = object(payload.authority_scope);
      normalizeAuthorityScope(scope);
      Object.assign(scope, {
        action_class: "gate-waiver", resource_selectors: [{ kind: "plan-object", object_kind: "gate", object_ref: "gate-a" }],
        operations: ["waive"], max_risk_tier: "T2",
      });
      Object.assign(object(scope.side_effect_constraints), { allowed_effect_classes: ["none"], allowed_effect_refs: [] });
      Object.assign(object(scope.data_constraints), { readable_classifications: [], exportable_classifications: [], sink_refs: [] });
      payload.action_scope_hash = hashCanonical(scope);
      break;
    }
    case "authority.grant-revoked":
      Object.assign(event, { sequence: 4, previous_event_hash: HASH });
      Object.assign(payload, { run_id: event.run_id, previous_revocation_epoch: 0, revocation_epoch: 1, effective_prefix_ref: ledgerRef(3), revoker_identity_ref: row.authority });
      break;
    case "lease.issued":
      Object.assign(payload, { issued_at: ISO, expires_at: "2026-08-10T12:05:00Z" });
      break;
    case "task.progress-fact-recorded":
      Object.assign(event, { sequence: 2 });
      Object.assign(payload, { result_event_ref: ledgerRef(1), facts: { "completed-items": 1 } });
      break;
    case "record.custody-state-recorded":
      Object.assign(payload, { export_state: "not-exportable", export_reason: "no-current-decision", export_decision_event_ref: null });
      break;
    case "record.export-decision-recorded":
      Object.assign(payload, { decision: "not-exportable", credential_scan_evidence_refs: [], privacy_review_evidence_refs: [] });
      payload.subject_hash = hashCanonical({
        purpose: "export-subject-v02", schema_version: "0.2", run_id: event.run_id,
        subject_kind: payload.subject_kind, subject_ref: payload.subject_ref,
        original_record_hash: payload.original_record_hash, original_content_hash: payload.original_content_hash,
        selected_bytes: payload.selected_bytes, policy_version: payload.policy_version,
      });
      object(payload.selected_bytes).ref = payload.subject_ref;
      payload.subject_hash = hashCanonical({
        purpose: "export-subject-v02", schema_version: "0.2", run_id: event.run_id,
        subject_kind: payload.subject_kind, subject_ref: payload.subject_ref,
        original_record_hash: payload.original_record_hash, original_content_hash: payload.original_content_hash,
        selected_bytes: payload.selected_bytes, policy_version: payload.policy_version,
      });
      break;
    case "task.action-settled": {
      const post = object(payload.repository_post_state);
      object(post.head).value = "a".repeat(40);
      object(post.merge_base).value = "a".repeat(40);
      const { repository_state_hash: _ignored, ...postFields } = post;
      post.repository_state_hash = hashCanonical({ purpose: "repository-state-v02", ...postFields });
      const observed = object(payload.observed_change_set);
      Object.assign(observed, {
        repository_root_ref: payload.repository_root_ref, base_ref_identity_hash: payload.repository_base_ref_identity_hash,
        repository_pre_state_hash: post.repository_state_hash, repository_post_state_hash: post.repository_state_hash,
        head_before: post.head, head_after: post.head, changes: [],
      });
      const { observed_change_set_hash: _oldObserved, ...observedFields } = observed;
      observed.observed_change_set_hash = hashCanonical({ purpose: "observed-repository-change-set-v02", ...observedFields });
      Object.assign(payload, {
        repository_root_ref: post.repository_root_ref, repository_base_ref_identity_hash: post.base_ref_identity_hash,
        repository_pre_state_hash: post.repository_state_hash, repository_post_state_hash: post.repository_state_hash,
        observed_change_set_hash: observed.observed_change_set_hash, repository_transition_status: "unchanged",
      });
      break;
    }
    case "task.progress-observed":
      payload.sample = { status: "source-missing", sample_ref: null, sample_hash: null, value_status: "value-unparseable", sample_value: null };
      break;
    case "run.terminal-freeze-revised":
      Object.assign(payload, { previous_candidate: "completed", candidate: "held" });
      break;
    case "run.compensation-requested":
      Object.assign(payload, { pending_terminal: "stalled", activation_reason: "terminal-stall" });
      break;
    case "run.compensation-request-revised":
      Object.assign(payload, { previous_pending_terminal: "stalled", pending_terminal: "exhausted", activation_reason: "terminal-exhaustion" });
      break;
    case "run.compensation-candidate-escalated":
      Object.assign(payload, { previous_pending_terminal: "stalled", pending_terminal: "exhausted", activation_reason: "terminal-exhaustion" });
      break;
    case "run.terminal-sealed":
      Object.assign(payload, { previous_fence_epoch: 0, fence_epoch: 1 });
      break;
  }
}

function fixture(row: ContractRow): Record<string, unknown> {
  const constructor = schemas[row.constructorName];
  if (!constructor || typeof constructor !== "object" || !("safeParse" in constructor)) {
    throw new Error(`missing runtime constructor ${row.constructorName}`);
  }
  const event = synthesize(constructor as ZodType) as Record<string, unknown>;
  Object.assign(event, { source: row.source, authority_ref: row.authority });
  normalizeFixture(row, event);
  return event;
}

describe("S35 independent runtime constructor contract matrix", () => {
  it("pins 46 independent constructor/source/authority rows in canonical order", () => {
    expect(rows.map((row) => row.eventType)).toEqual(schemas.RuntimeEventTypesV02);
    expect(new Set(rows.map((row) => row.constructorName)).size).toBe(46);
  });

  it("enforces bounded V02 identifiers and exact second timestamps at the event boundary", () => {
    const row = rows.find((candidate) => candidate.eventType === "run.initialized");
    if (row === undefined) throw new Error("missing run.initialized contract row");
    const constructor = schemas[row.constructorName] as ZodType;

    const oversizedId = fixture(row);
    oversizedId.event_id = `event_${"a".repeat(155)}`;
    expect(constructor.safeParse(oversizedId).success).toBe(false);

    const fractionalTimestamp = fixture(row);
    fractionalTimestamp.timestamp = "2026-08-10T12:00:00.123Z";
    expect(constructor.safeParse(fractionalTimestamp).success).toBe(false);
  });

  it.each(rows)("$eventType accepts its valid contract fixture", (row) => {
    const constructor = schemas[row.constructorName] as ZodType;
    const event = fixture(row);
    const result = constructor.safeParse(event);
    expect(result.success, result.success ? undefined : JSON.stringify(result.error.issues)).toBe(true);
    expect(schemas.RuntimeEventV02.safeParse(event).success).toBe(true);
  });

  it.each(rows)("$eventType rejects unknown payload keys", (row) => {
    const constructor = schemas[row.constructorName] as ZodType;
    const event = fixture(row);
    event.payload = { ...object(event.payload), unknown_contract_key: true };
    expect(constructor.safeParse(event).success).toBe(false);
  });

  it.each(rows)("$eventType rejects the wrong source", (row) => {
    const constructor = schemas[row.constructorName] as ZodType;
    const event = fixture(row);
    event.source = row.source === "kernel" ? "adapter" : "kernel";
    expect(constructor.safeParse(event).success).toBe(false);
  });

  it.each(rows)("$eventType rejects wrong or null authority", (row) => {
    const constructor = schemas[row.constructorName] as ZodType;
    const event = fixture(row);
    event.authority_ref = row.authority === null ? "wrong_authority" : null;
    expect(constructor.safeParse(event).success).toBe(false);
  });

  it("accepts a useful completed-action progress trace through the attempt boundary", () => {
    const byType = new Map(rows.map((row) => [row.eventType, row]));
    const row = (eventType: string): ContractRow => {
      const found = byType.get(eventType);
      if (!found) throw new Error(`missing contract row ${eventType}`);
      return found;
    };
    const completed = fixture(row("task.execution-completed"));
    Object.assign(completed, { sequence: 10, event_hash: `sha256:${"1".repeat(64)}` });
    const completedPayload = object(completed.payload);

    const fact = fixture(row("task.progress-fact-recorded"));
    Object.assign(fact, { sequence: 11, event_hash: `sha256:${"2".repeat(64)}` });
    Object.assign(object(fact.payload), {
      action_id: completedPayload.action_id,
      task_ref: completedPayload.task_ref,
      result_event_ref: { ledger_sequence: completed.sequence, event_hash: completed.event_hash },
    });

    const settlement = fixture(row("task.action-settled"));
    Object.assign(settlement, { sequence: 12, event_hash: `sha256:${"3".repeat(64)}` });
    Object.assign(object(settlement.payload), {
      action_id: completedPayload.action_id,
      task_ref: completedPayload.task_ref,
      terminal_event_ref: { ledger_sequence: completed.sequence, event_hash: completed.event_hash },
    });

    const observation = fixture(row("task.progress-observed"));
    Object.assign(observation, { sequence: 13, event_hash: `sha256:${"4".repeat(64)}` });
    Object.assign(object(observation.payload), {
      task_ref: completedPayload.task_ref,
      sample: {
        status: "source-present",
        sample_ref: { ledger_sequence: fact.sequence, event_hash: fact.event_hash },
        sample_hash: fact.event_hash,
        value_status: "parseable",
        sample_value: 1,
      },
    });

    const attempt = fixture(row("loop.attempt-completed"));
    Object.assign(attempt, { sequence: 14, event_hash: `sha256:${"5".repeat(64)}` });
    Object.assign(object(attempt.payload), {
      attempt_ordinal: 1,
      previous_attempt_event_ref: null,
      prefix_sequence: observation.sequence,
      prefix_head_hash: observation.event_hash,
      work_action_refs: [{ ledger_sequence: settlement.sequence, event_hash: settlement.event_hash }],
      progress_observation_refs: [{ ledger_sequence: observation.sequence, event_hash: observation.event_hash }],
    });

    const trace = [completed, fact, settlement, observation, attempt];
    expect(trace.map((event) => event.event_type)).toEqual([
      "task.execution-completed",
      "task.progress-fact-recorded",
      "task.action-settled",
      "task.progress-observed",
      "loop.attempt-completed",
    ]);
    expect(trace.map((event) => event.sequence)).toEqual([10, 11, 12, 13, 14]);
    trace.forEach((event) => {
      const parsed = schemas.RuntimeEventV02.safeParse(event);
      expect(parsed.success, parsed.success ? undefined : JSON.stringify(parsed.error.issues)).toBe(true);
    });
  });
});
