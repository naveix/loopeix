import { parseDocument } from "yaml";
import { hashCanonical } from "../hash.js";
import { RuntimeEventV02, type RuntimeEventV02Value } from "../schema/runtime.js";

export type RuntimeLedgerV02FailureReason =
  | "LEDGER_SYNTAX_INVALID"
  | "LEDGER_EVENT_SCHEMA_INVALID"
  | "LEDGER_HASH_CHAIN_INVALID"
  | "LEDGER_HISTORY_INVALID";

export type RuntimeLedgerV02StructuralFailureReason = Exclude<
  RuntimeLedgerV02FailureReason,
  "LEDGER_HISTORY_INVALID"
>;

export type RuntimeLedgerV02Issue = Readonly<{
  path: string;
  message: string;
}>;

export type RuntimeLedgerV02ValidationResult =
  | Readonly<{
      ok: true;
      events: readonly RuntimeEventV02Value[];
      sealed: boolean;
    }>
  | Readonly<{
      ok: false;
      reason: RuntimeLedgerV02FailureReason;
      issues: readonly RuntimeLedgerV02Issue[];
    }>;

export type RuntimeLedgerV02StructuralValidationResult =
  | Readonly<{
      ok: true;
      events: readonly RuntimeEventV02Value[];
    }>
  | Readonly<{
      ok: false;
      reason: RuntimeLedgerV02StructuralFailureReason;
      issues: readonly RuntimeLedgerV02Issue[];
    }>;

type RuntimeLedgerV02SyntaxFailure = Readonly<{
  ok: false;
  reason: "LEDGER_SYNTAX_INVALID";
  issues: readonly RuntimeLedgerV02Issue[];
}>;

function failure<E extends RuntimeLedgerV02FailureReason>(
  reason: E,
  path: string,
  message: string,
): Readonly<{ ok: false; reason: E; issues: readonly RuntimeLedgerV02Issue[] }> {
  return { ok: false, reason, issues: [{ path, message }] };
}

function ledgerRefKey(sequence: number, eventHash: string): string {
  return `${sequence}\0${eventHash}`;
}

function collectLedgerRefs(value: unknown, path: string, refs: Array<{ sequence: number; eventHash: string; path: string }>): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectLedgerRefs(entry, `${path}[${index}]`, refs));
    return;
  }
  if (typeof value !== "object" || value === null) return;
  const record = value as Record<string, unknown>;
  if (Number.isSafeInteger(record.ledger_sequence) && typeof record.event_hash === "string") {
    refs.push({
      sequence: record.ledger_sequence as number,
      eventHash: record.event_hash,
      path,
    });
    return;
  }
  for (const [key, entry] of Object.entries(record)) collectLedgerRefs(entry, `${path}.${key}`, refs);
}

type RecordDependencyRefLike = Readonly<{
  record_kind: string;
  record_id: string;
  record_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
}>;

function collectRecordDependencyRefs(value: unknown, path: string, refs: Array<{ ref: RecordDependencyRefLike; path: string }>): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectRecordDependencyRefs(entry, `${path}[${index}]`, refs));
    return;
  }
  if (typeof value !== "object" || value === null) return;
  const record = value as Record<string, unknown>;
  const eventRef = record.record_event_ref;
  if (typeof record.record_kind === "string" && typeof record.record_id === "string"
    && typeof eventRef === "object" && eventRef !== null
    && Number.isSafeInteger((eventRef as Record<string, unknown>).ledger_sequence)
    && typeof (eventRef as Record<string, unknown>).event_hash === "string") {
    refs.push({ ref: record as RecordDependencyRefLike, path });
    return;
  }
  for (const [key, entry] of Object.entries(record)) collectRecordDependencyRefs(entry, `${path}.${key}`, refs);
}

const RECORD_TARGETS: Readonly<Record<string, Readonly<{ eventType: RuntimeEventV02Value["event_type"]; idField: string }>>> = {
  "agency-recommendation": { eventType: "approval.recommendation-recorded", idField: "recommendation_id" },
  artifact: { eventType: "artifact.recorded", idField: "artifact_ref" },
  "authority-envelope": { eventType: "authority.envelope-recorded", idField: "authority_envelope_id" },
  "authority-revocation": { eventType: "authority.grant-revoked", idField: "revocation_id" },
  claim: { eventType: "claim.recorded", idField: "claim_id" },
  "evaluation-result": { eventType: "evaluation.result-recorded", idField: "result_id" },
  evidence: { eventType: "evidence.recorded", idField: "evidence_id" },
  "export-decision": { eventType: "record.export-decision-recorded", idField: "decision_id" },
  finding: { eventType: "finding.recorded", idField: "finding_id" },
  "gate-result": { eventType: "gate.result-recorded", idField: "result_id" },
  "gate-waiver-authority": { eventType: "authority.waiver-recorded", idField: "authority_record_id" },
  "human-authorization": { eventType: "authority.human-authorization-recorded", idField: "authorization_id" },
  "manual-observation": { eventType: "observation.manual-recorded", idField: "observation_id" },
  "task-result": { eventType: "task.execution-completed", idField: "result_id" },
  waiver: { eventType: "waiver.recorded", idField: "waiver_id" },
};

function payloadRecord(event: RuntimeEventV02Value): Record<string, unknown> {
  return event.payload as unknown as Record<string, unknown>;
}

function validateEarlierReferences(
  events: readonly RuntimeEventV02Value[],
): RuntimeLedgerV02ValidationResult | null {
  const priorRefs = new Set<string>();
  for (const [index, event] of events.entries()) {
    const refs: Array<{ sequence: number; eventHash: string; path: string }> = [];
    collectLedgerRefs(event.payload, `event[${index}].payload`, refs);
    for (const ref of refs) {
      if (ref.sequence >= event.sequence || !priorRefs.has(ledgerRefKey(ref.sequence, ref.eventHash))) {
        return failure(
          "LEDGER_HISTORY_INVALID",
          ref.path,
          "LedgerRef must resolve to an exact earlier event in this run.",
        );
      }
    }
    priorRefs.add(ledgerRefKey(event.sequence, event.event_hash));
  }
  return null;
}

function validateTypedRecordReferences(events: readonly RuntimeEventV02Value[]): RuntimeLedgerV02ValidationResult | null {
  const eventByRef = new Map(events.map((event) => [ledgerRefKey(event.sequence, event.event_hash), event]));
  for (const [index, event] of events.entries()) {
    const refs: Array<{ ref: RecordDependencyRefLike; path: string }> = [];
    collectRecordDependencyRefs(event.payload, `event[${index}].payload`, refs);
    for (const { ref, path } of refs) {
      const targetRule = RECORD_TARGETS[ref.record_kind];
      const target = eventByRef.get(ledgerRefKey(ref.record_event_ref.ledger_sequence, ref.record_event_ref.event_hash));
      const eventTypeMatches = target !== undefined && (
        ref.record_kind === "task-result"
          ? target.event_type === "task.execution-completed" || target.event_type === "task.execution-failed"
          : targetRule !== undefined && target.event_type === targetRule.eventType
      );
      if (targetRule === undefined || target === undefined || !eventTypeMatches
        || payloadRecord(target)[targetRule.idField] !== ref.record_id) {
        return failure("LEDGER_HISTORY_INVALID", path, "RecordDependencyRef must resolve to the exact typed record event and record ID.");
      }
    }
  }
  return null;
}

function validateEventLineage(events: readonly RuntimeEventV02Value[]): RuntimeLedgerV02ValidationResult | null {
  const eventByRef = new Map(events.map((event) => [ledgerRefKey(event.sequence, event.event_hash), event]));
  const resolve = (ref: { ledger_sequence: number; event_hash: string }): RuntimeEventV02Value | undefined =>
    eventByRef.get(ledgerRefKey(ref.ledger_sequence, ref.event_hash));

  for (const [index, event] of events.entries()) {
    if (event.event_type === "gate.result-recorded") {
      const required = resolve(event.payload.required_event_ref);
      if (required?.event_type !== "gate.result-required" || required.payload.gate_ref !== event.payload.gate_ref) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.required_event_ref`, "Gate result must resolve to its matching required event.");
      }
    }
    if (event.event_type === "waiver.recorded") {
      const authority = resolve(event.payload.authority_record_ref);
      const required = resolve(event.payload.required_event_ref);
      const clock = resolve(event.payload.boundary_clock_ref);
      const reviewedThrough = resolve(event.payload.reviewed_through_ref);
      if (authority?.event_type !== "authority.waiver-recorded"
        || !authority.payload.allowed_gate_refs.includes(event.payload.gate_ref)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.authority_record_ref`, "Waiver must resolve to an authority record that permits the same gate.");
      }
      if (required?.event_type !== "gate.result-required" || required.payload.gate_ref !== event.payload.gate_ref) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.required_event_ref`, "Waiver must resolve to the matching required gate event.");
      }
      if (clock?.event_type !== "run.clock-observed" || clock.payload.reason !== "waiver-boundary"
        || clock.payload.use_ref !== event.payload.waiver_id || clock !== events[index - 1]) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.boundary_clock_ref`, "Waiver must immediately consume its dedicated boundary clock.");
      }
      if (reviewedThrough === undefined || reviewedThrough.sequence + 1 !== clock.sequence
        || clock.previous_event_hash !== reviewedThrough.event_hash) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.reviewed_through_ref`, "Waiver boundary clock must immediately succeed the reviewed prefix.");
      }
    }
    if (event.event_type === "evaluation.result-recorded") {
      const required = resolve(event.payload.required_event_ref);
      if (required?.event_type !== "evaluation.result-required" || required.payload.evaluation_ref !== event.payload.evaluation_ref) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.required_event_ref`, "Evaluation result must resolve to its matching required event.");
      }
    }
    if (event.event_type === "lease.issued") {
      const decision = resolve(event.payload.policy_decision_ref);
      const authorityEnvelope = resolve(event.payload.authority_envelope_ref);
      if (decision?.event_type !== "policy.decision-recorded" || decision.payload.decision !== "allow"
        || decision.payload.decision_disposition !== "lease-eligible"
        || decision.payload.action_proposal_id !== event.payload.action_proposal_id
        || decision.payload.task_ref !== event.payload.task_ref) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.policy_decision_ref`, "Lease must resolve to the matching lease-eligible allow decision.");
      }
      if (authorityEnvelope?.event_type !== "authority.envelope-recorded"
        || authorityEnvelope.payload.authority_envelope_id !== decision.payload.authority_envelope_ref.record_id) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.authority_envelope_ref`, "Lease must resolve to the same authority envelope as its decision.");
      }
    }
    if (event.event_type === "task.action-admitted") {
      const lease = resolve(event.payload.lease_event_ref);
      const clock = resolve(event.payload.admission_clock_ref);
      if (lease?.event_type !== "lease.issued" || lease.payload.lease_id !== event.payload.lease_id
        || lease.payload.task_ref !== event.payload.task_ref || lease.payload.action_proposal_id !== event.payload.action_proposal_id) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.lease_event_ref`, "Action admission must consume its exact matching lease.");
      }
      if (clock?.event_type !== "run.clock-observed" || clock.payload.reason !== "action-admission"
        || clock.payload.use_ref !== event.payload.action_id || clock.sequence !== event.sequence - 1) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.admission_clock_ref`, "Action admission must immediately consume its dedicated clock event.");
      }
    }
    if (event.event_type === "evidence.recorded") {
      const producer = resolve(event.payload.producer_event_ref);
      const producerTypes: Readonly<Record<typeof event.payload.evidence_kind, readonly RuntimeEventV02Value["event_type"][]>> = {
        "command-capture": ["task.execution-completed", "task.execution-failed"],
        "filesystem-capture": ["artifact.recorded"],
        "browser-capture": ["task.execution-completed", "task.execution-failed"],
        "source-citation": ["task.execution-completed"],
        "human-authorization": ["authority.human-authorization-recorded"],
        "manual-observation": ["observation.manual-recorded"],
      };
      if (producer === undefined || !producerTypes[event.payload.evidence_kind].includes(producer.event_type)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.producer_event_ref`, "Evidence producer does not match the evidence kind's canonical event class.");
      }
      const rootTypes: Readonly<Record<string, readonly RuntimeEventV02Value["event_type"][]>> = {
        command: ["task.execution-completed", "task.execution-failed"],
        filesystem: ["artifact.recorded"],
        browser: ["task.execution-completed", "task.execution-failed"],
        source: ["task.execution-completed"],
        "human-authorization": ["authority.human-authorization-recorded"],
        "manual-observation": ["observation.manual-recorded"],
      };
      for (const [rootIndex, root] of event.payload.independence_roots.entries()) {
        const rootEvent = resolve(root.root_event_ref);
        if (rootEvent === undefined || !(rootTypes[root.source_class] ?? []).includes(rootEvent.event_type)) {
          return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.independence_roots[${rootIndex}].root_event_ref`, "Evidence independence root does not resolve to its declared source class.");
        }
      }
    }
    if (event.event_type === "artifact.recorded") {
      const admission = resolve(event.payload.write_admission_ref);
      const previous = events[index - 1];
      if (admission?.event_type !== "artifact.write-admitted" || admission !== previous
        || admission.payload.artifact_ref !== event.payload.artifact_ref
        || admission.payload.action_id !== event.payload.producer_action_id
        || admission.payload.task_ref !== event.payload.producer_task_ref
        || admission.payload.artifact_path !== event.payload.artifact_path) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.write_admission_ref`, "Artifact recording must immediately follow its exact write admission.");
      }
    }
    if (event.event_type === "task.progress-fact-recorded") {
      const result = resolve(event.payload.result_event_ref);
      if (result?.event_type !== "task.execution-completed" || result.payload.action_id !== event.payload.action_id
        || result.payload.task_ref !== event.payload.task_ref) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.result_event_ref`, "Progress fact must resolve to its matching successful task result event.");
      }
    }
    if (event.event_type === "task.action-settled") {
      const terminal = resolve(event.payload.terminal_event_ref);
      const allowedTerminal = terminal?.event_type === "task.execution-completed"
        || terminal?.event_type === "task.execution-failed"
        || terminal?.event_type === "task.action-outcome-unknown"
        || terminal?.event_type === "task.action-outcome-reconciled";
      if (!allowedTerminal || payloadRecord(terminal)["action_id"] !== event.payload.action_id
        || payloadRecord(terminal)["task_ref"] !== event.payload.task_ref) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.terminal_event_ref`, "Action settlement must resolve to its matching terminal event.");
      }
      for (const [outcomeIndex, outcome] of event.payload.effect_outcomes.entries()) {
        const outcomeEvent = resolve(outcome.outcome_event_ref);
        if (outcomeEvent?.event_type !== "effect.outcome" || outcomeEvent.payload.action_id !== event.payload.action_id
          || outcomeEvent.payload.effect_ref !== outcome.effect_ref || outcomeEvent.payload.outcome !== outcome.outcome) {
          return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.effect_outcomes[${outcomeIndex}]`, "Settled effect must resolve to its exact immutable outcome event.");
        }
      }
    }
    if (event.event_type === "authority.grant-revoked") {
      const prefix = resolve(event.payload.effective_prefix_ref);
      if (prefix !== events[index - 1]) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.effective_prefix_ref`, "Authority revocation must immediately follow its effective prefix.");
      }
    }
    if (event.event_type === "loop.attempt-completed") {
      const previous = events[index - 1];
      if (previous === undefined || event.payload.prefix_sequence !== previous.sequence || event.payload.prefix_head_hash !== previous.event_hash) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload`, "Loop attempt must bind the immediately preceding prefix.");
      }
      const priorAttempts = events.slice(0, index).filter((candidate) => candidate.event_type === "loop.attempt-completed");
      const expectedOrdinal = priorAttempts.length + 1;
      const expectedPrevious = priorAttempts.at(-1);
      const actualPrevious = event.payload.previous_attempt_event_ref;
      if (event.payload.attempt_ordinal !== expectedOrdinal
        || (expectedPrevious === undefined) !== (actualPrevious === null)
        || (expectedPrevious !== undefined && actualPrevious !== null
          && (actualPrevious.ledger_sequence !== expectedPrevious.sequence || actualPrevious.event_hash !== expectedPrevious.event_hash))) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.previous_attempt_event_ref`, "Loop attempts must have contiguous ordinals and exact prior-attempt lineage.");
      }
    }
  }
  return null;
}

function validateUniqueConsumption(
  events: readonly RuntimeEventV02Value[],
): RuntimeLedgerV02ValidationResult | null {
  const leaseIds = new Set<string>();
  const leasedDecisionRefs = new Set<string>();
  const consumedLeaseRefs = new Set<string>();
  const waiverIds = new Set<string>();
  const consumedWaiverRefs = new Set<string>();

  for (const [index, event] of events.entries()) {
    if (event.event_type === "lease.issued") {
      if (leaseIds.has(event.payload.lease_id)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.lease_id`, "Lease IDs must be globally unique in the run.");
      }
      leaseIds.add(event.payload.lease_id);
      const decisionKey = ledgerRefKey(
        event.payload.policy_decision_ref.ledger_sequence,
        event.payload.policy_decision_ref.event_hash,
      );
      if (leasedDecisionRefs.has(decisionKey)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.policy_decision_ref`, "A policy decision may issue at most one lease.");
      }
      leasedDecisionRefs.add(decisionKey);
    }

    if (event.event_type === "task.action-admitted") {
      const leaseKey = ledgerRefKey(event.payload.lease_event_ref.ledger_sequence, event.payload.lease_event_ref.event_hash);
      if (consumedLeaseRefs.has(leaseKey)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.lease_event_ref`, "A lease may be consumed by at most one action admission.");
      }
      consumedLeaseRefs.add(leaseKey);
    }

    if (event.event_type === "waiver.recorded") {
      if (waiverIds.has(event.payload.waiver_id)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.waiver_id`, "Waiver IDs must be globally unique in the run.");
      }
      waiverIds.add(event.payload.waiver_id);
    }

    if (event.event_type === "gate.result-recorded" && event.payload.waiver_event_ref !== null) {
      const waiverKey = ledgerRefKey(event.payload.waiver_event_ref.ledger_sequence, event.payload.waiver_event_ref.event_hash);
      if (consumedWaiverRefs.has(waiverKey)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.waiver_event_ref`, "A recorded waiver may satisfy at most one gate result.");
      }
      consumedWaiverRefs.add(waiverKey);
      const previous = events[index - 1];
      if (previous?.event_type !== "waiver.recorded"
        || previous.event_hash !== event.payload.waiver_event_ref.event_hash
        || previous.sequence !== event.payload.waiver_event_ref.ledger_sequence
        || previous.payload.gate_ref !== event.payload.gate_ref) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.waiver_event_ref`, "A WAIVED gate result must immediately follow its matching waiver.");
      }
    }
  }
  return null;
}

const RECOVERY_CANDIDATES = new Set(["stalled", "exhausted", "failed", "aborted"]);

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function validateControlHistory(
  events: readonly RuntimeEventV02Value[],
): RuntimeLedgerV02ValidationResult | null {
  const eventByRef = new Map(events.map((event) => [ledgerRefKey(event.sequence, event.event_hash), event]));
  let latestFreeze: Extract<RuntimeEventV02Value, { event_type: "run.terminal-freeze-entered" | "run.terminal-freeze-revised" }> | null = null;
  let latestRequest: Extract<RuntimeEventV02Value, { event_type: "run.compensation-requested" | "run.compensation-request-revised" }> | null = null;
  let phaseEntry: Extract<RuntimeEventV02Value, { event_type: "run.compensation-phase-entered" }> | null = null;
  let latestRecoveryCandidateEvent: RuntimeEventV02Value | null = null;
  const admittedActions = new Map<string, { taskRef: string; settled: boolean }>();
  const settledCompensations = new Set<string>();
  const requiredGates = new Set<string>();
  const recordedGates = new Set<string>();
  const requiredEvaluations = new Set<string>();
  const recordedEvaluations = new Set<string>();
  const custodySubjects = new Set<string>();
  const blockedPhases = new Set<string>();
  const recordIdentities = new Set<string>();
  let abortSeen = false;
  let currentFenceEpoch = 0;

  for (const [index, event] of events.entries()) {
    const recordIdentityRule = Object.entries(RECORD_TARGETS).find(([, rule]) => rule.eventType === event.event_type);
    if (recordIdentityRule !== undefined) {
      const [recordKind, rule] = recordIdentityRule;
      const recordId = payloadRecord(event)[rule.idField];
      if (typeof recordId === "string") {
        const recordIdentity = `${recordKind}\0${recordId}`;
        if (recordIdentities.has(recordIdentity)) {
          return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.${rule.idField}`, "Runtime record identity must be unique within its namespace.");
        }
        recordIdentities.add(recordIdentity);
      }
    }

    if (event.event_type === "task.action-admitted") {
      if (latestFreeze !== null) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}]`, "No ordinary action may be admitted after terminal freeze.");
      }
      const lease = eventByRef.get(ledgerRefKey(
        event.payload.lease_event_ref.ledger_sequence,
        event.payload.lease_event_ref.event_hash,
      ));
      if (lease?.event_type !== "lease.issued") {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.lease_event_ref`, "Action admission must resolve to its exact lease.");
      }
      const phaseKey = lease.payload.phase === "work"
        ? "work"
        : `compensation\0${lease.payload.compensation_ref}`;
      if (blockedPhases.has(phaseKey)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}]`, "No action may be admitted after its phase has recorded a limit block.");
      }
      if (admittedActions.has(event.payload.action_id)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.action_id`, "An action ID may be admitted at most once.");
      }
      admittedActions.set(event.payload.action_id, { taskRef: event.payload.task_ref, settled: false });
    }

    if (event.event_type === "control.abort-requested") {
      if (abortSeen) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}]`, "A run may contain at most one sticky abort request.");
      }
      abortSeen = true;
    }

    if (event.event_type === "run.fence-advanced") {
      if (event.payload.previous_fence_epoch !== currentFenceEpoch) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.previous_fence_epoch`, "Fence history must advance from the current epoch.");
      }
      currentFenceEpoch = event.payload.fence_epoch;
    }

    if (event.event_type === "gate.result-required") {
      if (requiredGates.has(event.payload.gate_ref)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.gate_ref`, "A gate may become required at most once.");
      }
      requiredGates.add(event.payload.gate_ref);
    }
    if (event.event_type === "gate.result-recorded") {
      if (recordedGates.has(event.payload.gate_ref)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.gate_ref`, "A gate may record at most one result.");
      }
      recordedGates.add(event.payload.gate_ref);
    }
    if (event.event_type === "evaluation.result-required") {
      if (requiredEvaluations.has(event.payload.evaluation_ref)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.evaluation_ref`, "An evaluation may become required at most once.");
      }
      requiredEvaluations.add(event.payload.evaluation_ref);
    }
    if (event.event_type === "evaluation.result-recorded") {
      if (recordedEvaluations.has(event.payload.evaluation_ref)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.evaluation_ref`, "An evaluation may record at most one result.");
      }
      recordedEvaluations.add(event.payload.evaluation_ref);
    }

    if (event.event_type === "record.custody-state-recorded") {
      const subject = `${event.payload.subject_kind}\0${event.payload.subject_ref}`;
      if (custodySubjects.has(subject)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.subject_ref`, "S35 permits exactly one pre-seal custody state per subject.");
      }
      custodySubjects.add(subject);
    }

    if (event.event_type === "limit.admission-blocked") {
      const phaseKey = event.payload.phase === "work" ? "work" : `compensation\0${event.payload.compensation_ref}`;
      if (blockedPhases.has(phaseKey)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload`, "A phase may contain at most one prospective limit block.");
      }
      blockedPhases.add(phaseKey);
    }

    if (event.event_type === "tool.call-admitted" || event.event_type === "artifact.write-admitted") {
      const action = admittedActions.get(event.payload.action_id);
      if (action === undefined || action.settled || action.taskRef !== event.payload.task_ref) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.action_id`, "Admission must belong to the matching unsettled admitted action.");
      }
    }

    if (event.event_type === "task.action-settled") {
      const action = admittedActions.get(event.payload.action_id);
      if (action === undefined || action.settled || action.taskRef !== event.payload.task_ref) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.action_id`, "Action settlement must close one matching unsettled admission.");
      }
      action.settled = true;
    }

    if (event.event_type === "run.terminal-freeze-entered") {
      if (latestFreeze !== null) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}]`, "Terminal freeze may be entered only once; later changes are revisions.");
      }
      if (event.payload.fence_epoch !== currentFenceEpoch) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.fence_epoch`, "Terminal freeze must capture the current fence epoch.");
      }
      latestFreeze = event;
    }

    if (event.event_type === "run.terminal-freeze-revised") {
      if (latestFreeze === null
        || event.payload.revision !== latestFreeze.payload.revision + 1
        || event.payload.previous_candidate !== latestFreeze.payload.candidate
        || event.payload.previous_freeze_event_hash !== latestFreeze.event_hash) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload`, "Terminal freeze revision must bind the exact prior revision and candidate.");
      }
      latestFreeze = event;
    }

    if (event.event_type === "run.compensation-requested") {
      if (latestRequest !== null || latestFreeze === null
        || !RECOVERY_CANDIDATES.has(latestFreeze.payload.candidate)
        || event.payload.pending_terminal !== latestFreeze.payload.candidate
        || event.payload.freeze_event_hash !== latestFreeze.event_hash) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload`, "Initial compensation request must bind the exact latest recovery freeze.");
      }
      if ([...admittedActions.values()].some((action) => !action.settled)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}]`, "Compensation cannot be requested while an action remains in flight.");
      }
      latestRequest = event;
      latestRecoveryCandidateEvent = event;
    }

    if (event.event_type === "run.compensation-request-revised") {
      if (latestRequest === null || latestFreeze === null
        || event.payload.revision !== latestRequest.payload.revision + 1
        || event.payload.previous_pending_terminal !== latestRequest.payload.pending_terminal
        || event.payload.previous_request_event_hash !== latestRequest.event_hash
        || event.payload.freeze_event_hash !== latestFreeze.event_hash
        || event.payload.pending_terminal !== latestFreeze.payload.candidate) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload`, "Compensation request revision must bind the exact latest request and freeze.");
      }
      const previousRefs = latestRequest.payload.compensation_refs;
      const currentRefs = event.payload.compensation_refs;
      const addedRefs = currentRefs.filter((ref) => !previousRefs.includes(ref));
      if (previousRefs.some((ref) => !currentRefs.includes(ref)) || !sameStrings(addedRefs, event.payload.added_compensation_refs)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.compensation_refs`, "Compensation request revisions may only add the exact declared ref difference.");
      }
      latestRequest = event;
      latestRecoveryCandidateEvent = event;
    }

    if (event.event_type === "run.compensation-phase-entered") {
      const previous = events[index - 1];
      if (phaseEntry !== null || latestRequest === null || latestFreeze === null
        || event.payload.request_revision !== latestRequest.payload.revision
        || event.payload.request_event_hash !== latestRequest.event_hash
        || event.payload.pending_terminal !== latestRequest.payload.pending_terminal
        || !sameStrings(event.payload.compensation_refs, latestRequest.payload.compensation_refs)
        || event.payload.freeze_event_hash !== latestFreeze.event_hash
        || previous?.event_type !== "run.fence-advanced"
        || previous.payload.reason !== "recovery-boundary"
        || [...admittedActions.values()].some((action) => !action.settled)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload`, "Compensation phase entry requires the exact latest request, recovery boundary, and quiescence.");
      }
      phaseEntry = event;
      latestRecoveryCandidateEvent = event;
    }

    if (event.event_type === "run.compensation-candidate-escalated") {
      if (phaseEntry === null || latestRecoveryCandidateEvent === null
        || event.payload.previous_pending_terminal !== payloadRecord(latestRecoveryCandidateEvent)["pending_terminal"]
        || event.payload.previous_candidate_event_hash !== latestRecoveryCandidateEvent.event_hash
        || !sameStrings(event.payload.compensation_refs, phaseEntry.payload.compensation_refs)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload`, "Compensation escalation must bind the latest candidate event and preserve the entered ref set.");
      }
      latestRecoveryCandidateEvent = event;
    }

    if (event.event_type === "compensation.settled") {
      if (phaseEntry === null || !phaseEntry.payload.compensation_refs.includes(event.payload.compensation_ref)
        || settledCompensations.has(event.payload.compensation_ref)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.compensation_ref`, "Compensation settlement must uniquely name a member of the entered phase.");
      }
      settledCompensations.add(event.payload.compensation_ref);
    }

    if (event.event_type === "run.terminal-sealed"
      && [...admittedActions.values()].some((action) => !action.settled)) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}]`, "Terminal seal requires every admitted action to be settled.");
    }
    if (event.event_type === "run.terminal-sealed") {
      if (latestFreeze === null) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}]`, "Terminal seal requires a preceding terminal freeze.");
      }
      const currentCandidate = latestRecoveryCandidateEvent === null
        ? latestFreeze.payload.candidate
        : payloadRecord(latestRecoveryCandidateEvent)["pending_terminal"];
      if (event.payload.outcome !== currentCandidate
        || event.payload.previous_fence_epoch !== currentFenceEpoch
        || (phaseEntry !== null && settledCompensations.size !== phaseEntry.payload.compensation_refs.length)) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload`, "Terminal seal must bind the current candidate, fence, and complete compensation set.");
      }
    }
  }
  return null;
}

function validateTerminalSeal(
  events: readonly RuntimeEventV02Value[],
): RuntimeLedgerV02ValidationResult | null {
  const sealIndex = events.findIndex((event) => event.event_type === "run.terminal-sealed");
  if (sealIndex < 0) return null;
  if (sealIndex !== events.length - 1) {
    return failure("LEDGER_HISTORY_INVALID", `event[${sealIndex + 1}]`, "No primary-ledger event may follow a valid terminal seal.");
  }
  const seal = events[sealIndex]!;
  if (seal.event_type !== "run.terminal-sealed") return null;
  const previous = events[sealIndex - 1];
  if (previous === undefined
    || seal.payload.pre_seal_ledger_sequence !== previous.sequence
    || seal.payload.pre_seal_ledger_head_hash !== previous.event_hash) {
    return failure("LEDGER_HISTORY_INVALID", `event[${sealIndex}].payload`, "Terminal seal must bind and immediately succeed the exact pre-seal prefix.");
  }
  return null;
}

function validateRuntimeLedgerEventSchemasV02(
  input: readonly unknown[],
): RuntimeLedgerV02StructuralValidationResult {
  const events: RuntimeEventV02Value[] = [];
  for (const [index, value] of input.entries()) {
    const parsed = RuntimeEventV02.safeParse(value);
    if (!parsed.success) {
      return {
        ok: false,
        reason: "LEDGER_EVENT_SCHEMA_INVALID",
        issues: parsed.error.issues.map((issue) => ({
          path: `event[${index}]${issue.path.length === 0 ? "" : `.${issue.path.map(String).join(".")}`}`,
          message: issue.message,
        })),
      };
    }
    events.push(parsed.data);
  }

  return { ok: true, events };
}

function validateRuntimeLedgerHashChainV02(
  events: readonly RuntimeEventV02Value[],
): RuntimeLedgerV02StructuralValidationResult;
function validateRuntimeLedgerHashChainV02(
  events: readonly RuntimeEventV02Value[],
  semanticVisitor: (event: RuntimeEventV02Value, index: number) => Extract<RuntimeLedgerV02ValidationResult, { ok: false }> | null,
): RuntimeLedgerV02ValidationResult;
function validateRuntimeLedgerHashChainV02(
  events: readonly RuntimeEventV02Value[],
  semanticVisitor?: (event: RuntimeEventV02Value, index: number) => Extract<RuntimeLedgerV02ValidationResult, { ok: false }> | null,
): RuntimeLedgerV02ValidationResult | RuntimeLedgerV02StructuralValidationResult {
  for (const [index, event] of events.entries()) {
    const expectedSequence = index + 1;
    if (event.sequence !== expectedSequence) {
      return failure("LEDGER_HASH_CHAIN_INVALID", `event[${index}].sequence`, `Expected contiguous sequence ${expectedSequence}.`);
    }
    const expectedPreviousHash = index === 0 ? null : events[index - 1]!.event_hash;
    if (event.previous_event_hash !== expectedPreviousHash) {
      return failure("LEDGER_HASH_CHAIN_INVALID", `event[${index}].previous_event_hash`, "previous_event_hash does not match the prior event.");
    }
    const semanticFailure = semanticVisitor?.(event, index);
    if (semanticFailure !== undefined && semanticFailure !== null) return semanticFailure;
  }

  for (const [index, event] of events.entries()) {
    const { event_hash: eventHash, ...preimage } = event;
    if (hashCanonical(preimage) !== eventHash) {
      return failure("LEDGER_HASH_CHAIN_INVALID", `event[${index}].event_hash`, "event_hash does not match the RFC 8785 event preimage.");
    }
  }

  return { ok: true, events };
}

function parseRuntimeLedgerJsonlV02(
  text: string,
): Readonly<{ ok: true; values: readonly unknown[] }> | RuntimeLedgerV02SyntaxFailure {
  if (!text.endsWith("\n")) {
    return failure("LEDGER_SYNTAX_INVALID", "(root)", "A V02 primary ledger must be newline-terminated; partial final lines are invalid.");
  }
  const lines = text.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.some((line) => line.length === 0)) {
    return failure("LEDGER_SYNTAX_INVALID", "(root)", "Every JSONL line must contain exactly one event.");
  }

  const values: unknown[] = [];
  for (const [index, line] of lines.entries()) {
    try {
      const duplicateCheck = parseDocument(line, { uniqueKeys: true });
      if (duplicateCheck.errors.length > 0) {
        return failure("LEDGER_SYNTAX_INVALID", `line[${index + 1}]`, "JSON line contains duplicate keys or invalid framing.");
      }
      values.push(JSON.parse(line) as unknown);
    } catch {
      return failure("LEDGER_SYNTAX_INVALID", `line[${index + 1}]`, "JSON line is invalid.");
    }
  }
  return { ok: true, values };
}

/** Package-private structural seam; intentionally absent from the package root. */
export function parseAndValidateRuntimeLedgerStructureV02(
  text: string,
): RuntimeLedgerV02StructuralValidationResult {
  const parsed = parseRuntimeLedgerJsonlV02(text);
  if (!parsed.ok) return parsed;
  const schemas = validateRuntimeLedgerEventSchemasV02(parsed.values);
  if (!schemas.ok) return schemas;
  return validateRuntimeLedgerHashChainV02(schemas.events);
}

export function validateRuntimeLedgerV02(input: readonly unknown[]): RuntimeLedgerV02ValidationResult {
  const schemas = validateRuntimeLedgerEventSchemasV02(input);
  if (!schemas.ok) return schemas;
  const events = schemas.events;

  const first = events[0];
  if (first?.event_type !== "run.initialized") {
    return failure("LEDGER_HISTORY_INVALID", "event[0]", "A V02 primary ledger must begin with run.initialized.");
  }

  const eventIds = new Set<string>();
  const hashChain = validateRuntimeLedgerHashChainV02(events, (event, index) => {
    if (event.run_id !== first.run_id) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].run_id`, "Every event must belong to the initialized run.");
    }
    const copiedPayload = payloadRecord(event);
    if (typeof copiedPayload.run_id === "string" && copiedPayload.run_id !== first.run_id) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.run_id`, "Copied payload run_id must equal the initialized run.");
    }
    if (typeof copiedPayload.plan_hash === "string" && copiedPayload.plan_hash !== first.payload.plan_hash) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.plan_hash`, "Copied payload plan_hash must equal the initialized plan.");
    }
    if (eventIds.has(event.event_id)) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].event_id`, "event_id must be unique in the run.");
    }
    eventIds.add(event.event_id);
    return null;
  });
  if (!hashChain.ok) return hashChain;

  const referenceFailure = validateEarlierReferences(events);
  if (referenceFailure !== null) return referenceFailure;
  const typedReferenceFailure = validateTypedRecordReferences(events);
  if (typedReferenceFailure !== null) return typedReferenceFailure;
  const lineageFailure = validateEventLineage(events);
  if (lineageFailure !== null) return lineageFailure;
  const consumptionFailure = validateUniqueConsumption(events);
  if (consumptionFailure !== null) return consumptionFailure;
  const controlFailure = validateControlHistory(events);
  if (controlFailure !== null) return controlFailure;
  const terminalFailure = validateTerminalSeal(events);
  if (terminalFailure !== null) return terminalFailure;

  return { ok: true, events, sealed: events.at(-1)?.event_type === "run.terminal-sealed" };
}

export function parseAndValidateRuntimeLedgerV02(text: string): RuntimeLedgerV02ValidationResult {
  const parsed = parseRuntimeLedgerJsonlV02(text);
  return parsed.ok ? validateRuntimeLedgerV02(parsed.values) : parsed;
}
