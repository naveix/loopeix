import type {
  LedgerRefV02Value,
  ResolvedRunPlanV02Value,
  RuntimeEventV02Value,
  TerminalEvaluationResultV02Value,
  TerminalObservationSnapshotV02,
} from "../schema/runtime.js";

type SnapshotTask = TerminalObservationSnapshotV02["tasks"][number];
type SnapshotEvaluation = TerminalObservationSnapshotV02["evaluations"][number];
type SnapshotEffect = TerminalObservationSnapshotV02["effects"][number];
type SnapshotLimit = TerminalObservationSnapshotV02["limits"][number];
type SnapshotPolicyBlock = TerminalObservationSnapshotV02["policy_blocks"][number];
type CompensationObservation = TerminalObservationSnapshotV02["compensations"][number];
type SettlementObservation = CompensationObservation["settlement"];
type SettlementDecision = Extract<
  TerminalEvaluationResultV02Value,
  { decision: "settle-compensation" }
>["settlement"];

export type CompensationProjectionInvalidReasonV02 =
  | "ACTIVATION_INVALID"
  | "COMPENSATION_REF_SET_INVALID"
  | "COMPENSATION_SETTLEMENT_INVALID";

export type DurableCompensationSettlementObservationV02 = Readonly<{
  ref: string;
  settlement: Exclude<SettlementObservation, { status: "pending" }>;
  event_ref: LedgerRefV02Value;
}>;

export type CompensationProjectionInputV02 = Readonly<{
  plan: ResolvedRunPlanV02Value;
  events: readonly RuntimeEventV02Value[];
  tasks: readonly SnapshotTask[];
  evaluations: readonly SnapshotEvaluation[];
  effects: readonly SnapshotEffect[];
  limits: readonly SnapshotLimit[];
  policy_blocks: readonly SnapshotPolicyBlock[];
}>;

export type CompensationProjectionResultV02 =
  | Readonly<{
    ok: true;
    value: Readonly<{
      compensations: readonly CompensationObservation[];
      durable_settlements: readonly DurableCompensationSettlementObservationV02[];
      pending_settlement_decisions: readonly SettlementDecision[];
    }>;
  }>
  | Readonly<{ ok: false; reason: CompensationProjectionInvalidReasonV02 }>;

const PENDING_SETTLEMENT: SettlementObservation = Object.freeze({
  status: "pending",
  unable_reason: null,
  evidence_refs: [] as [],
  transition_sequence: null,
  transition_event_hash: null,
});

const BUDGET_REASONS = [
  ["max-elapsed-ms", "elapsed-budget-exhausted"],
  ["max-tool-calls", "tool-call-budget-exhausted"],
  ["max-output-bytes", "output-budget-exhausted"],
  ["max-tokens", "token-budget-exhausted"],
  ["max-cost", "cost-budget-exhausted"],
] as const;

function eventRef(event: RuntimeEventV02Value): LedgerRefV02Value {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function refKey(ref: LedgerRefV02Value): string {
  return `${ref.ledger_sequence}:${ref.event_hash}`;
}

function canonicalRefs(refs: readonly LedgerRefV02Value[]): LedgerRefV02Value[] {
  const unique = new Map(refs.map((ref) => [refKey(ref), ref]));
  return [...unique.values()].sort((left, right) =>
    left.ledger_sequence - right.ledger_sequence
      || left.event_hash.localeCompare(right.event_hash),
  );
}

function sameRefs(
  left: readonly LedgerRefV02Value[],
  right: readonly LedgerRefV02Value[],
): boolean {
  return left.length === right.length
    && left.every((ref, index) => refKey(ref) === refKey(right[index]!));
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function pendingDecision(
  input: CompensationProjectionInputV02,
  compensation: ResolvedRunPlanV02Value["compensations"][number],
  applicable: boolean,
  phaseEnteredRefs: ReadonlySet<string>,
): SettlementDecision | null {
  if (!applicable || !phaseEnteredRefs.has(compensation.id)) return null;

  const protectedEffect = input.effects.find((effect) =>
    effect.task_ref === compensation.for_task && effect.effect_ref === compensation.for_effect,
  );
  if (protectedEffect?.outcome === "unknown" && protectedEffect.outcome_event_ref !== null) {
    return {
      ref: compensation.id,
      status: "unable",
      unable_reason: "unknown-action-outcome",
      evidence_refs: [protectedEffect.outcome_event_ref],
    };
  }

  const actionTask = input.tasks.find((task) => task.ref === compensation.action_task);
  const verifiers = compensation.verification_refs.map((verificationRef) =>
    input.evaluations.find((evaluation) => evaluation.ref === verificationRef),
  );
  const failedVerifierRefs = verifiers.flatMap((verifier) =>
    verifier?.status === "fail" && verifier.result_event_ref !== null
      ? [verifier.result_event_ref]
      : [],
  );
  if (actionTask?.status === "failed" || failedVerifierRefs.length > 0) {
    const evidence = canonicalRefs([
      ...(actionTask?.terminal_event_ref === null || actionTask?.terminal_event_ref === undefined
        ? []
        : [actionTask.terminal_event_ref]),
      ...failedVerifierRefs,
    ]);
    if (evidence.length === 0) return null;
    return {
      ref: compensation.id,
      status: "compensation-failed",
      unable_reason: null,
      evidence_refs: evidence as [LedgerRefV02Value, ...LedgerRefV02Value[]],
    };
  }

  if (actionTask?.status === "completed" && actionTask.terminal_event_ref !== null
    && verifiers.length > 0
    && verifiers.every((verifier) => verifier?.status === "pass" && verifier.result_event_ref !== null)) {
    const evidence = canonicalRefs([
      actionTask.terminal_event_ref,
      ...verifiers.map((verifier) => verifier!.result_event_ref!),
    ]);
    return {
      ref: compensation.id,
      status: "compensated",
      unable_reason: null,
      evidence_refs: evidence as [LedgerRefV02Value, ...LedgerRefV02Value[]],
    };
  }

  const safetyBlocks = input.policy_blocks.filter((block) =>
    block.active
    && block.phase === "compensation"
    && block.compensation_ref === compensation.id
    && block.task_ref === compensation.action_task
    && block.decision === "hold"
    && block.decision_disposition === "non-resumable",
  );
  if (safetyBlocks.length > 0) {
    const evidence = canonicalRefs(safetyBlocks.flatMap((block) => [
      ...block.evidence_refs,
      block.decision_event_ref,
    ]));
    if (evidence.length > 0) {
      return {
        ref: compensation.id,
        status: "unable",
        unable_reason: "safety-hold",
        evidence_refs: evidence as [LedgerRefV02Value, ...LedgerRefV02Value[]],
      };
    }
  }

  if (actionTask?.status !== "completed") {
    for (const [limitRef, unableReason] of BUDGET_REASONS) {
      if (limitRef === "max-tokens" && input.plan.limit_policy.max_tokens === null) continue;
      if (limitRef === "max-cost" && input.plan.limit_policy.max_cost_minor_units === null) continue;
      const limit = input.limits.find((candidate) =>
        candidate.ref === limitRef
        && (candidate.status === "at-ceiling"
          || candidate.status === "would-exceed"
          || candidate.status === "exceeded"),
      );
      if (limit !== undefined) {
        return {
          ref: compensation.id,
          status: "unable",
          unable_reason: unableReason,
          evidence_refs: [limit.evidence_ref],
        };
      }
    }
  }
  return null;
}

/**
 * Package-private pure reducer. Its inputs have already crossed the runtime
 * projection boundary; it does not parse caller-authored snapshots or mint
 * execution authority.
 */
export function deriveCompensationProjectionV02(
  input: CompensationProjectionInputV02,
): CompensationProjectionResultV02 {
  const knownRefs = new Set(input.plan.compensations.map((compensation) => compensation.id));
  const requestEvents = input.events.filter((event) =>
    event.event_type === "run.compensation-requested"
      || event.event_type === "run.compensation-request-revised",
  );
  const requestedRefs = new Set<string>();
  for (const requestEvent of requestEvents) {
    for (const compensationRef of requestEvent.payload.compensation_refs) {
      if (!knownRefs.has(compensationRef)) {
        return { ok: false, reason: "COMPENSATION_REF_SET_INVALID" };
      }
      const compensation = input.plan.compensations.find((candidate) => candidate.id === compensationRef)!;
      const protectedEffect = input.effects.find((effect) =>
        effect.task_ref === compensation.for_task && effect.effect_ref === compensation.for_effect,
      );
      if (protectedEffect === undefined
        || protectedEffect.outcome === "not-started"
        || protectedEffect.outcome === "not-committed") {
        return { ok: false, reason: "ACTIVATION_INVALID" };
      }
      requestedRefs.add(compensationRef);
    }
  }

  const latestRequest = requestEvents.at(-1);
  const latestRequestRefs = latestRequest?.payload.compensation_refs ?? [];
  const phaseEnteredEvents = input.events.filter((event) => event.event_type === "run.compensation-phase-entered");
  const phaseEnteredRefs = new Set<string>();
  for (const phaseEvent of phaseEnteredEvents) {
    if (latestRequest === undefined
      || phaseEvent.payload.request_event_hash !== latestRequest.event_hash
      || !sameStrings(phaseEvent.payload.compensation_refs, latestRequestRefs)
      || phaseEvent.payload.compensation_refs.some((ref) => !knownRefs.has(ref))) {
      return { ok: false, reason: "COMPENSATION_REF_SET_INVALID" };
    }
    phaseEvent.payload.compensation_refs.forEach((ref) => phaseEnteredRefs.add(ref));
  }

  const admittedTaskRefs = new Set(input.events.flatMap((event) =>
    event.event_type === "task.action-admitted"
      ? [event.payload.task_ref]
      : [],
  ));

  const settlementEvents = input.events.filter((event) => event.event_type === "compensation.settled");
  const settlementByRef = new Map<string, (typeof settlementEvents)[number]>();
  for (const settlementEvent of settlementEvents) {
    const compensationRef = settlementEvent.payload.compensation_ref;
    if (!knownRefs.has(compensationRef) || settlementByRef.has(compensationRef)) {
      return { ok: false, reason: "COMPENSATION_SETTLEMENT_INVALID" };
    }
    settlementByRef.set(compensationRef, settlementEvent);
  }

  const compensations: CompensationObservation[] = [];
  const durableSettlements: DurableCompensationSettlementObservationV02[] = [];
  const pendingDecisions: SettlementDecision[] = [];
  for (const compensation of input.plan.compensations) {
    const protectedEffect = input.effects.find((effect) =>
      effect.task_ref === compensation.for_task && effect.effect_ref === compensation.for_effect,
    );
    const activationRequested = requestedRefs.has(compensation.id);
    const applicable = activationRequested
      || protectedEffect?.outcome === "unknown"
      || admittedTaskRefs.has(compensation.action_task);
    const decision = pendingDecision(input, compensation, applicable, phaseEnteredRefs);
    const durable = settlementByRef.get(compensation.id);
    let settlement: SettlementObservation = PENDING_SETTLEMENT;
    let decisionEvidence: LedgerRefV02Value[] = decision?.evidence_refs ?? [];

    if (durable !== undefined) {
      if (decision === null
        || durable.payload.status !== decision.status
        || durable.payload.unable_reason !== decision.unable_reason
        || !sameRefs(durable.payload.evidence_refs, decision.evidence_refs)) {
        return { ok: false, reason: "COMPENSATION_SETTLEMENT_INVALID" };
      }
      settlement = {
        status: durable.payload.status,
        unable_reason: durable.payload.unable_reason,
        evidence_refs: durable.payload.evidence_refs,
        transition_sequence: durable.sequence,
        transition_event_hash: durable.event_hash,
      } as Exclude<SettlementObservation, { status: "pending" }>;
      const durableObservation = {
        ref: compensation.id,
        settlement,
        event_ref: eventRef(durable),
      } as DurableCompensationSettlementObservationV02;
      durableSettlements.push(durableObservation);
      decisionEvidence = durable.payload.evidence_refs;
    } else if (decision !== null) {
      pendingDecisions.push(decision);
    }

    compensations.push({
      ref: compensation.id,
      activation_requested: activationRequested,
      applicable,
      settlement,
      decision_evidence_refs: decisionEvidence,
    });
  }

  return {
    ok: true,
    value: {
      compensations,
      durable_settlements: durableSettlements,
      pending_settlement_decisions: pendingDecisions,
    },
  };
}
