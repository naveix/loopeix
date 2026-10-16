import type {
  LedgerRefV02Value,
  ResolvedRunPlanV02Value,
  RuntimeEventV02Value,
  TerminalObservationSnapshotV02,
} from "../schema/runtime.js";

type ActiveFailure = TerminalObservationSnapshotV02["active_failures"][number];
type PolicyBlock = TerminalObservationSnapshotV02["policy_blocks"][number];

export type FailurePolicyProjectionInputV02 = Readonly<{
  plan: ResolvedRunPlanV02Value;
  events: readonly RuntimeEventV02Value[];
}>;

export type FailurePolicyProjectionResultV02 =
  | Readonly<{
    ok: true;
    value: Readonly<{
      active_failures: readonly ActiveFailure[];
      policy_blocks: readonly PolicyBlock[];
    }>;
  }>
  | Readonly<{
    ok: false;
    reason: "TASK_EFFECT_OR_FAILURE_INVALID" | "ACTION_ADMISSION_OR_QUIESCENCE_INVALID";
  }>;

type RetryClock = Readonly<{
  event: Extract<RuntimeEventV02Value, { event_type: "run.clock-observed" }>;
  key: string;
}>;

type ActiveFailureInternal = Readonly<{
  observation: ActiveFailure;
  retry_clock_sequence: number | null;
}>;

type CurrentAdmission = Readonly<{
  event_ref: LedgerRefV02Value;
  clock_ref: LedgerRefV02Value;
}>;

function eventRef(event: RuntimeEventV02Value): LedgerRefV02Value {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function refKey(ref: LedgerRefV02Value): string {
  return `${ref.ledger_sequence}:${ref.event_hash}`;
}

function failureKey(taskRef: string, ordinal: number): string {
  return `${taskRef}\0${ordinal}`;
}

function taskClassKey(taskRef: string, failureClass: string): string {
  return `${taskRef}\0${failureClass}`;
}

function taskPhaseKey(taskRef: string, phase: "work" | "compensation"): string {
  return `${taskRef}\0${phase}`;
}

function deterministicDelay(
  rule: ResolvedRunPlanV02Value["retry_policy"]["rules"][number],
  failureOrdinal: number,
): number | null {
  if (!Number.isSafeInteger(failureOrdinal) || failureOrdinal < 1) return null;
  if (rule.backoff === "none") {
    return rule.base_delay_ms === 0 && rule.max_delay_ms === 0 ? 0 : null;
  }
  if (!Number.isSafeInteger(rule.base_delay_ms)
    || !Number.isSafeInteger(rule.max_delay_ms)
    || rule.base_delay_ms <= 0
    || rule.max_delay_ms <= 0) {
    return null;
  }
  if (rule.backoff === "fixed") {
    return rule.base_delay_ms === rule.max_delay_ms ? rule.base_delay_ms : null;
  }
  if (rule.base_delay_ms > rule.max_delay_ms) return null;

  let delay = rule.base_delay_ms;
  let doublingsRemaining = failureOrdinal - 1;
  while (doublingsRemaining > 0 && delay < rule.max_delay_ms) {
    delay = delay > Math.floor(rule.max_delay_ms / 2)
      ? rule.max_delay_ms
      : delay * 2;
    doublingsRemaining -= 1;
  }
  return delay;
}

function retryRuleValid(
  rule: ResolvedRunPlanV02Value["retry_policy"]["rules"][number],
): boolean {
  const transient = rule.failure_class === "transient-adapter"
    || rule.failure_class === "transient-network"
    || rule.failure_class === "contention";
  if (!rule.retryable) {
    return rule.max_task_executions === 1
      && rule.backoff === "none"
      && rule.base_delay_ms === 0
      && rule.max_delay_ms === 0;
  }
  return transient
    && rule.max_task_executions >= 2
    && rule.backoff !== "none"
    && deterministicDelay(rule, 1) !== null;
}

function retrySafetySatisfied(
  plan: ResolvedRunPlanV02Value,
  taskRef: string,
  safetyEvidenceCount: number,
): boolean {
  const effects = plan.side_effects.find((spec) => spec.task_id === taskRef)?.effects;
  if (effects === undefined || effects.length === 0) return false;
  return effects.every((effect) => {
    if (effect.effect_class === "none" || effect.idempotency === "not-required") return true;
    if (effect.idempotency === "unsupported") return false;
    return safetyEvidenceCount > 0;
  });
}

function phaseLineageValid(
  plan: ResolvedRunPlanV02Value,
  taskRef: string,
  phase: "work" | "compensation",
  compensationRef: string | null,
): boolean {
  const task = plan.tasks.find((candidate) => candidate.id === taskRef);
  if (task === undefined) return false;
  if (phase === "work") return task.kind === "work" && compensationRef === null;
  if (compensationRef === null || task.kind !== "compensation") return false;
  return plan.compensations.some((compensation) =>
    compensation.id === compensationRef && compensation.action_task === taskRef,
  );
}

function decisionBranchValid(
  decision: "allow" | "deny" | "escalate" | "abort" | "hold",
  disposition: "lease-eligible" | "proposal-final" | "human-exception-required" | "abort-run" | "redecide-after-prefix-change" | "non-resumable",
): boolean {
  return (decision === "allow" && disposition === "lease-eligible")
    || (decision === "deny" && disposition === "proposal-final")
    || (decision === "escalate" && disposition === "human-exception-required")
    || (decision === "abort" && disposition === "abort-run")
    || (decision === "hold"
      && (disposition === "redecide-after-prefix-change" || disposition === "non-resumable"));
}

function derivePolicyBlocks(
  plan: ResolvedRunPlanV02Value,
  events: readonly RuntimeEventV02Value[],
): FailurePolicyProjectionResultV02 {
  const decisions = events.filter((event) => event.event_type === "policy.decision-recorded");
  const permanentHolds = new Map<string, number>();
  const reviewedPrefixByProposal = new Map<string, number>();
  const blocks: PolicyBlock[] = [];

  for (const decisionEvent of decisions) {
    const payload = decisionEvent.payload;
    if (!phaseLineageValid(
      plan,
      payload.task_ref,
      payload.phase,
      payload.compensation_ref,
    ) || !decisionBranchValid(payload.decision, payload.decision_disposition)) {
      return { ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
    }

    const phaseKey = taskPhaseKey(payload.task_ref, payload.phase);
    const proposalKey = `${phaseKey}\0${payload.compensation_ref ?? ""}\0${payload.action_proposal_id}`;
    const previousReviewedPrefix = reviewedPrefixByProposal.get(proposalKey);
    if (previousReviewedPrefix !== undefined
      && payload.reviewed_through_ref.ledger_sequence <= previousReviewedPrefix) {
      return { ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
    }
    reviewedPrefixByProposal.set(proposalKey, payload.reviewed_through_ref.ledger_sequence);
    if (permanentHolds.has(phaseKey)) {
      return { ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
    }

    if (payload.decision_disposition === "non-resumable") {
      permanentHolds.set(phaseKey, decisionEvent.sequence);
    }
    if (payload.decision === "allow") continue;
    if (payload.decision_disposition === "lease-eligible") {
      return { ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
    }

    const supersededConditionHold = payload.decision_disposition === "redecide-after-prefix-change"
      && decisions.some((later) => later.sequence > decisionEvent.sequence
        && later.payload.task_ref === payload.task_ref
        && later.payload.phase === payload.phase
        && later.payload.compensation_ref === payload.compensation_ref
        && later.payload.action_proposal_id === payload.action_proposal_id
        && later.payload.reviewed_through_ref.ledger_sequence > payload.reviewed_through_ref.ledger_sequence);
    const active = payload.decision_disposition === "human-exception-required"
      || payload.decision_disposition === "non-resumable"
      || (payload.decision_disposition === "redecide-after-prefix-change" && !supersededConditionHold);

    blocks.push({
      task_ref: payload.task_ref,
      phase: payload.phase,
      compensation_ref: payload.compensation_ref,
      action_proposal_id: payload.action_proposal_id,
      policy_action_kind: payload.policy_action_kind,
      decision: payload.decision,
      decision_disposition: payload.decision_disposition,
      active,
      decision_event_ref: eventRef(decisionEvent),
      evidence_refs: payload.evidence_refs,
    });
  }

  for (const [key, holdSequence] of permanentHolds) {
    for (const event of events) {
      if (event.sequence <= holdSequence) continue;
      if (event.event_type !== "approval.recommendation-recorded"
        && event.event_type !== "policy.decision-recorded"
        && event.event_type !== "lease.issued"
        && event.event_type !== "task.action-admitted") {
        continue;
      }
      const eventPhase = event.event_type === "task.action-admitted"
        ? inputPlanTaskPhase(plan, event.payload.task_ref)
        : event.payload.phase;
      if (eventPhase === null) {
        return { ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
      }
      if (taskPhaseKey(event.payload.task_ref, eventPhase) === key) {
        return { ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
      }
    }
  }

  return { ok: true, value: { active_failures: [], policy_blocks: blocks } };
}

function inputPlanTaskPhase(
  plan: ResolvedRunPlanV02Value,
  taskRef: string,
): "work" | "compensation" | null {
  const task = plan.tasks.find((candidate) => candidate.id === taskRef);
  return task?.kind ?? null;
}

/**
 * Package-private pure reducer over an already validated plan and ledger.
 * It derives retry and policy observations but cannot mint execution authority.
 */
export function deriveFailurePolicyProjectionV02(
  input: FailurePolicyProjectionInputV02,
): FailurePolicyProjectionResultV02 {
  const tasks = new Set(input.plan.tasks.map((task) => task.id));
  const actionClocks = new Map<string, Extract<RuntimeEventV02Value, { event_type: "run.clock-observed" }>>();
  const retryClocks = new Map<string, RetryClock>();
  for (const event of input.events) {
    if (event.event_type !== "run.clock-observed") continue;
    if (event.payload.reason === "action-admission") {
      actionClocks.set(refKey(eventRef(event)), event);
      continue;
    }
    if (event.payload.reason !== "retry-check") continue;
    if (event.payload.task_ref === null || event.payload.failure_ordinal === null) {
      return { ok: false, reason: "TASK_EFFECT_OR_FAILURE_INVALID" };
    }
    const key = failureKey(event.payload.task_ref, event.payload.failure_ordinal);
    if (retryClocks.has(key)) {
      return { ok: false, reason: "TASK_EFFECT_OR_FAILURE_INVALID" };
    }
    retryClocks.set(key, { event, key });
  }

  const usedRetryClocks = new Set<string>();
  const admissionsByTask = new Map<string, number>();
  const currentAdmissionByTask = new Map<string, CurrentAdmission>();
  const failuresByTask = new Map<string, number>();
  const activeByTaskClass = new Map<string, ActiveFailureInternal>();
  const activeByTask = new Map<string, string>();

  for (const event of input.events) {
    if (event.event_type === "task.action-admitted") {
      const payload = event.payload;
      if (!tasks.has(payload.task_ref)) {
        return { ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
      }
      const expectedExecution = (admissionsByTask.get(payload.task_ref) ?? 0) + 1;
      const admissionClock = actionClocks.get(refKey(payload.admission_clock_ref));
      if (payload.execution_ordinal !== expectedExecution
        || payload.task_executions_after !== expectedExecution
        || admissionClock === undefined
        || admissionClock.sequence >= event.sequence
        || admissionClock.payload.task_ref !== payload.task_ref
        || admissionClock.payload.use_ref !== payload.action_id) {
        return { ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
      }
      if (expectedExecution === 1) {
        if (payload.retry_of_failure_ordinal !== null) {
          return { ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
        }
      } else {
        const activeKey = activeByTask.get(payload.task_ref);
        const active = activeKey === undefined ? undefined : activeByTaskClass.get(activeKey);
        if (active === undefined
          || payload.retry_of_failure_ordinal !== active.observation.failure_ordinal
          || active.observation.retry_disposition !== "ready"
          || active.retry_clock_sequence === null
          || active.retry_clock_sequence >= event.sequence) {
          return { ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
        }
        activeByTask.delete(payload.task_ref);
        activeByTaskClass.delete(activeKey!);
      }
      admissionsByTask.set(payload.task_ref, expectedExecution);
      currentAdmissionByTask.set(payload.task_ref, {
        event_ref: eventRef(event),
        clock_ref: payload.admission_clock_ref,
      });
      continue;
    }

    if (event.event_type !== "task.execution-failed") continue;
    const payload = event.payload;
    if (!tasks.has(payload.task_ref) || activeByTask.has(payload.task_ref)) {
      return { ok: false, reason: "TASK_EFFECT_OR_FAILURE_INVALID" };
    }
    const executionCount = admissionsByTask.get(payload.task_ref) ?? 0;
    const currentAdmission = currentAdmissionByTask.get(payload.task_ref);
    const expectedFailureOrdinal = (failuresByTask.get(payload.task_ref) ?? 0) + 1;
    if (executionCount < 1
      || currentAdmission === undefined
      || refKey(payload.admission_ref) !== refKey(currentAdmission.event_ref)
      || refKey(payload.failure_clock_ref) !== refKey(currentAdmission.clock_ref)
      || payload.failure_ordinal !== expectedFailureOrdinal) {
      return { ok: false, reason: "TASK_EFFECT_OR_FAILURE_INVALID" };
    }
    const failureClock = actionClocks.get(refKey(payload.failure_clock_ref));
    if (failureClock === undefined
      || failureClock.sequence >= event.sequence
      || failureClock.payload.task_ref !== payload.task_ref) {
      return { ok: false, reason: "TASK_EFFECT_OR_FAILURE_INVALID" };
    }
    const rule = input.plan.retry_policy.rules.find((candidate) =>
      candidate.task_ref === payload.task_ref && candidate.failure_class === payload.failure_class,
    );
    if (rule === undefined || !retryRuleValid(rule)) {
      return { ok: false, reason: "TASK_EFFECT_OR_FAILURE_INVALID" };
    }
    const delay = deterministicDelay(rule, payload.failure_ordinal);
    if (delay === null) return { ok: false, reason: "TASK_EFFECT_OR_FAILURE_INVALID" };

    const retryClock = retryClocks.get(failureKey(payload.task_ref, payload.failure_ordinal));
    let elapsed: number | null = null;
    if (retryClock !== undefined) {
      usedRetryClocks.add(retryClock.key);
      if (!rule.retryable
        || retryClock.event.sequence <= event.sequence
        || retryClock.event.payload.elapsed_ms < failureClock.payload.elapsed_ms) {
        return { ok: false, reason: "TASK_EFFECT_OR_FAILURE_INVALID" };
      }
      elapsed = retryClock.event.payload.elapsed_ms - failureClock.payload.elapsed_ms;
      if (!Number.isSafeInteger(elapsed) || elapsed < delay) {
        return { ok: false, reason: "TASK_EFFECT_OR_FAILURE_INVALID" };
      }
    }

    const eligible = rule.retryable
      && executionCount < rule.max_task_executions
      && retrySafetySatisfied(input.plan, payload.task_ref, payload.retry_safety_evidence_refs.length);
    const disposition: ActiveFailure["retry_disposition"] = !eligible
      ? "ineligible"
      : elapsed === null
        ? "waiting"
        : "ready";
    const key = taskClassKey(payload.task_ref, payload.failure_class);
    const observation: ActiveFailure = {
      task_ref: payload.task_ref,
      failure_class: payload.failure_class,
      task_execution_count: executionCount,
      failure_ordinal: payload.failure_ordinal,
      retry_disposition: disposition,
      failure_event_ref: eventRef(event),
      failure_clock_ref: payload.failure_clock_ref,
      retry_clock_ref: retryClock === undefined ? null : eventRef(retryClock.event),
    };
    activeByTaskClass.set(key, {
      observation,
      retry_clock_sequence: retryClock?.event.sequence ?? null,
    });
    activeByTask.set(payload.task_ref, key);
    failuresByTask.set(payload.task_ref, expectedFailureOrdinal);
  }

  if ([...retryClocks.keys()].some((key) => !usedRetryClocks.has(key))) {
    return { ok: false, reason: "TASK_EFFECT_OR_FAILURE_INVALID" };
  }

  const activeFailures = input.plan.retry_policy.rules.flatMap((rule) => {
    const active = activeByTaskClass.get(taskClassKey(rule.task_ref, rule.failure_class));
    return active === undefined ? [] : [active.observation];
  });
  const policy = derivePolicyBlocks(input.plan, input.events);
  if (!policy.ok) return policy;
  return {
    ok: true,
    value: {
      active_failures: activeFailures,
      policy_blocks: policy.value.policy_blocks,
    },
  };
}
