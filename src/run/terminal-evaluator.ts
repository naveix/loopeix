import type {
  LedgerRefV02Value,
  TerminalEvaluationResultV02Value,
  TerminalObservationSnapshotV02,
} from "../schema/runtime.js";
import {
  expectedCompensationActivationReasonV02,
  RECOVERY_PRIORITY_V02,
  TERMINAL_PRIORITY_V02,
} from "../schema/runtime.js";
import {
  compensationFactsForTerminalSnapshotV02,
  isTerminalObservationSnapshotV02,
  validatedProjectionForTerminalSnapshotV02,
} from "./terminal-snapshot.js";
import { hashCanonical } from "../hash.js";
import { deriveCompensationProjectionV02 } from "./compensation-projection-v02.js";

type TerminalCandidate = "completed" | "held" | "blocked" | "failed" | "stalled" | "exhausted" | "aborted";
type RecoveryCandidate = "stalled" | "exhausted" | "failed" | "aborted";
type NonEmptyRefs = [LedgerRefV02Value, ...LedgerRefV02Value[]];

function isFailedFailureClass(failureClass: TerminalObservationSnapshotV02["active_failures"][number]["failure_class"]): boolean {
  return failureClass === "invalid-input"
    || failureClass === "verification-failed"
    || failureClass === "permanent-execution";
}

function uniqueRefs(refs: readonly LedgerRefV02Value[]): LedgerRefV02Value[] {
  const seen = new Set<string>();
  return refs.filter((ref) => {
    const key = `${ref.ledger_sequence}:${ref.event_hash}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((left, right) => left.ledger_sequence - right.ledger_sequence);
}

function evaluationCountsAsCompleted(
  snapshot: TerminalObservationSnapshotV02,
  projection: Exclude<ReturnType<typeof validatedProjectionForTerminalSnapshotV02>, undefined>,
  evaluation: TerminalObservationSnapshotV02["evaluations"][number],
): boolean {
  void snapshot;
  const definitions = projection.plan.evaluations ?? [];
  const definition = definitions.find((candidate) => candidate.id === evaluation.ref);
  if (definition === undefined) return false;
  if (!evaluation.applicable) return true;
  return evaluation.due && evaluation.status === "pass";
}

function taskCountsAsCompleted(
  snapshot: TerminalObservationSnapshotV02,
  projection: Exclude<ReturnType<typeof validatedProjectionForTerminalSnapshotV02>, undefined>,
  task: TerminalObservationSnapshotV02["tasks"][number],
): boolean {
  const taskDefinitions = projection.plan.tasks ?? [];
  const definition = taskDefinitions.find((candidate) => candidate.id === task.ref);
  if (definition === undefined) return false;
  if (definition.kind === "work") return task.status === "completed";
  const compensations = projection.plan.compensations ?? [];
  const applicable = compensations.some((compensation) =>
    compensation.action_task === task.ref
    && snapshot.compensations.some((observation) => observation.ref === compensation.id && observation.applicable),
  );
  return !applicable || task.status === "completed";
}

function completionEvidence(
  snapshot: TerminalObservationSnapshotV02,
  projection: Exclude<ReturnType<typeof validatedProjectionForTerminalSnapshotV02>, undefined>,
): LedgerRefV02Value[] {
  const progressDefinitions = projection.plan.progress?.observations ?? [];
  const progressByRef = new Map(progressDefinitions.map((observation) => [observation.id, observation]));
  const completionReady = snapshot.gates.every((gate) => !gate.applicable || !gate.due || gate.status === "pass" || gate.status === "waived-valid")
    && snapshot.evaluations.every((evaluation) => evaluationCountsAsCompleted(snapshot, projection, evaluation))
    && snapshot.tasks.every((task) => taskCountsAsCompleted(snapshot, projection, task))
    && snapshot.progress.every((progress) => {
      const definition = progressByRef.get(progress.ref);
      return definition !== undefined && (definition.target === null || progress.target_reached);
    });
  if (!completionReady) return [];
  return uniqueRefs([
    ...snapshot.gates.flatMap((gate) => gate.condition_evidence_refs),
    ...snapshot.evaluations.flatMap((evaluation) => evaluation.condition_evidence_refs),
    ...snapshot.tasks.flatMap((task) => task.condition_evidence_refs),
    ...snapshot.progress.flatMap((progress) => progress.condition_evidence_refs),
  ]);
}

function terminalCandidate(snapshot: TerminalObservationSnapshotV02): Readonly<{
  candidate: TerminalCandidate;
  evidence: NonEmptyRefs;
}> | null;
function terminalCandidate(
  snapshot: TerminalObservationSnapshotV02,
  projection: Exclude<ReturnType<typeof validatedProjectionForTerminalSnapshotV02>, undefined>,
): Readonly<{
  candidate: TerminalCandidate;
  evidence: NonEmptyRefs;
}> | null;
function terminalCandidate(
  snapshot: TerminalObservationSnapshotV02,
  projection?: Exclude<ReturnType<typeof validatedProjectionForTerminalSnapshotV02>, undefined>,
): Readonly<{
  candidate: TerminalCandidate;
  evidence: NonEmptyRefs;
}> | null {
  const resolvedProjection = projection ?? validatedProjectionForTerminalSnapshotV02(snapshot);
  if (resolvedProjection === undefined) return null;
  const rows: Array<{ candidate: TerminalCandidate; evidence: NonEmptyRefs }> = [];
  if (snapshot.abort_requested && snapshot.abort_event_ref !== null) {
    rows.push({ candidate: "aborted", evidence: [snapshot.abort_event_ref] });
  }
  const failedFailures = snapshot.active_failures.filter((failure) => isFailedFailureClass(failure.failure_class));
  const failedControls = [
    ...snapshot.gates.filter((gate) => gate.applicable && gate.due && gate.status === "fail"),
    ...snapshot.evaluations.filter((evaluation) => evaluation.applicable && evaluation.due && evaluation.status === "fail"),
  ];
  const failedEvidence = [
    ...failedFailures.map((failure) => failure.failure_event_ref),
    ...snapshot.tasks.filter((task) => task.status === "failed").flatMap((task) => task.condition_evidence_refs),
    ...failedControls.flatMap((row) => row.condition_evidence_refs),
  ];
  if (failedEvidence.length > 0) rows.push({ candidate: "failed", evidence: uniqueRefs(failedEvidence) as NonEmptyRefs });
  const exhausted = snapshot.limits.filter((limit) => limit.status === "at-ceiling" || limit.status === "would-exceed" || limit.status === "exceeded");
  if (exhausted.length > 0) rows.push({ candidate: "exhausted", evidence: uniqueRefs(exhausted.map((limit) => limit.evidence_ref)) as NonEmptyRefs });
  const stalled = snapshot.progress.filter((progress) => progress.stalled);
  const stalledEvidence = uniqueRefs(stalled.flatMap((progress) => progress.condition_evidence_refs));
  if (stalledEvidence.length > 0) rows.push({ candidate: "stalled", evidence: stalledEvidence as NonEmptyRefs });
  const heldPolicyFailures = snapshot.active_failures
    .filter((failure) => failure.failure_class === "policy-hold")
    .map((failure) => failure.failure_event_ref);
  const heldPolicyBlocks = snapshot.policy_blocks
    .filter((block) => block.active && block.decision === "hold")
    .map((block) => block.decision_event_ref);
  const heldControls = [
    ...snapshot.gates.filter((gate) => gate.applicable && gate.due && gate.status === "hold"),
    ...snapshot.evaluations.filter((evaluation) => evaluation.applicable && evaluation.due && evaluation.status === "hold"),
  ];
  const heldEvidence = [
    ...heldPolicyFailures,
    ...heldPolicyBlocks,
    ...heldControls.flatMap((row) => row.condition_evidence_refs),
  ];
  if (heldEvidence.length > 0) rows.push({ candidate: "held", evidence: uniqueRefs(heldEvidence) as NonEmptyRefs });
  const retryableBlockedPairs = new Set(snapshot.active_failures
    .filter((failure) => failure.retry_disposition === "waiting" || failure.retry_disposition === "ready")
    .map((failure) => failure.task_ref));
  const blocked = snapshot.tasks.filter((task) => task.status === "blocked" && !retryableBlockedPairs.has(task.ref));
  const blockedEvidence = blocked.flatMap((task) => task.condition_evidence_refs);
  if (blockedEvidence.length > 0) rows.push({ candidate: "blocked", evidence: uniqueRefs(blockedEvidence) as NonEmptyRefs });

  const completedEvidence = completionEvidence(snapshot, resolvedProjection);
  if (completedEvidence.length > 0) rows.push({ candidate: "completed", evidence: completedEvidence as NonEmptyRefs });
  return rows.sort((left, right) => TERMINAL_PRIORITY_V02[right.candidate] - TERMINAL_PRIORITY_V02[left.candidate])[0] ?? null;
}

function preSealSnapshotHash(snapshot: TerminalObservationSnapshotV02): string {
  const { terminal_seal: _terminalSeal, ...rest } = snapshot;
  return hashCanonical({ purpose: "pre-seal-terminal-observation-snapshot-v02", ...rest, terminal_seal: null });
}

/**
 * Package-private and deliberately absent from `src/index.ts`.
 *
 * Structural forgeries receive no authority. Genuine initialized snapshots
 * retain their validated projection and therefore preserve the open work phase.
 */
export function evaluateTerminalV02(
  snapshot: TerminalObservationSnapshotV02,
): TerminalEvaluationResultV02Value {
  const projection = validatedProjectionForTerminalSnapshotV02(snapshot);
  if (
    !isTerminalObservationSnapshotV02(snapshot)
    || projection === undefined
  ) {
    return { decision: "continue", continuation: "terminal-quiescence" };
  }

  return evaluateTerminalDecisionTableV02(snapshot, projection);
}

/** Package-private pure decision reducer used by the builder-boundary tests. */
export function evaluateTerminalDecisionTableV02(
  snapshot: TerminalObservationSnapshotV02,
  projection: ReturnType<typeof validatedProjectionForTerminalSnapshotV02> extends infer T ? Exclude<T, undefined> : never,
): TerminalEvaluationResultV02Value {
  if (snapshot.terminal_seal !== null) {
    return {
      decision: "already-sealed",
      outcome: snapshot.terminal_seal.outcome,
      seal_sequence: snapshot.terminal_seal.ledger_sequence,
      fence_epoch: snapshot.terminal_seal.fence_epoch,
      pre_seal_snapshot_hash: snapshot.terminal_seal.pre_seal_snapshot_hash,
      seal_event_hash: snapshot.terminal_seal.event_hash,
    };
  }

  const selected = terminalCandidate(snapshot, projection);
  if (selected === null && snapshot.phase === "work" && snapshot.terminal_freeze === null) {
    return { decision: "continue", continuation: "work-open" };
  }
  if (selected !== null && snapshot.terminal_freeze === null) {
    return {
      decision: "freeze-work",
      candidate: selected.candidate,
      freeze_revision: 1,
      candidate_evidence_refs: selected.evidence,
      fence_epoch: snapshot.current_fence_epoch,
    };
  }
  if (snapshot.phase === "work" && selected !== null && snapshot.terminal_freeze !== null
    && TERMINAL_PRIORITY_V02[selected.candidate] > TERMINAL_PRIORITY_V02[snapshot.terminal_freeze.candidate]) {
    return {
      decision: "revise-terminal-freeze",
      previous_candidate: snapshot.terminal_freeze.candidate,
      candidate: selected.candidate,
      freeze_revision: snapshot.terminal_freeze.revision + 1,
      previous_freeze_event_hash: snapshot.terminal_freeze.event_hash,
      candidate_evidence_refs: selected.evidence,
    };
  }
  if (snapshot.active_workers > 0 || snapshot.in_flight_actions.some((action) => action.state === "admitted" || action.state === "started")) {
    return { decision: "continue", continuation: "terminal-quiescence" };
  }

  const frozenCandidate = snapshot.terminal_freeze?.candidate;
  const recoveryCandidate = frozenCandidate !== undefined && frozenCandidate in RECOVERY_PRIORITY_V02
    ? frozenCandidate as RecoveryCandidate
    : null;
  const compensationRefs = recoveryCandidate === null ? [] : projection.plan.compensations
    .filter((compensation) => snapshot.effects.some((effect) =>
      effect.task_ref === compensation.for_task
      && effect.effect_ref === compensation.for_effect
      && (effect.outcome === "committed" || effect.outcome === "unknown")))
    .map((compensation) => compensation.id);
  const effectEvidence = uniqueRefs(snapshot.effects
    .filter((effect) => effect.outcome === "committed" || effect.outcome === "unknown")
    .flatMap((effect) => effect.outcome_event_ref === null ? [] : [effect.outcome_event_ref]));

  if (snapshot.phase === "work" && recoveryCandidate !== null && compensationRefs.length > 0 && effectEvidence.length > 0) {
    if (snapshot.compensation_request === null) {
      return {
        decision: "request-compensation",
        request_revision: 1,
        pending_terminal: recoveryCandidate,
        activation_reason: expectedCompensationActivationReasonV02(recoveryCandidate),
        compensation_refs: compensationRefs,
        effect_evidence_refs: effectEvidence as NonEmptyRefs,
        freeze_event_hash: snapshot.terminal_freeze!.event_hash,
      };
    }
    const request = snapshot.compensation_request;
    const added = compensationRefs.filter((ref) => !request.compensation_refs.includes(ref));
    if (RECOVERY_PRIORITY_V02[recoveryCandidate] > RECOVERY_PRIORITY_V02[request.pending_terminal]
      || added.length > 0) {
      return {
        decision: "revise-compensation-request",
        request_revision: request.revision + 1,
        previous_pending_terminal: request.pending_terminal,
        pending_terminal: recoveryCandidate,
        activation_reason: expectedCompensationActivationReasonV02(recoveryCandidate),
        compensation_refs: compensationRefs,
        added_compensation_refs: added,
        previous_request_event_hash: request.event_hash,
        effect_evidence_refs: effectEvidence as NonEmptyRefs,
        freeze_event_hash: snapshot.terminal_freeze!.event_hash,
      };
    }
    return {
      decision: "enter-compensation",
      request_revision: request.revision,
      request_event_hash: request.event_hash,
      pending_terminal: request.pending_terminal,
      compensation_refs: request.compensation_refs,
      freeze_event_hash: snapshot.terminal_freeze!.event_hash,
    };
  }

  if (snapshot.phase === "compensation") {
    const escalationSelection = selected !== null && selected.candidate in RECOVERY_PRIORITY_V02
      ? selected
      : null;
    const escalationCandidate = escalationSelection?.candidate as RecoveryCandidate | undefined;
    if (escalationCandidate !== undefined && snapshot.pending_terminal !== null
      && RECOVERY_PRIORITY_V02[escalationCandidate] > RECOVERY_PRIORITY_V02[snapshot.pending_terminal]) {
      return {
        decision: "escalate-compensation",
        previous_pending_terminal: snapshot.pending_terminal,
        pending_terminal: escalationCandidate,
        activation_reason: expectedCompensationActivationReasonV02(escalationCandidate),
        compensation_refs: snapshot.compensation_request?.compensation_refs
          ?? snapshot.compensations.filter((compensation) => compensation.activation_requested).map((compensation) => compensation.ref),
        previous_candidate_event_hash: snapshot.pending_terminal_event_ref!.event_hash,
        candidate_evidence_refs: escalationSelection!.evidence,
      };
    }
    const capturedCompensation = compensationFactsForTerminalSnapshotV02(snapshot);
    const compensationValue = capturedCompensation?.value ?? (() => {
      const derived = deriveCompensationProjectionV02({
        plan: projection.plan,
        events: projection.events ?? [],
        tasks: snapshot.tasks,
        evaluations: snapshot.evaluations,
        effects: snapshot.effects,
        limits: snapshot.limits,
        policy_blocks: snapshot.policy_blocks,
      });
      return derived.ok ? derived.value : undefined;
    })();
    const settlement = compensationValue?.pending_settlement_decisions[0];
    if (settlement !== undefined) return { decision: "settle-compensation", settlement };
    if (snapshot.compensations.some((compensation) => compensation.applicable && compensation.settlement.status === "pending")) {
      return { decision: "continue", continuation: "compensation-open" };
    }
  }

  if (snapshot.terminal_freeze !== null) {
    return {
      decision: "seal",
      outcome: snapshot.pending_terminal ?? snapshot.terminal_freeze.candidate,
      expected_ledger_sequence: snapshot.ledger_sequence,
      expected_ledger_head_hash: snapshot.ledger_head_hash,
      pre_seal_snapshot_hash: preSealSnapshotHash(snapshot),
      current_fence_epoch: snapshot.current_fence_epoch,
      next_fence_epoch: snapshot.current_fence_epoch + 1,
    };
  }
  return { decision: "continue", continuation: snapshot.phase === "compensation" ? "compensation-open" : "work-open" };
}
