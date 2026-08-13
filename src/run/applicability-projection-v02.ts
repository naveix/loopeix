import type {
  LedgerRefV02Value,
  ResolvedRunPlanV02Value,
  RuntimeEventV02Value,
  RuntimeResult,
  TerminalObservationSnapshotV02,
} from "../schema/runtime.js";
import { compareRuntimeUtf8BytesV02 } from "../schema/runtime.js";
import { hashCanonical } from "../hash.js";

type GateObservationV02 = TerminalObservationSnapshotV02["gates"][number];
type EvaluationObservationV02 = TerminalObservationSnapshotV02["evaluations"][number];

export type ApplicabilityProjectionInputV02 = Readonly<{
  plan: ResolvedRunPlanV02Value;
  events: readonly RuntimeEventV02Value[];
  phase: "work" | "compensation";
  active_compensation_refs: readonly string[];
}>;

export type ApplicabilityProjectionV02 = Readonly<{
  gates: readonly GateObservationV02[];
  evaluations: readonly EvaluationObservationV02[];
}>;

export type ApplicabilityProjectionResultV02 = RuntimeResult<
  ApplicabilityProjectionV02,
  "APPLICABILITY_OR_DUE_INVALID"
>;

type ControlPrerequisiteV02 = ResolvedRunPlanV02Value["gates"][number]["prerequisites"][number];
type ControlSpecV02 = ResolvedRunPlanV02Value["gates"][number]
  | ResolvedRunPlanV02Value["evaluations"][number];
type RequiredEventV02 = Extract<RuntimeEventV02Value, {
  event_type: "gate.result-required" | "evaluation.result-required";
}>;
type GateRequiredEventV02 = Extract<RuntimeEventV02Value, { event_type: "gate.result-required" }>;
type GateResultEventV02 = Extract<RuntimeEventV02Value, { event_type: "gate.result-recorded" }>;
type EvaluationRequiredEventV02 = Extract<RuntimeEventV02Value, { event_type: "evaluation.result-required" }>;
type EvaluationResultEventV02 = Extract<RuntimeEventV02Value, { event_type: "evaluation.result-recorded" }>;

const INVALID = Object.freeze({ ok: false, error: "APPLICABILITY_OR_DUE_INVALID" } as const);

function eventRef(event: RuntimeEventV02Value): LedgerRefV02Value {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function sameRef(left: LedgerRefV02Value, right: LedgerRefV02Value): boolean {
  return left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function sameRefs(left: readonly LedgerRefV02Value[], right: readonly LedgerRefV02Value[]): boolean {
  return left.length === right.length && left.every((value, index) => sameRef(value, right[index]!));
}

function canonicalRefs(events: readonly RuntimeEventV02Value[]): LedgerRefV02Value[] {
  return [...events]
    .sort((left, right) => left.sequence - right.sequence
      || compareRuntimeUtf8BytesV02(left.event_hash, right.event_hash))
    .map(eventRef);
}

function latestEvent<T extends RuntimeEventV02Value>(events: readonly T[]): T | undefined {
  return events.reduce<T | undefined>((latest, event) =>
    latest === undefined || event.sequence > latest.sequence ? event : latest, undefined);
}

function resolvePrerequisiteEvents(
  plan: ResolvedRunPlanV02Value,
  events: readonly RuntimeEventV02Value[],
  prerequisite: ControlPrerequisiteV02,
): readonly RuntimeEventV02Value[] | null {
  if (prerequisite.kind === "run-initialized") {
    const initialized = events.filter((event) => event.event_type === "run.initialized");
    return initialized.length === 1 && initialized[0]!.sequence === 1 ? initialized : null;
  }
  if (prerequisite.kind === "task-terminal") {
    const settled = latestEvent(events.filter((event) =>
      event.event_type === "task.action-settled" && event.payload.task_ref === prerequisite.task_ref));
    return settled === undefined ? null : [settled];
  }
  if (prerequisite.kind === "artifact-recorded") {
    const artifacts = events.filter((event) =>
      event.event_type === "artifact.recorded" && event.payload.artifact_ref === prerequisite.artifact_ref);
    return artifacts.length === 1 ? artifacts : null;
  }
  if (prerequisite.kind === "evidence-recorded") {
    const evidence = events.filter((event) => event.event_type === "evidence.recorded"
      && event.payload.requirement_refs.includes(prerequisite.evidence_requirement_ref));
    const requirement = plan.evidence_requirements.find(({ id }) => id === prerequisite.evidence_requirement_ref);
    if (requirement === undefined) return null;
    const independenceKeys = new Set(evidence.flatMap((event) =>
      event.event_type === "evidence.recorded"
        ? event.payload.independence_roots.map((root) => root.independence_key)
        : []));
    return independenceKeys.size >= requirement.minimum_independent_roots ? evidence : null;
  }
  if (prerequisite.kind === "gate-pass") {
    const results = events.filter((event) => event.event_type === "gate.result-recorded"
      && event.payload.gate_ref === prerequisite.gate_ref && event.payload.status === "PASS");
    return results.length === 1 ? results : null;
  }
  if (prerequisite.kind === "evaluation-pass") {
    const results = events.filter((event) => event.event_type === "evaluation.result-recorded"
      && event.payload.evaluation_ref === prerequisite.evaluation_ref && event.payload.status === "PASS");
    return results.length === 1 ? results : null;
  }
  if (prerequisite.kind === "compensation-phase-entered") {
    const entries = events.filter((event) => event.event_type === "run.compensation-phase-entered"
      && event.payload.compensation_refs.includes(prerequisite.compensation_ref));
    return entries.length === 1 ? entries : null;
  }

  const compensation = plan.compensations.find(({ id }) => id === prerequisite.compensation_ref);
  if (compensation === undefined) return null;
  const settled = latestEvent(events.filter((event) => event.event_type === "task.action-settled"
    && event.payload.task_ref === compensation.action_task));
  return settled === undefined ? null : [settled];
}

function expectedPrerequisiteRefs(
  plan: ResolvedRunPlanV02Value,
  events: readonly RuntimeEventV02Value[],
  control: ControlSpecV02,
  required: RequiredEventV02,
): readonly LedgerRefV02Value[] | null {
  const earlierEvents = events.filter((event) => event.sequence < required.sequence);
  const facts: RuntimeEventV02Value[] = [];
  for (const prerequisite of control.prerequisites) {
    const resolved = resolvePrerequisiteEvents(plan, earlierEvents, prerequisite);
    if (resolved === null) return null;
    facts.push(...resolved);
  }
  const refs = canonicalRefs(facts);
  const unique = new Set(refs.map((ref) => `${ref.ledger_sequence}:${ref.event_hash}`));
  return unique.size === refs.length ? refs : null;
}

function applicabilityMatches(
  control: ControlSpecV02,
  required: RequiredEventV02,
): boolean {
  return required.payload.applicability === control.applicability.mode
    && required.payload.compensation_ref === (
      control.applicability.mode === "compensation" ? control.applicability.compensation_ref : null
    );
}

export function projectApplicabilityAndDueV02(
  input: ApplicabilityProjectionInputV02,
): ApplicabilityProjectionResultV02 {
  const activeCompensations = new Set(input.active_compensation_refs);
  // Phase is retained explicitly because callers derive activation and phase at
  // different precedence stages. Applicability itself is sticky across both.
  void input.phase;

  const gateIds = new Set(input.plan.gates.map(({ id }) => id));
  const evaluationIds = new Set(input.plan.evaluations.map(({ id }) => id));
  if (input.events.some((event) =>
    ((event.event_type === "gate.result-required" || event.event_type === "gate.result-recorded")
      && !gateIds.has(event.payload.gate_ref))
    || ((event.event_type === "evaluation.result-required" || event.event_type === "evaluation.result-recorded")
      && !evaluationIds.has(event.payload.evaluation_ref)))) return INVALID;

  const gates: GateObservationV02[] = [];
  for (const gate of input.plan.gates) {
    const requirements = input.events.filter((event): event is GateRequiredEventV02 =>
      event.event_type === "gate.result-required" && event.payload.gate_ref === gate.id);
    const results = input.events.filter((event): event is GateResultEventV02 =>
      event.event_type === "gate.result-recorded" && event.payload.gate_ref === gate.id);
    if (requirements.length > 1 || results.length > 1) return INVALID;
    const required = requirements[0];
    const result = results[0];
    const applicable = gate.applicability.mode === "always"
      || activeCompensations.has(gate.applicability.compensation_ref);
    if ((required !== undefined && !applicable) || (result !== undefined && required === undefined)) return INVALID;
    if (required !== undefined) {
      const expectedRefs = expectedPrerequisiteRefs(input.plan, input.events, gate, required);
      if (!applicabilityMatches(gate, required)
        || required.payload.prerequisite_set_hash !== hashCanonical(gate.prerequisites)
        || expectedRefs === null
        || !sameRefs(required.payload.prerequisite_refs, expectedRefs)) return INVALID;
    }
    if (result !== undefined && (required === undefined
      || result.sequence <= required.sequence
      || !sameRef(result.payload.required_event_ref, eventRef(required))
      || result.payload.evaluator_identity_ref !== gate.evaluator_binding.evaluator_identity_ref
      || result.payload.policy_digest !== gate.evaluator_binding.policy_digest)) return INVALID;
    let waiverActiveAtUse: boolean | null = null;
    let waiverUseEventRefs: LedgerRefV02Value[] = [];
    if (result?.payload.status === "WAIVED") {
      const waiverRef = result.payload.waiver_event_ref;
      const waiver = waiverRef === null ? undefined : input.events.find((event) =>
        event.event_type === "waiver.recorded" && sameRef(eventRef(event), waiverRef));
      if (!gate.waiver_allowed || waiver?.event_type !== "waiver.recorded"
        || waiver.payload.gate_ref !== gate.id || required === undefined
        || !sameRef(waiver.payload.required_event_ref, eventRef(required))
        || waiver.payload.prerequisite_set_hash !== required.payload.prerequisite_set_hash
        || waiver.sequence + 1 !== result.sequence) return INVALID;
      waiverActiveAtUse = true;
      waiverUseEventRefs = [waiverRef!];
    }
    const status: GateObservationV02["status"] = result === undefined ? "missing"
      : result.payload.status === "PASS" ? "pass"
        : result.payload.status === "HOLD" ? "hold"
          : result.payload.status === "FAIL" ? "fail" : "waived-valid";
    gates.push(Object.freeze({
      ref: gate.id,
      applicable,
      due: required !== undefined,
      status,
      required_event_ref: required === undefined ? null : eventRef(required),
      result_event_ref: result === undefined ? null : eventRef(result),
      condition_evidence_refs: result === undefined ? [] : [eventRef(result)],
      waiver_active_at_use: waiverActiveAtUse,
      waiver_use_event_refs: waiverUseEventRefs,
    }));
  }

  const evaluations: EvaluationObservationV02[] = [];
  for (const evaluation of input.plan.evaluations) {
    const requirements = input.events.filter((event): event is EvaluationRequiredEventV02 =>
      event.event_type === "evaluation.result-required" && event.payload.evaluation_ref === evaluation.id);
    const results = input.events.filter((event): event is EvaluationResultEventV02 =>
      event.event_type === "evaluation.result-recorded" && event.payload.evaluation_ref === evaluation.id);
    if (requirements.length > 1 || results.length > 1) return INVALID;
    const required = requirements[0];
    const result = results[0];
    const applicable = evaluation.applicability.mode === "always"
      || activeCompensations.has(evaluation.applicability.compensation_ref);
    if ((required !== undefined && !applicable) || (result !== undefined && required === undefined)) return INVALID;
    if (required !== undefined) {
      const expectedRefs = expectedPrerequisiteRefs(input.plan, input.events, evaluation, required);
      if (!applicabilityMatches(evaluation, required)
        || required.payload.prerequisite_set_hash !== hashCanonical(evaluation.prerequisites)
        || expectedRefs === null
        || !sameRefs(required.payload.prerequisite_refs, expectedRefs)) return INVALID;
    }
    if (result !== undefined && (required === undefined
      || result.sequence <= required.sequence
      || !sameRef(result.payload.required_event_ref, eventRef(required))
      || result.payload.evaluator_identity_ref !== evaluation.evaluator_binding.evaluator_identity_ref
      || result.payload.policy_digest !== evaluation.evaluator_binding.policy_digest
      || result.payload.export_check_role !== evaluation.evaluator_binding.export_check_role)) return INVALID;
    const status: EvaluationObservationV02["status"] = result === undefined ? "missing"
      : result.payload.status === "PASS" ? "pass"
        : result.payload.status === "HOLD" ? "hold"
          : result.payload.status === "FAIL" ? "fail" : "skipped";
    evaluations.push(Object.freeze({
      ref: evaluation.id,
      applicable,
      due: required !== undefined,
      status,
      required_event_ref: required === undefined ? null : eventRef(required),
      result_event_ref: result === undefined ? null : eventRef(result),
      condition_evidence_refs: result === undefined ? [] : [eventRef(result)],
    }));
  }

  return {
    ok: true,
    value: Object.freeze({
      gates: Object.freeze(gates),
      evaluations: Object.freeze(evaluations),
    }),
  };
}
