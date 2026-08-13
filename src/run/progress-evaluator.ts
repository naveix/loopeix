import type {
  LedgerRefV02Value,
  ProgressComparisonV02,
  TerminalSnapshotInvalidReasonV02,
  ValidatedRuntimeProjectionInputV02,
  ProgressEvaluationV02Value,
  ProgressObservationEvaluationV02Value,
  ProgressSampleV02Value,
  RuntimeResult,
} from "../schema/runtime.js";
import {
  compareRuntimeUtf8BytesV02,
  ProgressEvaluationV02,
} from "../schema/runtime.js";
import { isValidatedRuntimeProjectionInputV02 } from "./terminal-snapshot.js";

type ComparableSampleValue = string | number | boolean;
type DeclaredParseableSample = Extract<ProgressSampleV02Value, { status: "source-present"; value_status: "parseable" }>;
type ParseableObservation = {
  event: ValidatedRuntimeProjectionInputV02["observations"][number];
  value: ComparableSampleValue;
};

function ok<T, E extends string>(value: T): RuntimeResult<T, E> {
  return { ok: true, value };
}

function err<T, E extends string>(error: E): RuntimeResult<T, E> {
  return { ok: false, error };
}

function refFor(event: ValidatedRuntimeProjectionInputV02["observations"][number]): LedgerRefV02Value {
  return {
    ledger_sequence: event.sequence,
    event_hash: event.event_hash,
  };
}

function isDeclaredParseableSample(sample: ProgressSampleV02Value): sample is DeclaredParseableSample {
  return sample.status === "source-present" && sample.value_status === "parseable";
}

function matchesExpectedValueType(
  expected: "number" | "string" | "boolean",
  value: unknown,
): value is ComparableSampleValue {
  if (expected === "number") return typeof value === "number";
  if (expected === "string") return typeof value === "string";
  return typeof value === "boolean";
}

function compareValues(
  previous: ComparableSampleValue,
  current: ComparableSampleValue,
  improvesWhen: { operator: "increases" | "decreases" } | { operator: "equals"; target: string | number | boolean },
): ProgressComparisonV02 {
  switch (improvesWhen.operator) {
    case "increases":
      if (current > previous) return "improved";
      if (current === previous) return "unchanged";
      return "regressed";
    case "decreases":
      if (current < previous) return "improved";
      if (current === previous) return "unchanged";
      return "regressed";
    case "equals":
      if ((current === improvesWhen.target) === (previous === improvesWhen.target)) return "unchanged";
      return current === improvesWhen.target ? "improved" : "regressed";
  }
}

function targetReached(
  target: { operator: "gte" | "lte" | "equals"; value: string | number | boolean } | null,
  value: ComparableSampleValue,
): boolean {
  if (target === null) return false;
  if (target.operator === "equals") return value === target.value;
  if (typeof value !== "number" || typeof target.value !== "number") return false;
  return target.operator === "gte" ? value >= target.value : value <= target.value;
}

function evaluateObservation(
  input: ValidatedRuntimeProjectionInputV02,
  ref: string,
): RuntimeResult<ProgressObservationEvaluationV02Value, TerminalSnapshotInvalidReasonV02> {
  const definition = input.plan.progress.observations.find((observation) => observation.id === ref);
  if (definition === undefined) return err("SNAPSHOT_COVERAGE_OR_ORDER_INVALID");

  const eligible = input.observations
    .filter((event) => event.payload.observation_ref === ref && event.payload.pending_attempt_ordinal <= input.completed_loop_attempts)
    .sort((left, right) => left.sequence - right.sequence);

  let previousParseable: ComparableSampleValue | null = null;
  let baselineRef: LedgerRefV02Value | null = null;
  let latestRef: LedgerRefV02Value | null = null;
  let parseableCount = 0;
  let stallCounter = 0;
  const parseableEvents: ParseableObservation[] = [];

  for (const event of eligible) {
    const sample = event.payload.sample;
    if (isDeclaredParseableSample(sample)) {
      if (!matchesExpectedValueType(definition.value_type, sample.sample_value)) {
        return err("SNAPSHOT_COVERAGE_OR_ORDER_INVALID");
      }

      const parseableValue = sample.sample_value;
      parseableCount += 1;
      parseableEvents.push({ event, value: parseableValue });
      if (baselineRef === null) {
        baselineRef = refFor(event);
        latestRef = refFor(event);
        previousParseable = parseableValue;
        stallCounter = 0;
        continue;
      }

      if (previousParseable === null) {
        return err("SNAPSHOT_COVERAGE_OR_ORDER_INVALID");
      }
      const comparison = compareValues(previousParseable, parseableValue, definition.improves_when);
      latestRef = refFor(event);
      previousParseable = parseableValue;
      stallCounter = comparison === "improved" ? 0 : stallCounter + 1;
      continue;
    }

    if (baselineRef !== null) stallCounter += 1;
  }

  const current = eligible.at(-1);
  if (current === undefined || baselineRef === null || previousParseable === null) {
    return ok({
      ref,
      completed_loop_attempts: input.completed_loop_attempts,
      parseable_sample_count: 0,
      baseline_ref: null,
      latest_ref: null,
      comparison: "unavailable",
      target_reached: false,
      stalled: false,
    });
  }

  const currentSample = current.payload.sample;
  let comparison: ProgressComparisonV02;
  let reached = false;

  if (isDeclaredParseableSample(currentSample)) {
    if (!matchesExpectedValueType(definition.value_type, currentSample.sample_value)) {
      return err("SNAPSHOT_COVERAGE_OR_ORDER_INVALID");
    }
    reached = targetReached(definition.target, currentSample.sample_value);
    if (parseableCount === 1) comparison = "baseline";
    else {
      const previous = parseableEvents.at(-2);
      const currentParseable = parseableEvents.at(-1);
      if (previous === undefined || currentParseable === undefined) comparison = "baseline";
      else comparison = compareValues(previous.value, currentParseable.value, definition.improves_when);
    }
  } else {
    comparison = "unparseable";
  }

  return ok({
    ref,
    completed_loop_attempts: input.completed_loop_attempts,
    parseable_sample_count: parseableCount,
    baseline_ref: baselineRef,
    latest_ref: latestRef,
    comparison,
    target_reached: reached,
    stalled: stallCounter >= input.plan.progress.stall_after_loop_attempts,
  });
}

export function evaluateProgressV02(
  input: ValidatedRuntimeProjectionInputV02,
): RuntimeResult<ProgressEvaluationV02Value, TerminalSnapshotInvalidReasonV02> {
  if (!isValidatedRuntimeProjectionInputV02(input)) return err("PLAN_OR_LEDGER_LINEAGE_INVALID");
  return deriveProgressV02ForRuntime(input);
}

/** Package-private shared derivation; admission and branding remain at the public wrapper. */
export function deriveProgressV02ForRuntime(
  input: ValidatedRuntimeProjectionInputV02,
): RuntimeResult<ProgressEvaluationV02Value, TerminalSnapshotInvalidReasonV02> {
  const knownRefs = new Set(input.plan.progress.observations.map((observation) => observation.id));
  for (const event of input.observations) {
    if (event.run_id !== input.run_id) return err("PLAN_OR_LEDGER_LINEAGE_INVALID");
    if (!knownRefs.has(event.payload.observation_ref)) return err("SNAPSHOT_COVERAGE_OR_ORDER_INVALID");
    if (event.payload.pending_attempt_ordinal > input.plan.limit_policy.max_loop_attempts) {
      return err("SNAPSHOT_COVERAGE_OR_ORDER_INVALID");
    }
  }

  const orderedRefs = [...input.plan.progress.observations]
    .map((observation) => observation.id)
    .sort(compareRuntimeUtf8BytesV02);

  const observations: ProgressObservationEvaluationV02Value[] = [];
  for (const ref of orderedRefs) {
    const evaluated = evaluateObservation(input, ref);
    if (!evaluated.ok) return evaluated;
    observations.push(evaluated.value);
  }

  const value = ProgressEvaluationV02.parse({
    schema_version: "0.2",
    run_id: input.run_id,
    plan_hash: input.plan_hash,
    ledger_sequence: input.ledger_sequence,
    ledger_head_hash: input.ledger_head_hash,
    observations,
  });
  return ok(value as ProgressEvaluationV02Value);
}
