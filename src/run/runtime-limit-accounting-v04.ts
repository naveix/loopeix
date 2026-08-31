import { createHash } from "node:crypto";

import { z } from "zod";

import { canonicalize } from "../hash.js";
import { LedgerRefV02 } from "../schema/runtime.js";
import { HumanIdV02, MachineIdV02 } from "../schema/scalars-v02.js";
import { ResolvedRunPlanV03 } from "../schema/runtime-v04.js";
import {
  isValidatedRuntimePlanV03,
  type ValidatedRuntimePlanV03,
} from "./project-plan-v03.js";
import { reduceRuntimeEventPrefixV04, type RuntimeStateV04 } from "./runtime-state-reducer-v04.js";
import {
  isValidatedRunManifestPairV04,
  type ValidatedRunManifestV04,
} from "./runtime-manifest-v04.js";
import type { ValidatedRuntimeLedgerV04 } from "./runtime-ledger-v04.js";

const nonNegativeSafeInteger = z.number().int().nonnegative().refine(Number.isSafeInteger);
const positiveSafeInteger = nonNegativeSafeInteger.positive();

const RuntimeLimitCountersV04 = z.object({
  loop_attempts: nonNegativeSafeInteger,
  execution_attempts: nonNegativeSafeInteger,
  task_executions: z.record(HumanIdV02, nonNegativeSafeInteger),
  elapsed_ms: nonNegativeSafeInteger,
  tool_calls: nonNegativeSafeInteger,
  action_output_bytes: nonNegativeSafeInteger,
  control_output_bytes: nonNegativeSafeInteger,
  token_count: nonNegativeSafeInteger,
  cost_minor_units: nonNegativeSafeInteger,
  active_workers: nonNegativeSafeInteger,
}).strict();

const RuntimeLimitRequestV04 = z.object({
  task_ref: HumanIdV02.nullable(),
  loop_attempts: nonNegativeSafeInteger,
  execution_attempts: nonNegativeSafeInteger,
  task_executions: nonNegativeSafeInteger,
  elapsed_ms: nonNegativeSafeInteger,
  tool_calls: nonNegativeSafeInteger,
  action_output_bytes: nonNegativeSafeInteger,
  control_output_bytes: nonNegativeSafeInteger,
  token_count: nonNegativeSafeInteger,
  cost_minor_units: nonNegativeSafeInteger,
  workers: nonNegativeSafeInteger,
  process_runtime_ms: nonNegativeSafeInteger,
}).strict();

const RuntimeLimitAccountingInputV04 = z.object({
  plan: ResolvedRunPlanV03,
  phase: z.enum(["work", "compensation"]),
  consumed: RuntimeLimitCountersV04,
  requested: RuntimeLimitRequestV04,
}).strict();

const RuntimeRetryRuleV04 = z.object({
  retryable: z.boolean(),
  backoff: z.enum(["none", "fixed", "exponential"]),
  base_delay_ms: nonNegativeSafeInteger,
  max_delay_ms: nonNegativeSafeInteger,
}).strict();

const RuntimeRetryScheduleInputV04 = z.object({
  run_id: MachineIdV02,
  // The frozen vectors use a machine ID (`task_s41_retry`), while admitted
  // plan task refs use HumanIdV02 kebab-case. Both are canonical and bounded.
  task_ref: z.union([HumanIdV02, MachineIdV02]),
  failure_event_ref: LedgerRefV02,
  failure_ordinal: positiveSafeInteger,
  rule: RuntimeRetryRuleV04,
}).strict();

export type RuntimeLimitRefV04 =
  | "max-loop-attempts"
  | "max-elapsed-ms"
  | "max-tool-calls"
  | "max-output-bytes"
  | "max-tokens"
  | "max-cost"
  | "max-process-runtime"
  | "max-workers";

export type RuntimeLimitViolationV04 = Readonly<{
  limit_ref: RuntimeLimitRefV04;
  consumed: number;
  requested: number;
  ceiling: number;
}>;

type NullableNumber = number | null;

export type RuntimeLimitAccountingValueV04 = Readonly<{
  admitted: boolean;
  execution_attempts_exhausted: boolean;
  requested_task_executions_exhausted: boolean;
  exhausted_limit_refs: readonly RuntimeLimitRefV04[];
  ceilings: Readonly<{
    loop_attempts: number;
    execution_attempts: number;
    requested_task_executions: number | null;
    elapsed_ms: number;
    tool_calls: number;
    action_output_bytes: number;
    control_output_bytes: number;
    token_count: NullableNumber;
    cost_minor_units: NullableNumber;
    workers: number;
    process_runtime_ms: number;
  }>;
  prospective: Readonly<{
    loop_attempts: number;
    execution_attempts: number;
    requested_task_executions: number | null;
    elapsed_ms: number;
    tool_calls: number;
    action_output_bytes: number;
    control_output_bytes: number;
    token_count: number;
    cost_minor_units: number;
    workers: number;
    process_runtime_ms: number;
  }>;
  remaining: Readonly<{
    loop_attempts: number;
    execution_attempts: number;
    requested_task_executions: number | null;
    elapsed_ms: number;
    tool_calls: number;
    action_output_bytes: number;
    control_output_bytes: number;
    token_count: NullableNumber;
    cost_minor_units: NullableNumber;
    workers: number;
    process_runtime_ms: number;
  }>;
  violations: readonly RuntimeLimitViolationV04[];
}>;

export type RuntimeLimitAccountingResultV04 =
  | Readonly<{ ok: true; value: RuntimeLimitAccountingValueV04 }>
  | Readonly<{ ok: false; reason: "INVALID_RUNTIME_LIMIT_ACCOUNTING" }>;

export type RuntimeLimitCountersV04Value = Readonly<{
  loop_attempts: number;
  execution_attempts: number;
  task_executions: Readonly<Record<string, number>>;
  elapsed_ms: number;
  tool_calls: number;
  action_output_bytes: number;
  control_output_bytes: number;
  token_count: number;
  cost_minor_units: number;
  active_workers: number;
}>;

export type RuntimeLimitCounterProjectionV04Result =
  | Readonly<{ ok: true; value: RuntimeLimitCountersV04Value }>
  | Readonly<{ ok: false; reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION" }>;

export type RuntimeRetryScheduleValueV04 = Readonly<{
  identity_hash: string;
  deterministic_backoff_ms: number;
  jitter_window_ms: number;
  signed_jitter_ms: number;
  scheduled_delay_ms: number;
}>;

export type RuntimeRetryScheduleResultV04 =
  | Readonly<{ ok: true; value: RuntimeRetryScheduleValueV04 }>
  | Readonly<{ ok: false; reason: "INVALID_RUNTIME_RETRY_SCHEDULE" }>;

const INVALID_ACCOUNTING = Object.freeze({
  ok: false,
  reason: "INVALID_RUNTIME_LIMIT_ACCOUNTING",
} as const);
const INVALID_RETRY = Object.freeze({
  ok: false,
  reason: "INVALID_RUNTIME_RETRY_SCHEDULE",
} as const);
const INVALID_COUNTER_PROJECTION = Object.freeze({
  ok: false,
  reason: "INVALID_RUNTIME_LIMIT_COUNTER_PROJECTION",
} as const);

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function checkedAdd(left: number, right: number): number | null {
  if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right) || left < 0 || right < 0) return null;
  return left <= Number.MAX_SAFE_INTEGER - right ? left + right : null;
}

function checkedSubtract(left: number, right: number): number | null {
  if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right) || left < 0 || right < 0 || right > left) return null;
  return left - right;
}

function exactProjectionInput(input: unknown): Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
}> | null {
  try {
    if (typeof input !== "object" || input === null || Object.getPrototypeOf(input) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const keys = Object.keys(descriptors);
    if (keys.length !== 3 || !["validated_plan", "ledger", "manifest"].every((key) => keys.includes(key))) return null;
    if (Object.values(descriptors).some((descriptor) => !("value" in descriptor)
      || descriptor.get !== undefined || descriptor.set !== undefined || !descriptor.enumerable)) return null;
    return {
      validated_plan: descriptors.validated_plan!.value as ValidatedRuntimePlanV03,
      ledger: descriptors.ledger!.value as ValidatedRuntimeLedgerV04,
      manifest: descriptors.manifest!.value as ValidatedRunManifestV04,
    };
  } catch {
    return null;
  }
}

function exactPrefixProjectionInput(input: unknown): Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  prefix_event_ref: z.infer<typeof LedgerRefV02>;
}> | null {
  try {
    if (typeof input !== "object" || input === null || Object.getPrototypeOf(input) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const keys = Object.keys(descriptors);
    if (keys.length !== 4
      || !["validated_plan", "ledger", "manifest", "prefix_event_ref"].every((key) => keys.includes(key))) return null;
    if (Object.values(descriptors).some((descriptor) => !("value" in descriptor)
      || descriptor.get !== undefined || descriptor.set !== undefined || !descriptor.enumerable)) return null;
    return {
      validated_plan: descriptors.validated_plan!.value as ValidatedRuntimePlanV03,
      ledger: descriptors.ledger!.value as ValidatedRuntimeLedgerV04,
      manifest: descriptors.manifest!.value as ValidatedRunManifestV04,
      prefix_event_ref: descriptors.prefix_event_ref!.value as z.infer<typeof LedgerRefV02>,
    };
  } catch {
    return null;
  }
}

function exactReferencedEvent(
  events: readonly Readonly<{ sequence: number; event_hash: string }>[],
  ref: z.infer<typeof LedgerRefV02>,
): Readonly<{ sequence: number; event_hash: string }> | null {
  const candidate = events[ref.ledger_sequence - 1];
  return candidate?.event_hash === ref.event_hash ? candidate : null;
}

function summedLedgerLineBytes(
  lineByteLengths: readonly number[],
  prefixLength: number,
): number | null {
  let total = 0;
  if (prefixLength < 0 || prefixLength > lineByteLengths.length) return null;
  for (const length of lineByteLengths.slice(0, prefixLength)) {
    const next = checkedAdd(total, length);
    if (next === null) return null;
    total = next;
  }
  return total;
}

function summaryRecordControlBytesAtPrefix(
  ledger: ValidatedRuntimeLedgerV04,
  manifest: ValidatedRunManifestV04,
  prefixLength: number,
  requireExhaustiveCommittedRecords: boolean,
): number | null {
  const ledgerBytesThroughPrefix = summedLedgerLineBytes(ledger.line_byte_lengths, prefixLength);
  if (ledgerBytesThroughPrefix === null) return null;
  const presentRows = manifest.file_inventory.filter((row) =>
    row.exists && row.path.startsWith("summaries/records/"));
  const byPath = new Map(presentRows.map((row) => [row.path, row] as const));
  if (byPath.size !== presentRows.length) return null;
  let total = ledgerBytesThroughPrefix;
  let committedRecords = 0;
  for (const event of ledger.events.slice(0, prefixLength)) {
    if (event.event_type !== "run.compaction-recorded") continue;
    const row = byPath.get(event.payload.summary_record_path);
    if (row === undefined
      || row.family !== "record"
      || !row.required
      || row.mode !== 384
      || row.size_bytes === null
      || row.hash !== event.payload.summary_record_hash) return null;
    const next = checkedAdd(total, row.size_bytes);
    if (next === null) return null;
    total = next;
    committedRecords += 1;
    byPath.delete(event.payload.summary_record_path);
  }
  if (requireExhaustiveCommittedRecords && committedRecords !== presentRows.length) return null;
  return total;
}

function actionAdmissionCounters(payload: unknown): Readonly<{
  action_id: string;
  task_ref: string;
  task_executions_after: number;
  action_output_bytes_after: number;
}> | null {
  if (typeof payload !== "object" || payload === null) return null;
  const row = payload as Record<string, unknown>;
  if (typeof row.action_id !== "string"
    || typeof row.task_ref !== "string"
    || typeof row.task_executions_after !== "number"
    || !Number.isSafeInteger(row.task_executions_after)
    || row.task_executions_after < 1
    || typeof row.action_output_bytes_after !== "number"
    || !Number.isSafeInteger(row.action_output_bytes_after)
    || row.action_output_bytes_after < 0) return null;
  return {
    action_id: row.action_id,
    task_ref: row.task_ref,
    task_executions_after: row.task_executions_after,
    action_output_bytes_after: row.action_output_bytes_after,
  };
}

function validatedProjectionScope(
  validatedPlan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
  manifest: ValidatedRunManifestV04,
): boolean {
  const { plan } = validatedPlan;
  return validatedPlan.run_id === plan.run_id
    && validatedPlan.run_id === ledger.run_id
    && ledger.run_id === manifest.run_id
    && validatedPlan.plan_hash === ledger.plan_hash
    && ledger.plan_hash === manifest.plan_hash;
}

function hasExactCapturedLedgerBytes(ledger: ValidatedRuntimeLedgerV04): boolean {
  if (ledger.line_byte_lengths.length !== ledger.events.length) return false;
  return summedLedgerLineBytes(ledger.line_byte_lengths, ledger.line_byte_lengths.length) === ledger.ledger_byte_length;
}

function projectCounterStateFromPrefix(
  validatedPlan: ValidatedRuntimePlanV03,
  events: readonly ValidatedRuntimeLedgerV04["events"][number][],
  controlOutputBytes: number,
  expectedState: RuntimeStateV04,
): RuntimeLimitCounterProjectionV04Result {
  const { plan } = validatedPlan;
  const taskIds = [...plan.tasks.map((task) => task.id)].sort(compareUtf8);
  const taskExecutions = Object.fromEntries(taskIds.map((taskId) => [taskId, 0])) as Record<string, number>;
  const inFlight = new Set<string>();
  const admissions = new Map<string, { task_ref: string; task_executions_after: number }>();
  const terminalActions = new Set<string>();
  let executionAttempts = 0;
  let loopAttempts = 0;
  let completedLoopOrdinal = 0;
  let elapsedMs = 0;
  let toolCalls = 0;
  let actionOutputBytes = 0;
  let tokenCount = 0;
  let costMinorUnits = 0;

  for (const event of events) {
    switch (event.event_type) {
      case "run.clock-observed":
        if (event.payload.elapsed_ms < elapsedMs) return INVALID_COUNTER_PROJECTION;
        elapsedMs = event.payload.elapsed_ms;
        break;
      case "execution.attempt-started":
        executionAttempts += 1;
        if (!Number.isSafeInteger(executionAttempts) || event.payload.attempt_ordinal !== executionAttempts) {
          return INVALID_COUNTER_PROJECTION;
        }
        break;
      case "task.action-admitted": {
        const admissionCounters = actionAdmissionCounters(event.payload);
        if (admissionCounters === null) return INVALID_COUNTER_PROJECTION;
        const previous = taskExecutions[admissionCounters.task_ref];
        if (previous === undefined || admissions.has(admissionCounters.action_id)
          || admissionCounters.task_executions_after !== previous + 1
          || !Number.isSafeInteger(previous + 1)
          || admissionCounters.action_output_bytes_after < actionOutputBytes) return INVALID_COUNTER_PROJECTION;
        taskExecutions[admissionCounters.task_ref] = admissionCounters.task_executions_after;
        actionOutputBytes = admissionCounters.action_output_bytes_after;
        admissions.set(admissionCounters.action_id, {
          task_ref: admissionCounters.task_ref,
          task_executions_after: admissionCounters.task_executions_after,
        });
        inFlight.add(admissionCounters.action_id);
        break;
      }
      case "artifact.write-admitted":
        if (!inFlight.has(event.payload.action_id)
          || event.payload.action_output_bytes_after < actionOutputBytes) return INVALID_COUNTER_PROJECTION;
        actionOutputBytes = event.payload.action_output_bytes_after;
        break;
      case "tool.call-admitted": {
        const next = checkedAdd(toolCalls, 1);
        if (next === null || !inFlight.has(event.payload.action_id)
          || event.payload.tool_calls_after !== next) return INVALID_COUNTER_PROJECTION;
        toolCalls = next;
        break;
      }
      case "task.execution-completed":
      case "task.execution-failed": {
        const admission = admissions.get(event.payload.action_id);
        if (admission === undefined
          || !inFlight.has(event.payload.action_id)
          || terminalActions.has(event.payload.action_id)
          || admission.task_ref !== event.payload.task_ref
          || event.payload.task_executions_after !== admission.task_executions_after
          || event.payload.workers_after !== inFlight.size
          || event.payload.action_output_bytes_after < actionOutputBytes
          || event.payload.tool_calls_after < toolCalls
          || event.payload.loop_attempts_after < loopAttempts
          || event.payload.loop_attempts_after > loopAttempts + 1) return INVALID_COUNTER_PROJECTION;
        const nextTokens = checkedAdd(tokenCount, event.payload.token_count);
        if (nextTokens === null || event.payload.token_count_after !== nextTokens) return INVALID_COUNTER_PROJECTION;
        const observedCost = event.payload.observed_cost;
        if (observedCost.cost_minor_units === null || observedCost.cost_minor_units_after === null) {
          return INVALID_COUNTER_PROJECTION;
        }
        const nextCost = checkedAdd(costMinorUnits, observedCost.cost_minor_units);
        if (nextCost === null || observedCost.cost_minor_units_after !== nextCost) return INVALID_COUNTER_PROJECTION;
        loopAttempts = event.payload.loop_attempts_after;
        actionOutputBytes = event.payload.action_output_bytes_after;
        toolCalls = event.payload.tool_calls_after;
        tokenCount = event.payload.token_count_after;
        costMinorUnits = observedCost.cost_minor_units_after;
        terminalActions.add(event.payload.action_id);
        break;
      }
      case "loop.attempt-completed":
        completedLoopOrdinal += 1;
        if (!Number.isSafeInteger(completedLoopOrdinal)
          || event.payload.attempt_ordinal !== completedLoopOrdinal
          || completedLoopOrdinal < loopAttempts
          || completedLoopOrdinal > loopAttempts + 1) return INVALID_COUNTER_PROJECTION;
        loopAttempts = completedLoopOrdinal;
        break;
      case "run.compaction-recorded": {
        const next = checkedAdd(actionOutputBytes, event.payload.summary_size_bytes);
        if (next === null) return INVALID_COUNTER_PROJECTION;
        actionOutputBytes = next;
        break;
      }
      case "task.action-settled":
        if (!inFlight.delete(event.payload.action_id)) return INVALID_COUNTER_PROJECTION;
        break;
      default:
        break;
    }
  }
  if (executionAttempts !== (expectedState.current_attempt_ordinal ?? 0)
    || inFlight.size !== expectedState.in_flight_action_ids.length
    || [...inFlight].some((actionId) => !expectedState.in_flight_action_ids.includes(actionId))) {
    return INVALID_COUNTER_PROJECTION;
  }
  return {
    ok: true,
    value: deepFreeze({
      loop_attempts: loopAttempts,
      execution_attempts: executionAttempts,
      task_executions: taskExecutions,
      elapsed_ms: elapsedMs,
      tool_calls: toolCalls,
      action_output_bytes: actionOutputBytes,
      control_output_bytes: controlOutputBytes,
      token_count: tokenCount,
      cost_minor_units: costMinorUnits,
      active_workers: inFlight.size,
    }),
  };
}

/**
 * Projects run-global counters solely from a mutually branded raw plan,
 * admitted ledger, and exact manifest/ledger capture pair.
 */
export function projectRuntimeLimitCountersV04(input: unknown): RuntimeLimitCounterProjectionV04Result {
  const exact = exactProjectionInput(input);
  if (exact === null
    || !isValidatedRuntimePlanV03(exact.validated_plan)
    || !isValidatedRunManifestPairV04(exact.manifest, exact.ledger)) return INVALID_COUNTER_PROJECTION;
  const { validated_plan: validatedPlan, ledger, manifest } = exact;
  if (!validatedProjectionScope(validatedPlan, ledger, manifest) || !hasExactCapturedLedgerBytes(ledger)) {
    return INVALID_COUNTER_PROJECTION;
  }
  const controlOutputBytes = summaryRecordControlBytesAtPrefix(
    ledger,
    manifest,
    ledger.events.length,
    true,
  );
  if (controlOutputBytes === null) return INVALID_COUNTER_PROJECTION;
  return projectCounterStateFromPrefix(validatedPlan, ledger.events, controlOutputBytes, ledger.state);
}

/**
 * Projects run-global counters from the inclusive ledger prefix addressed by
 * one exact event reference, using only validated durable artifacts.
 */
export function projectRuntimeLimitCountersAtPrefixV04(input: unknown): RuntimeLimitCounterProjectionV04Result {
  const exact = exactPrefixProjectionInput(input);
  const parsedPrefixRef = LedgerRefV02.safeParse(exact?.prefix_event_ref);
  if (exact === null
    || !parsedPrefixRef.success
    || !isValidatedRuntimePlanV03(exact.validated_plan)
    || !isValidatedRunManifestPairV04(exact.manifest, exact.ledger)) return INVALID_COUNTER_PROJECTION;
  const { validated_plan: validatedPlan, ledger, manifest } = exact;
  if (!validatedProjectionScope(validatedPlan, ledger, manifest) || !hasExactCapturedLedgerBytes(ledger)) {
    return INVALID_COUNTER_PROJECTION;
  }
  const prefixEvent = exactReferencedEvent(ledger.events, parsedPrefixRef.data);
  if (prefixEvent === null) return INVALID_COUNTER_PROJECTION;
  const prefixLength = prefixEvent.sequence;
  const prefixEvents = ledger.events.slice(0, prefixLength);
  const prefixState = reduceRuntimeEventPrefixV04(prefixEvents);
  if (!prefixState.ok) return INVALID_COUNTER_PROJECTION;
  const controlOutputBytes = summaryRecordControlBytesAtPrefix(
    ledger,
    manifest,
    prefixLength,
    false,
  );
  if (controlOutputBytes === null) return INVALID_COUNTER_PROJECTION;
  return projectCounterStateFromPrefix(validatedPlan, prefixEvents, controlOutputBytes, prefixState.state);
}

function remaining(ceiling: number, prospective: number): number {
  return prospective >= ceiling ? 0 : ceiling - prospective;
}

function nullableRemaining(ceiling: number | null, prospective: number): number | null {
  return ceiling === null ? null : remaining(ceiling, prospective);
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function maximumTaskExecutions(
  plan: z.infer<typeof ResolvedRunPlanV03>,
  taskRef: string,
): number | null {
  const rules = plan.retry_policy.rules.filter((rule) => rule.task_ref === taskRef);
  if (rules.length === 0) return null;
  return Math.max(...rules.map((rule) => rule.max_task_executions));
}

/**
 * Evaluates one prospective request against immutable run-global counters.
 * The returned violation literals are exactly the eight values accepted by V04
 * `limit.admission-blocked`; attempt exhaustion remains recovery-only metadata.
 */
export function evaluateRuntimeLimitAccountingV04(input: unknown): RuntimeLimitAccountingResultV04 {
  const parsed = RuntimeLimitAccountingInputV04.safeParse(input);
  if (!parsed.success) return INVALID_ACCOUNTING;
  const { plan, phase, consumed, requested } = parsed.data;

  const taskIds = plan.tasks.map((task) => task.id);
  const suppliedTaskIds = Object.keys(consumed.task_executions);
  if (suppliedTaskIds.length !== taskIds.length
    || taskIds.some((taskId) => !Object.hasOwn(consumed.task_executions, taskId))
    || suppliedTaskIds.some((taskId) => !taskIds.includes(taskId))) return INVALID_ACCOUNTING;
  if (requested.task_executions > 0 && requested.task_ref === null) return INVALID_ACCOUNTING;
  if (requested.task_ref !== null && !taskIds.includes(requested.task_ref)) return INVALID_ACCOUNTING;
  // Action bytes and control bytes belong to distinct admission requests and
  // distinct reserve buckets; combining them would make one persisted violation ambiguous.
  if (requested.action_output_bytes > 0 && requested.control_output_bytes > 0) return INVALID_ACCOUNTING;

  const recovery = phase === "work" ? plan.recovery_policy.reserve : {
    max_elapsed_ms: 0,
    max_tool_calls: 0,
    max_output_bytes: 0,
    max_tokens: null,
    max_cost_minor_units: null,
  };
  const outputAfterControl = checkedSubtract(
    plan.limit_policy.max_output_bytes,
    plan.limit_policy.control_plane_output_reserve_bytes,
  );
  if (outputAfterControl === null) return INVALID_ACCOUNTING;
  const actionOutputCeiling = checkedSubtract(outputAfterControl, recovery.max_output_bytes);
  const elapsedCeiling = checkedSubtract(plan.limit_policy.max_elapsed_ms, recovery.max_elapsed_ms);
  const toolCeiling = checkedSubtract(plan.limit_policy.max_tool_calls, recovery.max_tool_calls);
  const tokenCeiling = plan.limit_policy.max_tokens === null
    ? null
    : checkedSubtract(plan.limit_policy.max_tokens, recovery.max_tokens ?? 0);
  const costCeiling = plan.limit_policy.max_cost_minor_units === null
    ? null
    : checkedSubtract(plan.limit_policy.max_cost_minor_units, recovery.max_cost_minor_units ?? 0);
  if (actionOutputCeiling === null || elapsedCeiling === null || toolCeiling === null
    || (plan.limit_policy.max_tokens !== null && tokenCeiling === null)
    || (plan.limit_policy.max_cost_minor_units !== null && costCeiling === null)) return INVALID_ACCOUNTING;

  const requestedTaskConsumed = requested.task_ref === null ? null : consumed.task_executions[requested.task_ref]!;
  const requestedTaskCeiling = requested.task_ref === null ? null : maximumTaskExecutions(plan, requested.task_ref);
  if (requested.task_ref !== null && requestedTaskCeiling === null) return INVALID_ACCOUNTING;
  const prospective = {
    loop_attempts: checkedAdd(consumed.loop_attempts, requested.loop_attempts),
    execution_attempts: checkedAdd(consumed.execution_attempts, requested.execution_attempts),
    requested_task_executions: requestedTaskConsumed === null
      ? null
      : checkedAdd(requestedTaskConsumed, requested.task_executions),
    elapsed_ms: checkedAdd(consumed.elapsed_ms, requested.elapsed_ms),
    tool_calls: checkedAdd(consumed.tool_calls, requested.tool_calls),
    action_output_bytes: checkedAdd(consumed.action_output_bytes, requested.action_output_bytes),
    control_output_bytes: checkedAdd(consumed.control_output_bytes, requested.control_output_bytes),
    token_count: checkedAdd(consumed.token_count, requested.token_count),
    cost_minor_units: checkedAdd(consumed.cost_minor_units, requested.cost_minor_units),
    workers: checkedAdd(consumed.active_workers, requested.workers),
    process_runtime_ms: requested.process_runtime_ms,
  };
  if (prospective.loop_attempts === null
    || prospective.execution_attempts === null
    || prospective.elapsed_ms === null
    || prospective.tool_calls === null
    || prospective.action_output_bytes === null
    || prospective.control_output_bytes === null
    || prospective.token_count === null
    || prospective.cost_minor_units === null
    || prospective.workers === null
    || (requested.task_ref !== null && prospective.requested_task_executions === null)) return INVALID_ACCOUNTING;
  const totals = prospective as { [K in keyof typeof prospective]: Exclude<(typeof prospective)[K], null> };
  const workerCeiling = phase === "compensation"
    ? Math.min(plan.limit_policy.max_workers, plan.recovery_policy.max_compensation_workers)
    : plan.limit_policy.max_workers;
  const ceilings = {
    loop_attempts: plan.limit_policy.max_loop_attempts,
    execution_attempts: plan.runtime_execution_policy.max_execution_attempts,
    requested_task_executions: requestedTaskCeiling,
    elapsed_ms: elapsedCeiling,
    tool_calls: toolCeiling,
    action_output_bytes: actionOutputCeiling,
    control_output_bytes: plan.limit_policy.control_plane_output_reserve_bytes,
    token_count: tokenCeiling,
    cost_minor_units: costCeiling,
    workers: workerCeiling,
    process_runtime_ms: plan.runtime_execution_policy.max_process_runtime_ms,
  } as const;

  const violations: RuntimeLimitViolationV04[] = [];
  const addViolation = (
    limitRef: RuntimeLimitRefV04,
    current: number,
    delta: number,
    ceiling: number | null,
  ): void => {
    if (ceiling !== null && delta > 0 && current <= ceiling && current + delta > ceiling) {
      violations.push({ limit_ref: limitRef, consumed: current, requested: delta, ceiling });
    }
  };
  addViolation("max-loop-attempts", consumed.loop_attempts, requested.loop_attempts, ceilings.loop_attempts);
  addViolation("max-elapsed-ms", consumed.elapsed_ms, requested.elapsed_ms, ceilings.elapsed_ms);
  addViolation("max-tool-calls", consumed.tool_calls, requested.tool_calls, ceilings.tool_calls);
  if (requested.action_output_bytes > 0) {
    addViolation("max-output-bytes", consumed.action_output_bytes, requested.action_output_bytes, ceilings.action_output_bytes);
  } else {
    addViolation("max-output-bytes", consumed.control_output_bytes, requested.control_output_bytes, ceilings.control_output_bytes);
  }
  addViolation("max-tokens", consumed.token_count, requested.token_count, ceilings.token_count);
  addViolation("max-cost", consumed.cost_minor_units, requested.cost_minor_units, ceilings.cost_minor_units);
  addViolation("max-process-runtime", 0, requested.process_runtime_ms, ceilings.process_runtime_ms);
  addViolation("max-workers", consumed.active_workers, requested.workers, ceilings.workers);
  violations.sort((left, right) => compareUtf8(left.limit_ref, right.limit_ref));

  const limitRows = ([
    ["max-loop-attempts", totals.loop_attempts, ceilings.loop_attempts],
    ["max-elapsed-ms", totals.elapsed_ms, ceilings.elapsed_ms],
    ["max-tool-calls", totals.tool_calls, ceilings.tool_calls],
    ["max-output-bytes", totals.action_output_bytes, ceilings.action_output_bytes],
    ["max-output-bytes", totals.control_output_bytes, ceilings.control_output_bytes],
    ["max-tokens", totals.token_count, ceilings.token_count],
    ["max-cost", totals.cost_minor_units, ceilings.cost_minor_units],
    ["max-process-runtime", totals.process_runtime_ms, ceilings.process_runtime_ms],
    ["max-workers", totals.workers, ceilings.workers],
  ] as const);
  const exhaustedLimitRefs = limitRows
    .flatMap(([ref, value, ceiling]) => ceiling !== null && value >= ceiling ? [ref] : []);
  const overLimitRefs = limitRows
    .flatMap(([ref, value, ceiling]) => ceiling !== null && value > ceiling ? [ref] : []);
  const uniqueExhaustedLimitRefs = [...new Set(exhaustedLimitRefs)]
    .sort(compareUtf8) as RuntimeLimitRefV04[];
  const executionAttemptsExhausted = totals.execution_attempts >= ceilings.execution_attempts;
  const requestedTaskExecutionsExhausted = totals.requested_task_executions !== null
    && ceilings.requested_task_executions !== null
    && totals.requested_task_executions >= ceilings.requested_task_executions;

  return {
    ok: true,
    value: deepFreeze({
      admitted: violations.length === 0
        && overLimitRefs.length === 0
        && totals.execution_attempts <= ceilings.execution_attempts
        && (totals.requested_task_executions === null
          || ceilings.requested_task_executions === null
          || totals.requested_task_executions <= ceilings.requested_task_executions),
      execution_attempts_exhausted: executionAttemptsExhausted,
      requested_task_executions_exhausted: requestedTaskExecutionsExhausted,
      exhausted_limit_refs: uniqueExhaustedLimitRefs,
      ceilings,
      prospective: totals,
      remaining: {
        loop_attempts: remaining(ceilings.loop_attempts, totals.loop_attempts),
        execution_attempts: remaining(ceilings.execution_attempts, totals.execution_attempts),
        requested_task_executions: ceilings.requested_task_executions === null
          || totals.requested_task_executions === null
          ? null
          : remaining(ceilings.requested_task_executions, totals.requested_task_executions),
        elapsed_ms: remaining(ceilings.elapsed_ms, totals.elapsed_ms),
        tool_calls: remaining(ceilings.tool_calls, totals.tool_calls),
        action_output_bytes: remaining(ceilings.action_output_bytes, totals.action_output_bytes),
        control_output_bytes: remaining(ceilings.control_output_bytes, totals.control_output_bytes),
        token_count: nullableRemaining(ceilings.token_count, totals.token_count),
        cost_minor_units: nullableRemaining(ceilings.cost_minor_units, totals.cost_minor_units),
        workers: remaining(ceilings.workers, totals.workers),
        process_runtime_ms: remaining(ceilings.process_runtime_ms, totals.process_runtime_ms),
      },
      violations,
    }),
  };
}

function deterministicBackoff(
  rule: z.infer<typeof RuntimeRetryRuleV04>,
  failureOrdinal: number,
): number | null {
  if (!rule.retryable || rule.backoff === "none") {
    return rule.backoff === "none" && rule.base_delay_ms === 0 && rule.max_delay_ms === 0 ? 0 : null;
  }
  if (rule.base_delay_ms <= 0 || rule.max_delay_ms <= 0 || rule.base_delay_ms > rule.max_delay_ms) return null;
  if (rule.backoff === "fixed") return rule.base_delay_ms === rule.max_delay_ms ? rule.base_delay_ms : null;

  let delay = rule.base_delay_ms;
  let doublingsRemaining = failureOrdinal - 1;
  while (doublingsRemaining > 0 && delay < rule.max_delay_ms) {
    delay = delay > Math.floor(rule.max_delay_ms / 2) ? rule.max_delay_ms : delay * 2;
    if (!Number.isSafeInteger(delay)) return null;
    doublingsRemaining -= 1;
  }
  return delay;
}

/** Derives replay-stable V04 retry delay without wall-clock or machine randomness. */
export function scheduleRuntimeRetryV04(input: unknown): RuntimeRetryScheduleResultV04 {
  const parsed = RuntimeRetryScheduleInputV04.safeParse(input);
  if (!parsed.success) return INVALID_RETRY;
  const { rule, failure_ordinal: failureOrdinal } = parsed.data;
  const backoff = deterministicBackoff(rule, failureOrdinal);
  if (backoff === null) return INVALID_RETRY;

  const identity = {
    domain: "loopeix.runtime-retry-jitter.v04",
    run_id: parsed.data.run_id,
    task_ref: parsed.data.task_ref,
    failure_event_ref: parsed.data.failure_event_ref,
    failure_ordinal: failureOrdinal,
  } as const;
  const digest = createHash("sha256").update(canonicalize(identity), "utf8").digest();
  const identityHash = `sha256:${digest.toString("hex")}`;
  if (backoff === 0) {
    return {
      ok: true,
      value: Object.freeze({
        identity_hash: identityHash,
        deterministic_backoff_ms: 0,
        jitter_window_ms: 0,
        signed_jitter_ms: 0,
        scheduled_delay_ms: 0,
      }),
    };
  }

  const jitterWindow = Math.min(1_000, Math.floor(backoff / 5));
  const modulus = (2 * jitterWindow) + 1;
  if (!Number.isSafeInteger(modulus) || modulus < 1) return INVALID_RETRY;
  const firstSixBytes = digest.readUIntBE(0, 6);
  const signedJitter = (firstSixBytes % modulus) - jitterWindow;
  const jittered = backoff + signedJitter;
  if (!Number.isSafeInteger(jittered)) return INVALID_RETRY;
  const scheduled = Math.max(0, Math.min(rule.max_delay_ms, jittered));
  return {
    ok: true,
    value: Object.freeze({
      identity_hash: identityHash,
      deterministic_backoff_ms: backoff,
      jitter_window_ms: jitterWindow,
      signed_jitter_ms: signedJitter,
      scheduled_delay_ms: scheduled,
    }),
  };
}
