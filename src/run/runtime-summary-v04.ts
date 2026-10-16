import { parseDocument } from "yaml";
import { z } from "zod";

import { canonicalize, hashCanonical, hashRawBytes } from "../hash.js";
import { LedgerRefV02, compareRuntimeUtf8BytesV02 } from "../schema/runtime.js";
import { HumanIdV02, MachineIdV02, RelativeRunPathV02 } from "../schema/scalars-v02.js";
import { Hash } from "../schema/scalars.js";
import type { RuntimeEventV04Value } from "../schema/runtime-v04.js";
import {
  isValidatedRuntimePlanV03,
  type ValidatedRuntimePlanV03,
} from "./project-plan-v03.js";
import {
  evaluateRuntimeLimitAccountingV04,
  projectRuntimeLimitCountersAtPrefixV04,
  type RuntimeLimitAccountingResultV04,
} from "./runtime-limit-accounting-v04.js";
import {
  isValidatedRuntimeLedgerV04,
  type ValidatedRuntimeLedgerV04,
} from "./runtime-ledger-v04.js";
import {
  captureValidatedRunManifestFileV04,
  isValidatedRunManifestPairV04,
  type ValidatedRunManifestV04,
} from "./runtime-manifest-v04.js";
import { reduceRuntimeEventPrefixV04 } from "./runtime-state-reducer-v04.js";

const MAX_SUMMARY_RECORD_BYTES = 262_144;
const MAX_SUMMARY_CONTENT_BYTES = 65_536;
const safeInteger = z.number().int().refine(Number.isSafeInteger);
const nonNegativeSafeInteger = safeInteger.nonnegative();
const positiveSafeInteger = safeInteger.positive();
const inspectedSummaries = new WeakSet<object>();
const validatedSummaries = new WeakSet<object>();
const inspectedSummaryMetadata = new WeakMap<object, Readonly<{
  record_raw_hash: string;
  compaction_event_ref: LedgerRef;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
}>>();

export const SUMMARY_INVALIDATION_RULES_V04 = Object.freeze([
  "source-range-mismatch",
  "source-head-mismatch",
  "run-mismatch",
  "attempt-mismatch",
  "plan-mismatch",
  "input-mismatch",
  "policy-mismatch",
  "authority-mismatch",
  "producer-mismatch",
  "content-mismatch",
  "record-mismatch",
  "retained-counter-mismatch",
  "budget-mismatch",
  "fence-mismatch",
  "resume-boundary-mismatch",
  "lossiness-mismatch",
  "path-mismatch",
] as const);

const InvalidationRules = z.tuple([
  z.literal("source-range-mismatch"), z.literal("source-head-mismatch"), z.literal("run-mismatch"),
  z.literal("attempt-mismatch"), z.literal("plan-mismatch"), z.literal("input-mismatch"),
  z.literal("policy-mismatch"), z.literal("authority-mismatch"), z.literal("producer-mismatch"),
  z.literal("content-mismatch"), z.literal("record-mismatch"), z.literal("retained-counter-mismatch"),
  z.literal("budget-mismatch"), z.literal("fence-mismatch"), z.literal("resume-boundary-mismatch"),
  z.literal("lossiness-mismatch"), z.literal("path-mismatch"),
]);

const RetainedBudgetState = z.object({
  remaining_elapsed_ms: nonNegativeSafeInteger,
  remaining_tool_calls: nonNegativeSafeInteger,
  remaining_action_output_bytes: nonNegativeSafeInteger,
  remaining_control_output_bytes: nonNegativeSafeInteger,
  remaining_tokens: nonNegativeSafeInteger.nullable(),
  remaining_cost_minor_units: nonNegativeSafeInteger.nullable(),
  remaining_workers: nonNegativeSafeInteger,
}).strict();

const PerTaskExecution = z.object({
  task_ref: HumanIdV02,
  task_executions_after: nonNegativeSafeInteger,
}).strict();

const PerTaskExecutions = z.array(PerTaskExecution).superRefine((rows, ctx) => {
  for (let index = 1; index < rows.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(rows[index - 1]!.task_ref, rows[index]!.task_ref) >= 0) {
      ctx.addIssue({ code: "custom", path: [index, "task_ref"], message: "task rows must be unique and sorted by UTF-8 bytes" });
    }
  }
});

const RetainedCounterState = z.object({
  loop_attempts_after: nonNegativeSafeInteger,
  execution_attempts_after: nonNegativeSafeInteger,
  per_task_executions_after: PerTaskExecutions,
  action_output_bytes_after: nonNegativeSafeInteger,
  control_output_bytes_after: nonNegativeSafeInteger,
  tool_calls_after: nonNegativeSafeInteger,
  tokens_after: nonNegativeSafeInteger,
  cost_minor_units_after: nonNegativeSafeInteger,
  active_workers_after: nonNegativeSafeInteger,
}).strict();

const ResumeBoundary = z.object({
  source_boundary_sequence: positiveSafeInteger,
  source_boundary_head_hash: Hash,
  source_manifest_hash: Hash,
  attempt_event_ref: LedgerRefV02,
  fence_epoch: nonNegativeSafeInteger,
}).strict();

const SummaryArtifactV01 = z.object({
  schema_version: z.literal("0.1"),
  summary_id: MachineIdV02,
  run_id: MachineIdV02,
  attempt_id: MachineIdV02,
  plan_hash: Hash,
  input_hash: Hash,
  recovery_policy_hash: Hash,
  authority_envelope_hash: Hash,
  producer_ref: LedgerRefV02,
  source_first_event_ref: LedgerRefV02,
  source_last_event_ref: LedgerRefV02,
  source_prefix_sequence: positiveSafeInteger,
  source_prefix_head_hash: Hash,
  lossiness_class: z.enum(["lossless", "lossy-narrative-only"]),
  retained_budget_state: RetainedBudgetState,
  retained_counter_state: RetainedCounterState,
  fence_epoch: nonNegativeSafeInteger,
  resume_boundary: ResumeBoundary,
  invalidation_rules: InvalidationRules,
  content_path: RelativeRunPathV02,
  content_hash: Hash,
  content_size_bytes: positiveSafeInteger.max(MAX_SUMMARY_CONTENT_BYTES),
  record_hash: Hash,
}).strict().superRefine((summary, ctx) => {
  if (summary.source_first_event_ref.ledger_sequence > summary.source_last_event_ref.ledger_sequence
    || summary.source_last_event_ref.ledger_sequence > summary.source_prefix_sequence) {
    ctx.addIssue({ code: "custom", path: ["source_first_event_ref"], message: "source range must be ordered within the prefix" });
  }
  if (summary.content_path !== contentPath(summary.summary_id)) {
    ctx.addIssue({ code: "custom", path: ["content_path"], message: "content path must match the fixed summary path" });
  }
});

export type SummaryInvalidationReasonV04 = (typeof SUMMARY_INVALIDATION_RULES_V04)[number];
export type SummaryArtifactV01Value = z.infer<typeof SummaryArtifactV01>;
export type InspectedSummaryArtifactV01 = SummaryArtifactV01Value & Readonly<{
  readonly __inspected_summary_artifact_v01: unique symbol;
}>;
export type ValidatedSummaryArtifactV01 = SummaryArtifactV01Value & Readonly<{
  readonly __validated_summary_artifact_v01: unique symbol;
}>;

type SummaryStructuralFailure =
  | "SUMMARY_INPUT_INVALID"
  | "SUMMARY_RECORD_SYNTAX_INVALID"
  | "SUMMARY_RECORD_SCHEMA_INVALID"
  | "SUMMARY_RECORD_HASH_INVALID"
  | "SUMMARY_CONTENT_HASH_INVALID"
  | "SUMMARY_LEDGER_BINDING_INVALID"
  | "SUMMARY_MANIFEST_BINDING_INVALID";

export type RuntimeSummaryInspectionResultV04 =
  | Readonly<{
      ok: true;
      summary: SummaryArtifactV01Value;
      inspected_summary: InspectedSummaryArtifactV01;
      record_bytes: Uint8Array;
      content_bytes: Uint8Array;
    }>
  | Readonly<{ ok: false; reason: SummaryStructuralFailure }>;

export type RuntimeTrustedSummaryValidationResultV04 =
  | Readonly<{ ok: true; summary: SummaryArtifactV01Value; validated_summary: ValidatedSummaryArtifactV01 }>
  | Readonly<{ ok: false; reason: "SUMMARY_INPUT_INVALID" }>
  | Readonly<{ ok: false; reason: "SUMMARY_INVALIDATED"; invalidation_reason: SummaryInvalidationReasonV04 }>;

export type RuntimeSummaryArtifactBuildResultV04 =
  | Readonly<{
      ok: true;
      artifact: SummaryArtifactV01Value;
      record_path: string;
      record_raw_hash: string;
      record_bytes: Uint8Array;
      content_path: string;
      content_bytes: Uint8Array;
      pre_context_hash: string;
      post_context_hash: string;
    }>
  | Readonly<{
      ok: false;
      reason:
        | "SUMMARY_BUILD_INPUT_INVALID"
        | "SUMMARY_BUILD_CONTENT_INVALID"
        | "SUMMARY_BUILD_INELIGIBLE"
        | "SUMMARY_BUILD_LIMIT_EXCEEDED";
    }>;

type LedgerRef = z.infer<typeof LedgerRefV02>;
export type RuntimeCompactionContextHashesV04 = Readonly<{
  pre_context_hash: string;
  post_context_hash: string;
}>;

function contentPath(summaryId: string): string {
  return `summaries/content/${summaryId}.bin`;
}

function recordPath(summaryId: string): string {
  return `summaries/records/${summaryId}.json`;
}

function sameRef(left: LedgerRef, right: LedgerRef): boolean {
  return left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function sameValue(left: unknown, right: unknown): boolean {
  return canonicalize(left) === canonicalize(right);
}

function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  try {
    if (typeof value !== "object" || value === null || Object.getPrototypeOf(value) !== Object.prototype) return null;
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.keys(descriptors).sort().join("\0") !== [...keys].sort().join("\0")) return null;
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true) return null;
    }
    return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
  } catch {
    return null;
  }
}

function captureBytes(value: unknown, maximum: number): Uint8Array | null {
  try {
    if (!(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype
      || value.buffer instanceof SharedArrayBuffer || value.byteLength === 0 || value.byteLength > maximum) return null;
    return new Uint8Array(value);
  } catch {
    return null;
  }
}

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

function eventAt(ledger: ValidatedRuntimeLedgerV04, eventRef: LedgerRef): RuntimeEventV04Value | null {
  const event = ledger.events[eventRef.ledger_sequence - 1];
  return event?.event_hash === eventRef.event_hash ? event : null;
}

function rootContextHash(validatedPlan: ValidatedRuntimePlanV03): string {
  return hashCanonical({
    purpose: "runtime-context-root-v01",
    schema_version: "0.1",
    run_id: validatedPlan.run_id,
    plan_hash: validatedPlan.plan_hash,
    runtime_input_hash: validatedPlan.plan.runtime_input_hash,
    context_snapshot: validatedPlan.plan.context_snapshot,
  });
}

function latestCompactionBefore(
  ledger: ValidatedRuntimeLedgerV04,
  exclusiveSequence: number,
): Extract<RuntimeEventV04Value, { event_type: "run.compaction-recorded" }> | null {
  const limit = Math.min(Math.max(exclusiveSequence - 1, 0), ledger.events.length);
  for (let index = limit - 1; index >= 0; index -= 1) {
    const event = ledger.events[index];
    if (event?.event_type === "run.compaction-recorded") return event;
  }
  return null;
}

function deriveRuntimeCompactionContextHashesAtBoundaryV04(
  validatedPlan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
  summary: SummaryArtifactV01Value,
  recordBytes: Uint8Array,
  exclusiveSequence: number,
): RuntimeCompactionContextHashesV04 | null {
  const first = eventAt(ledger, summary.source_first_event_ref);
  const last = eventAt(ledger, summary.source_last_event_ref);
  const prefix = ledger.events[summary.source_prefix_sequence - 1];
  if (validatedPlan.run_id !== ledger.run_id
    || validatedPlan.plan_hash !== ledger.plan_hash
    || summary.run_id !== ledger.run_id
    || summary.plan_hash !== validatedPlan.plan_hash
    || first === null
    || last === null
    || prefix?.event_hash !== summary.source_prefix_head_hash
    || summary.source_first_event_ref.ledger_sequence > summary.source_last_event_ref.ledger_sequence
    || summary.source_last_event_ref.ledger_sequence > summary.source_prefix_sequence) {
    return null;
  }
  const previous = latestCompactionBefore(ledger, exclusiveSequence);
  const pre_context_hash = previous?.payload.post_context_hash ?? rootContextHash(validatedPlan);
  return Object.freeze({
    pre_context_hash,
    post_context_hash: hashCanonical({
      purpose: "runtime-context-compaction-v01",
      schema_version: "0.1",
      run_id: ledger.run_id,
      plan_hash: validatedPlan.plan_hash,
      pre_context_hash,
      summary_id: summary.summary_id,
      summary_record_hash: hashRawBytes(recordBytes),
      summary_content_hash: summary.content_hash,
      source_first_event_ref: summary.source_first_event_ref,
      source_last_event_ref: summary.source_last_event_ref,
      source_prefix_sequence: summary.source_prefix_sequence,
      source_prefix_head_hash: summary.source_prefix_head_hash,
    }),
  });
}

export function deriveRuntimeCompactionContextHashesV04(
  input: unknown,
): RuntimeCompactionContextHashesV04 | null {
  const captured = exactObject(input, ["validated_plan", "ledger", "summary", "record_bytes"]);
  if (captured === null
    || !isValidatedRuntimePlanV03(captured.validated_plan)
    || !isValidatedRuntimeLedgerV04(captured.ledger)) {
    return null;
  }
  const parsedSummary = SummaryArtifactV01.safeParse(captured.summary);
  const recordBytes = captureBytes(captured.record_bytes, MAX_SUMMARY_RECORD_BYTES);
  if (!parsedSummary.success || recordBytes === null) return null;
  return deriveRuntimeCompactionContextHashesAtBoundaryV04(
    captured.validated_plan,
    captured.ledger,
    parsedSummary.data,
    recordBytes,
    captured.ledger.sequence + 1,
  );
}

function phaseAtSummaryPrefix(ledger: ValidatedRuntimeLedgerV04, sourcePrefixSequence: number): "work" | "compensation" {
  for (let index = 0; index < sourcePrefixSequence; index += 1) {
    if (ledger.events[index]?.event_type === "run.compensation-phase-entered") return "compensation";
  }
  return "work";
}

function sameRemainingBudget(
  summary: SummaryArtifactV01Value,
  expected: RuntimeLimitAccountingResultV04,
): boolean {
  if (!expected.ok) return false;
  return sameValue(summary.retained_budget_state, {
    remaining_elapsed_ms: expected.value.remaining.elapsed_ms,
    remaining_tool_calls: expected.value.remaining.tool_calls,
    remaining_action_output_bytes: expected.value.remaining.action_output_bytes,
    remaining_control_output_bytes: expected.value.remaining.control_output_bytes,
    remaining_tokens: expected.value.remaining.token_count,
    remaining_cost_minor_units: expected.value.remaining.cost_minor_units,
    remaining_workers: expected.value.remaining.workers,
  });
}

function directLedgerBindingsMatch(
  summary: SummaryArtifactV01Value,
  ledger: ValidatedRuntimeLedgerV04,
  event: Extract<RuntimeEventV04Value, { event_type: "run.compaction-recorded" }>,
  recordBytes: Uint8Array,
): boolean {
  const payload = event.payload;
  const attempt = eventAt(ledger, payload.attempt_event_ref);
  const producer = eventAt(ledger, payload.integrator_lease_event_ref);
  const first = eventAt(ledger, summary.source_first_event_ref);
  const last = eventAt(ledger, summary.source_last_event_ref);
  const prefix = ledger.events[summary.source_prefix_sequence - 1];
  return summary.summary_id === payload.summary_id
    && payload.summary_record_path === recordPath(summary.summary_id)
    && payload.summary_record_hash === hashRawBytes(recordBytes)
    && summary.content_path === payload.summary_content_path
    && summary.content_hash === payload.summary_content_hash
    && summary.content_size_bytes === payload.summary_size_bytes
    && sameRef(summary.source_first_event_ref, payload.source_first_event_ref)
    && sameRef(summary.source_last_event_ref, payload.source_last_event_ref)
    && summary.source_prefix_sequence === payload.source_prefix_sequence
    && summary.source_prefix_head_hash === payload.source_prefix_head_hash
    && first !== null && last !== null && prefix?.event_hash === summary.source_prefix_head_hash
    && sameRef(summary.producer_ref, payload.integrator_lease_event_ref)
    && producer?.event_type === "ownership.lease-acquired" && producer.payload.scope === "integrator"
    && producer.payload.scope_ref === summary.summary_id
    && sameRef(producer.payload.attempt_event_ref, payload.attempt_event_ref)
    && attempt?.event_type === "execution.attempt-started"
    && summary.attempt_id === attempt.payload.attempt_id
    && summary.plan_hash === attempt.payload.plan_hash
    && summary.input_hash === attempt.payload.input_hash
    && summary.recovery_policy_hash === attempt.payload.recovery_policy_hash
    && summary.authority_envelope_hash === attempt.payload.authority_envelope_hash
    && summary.fence_epoch === attempt.payload.fence_epoch
    && summary.resume_boundary.source_boundary_sequence === attempt.payload.source_boundary_sequence
    && summary.resume_boundary.source_boundary_head_hash === attempt.payload.source_boundary_head_hash
    && summary.resume_boundary.source_manifest_hash === attempt.payload.source_manifest_hash
    && sameRef(summary.resume_boundary.attempt_event_ref, payload.attempt_event_ref)
    && summary.resume_boundary.fence_epoch === attempt.payload.fence_epoch;
}

/**
 * Builds the two create-new summary files from authenticated runtime custody.
 * The caller supplies identity, opaque narrative bytes, and exact ledger refs;
 * every authority, lineage, counter, budget, path, and hash is derived here.
 */
export function buildRuntimeSummaryArtifactsV04(input: unknown): RuntimeSummaryArtifactBuildResultV04 {
  try {
    const captured = exactObject(input, [
      "validated_plan",
      "ledger",
      "manifest",
      "summary_id",
      "content_bytes",
      "integrator_lease_event_ref",
      "source_first_event_ref",
      "source_last_event_ref",
      "source_prefix_event_ref",
    ]);
    if (captured === null
      || !isValidatedRuntimePlanV03(captured.validated_plan)
      || !isValidatedRunManifestPairV04(captured.manifest, captured.ledger)) {
      return { ok: false, reason: "SUMMARY_BUILD_INPUT_INVALID" };
    }
    const summaryId = MachineIdV02.safeParse(captured.summary_id);
    const producerRef = LedgerRefV02.safeParse(captured.integrator_lease_event_ref);
    const firstRef = LedgerRefV02.safeParse(captured.source_first_event_ref);
    const lastRef = LedgerRefV02.safeParse(captured.source_last_event_ref);
    const prefixRef = LedgerRefV02.safeParse(captured.source_prefix_event_ref);
    if (!summaryId.success || !producerRef.success || !firstRef.success || !lastRef.success || !prefixRef.success) {
      return { ok: false, reason: "SUMMARY_BUILD_INPUT_INVALID" };
    }
    const contentBytes = captureBytes(captured.content_bytes, MAX_SUMMARY_CONTENT_BYTES);
    if (contentBytes === null) return { ok: false, reason: "SUMMARY_BUILD_CONTENT_INVALID" };

    const validatedPlan = captured.validated_plan as ValidatedRuntimePlanV03;
    const ledger = captured.ledger as ValidatedRuntimeLedgerV04;
    const manifest = captured.manifest as ValidatedRunManifestV04;
    if (validatedPlan.run_id !== ledger.run_id
      || ledger.run_id !== manifest.run_id
      || validatedPlan.plan_hash !== ledger.plan_hash
      || ledger.plan_hash !== manifest.plan_hash) {
      return { ok: false, reason: "SUMMARY_BUILD_INPUT_INVALID" };
    }
    if (contentBytes.byteLength > validatedPlan.plan.runtime_execution_policy.max_summary_content_bytes) {
      return { ok: false, reason: "SUMMARY_BUILD_CONTENT_INVALID" };
    }

    const head = ledger.events.at(-1);
    const first = eventAt(ledger, firstRef.data);
    const last = eventAt(ledger, lastRef.data);
    const prefix = eventAt(ledger, prefixRef.data);
    const producer = eventAt(ledger, producerRef.data);
    if (head === undefined || first === null || last === null || prefix === null || producer === null
      || prefix.sequence !== head.sequence || prefix.event_hash !== head.event_hash
      || first.sequence > last.sequence || last.sequence > prefix.sequence
      || producer.event_type !== "ownership.lease-acquired"
      || producer.payload.scope !== "integrator"
      || producer.payload.scope_ref !== summaryId.data) {
      return { ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" };
    }

    const existingCompactions = ledger.events.filter((event) => event.event_type === "run.compaction-recorded");
    const policy = validatedPlan.plan.runtime_execution_policy;
    if (existingCompactions.length >= policy.max_compaction_events
      || existingCompactions.length >= policy.max_summary_records) {
      return { ok: false, reason: "SUMMARY_BUILD_LIMIT_EXCEEDED" };
    }
    if (existingCompactions.some((event) => event.payload.summary_id === summaryId.data)
      || manifest.file_inventory.some((row) => row.path === contentPath(summaryId.data) || row.path === recordPath(summaryId.data))) {
      return { ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" };
    }

    const reduced = reduceRuntimeEventPrefixV04(ledger.events);
    if (!reduced.ok
      || reduced.state.state !== "running"
      || reduced.state.abort_requested
      || reduced.state.terminal_freeze_entered
      || reduced.state.terminal_sealed
      || reduced.state.pending_resume_request !== null
      || reduced.state.in_flight_action_ids.length !== 0) {
      return { ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" };
    }
    const activeIntegrator = reduced.state.subordinate_owner_leases.find((lease) =>
      lease.scope === "integrator" && sameRef(lease.lease_event_ref, producerRef.data));
    if (activeIntegrator === undefined || !activeIntegrator.active || activeIntegrator.released
      || activeIntegrator.fence_epoch !== reduced.state.current_fence_epoch
      || reduced.state.current_attempt_event_ref === null
      || !sameRef(activeIntegrator.attempt_event_ref, reduced.state.current_attempt_event_ref)) {
      return { ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" };
    }
    const attempt = eventAt(ledger, activeIntegrator.attempt_event_ref);
    if (attempt?.event_type !== "execution.attempt-started") {
      return { ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" };
    }

    const counters = projectRuntimeLimitCountersAtPrefixV04({
      validated_plan: validatedPlan,
      ledger,
      manifest,
      prefix_event_ref: prefixRef.data,
    });
    if (!counters.ok) return { ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" };
    const phase = phaseAtSummaryPrefix(ledger, prefix.sequence);
    const zeroRequest = {
      task_ref: null,
      loop_attempts: 0,
      execution_attempts: 0,
      task_executions: 0,
      elapsed_ms: 0,
      tool_calls: 0,
      action_output_bytes: 0,
      control_output_bytes: 0,
      token_count: 0,
      cost_minor_units: 0,
      workers: 0,
      process_runtime_ms: 0,
    } as const;
    const accounting = evaluateRuntimeLimitAccountingV04({
      plan: validatedPlan.plan,
      phase,
      consumed: counters.value,
      requested: zeroRequest,
    });
    const contentAdmission = evaluateRuntimeLimitAccountingV04({
      plan: validatedPlan.plan,
      phase,
      consumed: counters.value,
      requested: { ...zeroRequest, action_output_bytes: contentBytes.byteLength },
    });
    if (!accounting.ok || !accounting.value.admitted || !contentAdmission.ok || !contentAdmission.value.admitted) {
      return { ok: false, reason: "SUMMARY_BUILD_LIMIT_EXCEEDED" };
    }

    const taskRefs = validatedPlan.plan.tasks.map((task) => task.id).sort(compareRuntimeUtf8BytesV02);
    const preimage = {
      schema_version: "0.1" as const,
      summary_id: summaryId.data,
      run_id: ledger.run_id,
      attempt_id: attempt.payload.attempt_id,
      plan_hash: validatedPlan.plan_hash,
      input_hash: attempt.payload.input_hash,
      recovery_policy_hash: attempt.payload.recovery_policy_hash,
      authority_envelope_hash: attempt.payload.authority_envelope_hash,
      producer_ref: producerRef.data,
      source_first_event_ref: firstRef.data,
      source_last_event_ref: lastRef.data,
      source_prefix_sequence: prefix.sequence,
      source_prefix_head_hash: prefix.event_hash,
      lossiness_class: "lossless" as const,
      retained_budget_state: {
        remaining_elapsed_ms: accounting.value.remaining.elapsed_ms,
        remaining_tool_calls: accounting.value.remaining.tool_calls,
        remaining_action_output_bytes: accounting.value.remaining.action_output_bytes,
        remaining_control_output_bytes: accounting.value.remaining.control_output_bytes,
        remaining_tokens: accounting.value.remaining.token_count,
        remaining_cost_minor_units: accounting.value.remaining.cost_minor_units,
        remaining_workers: accounting.value.remaining.workers,
      },
      retained_counter_state: {
        loop_attempts_after: counters.value.loop_attempts,
        execution_attempts_after: counters.value.execution_attempts,
        per_task_executions_after: taskRefs.map((taskRef) => ({
          task_ref: taskRef,
          task_executions_after: counters.value.task_executions[taskRef]!,
        })),
        action_output_bytes_after: counters.value.action_output_bytes,
        control_output_bytes_after: counters.value.control_output_bytes,
        tool_calls_after: counters.value.tool_calls,
        tokens_after: counters.value.token_count,
        cost_minor_units_after: counters.value.cost_minor_units,
        active_workers_after: counters.value.active_workers,
      },
      fence_epoch: attempt.payload.fence_epoch,
      resume_boundary: {
        source_boundary_sequence: attempt.payload.source_boundary_sequence,
        source_boundary_head_hash: attempt.payload.source_boundary_head_hash,
        source_manifest_hash: attempt.payload.source_manifest_hash,
        attempt_event_ref: activeIntegrator.attempt_event_ref,
        fence_epoch: attempt.payload.fence_epoch,
      },
      invalidation_rules: SUMMARY_INVALIDATION_RULES_V04,
      content_path: contentPath(summaryId.data),
      content_hash: hashRawBytes(contentBytes),
      content_size_bytes: contentBytes.byteLength,
    };
    const artifact = SummaryArtifactV01.parse({ ...preimage, record_hash: hashCanonical(preimage) });
    const recordBytes = new TextEncoder().encode(`${canonicalize(artifact)}\n`);
    if (recordBytes.byteLength > MAX_SUMMARY_RECORD_BYTES
      || recordBytes.byteLength > accounting.value.remaining.control_output_bytes) {
      return { ok: false, reason: "SUMMARY_BUILD_LIMIT_EXCEEDED" };
    }
    const contextHashes = deriveRuntimeCompactionContextHashesAtBoundaryV04(
      validatedPlan,
      ledger,
      artifact,
      recordBytes,
      ledger.sequence + 1,
    );
    if (contextHashes === null) {
      return { ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" };
    }
    const frozenArtifact = freezeDeep(artifact);
    return Object.freeze({
      ok: true,
      artifact: frozenArtifact,
      record_path: recordPath(summaryId.data),
      record_raw_hash: hashRawBytes(recordBytes),
      record_bytes: recordBytes,
      content_path: frozenArtifact.content_path,
      content_bytes: contentBytes,
      pre_context_hash: contextHashes.pre_context_hash,
      post_context_hash: contextHashes.post_context_hash,
    });
  } catch {
    return { ok: false, reason: "SUMMARY_BUILD_INPUT_INVALID" };
  }
}

export function isInspectedSummaryArtifactV01(input: unknown): input is InspectedSummaryArtifactV01 {
  return typeof input === "object" && input !== null && inspectedSummaries.has(input);
}

export function isValidatedSummaryArtifactV01(input: unknown): input is ValidatedSummaryArtifactV01 {
  return typeof input === "object" && input !== null && validatedSummaries.has(input);
}

export function inspectRuntimeSummaryV04(input: unknown): RuntimeSummaryInspectionResultV04 {
  try {
    const captured = exactObject(input, ["ledger", "manifest", "compaction_event_ref"]);
    if (captured === null || !isValidatedRunManifestPairV04(captured.manifest, captured.ledger)) {
      return { ok: false, reason: "SUMMARY_INPUT_INVALID" };
    }
    const ledger = captured.ledger as ValidatedRuntimeLedgerV04;
    const manifest = captured.manifest as ValidatedRunManifestV04;
    const compactionRef = LedgerRefV02.safeParse(captured.compaction_event_ref);
    if (!compactionRef.success) {
      return { ok: false, reason: "SUMMARY_INPUT_INVALID" };
    }
    const compaction = eventAt(ledger, compactionRef.data);
    if (compaction?.event_type !== "run.compaction-recorded") {
      return { ok: false, reason: "SUMMARY_LEDGER_BINDING_INVALID" };
    }
    const capturedRecord = captureValidatedRunManifestFileV04(manifest, compaction.payload.summary_record_path);
    const capturedContent = captureValidatedRunManifestFileV04(manifest, compaction.payload.summary_content_path);
    if (!capturedRecord.ok || capturedRecord.bytes === null
      || !capturedContent.ok || capturedContent.bytes === null) {
      return { ok: false, reason: "SUMMARY_MANIFEST_BINDING_INVALID" };
    }
    const recordBytes = captureBytes(capturedRecord.bytes, MAX_SUMMARY_RECORD_BYTES);
    const contentBytes = captureBytes(capturedContent.bytes, MAX_SUMMARY_CONTENT_BYTES);
    if (recordBytes === null || contentBytes === null) {
      return { ok: false, reason: "SUMMARY_INPUT_INVALID" };
    }
    let raw: unknown;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(recordBytes);
      const document = parseDocument(text, { uniqueKeys: true });
      if (document.errors.length > 0) return { ok: false, reason: "SUMMARY_RECORD_SYNTAX_INVALID" };
      raw = JSON.parse(text) as unknown;
    } catch {
      return { ok: false, reason: "SUMMARY_RECORD_SYNTAX_INVALID" };
    }
    const parsed = SummaryArtifactV01.safeParse(raw);
    if (!parsed.success) return { ok: false, reason: "SUMMARY_RECORD_SCHEMA_INVALID" };
    const { record_hash: _recordHash, ...preimage } = parsed.data;
    if (parsed.data.record_hash !== hashCanonical(preimage)) {
      return { ok: false, reason: "SUMMARY_RECORD_HASH_INVALID" };
    }
    if (parsed.data.content_hash !== hashRawBytes(contentBytes)
      || parsed.data.content_size_bytes !== contentBytes.byteLength) {
      return { ok: false, reason: "SUMMARY_CONTENT_HASH_INVALID" };
    }
    if (!directLedgerBindingsMatch(parsed.data, ledger, compaction, recordBytes)) {
      return { ok: false, reason: "SUMMARY_LEDGER_BINDING_INVALID" };
    }
    if (manifest.run_id !== parsed.data.run_id || manifest.plan_hash !== parsed.data.plan_hash
      || manifest.ledger_sequence < compaction.sequence) {
      return { ok: false, reason: "SUMMARY_MANIFEST_BINDING_INVALID" };
    }
    const summary = freezeDeep(parsed.data);
    const inspected = summary as InspectedSummaryArtifactV01;
    inspectedSummaries.add(inspected);
    inspectedSummaryMetadata.set(inspected, Object.freeze({
      record_raw_hash: hashRawBytes(recordBytes),
      compaction_event_ref: compactionRef.data,
      ledger,
      manifest,
    }));
    return { ok: true, summary, inspected_summary: inspected, record_bytes: recordBytes, content_bytes: contentBytes };
  } catch {
    return { ok: false, reason: "SUMMARY_INPUT_INVALID" };
  }
}

export function validateRuntimeSummaryForRecoveryV04(
  input: unknown,
): RuntimeTrustedSummaryValidationResultV04 {
  try {
    const captured = exactObject(input, ["inspected_summary", "validated_plan", "ledger", "manifest"]);
    if (captured === null
      || !isInspectedSummaryArtifactV01(captured.inspected_summary)
      || !isValidatedRuntimePlanV03(captured.validated_plan)
      || !isValidatedRunManifestPairV04(captured.manifest, captured.ledger)) {
      return { ok: false, reason: "SUMMARY_INPUT_INVALID" };
    }
    const summary = captured.inspected_summary;
    const validatedPlan = captured.validated_plan as ValidatedRuntimePlanV03;
    const ledger = captured.ledger as ValidatedRuntimeLedgerV04;
    const manifest = captured.manifest as ValidatedRunManifestV04;
    const metadata = inspectedSummaryMetadata.get(summary);
    if (metadata === undefined || metadata.ledger !== ledger || metadata.manifest !== manifest) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "source-head-mismatch" };
    }
    if (validatedPlan.run_id !== ledger.run_id
      || ledger.run_id !== manifest.run_id
      || validatedPlan.plan_hash !== ledger.plan_hash
      || ledger.plan_hash !== manifest.plan_hash
      || validatedPlan.plan.run_id !== ledger.run_id) {
      return { ok: false, reason: "SUMMARY_INPUT_INVALID" };
    }
    const compaction = eventAt(ledger, metadata.compaction_event_ref);
    if (compaction?.event_type !== "run.compaction-recorded") {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "source-range-mismatch" };
    }
    const currentHead = ledger.events.at(-1);
    if (currentHead === undefined || currentHead.sequence !== compaction.sequence || currentHead.event_hash !== compaction.event_hash) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "source-head-mismatch" };
    }
    const capturedRecord = captureValidatedRunManifestFileV04(manifest, compaction.payload.summary_record_path);
    const capturedContent = captureValidatedRunManifestFileV04(manifest, compaction.payload.summary_content_path);
    const capturedLedger = captureValidatedRunManifestFileV04(manifest, "ledger.jsonl");
    if (!capturedRecord.ok || capturedRecord.bytes === null
      || !capturedContent.ok || capturedContent.bytes === null
      || !capturedLedger.ok || capturedLedger.bytes === null) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "record-mismatch" };
    }
    if (hashRawBytes(capturedRecord.bytes) !== metadata.record_raw_hash) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "record-mismatch" };
    }
    if (summary.content_hash !== hashRawBytes(capturedContent.bytes)
      || summary.content_size_bytes !== capturedContent.bytes.byteLength
      || summary.content_size_bytes > validatedPlan.plan.runtime_execution_policy.max_summary_content_bytes) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "content-mismatch" };
    }
    if (!directLedgerBindingsMatch(summary, ledger, compaction, capturedRecord.bytes)) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "source-head-mismatch" };
    }
    const attempt = eventAt(ledger, compaction.payload.attempt_event_ref);
    if (attempt?.event_type !== "execution.attempt-started") {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "attempt-mismatch" };
    }
    const taskRefs = validatedPlan.plan.tasks.map((task) => task.id).sort(compareRuntimeUtf8BytesV02);
    const actualTaskRefs = summary.retained_counter_state.per_task_executions_after.map((row) => row.task_ref);
    if (!sameValue(actualTaskRefs, taskRefs)) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "retained-counter-mismatch" };
    }
    if (summary.run_id !== ledger.run_id) return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "run-mismatch" };
    if (summary.attempt_id !== attempt.payload.attempt_id) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "attempt-mismatch" };
    }
    if (summary.plan_hash !== validatedPlan.plan_hash) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "plan-mismatch" };
    }
    if (summary.input_hash !== attempt.payload.input_hash) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "input-mismatch" };
    }
    if (summary.recovery_policy_hash !== attempt.payload.recovery_policy_hash) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "policy-mismatch" };
    }
    if (summary.authority_envelope_hash !== attempt.payload.authority_envelope_hash) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "authority-mismatch" };
    }
    if (!sameRef(summary.producer_ref, compaction.payload.integrator_lease_event_ref)) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "producer-mismatch" };
    }
    if (summary.content_path !== contentPath(summary.summary_id)
      || compaction.payload.summary_record_path !== recordPath(summary.summary_id)) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "path-mismatch" };
    }
    const expectedContextHashes = deriveRuntimeCompactionContextHashesAtBoundaryV04(
      validatedPlan,
      ledger,
      summary,
      capturedRecord.bytes,
      compaction.sequence,
    );
    if (expectedContextHashes === null
      || compaction.payload.pre_context_hash !== expectedContextHashes.pre_context_hash
      || compaction.payload.post_context_hash !== expectedContextHashes.post_context_hash) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "source-head-mismatch" };
    }
    if (summary.lossiness_class !== "lossless") {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "lossiness-mismatch" };
    }
    if (!sameValue(summary.resume_boundary, {
      source_boundary_sequence: attempt.payload.source_boundary_sequence,
      source_boundary_head_hash: attempt.payload.source_boundary_head_hash,
      source_manifest_hash: attempt.payload.source_manifest_hash,
      attempt_event_ref: compaction.payload.attempt_event_ref,
      fence_epoch: attempt.payload.fence_epoch,
    })) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "resume-boundary-mismatch" };
    }
    const prefixCounters = projectRuntimeLimitCountersAtPrefixV04({
      validated_plan: validatedPlan,
      ledger,
      manifest,
      prefix_event_ref: {
        ledger_sequence: summary.source_prefix_sequence,
        event_hash: summary.source_prefix_head_hash,
      },
    });
    if (!prefixCounters.ok) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "source-head-mismatch" };
    }
    const expectedCounterState = {
      loop_attempts_after: prefixCounters.value.loop_attempts,
      execution_attempts_after: prefixCounters.value.execution_attempts,
      per_task_executions_after: taskRefs.map((taskRef) => ({
        task_ref: taskRef,
        task_executions_after: prefixCounters.value.task_executions[taskRef]!,
      })),
      action_output_bytes_after: prefixCounters.value.action_output_bytes,
      control_output_bytes_after: prefixCounters.value.control_output_bytes,
      tool_calls_after: prefixCounters.value.tool_calls,
      tokens_after: prefixCounters.value.token_count,
      cost_minor_units_after: prefixCounters.value.cost_minor_units,
      active_workers_after: prefixCounters.value.active_workers,
    };
    if (!sameValue(summary.retained_counter_state, expectedCounterState)) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "retained-counter-mismatch" };
    }
    const internalBudget = evaluateRuntimeLimitAccountingV04({
      plan: validatedPlan.plan,
      phase: phaseAtSummaryPrefix(ledger, summary.source_prefix_sequence),
      consumed: {
        ...prefixCounters.value,
      },
      requested: {
        task_ref: null,
        loop_attempts: 0,
        execution_attempts: 0,
        task_executions: 0,
        elapsed_ms: 0,
        tool_calls: 0,
        action_output_bytes: 0,
        control_output_bytes: 0,
        token_count: 0,
        cost_minor_units: 0,
        workers: 0,
        process_runtime_ms: 0,
      },
    });
    if (!sameRemainingBudget(summary, internalBudget)) {
      return { ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "budget-mismatch" };
    }
    const validated = summary as unknown as ValidatedSummaryArtifactV01;
    validatedSummaries.add(validated);
    return { ok: true, summary, validated_summary: validated };
  } catch {
    return { ok: false, reason: "SUMMARY_INPUT_INVALID" };
  }
}
