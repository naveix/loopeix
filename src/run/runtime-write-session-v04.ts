import { z } from "zod";
import { isProxy } from "node:util/types";

import { hashCanonical } from "../hash.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../schema/runtime-v04.js";
import { Hash } from "../schema/scalars.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import { inspectRuntimePlanV03, type ValidatedRuntimePlanV03 } from "./project-plan-v03.js";
import {
  closeRuntimeFileStoreSessionV04,
  commitRuntimeCompactionFileStoreSessionV04,
  commitRuntimeFileStoreSessionV04,
  openRuntimeFileStoreSessionV04,
  readRuntimeFileStoreSessionSnapshotV04,
  type CapturedRuntimeFileStoreV04,
  type RuntimeFileStoreSessionSnapshotV04,
  type RuntimeFileStoreSessionV04,
} from "./runtime-file-store-v04.js";
import { inspectRuntimeLedgerV04, type ValidatedRuntimeLedgerV04 } from "./runtime-ledger-v04.js";
import {
  consumeRuntimeClockObservationV04,
  type CapturedRuntimeClockObservationV04,
  type RuntimeClockObservationFactsV04,
} from "./runtime-clock-observation-v04.js";
import {
  buildRunManifestV04,
  inspectRunManifestV04,
  type ValidatedRunManifestV04,
} from "./runtime-manifest-v04.js";
import { buildRuntimeSummaryArtifactsV04 } from "./runtime-summary-v04.js";
import {
  consumeCapturedRuntimeRecoveryRequestV04,
  inspectCapturedRuntimeRecoveryRequestV04,
  type CapturedRuntimeRecoveryRequestV04,
} from "./runtime-recovery-authorization-v04.js";
import {
  consumeCapturedRuntimePauseRequestV04,
  inspectCapturedRuntimePauseRequestV04,
  type CapturedRuntimePauseRequestV04,
  type CapturedRuntimePauseRequestBindingV04,
} from "./runtime-pause-authorization-v04.js";
import {
  planRuntimeRecoveryV04,
  validatePendingRuntimeRecoveryV04,
  type RuntimeRecoveryEligibilityDecisionV04,
} from "./runtime-recovery-v04.js";
import {
  reduceRuntimeEventPrefixV04,
  type RuntimeOwnerLeaseV04,
  type RuntimeStateV04,
} from "./runtime-state-reducer-v04.js";

const RequestClockInputV04 = z.object({
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  event_id: MachineIdV02,
  clock_id: MachineIdV02,
}).strict();

const RunOwnerClockInputV04 = RequestClockInputV04.extend({
  run_owner_lease_id: MachineIdV02,
}).strict();

const EventEnvelopeInputV04 = z.object({
  event_id: MachineIdV02,
}).strict();

const PendingRefInputV04 = z.object({
  ledger_sequence: z.number().int().positive().refine(Number.isSafeInteger),
  event_hash: Hash,
}).strict();

const FreshResumeInputV04 = z.object({
  kind: z.literal("fresh"),
  captured_request: z.custom<CapturedRuntimeRecoveryRequestV04>(),
  owner_status: z.unknown(),
  summary: z.unknown(),
  request_clock: RequestClockInputV04,
  run_owner_clock: RunOwnerClockInputV04,
  request_event: EventEnvelopeInputV04,
  attempt_event: EventEnvelopeInputV04.extend({ attempt_id: MachineIdV02 }).strict(),
}).strict();

const ContinuePendingResumeInputV04 = z.object({
  kind: z.literal("continue-pending"),
  pending_request_event_ref: PendingRefInputV04,
  owner_status: z.unknown(),
  attempt_observation: z.custom<CapturedRuntimeClockObservationV04>(),
  attempt_event: EventEnvelopeInputV04.extend({ attempt_id: MachineIdV02 }).strict(),
}).strict();

const ResumeInputV04 = z.discriminatedUnion("kind", [FreshResumeInputV04, ContinuePendingResumeInputV04]);

const OwnerLeaseRefInputV04 = z.object({
  ledger_sequence: z.number().int().positive().refine(Number.isSafeInteger),
  event_hash: Hash,
}).strict();

const HeartbeatOwnerLeaseInputV04 = z.object({
  owner_lease_event_ref: OwnerLeaseRefInputV04,
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  clock_event_id: MachineIdV02,
  heartbeat_event_id: MachineIdV02,
}).strict();

const ReleaseOwnerLeaseInputV04 = z.object({
  owner_lease_event_ref: OwnerLeaseRefInputV04,
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  clock_event_id: MachineIdV02,
  release_event_id: MachineIdV02,
  reason: z.enum(["completed", "pause", "abort", "revoked", "superseded"]),
}).strict();

const PauseRuntimeInputV04 = z.object({
  captured_request: z.custom<CapturedRuntimePauseRequestV04>(),
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  clock_event_id: MachineIdV02,
  request_event_id: MachineIdV02,
  fence_event_id: MachineIdV02,
  paused_event_id: MachineIdV02,
}).strict();

const ContinuePendingPauseInputV04 = z.object({
  pending_request_event_ref: OwnerLeaseRefInputV04,
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  fence_event_id: MachineIdV02,
  paused_event_id: MachineIdV02,
}).strict();

const CompactionRuntimeInputV04 = z.object({
  summary_id: MachineIdV02,
  content_bytes: z.custom<Uint8Array>(),
  integrator_lease_event_ref: OwnerLeaseRefInputV04,
  source_first_event_ref: OwnerLeaseRefInputV04,
  source_last_event_ref: OwnerLeaseRefInputV04,
  source_prefix_event_ref: OwnerLeaseRefInputV04,
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  event_id: MachineIdV02,
}).strict();

type LedgerRef = Readonly<{ ledger_sequence: number; event_hash: string }>;
type ParsedResumeInput = z.infer<typeof ResumeInputV04>;
type InspectedStore = Readonly<{
  snapshot: RuntimeFileStoreSessionSnapshotV04;
  plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
}>;

export type ResumeRuntimeV04Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      request_event_ref: LedgerRef;
      attempt_event_ref: LedgerRef;
      ledger_bytes_hash: string;
      manifest_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification:
        | "NOT_COMMITTED"
        | "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED"
        | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_RECOVERY_INPUT_INVALID"
        | "RUNTIME_RECOVERY_AUTHORIZATION_INVALID"
        | "RUNTIME_RECOVERY_PREFIX_INVALID"
        | "RUNTIME_RECOVERY_REFUSED"
        | "RUNTIME_RECOVERY_REQUEST_NOT_COMMITTED"
        | "RUNTIME_RECOVERY_ATTEMPT_NOT_COMMITTED"
        | "RUNTIME_RECOVERY_OUTCOME_UNKNOWN";
      refusal_reason?: string;
      request_event_ref?: LedgerRef;
    }>;

export type RuntimeOwnerLeaseWriteV04Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      clock_event_ref: LedgerRef;
      operation_event_ref: LedgerRef;
      ledger_bytes_hash: string;
      manifest_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_OWNER_LEASE_INPUT_INVALID"
        | "RUNTIME_OWNER_LEASE_PREFIX_INVALID"
        | "RUNTIME_OWNER_LEASE_REFUSED"
        | "RUNTIME_OWNER_LEASE_NOT_COMMITTED"
        | "RUNTIME_OWNER_LEASE_OUTCOME_UNKNOWN";
      refusal_reason?: string;
    }>;

export type PauseRuntimeV04Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      request_event_ref: LedgerRef;
      paused_event_ref: LedgerRef;
      ledger_bytes_hash: string;
      manifest_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "REQUEST_COMMITTED_PAUSE_NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_PAUSE_INPUT_INVALID"
        | "RUNTIME_PAUSE_AUTHORIZATION_INVALID"
        | "RUNTIME_PAUSE_PREFIX_INVALID"
        | "RUNTIME_PAUSE_REFUSED"
        | "RUNTIME_PAUSE_REQUEST_NOT_COMMITTED"
        | "RUNTIME_PAUSE_NOT_COMMITTED"
        | "RUNTIME_PAUSE_OUTCOME_UNKNOWN";
      refusal_reason?: string;
      request_event_ref?: LedgerRef;
    }>;

export type CompactRuntimeV04Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      compaction_event_ref: LedgerRef;
      summary_content_path: string;
      summary_record_path: string;
      ledger_bytes_hash: string;
      manifest_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_COMPACTION_INPUT_INVALID"
        | "RUNTIME_COMPACTION_PREFIX_INVALID"
        | "RUNTIME_COMPACTION_REFUSED"
        | "RUNTIME_COMPACTION_NOT_COMMITTED"
        | "RUNTIME_COMPACTION_OUTCOME_UNKNOWN";
      refusal_reason?: string;
    }>;

const encoder = new TextEncoder();

function exactPlainObject(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value) || isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).some((key) => typeof key !== "string")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.keys(descriptors).sort().join("\0") !== [...keys].sort().join("\0")) return null;
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined
        || descriptor.enumerable !== true) return null;
    }
    return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
  } catch {
    return null;
  }
}

function hasSafeOwnerLeaseInputShape(value: unknown, kind: "heartbeat" | "release"): boolean {
  const keys = kind === "heartbeat"
    ? ["owner_lease_event_ref", "observation", "clock_event_id", "heartbeat_event_id"]
    : ["owner_lease_event_ref", "observation", "clock_event_id", "release_event_id", "reason"];
  const parsed = exactPlainObject(value, keys);
  return parsed !== null
    && exactPlainObject(parsed.owner_lease_event_ref, ["ledger_sequence", "event_hash"]) !== null;
}

function hasSafePauseInputShape(value: unknown): boolean {
  return exactPlainObject(value, [
    "captured_request", "observation", "clock_event_id", "request_event_id", "fence_event_id", "paused_event_id",
  ]) !== null;
}

function hasSafeContinuePauseInputShape(value: unknown): boolean {
  const parsed = exactPlainObject(value, [
    "pending_request_event_ref", "observation", "fence_event_id", "paused_event_id",
  ]);
  return parsed !== null
    && exactPlainObject(parsed.pending_request_event_ref, ["ledger_sequence", "event_hash"]) !== null;
}

function hasSafeCompactionInputShape(value: unknown): boolean {
  const parsed = exactPlainObject(value, [
    "summary_id", "content_bytes", "integrator_lease_event_ref", "source_first_event_ref",
    "source_last_event_ref", "source_prefix_event_ref", "observation", "event_id",
  ]);
  return parsed !== null && [
    parsed.integrator_lease_event_ref,
    parsed.source_first_event_ref,
    parsed.source_last_event_ref,
    parsed.source_prefix_event_ref,
  ].every((reference) => exactPlainObject(reference, ["ledger_sequence", "event_hash"]) !== null);
}

function hasSafeResumeInputShape(value: unknown): boolean {
  const commonAttempt = ["event_id", "attempt_id"] as const;
  const fresh = exactPlainObject(value, [
    "kind", "captured_request", "owner_status", "summary", "request_clock", "run_owner_clock",
    "request_event", "attempt_event",
  ]);
  if (fresh?.kind === "fresh") {
    return exactPlainObject(fresh.request_clock, ["observation", "event_id", "clock_id"]) !== null
      && exactPlainObject(fresh.run_owner_clock, [
        "observation", "event_id", "clock_id", "run_owner_lease_id",
      ]) !== null
      && exactPlainObject(fresh.request_event, ["event_id"]) !== null
      && exactPlainObject(fresh.attempt_event, commonAttempt) !== null;
  }
  const continuation = exactPlainObject(value, [
    "kind", "pending_request_event_ref", "owner_status", "attempt_observation", "attempt_event",
  ]);
  return continuation?.kind === "continue-pending"
    && exactPlainObject(continuation.pending_request_event_ref, ["ledger_sequence", "event_hash"]) !== null
    && exactPlainObject(continuation.attempt_event, commonAttempt) !== null;
}

function refOf(event: Readonly<{ sequence: number; event_hash: string }>): LedgerRef {
  return Object.freeze({ ledger_sequence: event.sequence, event_hash: event.event_hash });
}

function exactBoundaryMatches(
  binding: NonNullable<ReturnType<typeof inspectCapturedRuntimeRecoveryRequestV04>>,
  inspected: InspectedStore,
): boolean {
  return binding.run_id === inspected.plan.run_id
    && binding.run_id === inspected.ledger.run_id
    && binding.plan_hash === inspected.plan.plan_hash
    && binding.plan_hash === inspected.ledger.plan_hash
    && binding.source_boundary_sequence === inspected.ledger.sequence
    && binding.source_boundary_head_hash === inspected.ledger.head_hash
    && binding.source_manifest_hash === inspected.manifest.manifest_hash
    && binding.ledger.ledger_bytes_hash === inspected.ledger.ledger_bytes_hash
    && binding.ledger.ledger_byte_length === inspected.ledger.ledger_byte_length
    && binding.manifest.ledger_bytes_hash === inspected.manifest.ledger_bytes_hash
    && binding.manifest.ledger_sequence === inspected.manifest.ledger_sequence
    && binding.manifest.ledger_head_hash === inspected.manifest.ledger_head_hash;
}

function exactPauseBoundaryMatches(
  binding: CapturedRuntimePauseRequestBindingV04,
  inspected: InspectedStore,
): boolean {
  return binding.run_id === inspected.plan.run_id
    && binding.run_id === inspected.ledger.run_id
    && binding.plan_hash === inspected.plan.plan_hash
    && binding.plan_hash === inspected.ledger.plan_hash
    && binding.source_boundary_sequence === inspected.ledger.sequence
    && binding.source_boundary_head_hash === inspected.ledger.head_hash
    && binding.source_manifest_hash === inspected.manifest.manifest_hash
    && binding.ledger.ledger_bytes_hash === inspected.ledger.ledger_bytes_hash
    && binding.ledger.ledger_byte_length === inspected.ledger.ledger_byte_length
    && binding.manifest.ledger_bytes_hash === inspected.manifest.ledger_bytes_hash
    && binding.manifest.ledger_sequence === inspected.manifest.ledger_sequence
    && binding.manifest.ledger_head_hash === inspected.manifest.ledger_head_hash;
}

function capturedFilesWithLedger(
  snapshot: RuntimeFileStoreSessionSnapshotV04,
  ledgerBytes: Uint8Array,
) {
  return snapshot.captured_files.map((file) => Object.freeze({
    path: file.path,
    family: file.family,
    required: file.required,
    mode: file.path === "ledger.jsonl" ? 384 as const : file.mode,
    bytes: file.path === "ledger.jsonl"
      ? new Uint8Array(ledgerBytes)
      : file.bytes === null ? null : new Uint8Array(file.bytes),
  }));
}

function inspectStoreSnapshot(session: RuntimeFileStoreSessionV04): InspectedStore | null {
  const read = readRuntimeFileStoreSessionSnapshotV04(session);
  if (!read.ok) return null;
  const plan = inspectRuntimePlanV03(read.snapshot.resolved_run_plan_bytes);
  const ledger = inspectRuntimeLedgerV04(read.snapshot.ledger_bytes);
  if (!plan.ok || !ledger.ok) return null;
  const manifest = inspectRunManifestV04({
    manifest_bytes: read.snapshot.manifest_bytes,
    ledger_bytes: read.snapshot.ledger_bytes,
    captured_files: capturedFilesWithLedger(read.snapshot, read.snapshot.ledger_bytes),
  });
  if (!manifest.ok
    || plan.validated_plan.run_id !== ledger.ledger.run_id
    || plan.validated_plan.plan_hash !== ledger.ledger.plan_hash
    || manifest.manifest.run_id !== ledger.ledger.run_id
    || manifest.manifest.plan_hash !== ledger.ledger.plan_hash) return null;
  return Object.freeze({
    snapshot: read.snapshot,
    plan: plan.validated_plan,
    ledger: manifest.ledger,
    manifest: manifest.validated_manifest,
  });
}

function event(
  prior: readonly RuntimeEventV04Value[],
  envelope: Readonly<{ event_id: string; recorded_at: string }>,
  eventType: RuntimeEventV04Value["event_type"],
  source: RuntimeEventV04Value["source"],
  authorityRef: string | null,
  riskTier: RuntimeEventV04Value["risk_tier"],
  payload: unknown,
): RuntimeEventV04Value | null {
  const sequence = prior.length + 1;
  const preimage = {
    schema_version: "0.4" as const,
    event_id: envelope.event_id,
    run_id: prior[0]!.run_id,
    sequence,
    recorded_at: envelope.recorded_at,
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: riskTier,
    related_ids: [],
    previous_event_hash: prior.at(-1)!.event_hash,
    payload,
  };
  const parsed = RuntimeEventV04.safeParse({ ...preimage, event_hash: hashCanonical(preimage) });
  return parsed.success ? parsed.data : null;
}

function appendLedgerBytes(
  source: Uint8Array,
  events: readonly RuntimeEventV04Value[],
): Uint8Array {
  const tail = encoder.encode(events.map((row) => `${JSON.stringify(row)}\n`).join(""));
  const joined = new Uint8Array(source.byteLength + tail.byteLength);
  joined.set(source, 0);
  joined.set(tail, source.byteLength);
  return joined;
}

function nextState(
  inspected: InspectedStore,
  events: readonly RuntimeEventV04Value[],
): Readonly<{ ledger_bytes: Uint8Array; manifest_bytes: Uint8Array; manifest_hash: string }> | null {
  const ledgerBytes = appendLedgerBytes(inspected.snapshot.ledger_bytes, events);
  const built = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: inspected.manifest.created_at,
    captured_files: capturedFilesWithLedger(inspected.snapshot, ledgerBytes),
  });
  return built.ok
    ? Object.freeze({
        ledger_bytes: ledgerBytes,
        manifest_bytes: built.bytes,
        manifest_hash: built.manifest.manifest_hash,
      })
    : null;
}

function nextCompactionState(
  inspected: InspectedStore,
  compactionEvent: RuntimeEventV04Value,
  summary: Readonly<{
    content_path: string;
    content_bytes: Uint8Array;
    record_path: string;
    record_bytes: Uint8Array;
  }>,
): Readonly<{ ledger_bytes: Uint8Array; manifest_bytes: Uint8Array }> | null {
  const ledgerBytes = appendLedgerBytes(inspected.snapshot.ledger_bytes, [compactionEvent]);
  const capturedFiles = [
    ...capturedFilesWithLedger(inspected.snapshot, ledgerBytes),
    Object.freeze({
      path: summary.content_path,
      family: "record" as const,
      required: true,
      mode: 384 as const,
      bytes: new Uint8Array(summary.content_bytes),
    }),
    Object.freeze({
      path: summary.record_path,
      family: "record" as const,
      required: true,
      mode: 384 as const,
      bytes: new Uint8Array(summary.record_bytes),
    }),
  ];
  const built = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: inspected.manifest.created_at,
    captured_files: capturedFiles,
  });
  return built.ok
    ? Object.freeze({ ledger_bytes: ledgerBytes, manifest_bytes: built.bytes })
    : null;
}

function safeDeadline(plan: ValidatedRuntimePlanV03, elapsedMs: number): number | null {
  const duration = plan.plan.runtime_execution_policy.owner_lease_duration_ms;
  const maximum = plan.plan.limit_policy.max_elapsed_ms;
  if (!Number.isSafeInteger(duration) || duration <= 0
    || !Number.isSafeInteger(maximum) || maximum <= elapsedMs
    || elapsedMs > Number.MAX_SAFE_INTEGER - duration) return null;
  const deadline = elapsedMs + duration;
  if (deadline > maximum) return null;
  return deadline > elapsedMs && Number.isSafeInteger(deadline) ? deadline : null;
}

function maximumObservedElapsed(ledger: ValidatedRuntimeLedgerV04): number {
  let maximum = 0;
  for (const row of ledger.events) {
    if (row.event_type === "run.clock-observed") maximum = Math.max(maximum, row.payload.elapsed_ms);
  }
  return maximum;
}

function sameRef(left: LedgerRef, right: LedgerRef): boolean {
  return left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function ownerScopeForRef(
  ledger: ValidatedRuntimeLedgerV04,
  ownerRef: LedgerRef,
): "run" | "task" | "integrator" | null {
  const row = ledger.events[ownerRef.ledger_sequence - 1];
  if (row?.event_hash !== ownerRef.event_hash) return null;
  if (row.event_type === "execution.attempt-started") return "run";
  return row.event_type === "ownership.lease-acquired" ? row.payload.scope : null;
}

function exactActiveOwner(
  state: RuntimeStateV04,
  ownerRef: LedgerRef,
): RuntimeOwnerLeaseV04 | null {
  const candidates = [
    ...(state.active_run_owner === null ? [] : [state.active_run_owner]),
    ...state.subordinate_owner_leases,
  ];
  return candidates.find((lease) => sameRef(lease.lease_event_ref, ownerRef)) ?? null;
}

function scopeHeartbeatCount(
  ledger: ValidatedRuntimeLedgerV04,
  scope: "run" | "task" | "integrator",
): number {
  let count = 0;
  for (const row of ledger.events) {
    if (row.event_type === "ownership.lease-heartbeat-recorded"
      && ownerScopeForRef(ledger, row.payload.owner_lease_event_ref) === scope) count += 1;
  }
  return count;
}

function scopeReleaseCount(
  ledger: ValidatedRuntimeLedgerV04,
  scope: "run" | "task" | "integrator",
): number {
  let count = 0;
  for (const row of ledger.events) {
    if (row.event_type === "ownership.lease-released"
      && ownerScopeForRef(ledger, row.payload.owner_lease_event_ref) === scope) count += 1;
  }
  return count;
}

function scopeHeartbeatMaximum(plan: ValidatedRuntimePlanV03, scope: "run" | "task" | "integrator"): number {
  const policy = plan.plan.runtime_execution_policy;
  return scope === "run"
    ? policy.run_heartbeat_event_max
    : scope === "task" ? policy.task_heartbeat_event_max : policy.integrator_heartbeat_event_max;
}

function scopeReleaseMaximum(plan: ValidatedRuntimePlanV03, scope: "run" | "task" | "integrator"): number {
  const policy = plan.plan.runtime_execution_policy;
  return scope === "run"
    ? policy.run_owner_release_max
    : scope === "task" ? policy.task_owner_release_max : policy.integrator_release_max;
}

function ownerClockEvent(
  ledger: ValidatedRuntimeLedgerV04,
  lease: RuntimeOwnerLeaseV04,
  facts: RuntimeClockObservationFactsV04,
  eventId: string,
  reason: "owner-heartbeat" | "owner-release",
): RuntimeEventV04Value | null {
  return event(ledger.events, { event_id: eventId, recorded_at: facts.observed_at }, "run.clock-observed", "kernel", null, "T1", {
    clock_id: eventId,
    observed_at: facts.observed_at,
    elapsed_ms: facts.elapsed_ms,
    reason,
    task_ref: null,
    failure_ordinal: null,
    use_ref: lease.owner_lease_id,
    attempt_ref: lease.attempt_event_ref,
    owner_lease_ref: lease.lease_event_ref,
    boot_id_hash: facts.boot_id_hash,
    monotonic_clock_id: facts.monotonic_clock_id,
  });
}

async function commitClosedOwnerEvents(
  session: RuntimeFileStoreSessionV04,
  inspected: InspectedStore,
  clock: RuntimeEventV04Value,
  operation: RuntimeEventV04Value,
): Promise<RuntimeOwnerLeaseWriteV04Result> {
  const next = nextState(inspected, [clock, operation]);
  if (next === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_PREFIX_INVALID" });
  }
  const committed = await commitRuntimeFileStoreSessionV04(session, {
    expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
    expected_manifest_hash: inspected.manifest.manifest_hash,
    next_ledger_bytes: next.ledger_bytes,
    next_manifest_bytes: next.manifest_bytes,
  });
  if (!committed.ok) {
    return committed.classification === "OUTCOME_UNKNOWN"
      ? Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_OWNER_LEASE_OUTCOME_UNKNOWN" })
      : Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_NOT_COMMITTED" });
  }
  // The file-store commit performs exact ledger and manifest readback before it
  // returns COMMITTED; a failed or ambiguous readback is classified there.
  return Object.freeze({
    ok: true,
    classification: "COMMITTED",
    clock_event_ref: refOf(clock),
    operation_event_ref: refOf(operation),
    ledger_bytes_hash: committed.ledger_bytes_hash,
    manifest_hash: committed.manifest_hash,
  });
}

async function writeRuntimeOwnerLeaseEventV04(
  store: CapturedRuntimeFileStoreV04,
  kind: "heartbeat" | "release",
  rawInput: unknown,
): Promise<RuntimeOwnerLeaseWriteV04Result> {
  if (!hasSafeOwnerLeaseInputShape(rawInput, kind)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
  }
  const parsed = kind === "heartbeat"
    ? HeartbeatOwnerLeaseInputV04.safeParse(rawInput)
    : ReleaseOwnerLeaseInputV04.safeParse(rawInput);
  if (!parsed.success) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
  }
  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) {
    return opened.error === "RUNTIME_FILE_STORE_POISONED"
      ? Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_OWNER_LEASE_OUTCOME_UNKNOWN" })
      : Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_PREFIX_INVALID" });
  }
  try {
    const inspected = inspectStoreSnapshot(opened.session);
    if (inspected === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_PREFIX_INVALID" });
    }
    const reduced = reduceRuntimeEventPrefixV04(inspected.ledger.events);
    if (!reduced.ok) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_PREFIX_INVALID" });
    }
    const lease = exactActiveOwner(reduced.state, parsed.data.owner_lease_event_ref);
    if (lease === null || !lease.active || lease.released) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_REFUSED", refusal_reason: "owner-not-active" });
    }
    const scope = lease.scope;
    const ownerEvent = inspected.ledger.events[lease.lease_event_ref.ledger_sequence - 1];
    if (ownerEvent?.event_hash !== lease.lease_event_ref.event_hash) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_PREFIX_INVALID" });
    }
    if (kind === "heartbeat") {
      if (!("heartbeat_event_id" in parsed.data)) {
        return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
      }
      const subordinateLimit = ownerEvent.event_type === "ownership.lease-acquired"
        ? ownerEvent.payload.heartbeat_limit : null;
      if ((subordinateLimit !== null && lease.heartbeat_ordinal >= subordinateLimit)
        || scopeHeartbeatCount(inspected.ledger, scope) >= scopeHeartbeatMaximum(inspected.plan, scope)) {
        return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_REFUSED", refusal_reason: "heartbeat-limit-reached" });
      }
    } else if (scopeReleaseCount(inspected.ledger, scope) >= scopeReleaseMaximum(inspected.plan, scope)) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_REFUSED", refusal_reason: "release-limit-reached" });
    }
    const facts = consumeRuntimeClockObservationV04(parsed.data.observation);
    if (facts === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
    }
    if (facts.boot_id_hash !== lease.boot_id_hash
      || facts.monotonic_clock_id !== lease.monotonic_clock_id
      || facts.elapsed_ms < maximumObservedElapsed(inspected.ledger)) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_REFUSED", refusal_reason: "clock-domain-or-order-invalid" });
    }
    if (kind === "heartbeat" && facts.elapsed_ms >= lease.deadline_elapsed_ms) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_REFUSED", refusal_reason: "lease-deadline-reached" });
    }
    const clock = ownerClockEvent(inspected.ledger, lease, facts, parsed.data.clock_event_id, kind === "heartbeat" ? "owner-heartbeat" : "owner-release");
    if (clock === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
    }
    if (kind === "heartbeat") {
      if (!("heartbeat_event_id" in parsed.data)) {
        return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
      }
      const duration = inspected.plan.plan.runtime_execution_policy.owner_lease_duration_ms;
      if (facts.elapsed_ms > Number.MAX_SAFE_INTEGER - duration) {
        return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_REFUSED", refusal_reason: "deadline-overflow" });
      }
      const parentDeadline = scope === "run"
        ? inspected.plan.plan.limit_policy.max_elapsed_ms
        : reduced.state.active_run_owner?.active === true
          && reduced.state.active_run_owner.owner_lease_id === lease.parent_run_owner_lease_id
          ? reduced.state.active_run_owner.deadline_elapsed_ms : null;
      if (parentDeadline === null) {
        return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_REFUSED", refusal_reason: "parent-owner-not-active" });
      }
      const deadline = Math.min(
        facts.elapsed_ms + duration,
        inspected.plan.plan.limit_policy.max_elapsed_ms,
        parentDeadline,
      );
      if (!Number.isSafeInteger(deadline) || deadline <= lease.deadline_elapsed_ms) {
        return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_REFUSED", refusal_reason: "lease-cannot-be-extended" });
      }
      const operation = event([...inspected.ledger.events, clock], {
        event_id: parsed.data.heartbeat_event_id,
        recorded_at: facts.observed_at,
      }, "ownership.lease-heartbeat-recorded", "kernel", null, "T1", {
        owner_lease_event_ref: lease.lease_event_ref,
        heartbeat_ordinal: lease.heartbeat_ordinal + 1,
        observation_clock_ref: refOf(clock),
        previous_deadline_elapsed_ms: lease.deadline_elapsed_ms,
        deadline_elapsed_ms: deadline,
        boot_id_hash: lease.boot_id_hash,
        monotonic_clock_id: lease.monotonic_clock_id,
        fence_epoch: lease.fence_epoch,
      });
      return operation === null
        ? Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" })
        : commitClosedOwnerEvents(opened.session, inspected, clock, operation);
    }
    if (!("release_event_id" in parsed.data) || !("reason" in parsed.data)) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
    }
    const operation = event([...inspected.ledger.events, clock], {
      event_id: parsed.data.release_event_id,
      recorded_at: facts.observed_at,
    }, "ownership.lease-released", "kernel", null, "T1", {
      owner_lease_event_ref: lease.lease_event_ref,
      release_clock_ref: refOf(clock),
      reason: parsed.data.reason,
      fence_epoch: lease.fence_epoch,
    });
    return operation === null
      ? Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" })
      : commitClosedOwnerEvents(opened.session, inspected, clock, operation);
  } finally {
    await closeRuntimeFileStoreSessionV04(opened.session);
  }
}

/** Package-private: records one bounded heartbeat transaction without retry. */
export function heartbeatRuntimeOwnerLeaseV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<RuntimeOwnerLeaseWriteV04Result> {
  return writeRuntimeOwnerLeaseEventV04(store, "heartbeat", input);
}

/** Package-private: records one bounded release transaction without retry. */
export function releaseRuntimeOwnerLeaseV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<RuntimeOwnerLeaseWriteV04Result> {
  return writeRuntimeOwnerLeaseEventV04(store, "release", input);
}

function activeOwnerRefsForPause(state: RuntimeStateV04): readonly LedgerRef[] | null {
  const leases = [
    ...(state.active_run_owner?.active === true && !state.active_run_owner.released
      ? [state.active_run_owner]
      : []),
    ...state.subordinate_owner_leases.filter((lease) => lease.active && !lease.released),
  ];
  if (leases.length === 0) return null;
  return Object.freeze(leases
    .map((lease) => refOf({
      sequence: lease.lease_event_ref.ledger_sequence,
      event_hash: lease.lease_event_ref.event_hash,
    }))
    .sort((left, right) => left.ledger_sequence - right.ledger_sequence
      || left.event_hash.localeCompare(right.event_hash)));
}

function pauseCommitFailure(
  committed: Awaited<ReturnType<typeof commitRuntimeFileStoreSessionV04>>,
  requestRef?: LedgerRef,
): Extract<PauseRuntimeV04Result, { ok: false }> {
  if (committed.classification === "OUTCOME_UNKNOWN") {
    return Object.freeze({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_PAUSE_OUTCOME_UNKNOWN",
      ...(requestRef === undefined ? {} : { request_event_ref: requestRef }),
    });
  }
  return requestRef === undefined
    ? Object.freeze({
        ok: false,
        classification: "NOT_COMMITTED",
        error: "RUNTIME_PAUSE_REQUEST_NOT_COMMITTED",
      })
    : Object.freeze({
        ok: false,
        classification: "REQUEST_COMMITTED_PAUSE_NOT_COMMITTED",
        error: "RUNTIME_PAUSE_NOT_COMMITTED",
        request_event_ref: requestRef,
      });
}

/**
 * Package-private: commits one operator pause without retry. The durable intent
 * is deliberately separate from the fence boundary so a crash cannot falsely
 * report that an uncommitted pause completed.
 */
export async function pauseRuntimeWriteSessionV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<PauseRuntimeV04Result> {
  if (!hasSafePauseInputShape(input)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_INPUT_INVALID" });
  }
  const parsed = PauseRuntimeInputV04.safeParse(input);
  if (!parsed.success) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_INPUT_INVALID" });
  }
  const binding = inspectCapturedRuntimePauseRequestV04(parsed.data.captured_request);
  if (binding === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_AUTHORIZATION_INVALID" });
  }
  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) {
    return opened.error === "RUNTIME_FILE_STORE_POISONED"
      ? Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_PAUSE_OUTCOME_UNKNOWN" })
      : Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_PREFIX_INVALID" });
  }
  try {
    const inspected = inspectStoreSnapshot(opened.session);
    if (inspected === null || !exactPauseBoundaryMatches(binding, inspected)) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_AUTHORIZATION_INVALID" });
    }
    const reduced = reduceRuntimeEventPrefixV04(inspected.ledger.events);
    if (!reduced.ok) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_PREFIX_INVALID" });
    }
    if (reduced.state.state !== "running"
      || reduced.state.terminal_sealed
      || reduced.state.pending_resume_request !== null
      || reduced.state.current_attempt_event_ref === null
      || reduced.state.active_run_owner?.active !== true
      || reduced.state.in_flight_action_ids.length !== 0
      || reduced.state.current_fence_epoch >= Number.MAX_SAFE_INTEGER) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_REFUSED", refusal_reason: "run-not-quiescent-and-pausable" });
    }
    if (!sameRef(binding.current_attempt_event_ref, reduced.state.current_attempt_event_ref)
      || !sameRef(binding.run_owner_lease_event_ref, reduced.state.active_run_owner.lease_event_ref)
      || binding.current_fence_epoch !== reduced.state.current_fence_epoch) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_AUTHORIZATION_INVALID" });
    }
    const ownerRefs = activeOwnerRefsForPause(reduced.state);
    if (ownerRefs === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_REFUSED", refusal_reason: "no-active-owner" });
    }
    const clockFacts = consumeRuntimeClockObservationV04(parsed.data.observation);
    const expiresAt = Date.parse(binding.expires_at);
    if (clockFacts === null
      || !Number.isFinite(expiresAt)
      || Date.parse(clockFacts.observed_at) > expiresAt
      || clockFacts.elapsed_ms < maximumObservedElapsed(inspected.ledger)) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_AUTHORIZATION_INVALID" });
    }
    const clock = event(inspected.ledger.events, {
      event_id: parsed.data.clock_event_id,
      recorded_at: clockFacts.observed_at,
    }, "run.clock-observed", "kernel", null, "T1", {
      clock_id: parsed.data.clock_event_id,
      observed_at: clockFacts.observed_at,
      elapsed_ms: clockFacts.elapsed_ms,
      reason: "pause-request",
      task_ref: null,
      failure_ordinal: null,
      use_ref: binding.request.request_id,
      attempt_ref: binding.current_attempt_event_ref,
      owner_lease_ref: binding.run_owner_lease_event_ref,
      boot_id_hash: null,
      monotonic_clock_id: null,
    });
    const requested = clock === null ? null : event([...inspected.ledger.events, clock], {
      event_id: parsed.data.request_event_id,
      recorded_at: clockFacts.observed_at,
    }, "control.pause-requested", "operator", binding.authority_ref, binding.approved_risk_tier, {
      request_id: binding.request.request_id,
      requested_by: binding.request.requested_by,
      reason_code: binding.request.reason_code,
      attempt_event_ref: binding.current_attempt_event_ref,
      run_owner_lease_ref: binding.run_owner_lease_event_ref,
      request_clock_ref: refOf(clock),
      fence_epoch: binding.current_fence_epoch,
    });
    if (clock === null || requested === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_INPUT_INVALID" });
    }
    const first = nextState(inspected, [clock, requested]);
    if (first === null || consumeCapturedRuntimePauseRequestV04(parsed.data.captured_request) === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_AUTHORIZATION_INVALID" });
    }
    const requestCommit = await commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
      expected_manifest_hash: inspected.manifest.manifest_hash,
      next_ledger_bytes: first.ledger_bytes,
      next_manifest_bytes: first.manifest_bytes,
    });
    if (!requestCommit.ok) return pauseCommitFailure(requestCommit);

    const afterRequest = inspectStoreSnapshot(opened.session);
    if (afterRequest === null) {
      return Object.freeze({ ok: false, classification: "REQUEST_COMMITTED_PAUSE_NOT_COMMITTED", error: "RUNTIME_PAUSE_NOT_COMMITTED", request_event_ref: refOf(requested) });
    }
    const afterReduced = reduceRuntimeEventPrefixV04(afterRequest.ledger.events);
    if (!afterReduced.ok
      || afterReduced.state.state !== "running"
      || afterReduced.state.in_flight_action_ids.length !== 0
      || afterReduced.state.current_attempt_event_ref === null
      || !sameRef(afterReduced.state.current_attempt_event_ref, binding.current_attempt_event_ref)
      || afterReduced.state.current_fence_epoch !== binding.current_fence_epoch) {
      return Object.freeze({ ok: false, classification: "REQUEST_COMMITTED_PAUSE_NOT_COMMITTED", error: "RUNTIME_PAUSE_NOT_COMMITTED", request_event_ref: refOf(requested) });
    }
    const fence = event(afterRequest.ledger.events, {
      event_id: parsed.data.fence_event_id,
      recorded_at: clockFacts.observed_at,
    }, "run.fence-advanced", "policy-enforcement-point", binding.authority_ref, binding.approved_risk_tier, {
      previous_fence_epoch: binding.current_fence_epoch,
      fence_epoch: binding.current_fence_epoch + 1,
      reason: "pause-request",
      evidence_refs: [refOf(requested)],
      attempt_ref: binding.current_attempt_event_ref,
      owner_lease_refs: ownerRefs,
    });
    const paused = fence === null ? null : event([...afterRequest.ledger.events, fence], {
      event_id: parsed.data.paused_event_id,
      recorded_at: clockFacts.observed_at,
    }, "run.paused", "operator", binding.authority_ref, binding.approved_risk_tier, {
      requested_by: binding.request.requested_by,
      reason_code: binding.request.reason_code,
      request_event_ref: refOf(requested),
      attempt_event_ref: binding.current_attempt_event_ref,
      quiescent_boundary_sequence: fence.sequence,
      quiescent_boundary_head_hash: fence.event_hash,
      previous_fence_epoch: binding.current_fence_epoch,
      fence_epoch: binding.current_fence_epoch + 1,
      invalidated_owner_lease_refs: ownerRefs,
    });
    const second = fence === null || paused === null ? null : nextState(afterRequest, [fence, paused]);
    if (second === null || paused === null) {
      return Object.freeze({ ok: false, classification: "REQUEST_COMMITTED_PAUSE_NOT_COMMITTED", error: "RUNTIME_PAUSE_NOT_COMMITTED", request_event_ref: refOf(requested) });
    }
    const pauseCommit = await commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: afterRequest.ledger.ledger_bytes_hash,
      expected_manifest_hash: afterRequest.manifest.manifest_hash,
      next_ledger_bytes: second.ledger_bytes,
      next_manifest_bytes: second.manifest_bytes,
    });
    if (!pauseCommit.ok) return pauseCommitFailure(pauseCommit, refOf(requested));
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      request_event_ref: refOf(requested),
      paused_event_ref: refOf(paused),
      ledger_bytes_hash: pauseCommit.ledger_bytes_hash,
      manifest_hash: pauseCommit.manifest_hash,
    });
  } finally {
    await closeRuntimeFileStoreSessionV04(opened.session);
  }
}

/** Completes one previously durable pause intent from its unchanged exact head. */
export async function continuePendingPauseRuntimeWriteSessionV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<PauseRuntimeV04Result> {
  if (!hasSafeContinuePauseInputShape(input)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_INPUT_INVALID" });
  }
  const parsed = ContinuePendingPauseInputV04.safeParse(input);
  if (!parsed.success) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_INPUT_INVALID" });
  }
  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) {
    return opened.error === "RUNTIME_FILE_STORE_POISONED"
      ? Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_PAUSE_OUTCOME_UNKNOWN" })
      : Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_PREFIX_INVALID" });
  }
  try {
    const inspected = inspectStoreSnapshot(opened.session);
    if (inspected === null
      || inspected.ledger.sequence !== parsed.data.pending_request_event_ref.ledger_sequence
      || inspected.ledger.head_hash !== parsed.data.pending_request_event_ref.event_hash) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_PAUSE_PREFIX_INVALID" });
    }
    const request = inspected.ledger.events.at(-1);
    const reduced = reduceRuntimeEventPrefixV04(inspected.ledger.events);
    if (request?.event_type !== "control.pause-requested"
      || request.payload.requested_by !== "operator"
      || request.authority_ref === null
      || !reduced.ok
      || reduced.state.state !== "running"
      || reduced.state.terminal_sealed
      || reduced.state.pending_resume_request !== null
      || reduced.state.in_flight_action_ids.length !== 0
      || reduced.state.current_attempt_event_ref === null
      || !sameRef(request.payload.attempt_event_ref, reduced.state.current_attempt_event_ref)
      || reduced.state.active_run_owner?.active !== true
      || !sameRef(request.payload.run_owner_lease_ref, reduced.state.active_run_owner.lease_event_ref)
      || request.payload.fence_epoch !== reduced.state.current_fence_epoch
      || reduced.state.current_fence_epoch >= Number.MAX_SAFE_INTEGER) {
      return Object.freeze({ ok: false, classification: "REQUEST_COMMITTED_PAUSE_NOT_COMMITTED", error: "RUNTIME_PAUSE_NOT_COMMITTED", request_event_ref: parsed.data.pending_request_event_ref });
    }
    const ownerRefs = activeOwnerRefsForPause(reduced.state);
    const clockFacts = consumeRuntimeClockObservationV04(parsed.data.observation);
    if (ownerRefs === null
      || clockFacts === null
      || clockFacts.elapsed_ms < maximumObservedElapsed(inspected.ledger)
      || Date.parse(clockFacts.observed_at) < Date.parse(request.recorded_at)) {
      return Object.freeze({ ok: false, classification: "REQUEST_COMMITTED_PAUSE_NOT_COMMITTED", error: "RUNTIME_PAUSE_NOT_COMMITTED", request_event_ref: parsed.data.pending_request_event_ref });
    }
    const nextFence = reduced.state.current_fence_epoch + 1;
    const fence = event(inspected.ledger.events, {
      event_id: parsed.data.fence_event_id,
      recorded_at: clockFacts.observed_at,
    }, "run.fence-advanced", "policy-enforcement-point", request.authority_ref, request.risk_tier, {
      previous_fence_epoch: reduced.state.current_fence_epoch,
      fence_epoch: nextFence,
      reason: "pause-request",
      evidence_refs: [parsed.data.pending_request_event_ref],
      attempt_ref: request.payload.attempt_event_ref,
      owner_lease_refs: ownerRefs,
    });
    const paused = fence === null ? null : event([...inspected.ledger.events, fence], {
      event_id: parsed.data.paused_event_id,
      recorded_at: clockFacts.observed_at,
    }, "run.paused", "operator", request.authority_ref, request.risk_tier, {
      requested_by: request.payload.requested_by,
      reason_code: request.payload.reason_code,
      request_event_ref: parsed.data.pending_request_event_ref,
      attempt_event_ref: request.payload.attempt_event_ref,
      quiescent_boundary_sequence: fence.sequence,
      quiescent_boundary_head_hash: fence.event_hash,
      previous_fence_epoch: reduced.state.current_fence_epoch,
      fence_epoch: nextFence,
      invalidated_owner_lease_refs: ownerRefs,
    });
    const next = fence === null || paused === null ? null : nextState(inspected, [fence, paused]);
    if (next === null || paused === null) {
      return Object.freeze({ ok: false, classification: "REQUEST_COMMITTED_PAUSE_NOT_COMMITTED", error: "RUNTIME_PAUSE_NOT_COMMITTED", request_event_ref: parsed.data.pending_request_event_ref });
    }
    const committed = await commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
      expected_manifest_hash: inspected.manifest.manifest_hash,
      next_ledger_bytes: next.ledger_bytes,
      next_manifest_bytes: next.manifest_bytes,
    });
    if (!committed.ok) return pauseCommitFailure(committed, parsed.data.pending_request_event_ref);
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      request_event_ref: parsed.data.pending_request_event_ref,
      paused_event_ref: refOf(paused),
      ledger_bytes_hash: committed.ledger_bytes_hash,
      manifest_hash: committed.manifest_hash,
    });
  } finally {
    await closeRuntimeFileStoreSessionV04(opened.session);
  }
}

/** Builds and commits one immutable summary plus its exact compaction event. */
export async function compactRuntimeWriteSessionV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<CompactRuntimeV04Result> {
  if (!hasSafeCompactionInputShape(input)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INPUT_INVALID" });
  }
  const parsed = CompactionRuntimeInputV04.safeParse(input);
  if (!parsed.success) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INPUT_INVALID" });
  }
  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) {
    return opened.error === "RUNTIME_FILE_STORE_POISONED"
      ? Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_COMPACTION_OUTCOME_UNKNOWN" })
      : Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_PREFIX_INVALID" });
  }
  try {
    const inspected = inspectStoreSnapshot(opened.session);
    if (inspected === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_PREFIX_INVALID" });
    }
    const clockFacts = consumeRuntimeClockObservationV04(parsed.data.observation);
    if (clockFacts === null
      || clockFacts.elapsed_ms < maximumObservedElapsed(inspected.ledger)
      || Date.parse(clockFacts.observed_at) < Date.parse(inspected.ledger.events.at(-1)!.recorded_at)) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INPUT_INVALID" });
    }
    const built = buildRuntimeSummaryArtifactsV04({
      validated_plan: inspected.plan,
      ledger: inspected.ledger,
      manifest: inspected.manifest,
      summary_id: parsed.data.summary_id,
      content_bytes: parsed.data.content_bytes,
      integrator_lease_event_ref: parsed.data.integrator_lease_event_ref,
      source_first_event_ref: parsed.data.source_first_event_ref,
      source_last_event_ref: parsed.data.source_last_event_ref,
      source_prefix_event_ref: parsed.data.source_prefix_event_ref,
    });
    if (!built.ok) {
      return Object.freeze({
        ok: false,
        classification: "NOT_COMMITTED",
        error: built.reason === "SUMMARY_BUILD_INPUT_INVALID" || built.reason === "SUMMARY_BUILD_CONTENT_INVALID"
          ? "RUNTIME_COMPACTION_INPUT_INVALID"
          : "RUNTIME_COMPACTION_REFUSED",
        ...(built.reason === "SUMMARY_BUILD_INPUT_INVALID" || built.reason === "SUMMARY_BUILD_CONTENT_INVALID"
          ? {}
          : { refusal_reason: built.reason }),
      });
    }
    const attemptRef = built.artifact.resume_boundary.attempt_event_ref;
    const compaction = event(inspected.ledger.events, {
      event_id: parsed.data.event_id,
      recorded_at: clockFacts.observed_at,
    }, "run.compaction-recorded", "kernel", null, "T1", {
      summary_id: built.artifact.summary_id,
      summary_record_path: built.record_path,
      summary_record_hash: built.record_raw_hash,
      summary_content_path: built.content_path,
      summary_content_hash: built.artifact.content_hash,
      summary_size_bytes: built.content_bytes.byteLength,
      attempt_event_ref: attemptRef,
      integrator_lease_event_ref: parsed.data.integrator_lease_event_ref,
      source_first_event_ref: built.artifact.source_first_event_ref,
      source_last_event_ref: built.artifact.source_last_event_ref,
      source_prefix_sequence: built.artifact.source_prefix_sequence,
      source_prefix_head_hash: built.artifact.source_prefix_head_hash,
      pre_context_hash: built.pre_context_hash,
      post_context_hash: built.post_context_hash,
    });
    if (compaction === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_PREFIX_INVALID" });
    }
    const next = nextCompactionState(inspected, compaction, {
      content_path: built.content_path,
      content_bytes: built.content_bytes,
      record_path: built.record_path,
      record_bytes: built.record_bytes,
    });
    if (next === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_PREFIX_INVALID" });
    }
    const committed = await commitRuntimeCompactionFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
      expected_manifest_hash: inspected.manifest.manifest_hash,
      summary_content: { relative_path: built.content_path, bytes: built.content_bytes },
      summary_record: { relative_path: built.record_path, bytes: built.record_bytes },
      next_ledger_bytes: next.ledger_bytes,
      next_manifest_bytes: next.manifest_bytes,
    });
    if (!committed.ok) {
      return committed.classification === "OUTCOME_UNKNOWN"
        ? Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_COMPACTION_OUTCOME_UNKNOWN" })
        : Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_NOT_COMMITTED" });
    }
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      compaction_event_ref: refOf(compaction),
      summary_content_path: built.content_path,
      summary_record_path: built.record_path,
      ledger_bytes_hash: committed.ledger_bytes_hash,
      manifest_hash: committed.manifest_hash,
    });
  } finally {
    await closeRuntimeFileStoreSessionV04(opened.session);
  }
}

function requestClockEvent(
  ledger: ValidatedRuntimeLedgerV04,
  input: z.infer<typeof RequestClockInputV04>,
  facts: RuntimeClockObservationFactsV04,
  decision: RuntimeRecoveryEligibilityDecisionV04,
): RuntimeEventV04Value | null {
  return event(ledger.events, { event_id: input.event_id, recorded_at: facts.observed_at }, "run.clock-observed", "kernel", null, "T1", {
    clock_id: input.clock_id,
    observed_at: facts.observed_at,
    elapsed_ms: facts.elapsed_ms,
    reason: "recovery-request",
    task_ref: null,
    failure_ordinal: null,
    use_ref: decision.request_projection.request_id,
    attempt_ref: decision.request_projection.previous_attempt_event_ref,
    owner_lease_ref: decision.request_projection.previous_attempt_event_ref,
    boot_id_hash: null,
    monotonic_clock_id: null,
  });
}

function runOwnerClockEvent(
  prior: readonly RuntimeEventV04Value[],
  input: z.infer<typeof RunOwnerClockInputV04>,
  facts: RuntimeClockObservationFactsV04,
): RuntimeEventV04Value | null {
  return event(prior, { event_id: input.event_id, recorded_at: facts.observed_at }, "run.clock-observed", "kernel", null, "T1", {
    clock_id: input.clock_id,
    observed_at: facts.observed_at,
    elapsed_ms: facts.elapsed_ms,
    reason: "run-owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: input.run_owner_lease_id,
    attempt_ref: null,
    owner_lease_ref: null,
    boot_id_hash: facts.boot_id_hash,
    monotonic_clock_id: facts.monotonic_clock_id,
  });
}

function requestEvent(
  prior: readonly RuntimeEventV04Value[],
  input: z.infer<typeof EventEnvelopeInputV04>,
  recordedAt: string,
  decision: RuntimeRecoveryEligibilityDecisionV04,
  requestClockRef: LedgerRef,
  authorityRef: string,
  riskTier: RuntimeEventV04Value["risk_tier"],
): RuntimeEventV04Value | null {
  const projection = decision.request_projection;
  return event(prior, { event_id: input.event_id, recorded_at: recordedAt }, "recovery.resume-requested", "operator", authorityRef, riskTier, {
    request_id: projection.request_id,
    mode: projection.mode,
    resume_nonce_hash: projection.resume_nonce_hash,
    previous_attempt_event_ref: projection.previous_attempt_event_ref,
    source_boundary_sequence: projection.source_boundary_sequence,
    source_boundary_head_hash: projection.source_boundary_head_hash,
    source_manifest_hash: projection.source_manifest_hash,
    plan_hash: projection.plan_hash,
    input_hash: projection.input_hash,
    recovery_policy_hash: projection.recovery_policy_hash,
    authority_envelope_hash: projection.authority_envelope_hash,
    repository_state_hash: projection.repository_state_hash,
    request_clock_ref: requestClockRef,
    target_action_admission_ref: projection.target_action_admission_ref,
    compensation_phase_event_ref: projection.compensation_phase_event_ref,
  });
}

function buildAttemptEvent(
  plan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
  decision: RuntimeRecoveryEligibilityDecisionV04,
  pendingRequestRef: LedgerRef,
  attemptInput: Readonly<{ event_id: string; attempt_id: string }>,
  recordedAt: string,
): RuntimeEventV04Value | null {
  const pending = ledger.events[pendingRequestRef.ledger_sequence - 1];
  const ownerClock = ledger.events[pendingRequestRef.ledger_sequence - 2];
  if (pending?.event_type !== "recovery.resume-requested"
    || pending.event_hash !== pendingRequestRef.event_hash
    || ownerClock?.event_type !== "run.clock-observed"
    || ownerClock.payload.reason !== "run-owner-acquisition") return null;
  const deadline = safeDeadline(plan, ownerClock.payload.elapsed_ms);
  if (deadline === null) return null;
  const projection = decision.request_projection;
  return event(ledger.events, { event_id: attemptInput.event_id, recorded_at: recordedAt }, "execution.attempt-started", "kernel", null, pending.risk_tier, {
    attempt_id: attemptInput.attempt_id,
    attempt_ordinal: decision.next_attempt_ordinal,
    mode: projection.mode,
    previous_attempt_event_ref: projection.previous_attempt_event_ref,
    resume_request_event_ref: pendingRequestRef,
    resume_nonce_hash: projection.resume_nonce_hash,
    source_boundary_sequence: projection.source_boundary_sequence,
    source_boundary_head_hash: projection.source_boundary_head_hash,
    source_manifest_hash: projection.source_manifest_hash,
    plan_hash: projection.plan_hash,
    input_hash: projection.input_hash,
    recovery_policy_hash: projection.recovery_policy_hash,
    authority_envelope_hash: projection.authority_envelope_hash,
    repository_state_hash: projection.repository_state_hash,
    run_owner_lease_id: ownerClock.payload.use_ref,
    issued_clock_ref: refOf(ownerClock),
    deadline_elapsed_ms: deadline,
    boot_id_hash: ownerClock.payload.boot_id_hash,
    monotonic_clock_id: ownerClock.payload.monotonic_clock_id,
    previous_fence_epoch: decision.resume_boundary.fence_epoch,
    fence_epoch: decision.next_fence_epoch,
  });
}

function commitFailure(
  result: Awaited<ReturnType<typeof commitRuntimeFileStoreSessionV04>>,
  requestCommitted: boolean,
  requestRef?: LedgerRef,
): Extract<ResumeRuntimeV04Result, { ok: false }> {
  if (result.classification === "OUTCOME_UNKNOWN") {
    return Object.freeze({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_RECOVERY_OUTCOME_UNKNOWN",
      ...(requestRef === undefined ? {} : { request_event_ref: requestRef }),
    });
  }
  return Object.freeze({
    ok: false,
    classification: requestCommitted ? "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED" : "NOT_COMMITTED",
    error: requestCommitted ? "RUNTIME_RECOVERY_ATTEMPT_NOT_COMMITTED" : "RUNTIME_RECOVERY_REQUEST_NOT_COMMITTED",
    ...(requestRef === undefined ? {} : { request_event_ref: requestRef }),
  });
}

async function commitAttempt(
  session: RuntimeFileStoreSessionV04,
  inspected: InspectedStore,
  decision: RuntimeRecoveryEligibilityDecisionV04,
  pendingRequestRef: LedgerRef,
  attemptInput: Readonly<{ event_id: string; attempt_id: string }>,
  recordedAt: string,
  requestCommitted: boolean,
): Promise<ResumeRuntimeV04Result> {
  const attempt = buildAttemptEvent(inspected.plan, inspected.ledger, decision, pendingRequestRef, attemptInput, recordedAt);
  if (attempt === null) {
    return Object.freeze({
      ok: false,
      classification: requestCommitted ? "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED" : "NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_PREFIX_INVALID",
      request_event_ref: pendingRequestRef,
    });
  }
  const next = nextState(inspected, [attempt]);
  if (next === null) {
    return Object.freeze({
      ok: false,
      classification: requestCommitted ? "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED" : "NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_PREFIX_INVALID",
      request_event_ref: pendingRequestRef,
    });
  }
  const committed = await commitRuntimeFileStoreSessionV04(session, {
    expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
    expected_manifest_hash: inspected.manifest.manifest_hash,
    next_ledger_bytes: next.ledger_bytes,
    next_manifest_bytes: next.manifest_bytes,
  });
  if (!committed.ok) return commitFailure(committed, requestCommitted, pendingRequestRef);
  return Object.freeze({
    ok: true,
    classification: "COMMITTED",
    request_event_ref: pendingRequestRef,
    attempt_event_ref: refOf(attempt),
    ledger_bytes_hash: committed.ledger_bytes_hash,
    manifest_hash: committed.manifest_hash,
  });
}

async function freshResume(
  session: RuntimeFileStoreSessionV04,
  inspected: InspectedStore,
  input: Extract<ParsedResumeInput, { kind: "fresh" }>,
): Promise<ResumeRuntimeV04Result> {
  const binding = inspectCapturedRuntimeRecoveryRequestV04(input.captured_request);
  if (binding === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_AUTHORIZATION_INVALID" });
  }
  const requestClockFacts = consumeRuntimeClockObservationV04(input.request_clock.observation);
  const ownerClockFacts = consumeRuntimeClockObservationV04(input.run_owner_clock.observation);
  if (requestClockFacts === null || ownerClockFacts === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_INPUT_INVALID" });
  }
  if (!exactBoundaryMatches(binding, inspected)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_AUTHORIZATION_INVALID" });
  }
  const expiresAt = Date.parse(binding.expires_at);
  const requestClockAt = Date.parse(requestClockFacts.observed_at);
  const ownerClockAt = Date.parse(ownerClockFacts.observed_at);
  if (!Number.isFinite(expiresAt)
    || requestClockAt > ownerClockAt
    || ownerClockAt > expiresAt) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_AUTHORIZATION_INVALID" });
  }
  const planned = planRuntimeRecoveryV04({
    ledger: binding.ledger,
    manifest: binding.manifest,
    plan: binding.validated_plan,
    owner_status: input.owner_status,
    request: input.captured_request,
    summary: input.summary,
  });
  if (!planned.ok) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_INPUT_INVALID" });
  }
  if (planned.decision.disposition === "refused") {
    return Object.freeze({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_REFUSED",
      refusal_reason: planned.decision.reason_code,
    });
  }
  if (requestClockFacts.elapsed_ms < maximumObservedElapsed(inspected.ledger)
    || requestClockFacts.elapsed_ms > ownerClockFacts.elapsed_ms) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_INPUT_INVALID" });
  }
  const requestClock = requestClockEvent(inspected.ledger, input.request_clock, requestClockFacts, planned.decision);
  if (requestClock === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_INPUT_INVALID" });
  }
  const ownerClock = runOwnerClockEvent([...inspected.ledger.events, requestClock], input.run_owner_clock, ownerClockFacts);
  if (ownerClock === null
    || ownerClock.event_type !== "run.clock-observed"
    || ownerClock.payload.reason !== "run-owner-acquisition"
    || safeDeadline(inspected.plan, ownerClock.payload.elapsed_ms) === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_INPUT_INVALID" });
  }
  const requested = requestEvent(
    [...inspected.ledger.events, requestClock, ownerClock],
    input.request_event,
    ownerClockFacts.observed_at,
    planned.decision,
    refOf(requestClock),
    binding.authority_ref,
    binding.approved_risk_tier,
  );
  if (requested === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_INPUT_INVALID" });
  }
  const batch = nextState(inspected, [requestClock, ownerClock, requested]);
  if (batch === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_PREFIX_INVALID" });
  }
  if (consumeCapturedRuntimeRecoveryRequestV04(input.captured_request) === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_AUTHORIZATION_INVALID" });
  }
  const requestCommit = await commitRuntimeFileStoreSessionV04(session, {
    expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
    expected_manifest_hash: inspected.manifest.manifest_hash,
    next_ledger_bytes: batch.ledger_bytes,
    next_manifest_bytes: batch.manifest_bytes,
  });
  if (!requestCommit.ok) return commitFailure(requestCommit, false);

  const afterRequest = inspectStoreSnapshot(session);
  if (afterRequest === null) {
    return Object.freeze({
      ok: false,
      classification: "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_ATTEMPT_NOT_COMMITTED",
      request_event_ref: refOf(requested),
    });
  }
  const revalidated = validatePendingRuntimeRecoveryV04({
    ledger: afterRequest.ledger,
    manifest: afterRequest.manifest,
    plan: afterRequest.plan,
    owner_status: input.owner_status,
    pending_request_event_ref: refOf(requested),
    summary: null,
  });
  if (!revalidated.ok) {
    return Object.freeze({
      ok: false,
      classification: "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_ATTEMPT_NOT_COMMITTED",
      request_event_ref: refOf(requested),
    });
  }
  if (revalidated.decision.disposition !== "eligible") {
    return Object.freeze({
      ok: false,
      classification: "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_ATTEMPT_NOT_COMMITTED",
      request_event_ref: refOf(requested),
      refusal_reason: revalidated.decision.reason_code,
    });
  }
  return commitAttempt(
    session,
    afterRequest,
    revalidated.decision,
    refOf(requested),
    input.attempt_event,
    ownerClockFacts.observed_at,
    true,
  );
}

async function continuePending(
  session: RuntimeFileStoreSessionV04,
  inspected: InspectedStore,
  input: Extract<ParsedResumeInput, { kind: "continue-pending" }>,
): Promise<ResumeRuntimeV04Result> {
  if (inspected.ledger.sequence !== input.pending_request_event_ref.ledger_sequence
    || inspected.ledger.head_hash !== input.pending_request_event_ref.event_hash) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_PREFIX_INVALID" });
  }
  const pending = inspected.ledger.events.at(-1);
  if (pending?.event_type !== "recovery.resume-requested") {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_PREFIX_INVALID" });
  }
  const ownerClock = inspected.ledger.events[input.pending_request_event_ref.ledger_sequence - 2];
  const attemptFacts = consumeRuntimeClockObservationV04(input.attempt_observation);
  if (ownerClock?.event_type !== "run.clock-observed"
    || ownerClock.payload.reason !== "run-owner-acquisition"
    || attemptFacts === null
    || attemptFacts.boot_id_hash !== ownerClock.payload.boot_id_hash
    || attemptFacts.monotonic_clock_id !== ownerClock.payload.monotonic_clock_id
    || attemptFacts.elapsed_ms < ownerClock.payload.elapsed_ms
    || Date.parse(attemptFacts.observed_at) < Date.parse(pending.recorded_at)) {
    return Object.freeze({ ok: false, classification: "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED", error: "RUNTIME_RECOVERY_ATTEMPT_NOT_COMMITTED", request_event_ref: input.pending_request_event_ref });
  }
  const revalidated = validatePendingRuntimeRecoveryV04({
    ledger: inspected.ledger,
    manifest: inspected.manifest,
    plan: inspected.plan,
    owner_status: input.owner_status,
    pending_request_event_ref: input.pending_request_event_ref,
    summary: null,
  });
  if (!revalidated.ok) {
    return Object.freeze({
      ok: false,
      classification: "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_ATTEMPT_NOT_COMMITTED",
      request_event_ref: input.pending_request_event_ref,
    });
  }
  if (revalidated.decision.disposition === "refused") {
    return Object.freeze({
      ok: false,
      classification: "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_ATTEMPT_NOT_COMMITTED",
      refusal_reason: revalidated.decision.reason_code,
      request_event_ref: input.pending_request_event_ref,
    });
  }
  return commitAttempt(
    session,
    inspected,
    revalidated.decision,
    input.pending_request_event_ref,
    input.attempt_event,
    attemptFacts.observed_at,
    true,
  );
}

/**
 * Performs exactly one bounded recovery transaction under the real V04 file
 * lock. It never retries an append and always closes the owned lock session.
 */
export async function resumeRuntimeWriteSessionV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<ResumeRuntimeV04Result> {
  if (!hasSafeResumeInputShape(input)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_INPUT_INVALID" });
  }
  const parsed = ResumeInputV04.safeParse(input);
  if (!parsed.success) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_INPUT_INVALID" });
  }
  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) {
    if (opened.error === "RUNTIME_FILE_STORE_POISONED") {
      return Object.freeze({
        ok: false,
        classification: "OUTCOME_UNKNOWN",
        error: "RUNTIME_RECOVERY_OUTCOME_UNKNOWN",
      });
    }
    return Object.freeze({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_PREFIX_INVALID",
    });
  }
  try {
    const inspected = inspectStoreSnapshot(opened.session);
    if (inspected === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECOVERY_PREFIX_INVALID" });
    }
    return parsed.data.kind === "fresh"
      ? await freshResume(opened.session, inspected, parsed.data)
      : await continuePending(opened.session, inspected, parsed.data);
  } finally {
    await closeRuntimeFileStoreSessionV04(opened.session);
  }
}
