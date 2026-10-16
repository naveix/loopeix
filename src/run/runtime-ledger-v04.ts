import { parseDocument } from "yaml";

import { hashCanonical, hashRawBytes } from "../hash.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../schema/runtime-v04.js";
import {
  reduceRuntimeEventPrefixV04,
  type RuntimeStateV04,
} from "./runtime-state-reducer-v04.js";

const MAX_LEDGER_BYTES = 67_108_864;
const MAX_EVENT_BYTES = 4_194_304;
const MAX_EVENTS = 100_000;
const validatedRuntimeLedgersV04 = new WeakSet<object>();

export type RuntimeLedgerV04FailureReason =
  | "LEDGER_SYNTAX_INVALID"
  | "LEDGER_EVENT_SCHEMA_INVALID"
  | "LEDGER_HASH_CHAIN_INVALID"
  | "LEDGER_HISTORY_INVALID"
  | "LEDGER_TRANSITION_INVALID";

export type RuntimeLedgerV04Issue = Readonly<{ path: string; message: string }>;

export type ValidatedRuntimeLedgerV04 = Readonly<{
  readonly __validated_runtime_ledger_v04: unique symbol;
  run_id: string;
  plan_hash: string;
  events: readonly RuntimeEventV04Value[];
  sequence: number;
  head_hash: string;
  ledger_bytes_hash: string;
  ledger_byte_length: number;
  line_byte_lengths: readonly number[];
  sealed: boolean;
  state: RuntimeStateV04;
}>;

export type RuntimeLedgerInspectionV04 =
  | Readonly<{ ok: true; ledger: ValidatedRuntimeLedgerV04; state: RuntimeStateV04 }>
  | Readonly<{ ok: false; reason: RuntimeLedgerV04FailureReason; issues: readonly RuntimeLedgerV04Issue[] }>;

export function isValidatedRuntimeLedgerV04(input: unknown): input is ValidatedRuntimeLedgerV04 {
  return typeof input === "object" && input !== null && validatedRuntimeLedgersV04.has(input);
}

function failure(
  reason: RuntimeLedgerV04FailureReason,
  path: string,
  message: string,
): Extract<RuntimeLedgerInspectionV04, { ok: false }> {
  return { ok: false, reason, issues: [{ path, message }] };
}

function refKey(sequence: number, eventHash: string): string {
  return `${sequence}\0${eventHash}`;
}

function collectLedgerRefs(
  value: unknown,
  path: string,
  refs: Array<{ sequence: number; eventHash: string; path: string }>,
): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectLedgerRefs(entry, `${path}[${index}]`, refs));
    return;
  }
  if (typeof value !== "object" || value === null) return;
  const record = value as Record<string, unknown>;
  if (Number.isSafeInteger(record.ledger_sequence) && typeof record.event_hash === "string") {
    refs.push({ sequence: record.ledger_sequence as number, eventHash: record.event_hash, path });
    return;
  }
  for (const [key, entry] of Object.entries(record)) collectLedgerRefs(entry, `${path}.${key}`, refs);
}

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

type HistoryResult =
  | Readonly<{ ok: true; state: RuntimeStateV04; runId: string; planHash: string }>
  | Extract<RuntimeLedgerInspectionV04, { ok: false }>;

function exactReferencedEvent(
  events: readonly RuntimeEventV04Value[],
  ref: Readonly<{ ledger_sequence: number; event_hash: string }>,
): RuntimeEventV04Value | null {
  const candidate = events[ref.ledger_sequence - 1];
  return candidate?.event_hash === ref.event_hash ? candidate : null;
}

function sameLedgerRef(
  left: Readonly<{ ledger_sequence: number; event_hash: string }>,
  right: Readonly<{ ledger_sequence: number; event_hash: string }>,
): boolean {
  return left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function actionFactMatches(event: RuntimeEventV04Value, actionId: string): boolean {
  const payload = event.payload as unknown as Record<string, unknown>;
  return payload.action_id === actionId && [
    "task.execution-started",
    "task.execution-completed",
    "task.execution-failed",
    "task.progress-fact-recorded",
    "task.action-outcome-unknown",
    "task.action-outcome-reconciled",
    "effect.outcome",
    "task.action-settled",
  ].includes(event.event_type);
}

function validateV04SpecificHistory(
  events: readonly RuntimeEventV04Value[],
  index: number,
): Extract<RuntimeLedgerInspectionV04, { ok: false }> | null {
  const event = events[index]!;
  const path = `event[${index}].payload`;
  if (event.event_type === "run.quarantined") {
    const previous = events[index - 1];
    const evidence = event.payload.evidence_refs[0];
    if (previous?.event_type !== "integrity.observation-rejected"
      || evidence === undefined
      || evidence.ledger_sequence !== previous.sequence
      || evidence.event_hash !== previous.event_hash
      || event.payload.reason_code !== previous.payload.reason_code) {
      return failure("LEDGER_HISTORY_INVALID", path, "Quarantine must immediately name the same-reason rejected observation.");
    }
  }
  if (event.event_type === "run.terminal-sealed") {
    const previous = events[index - 1];
    if (previous === undefined
      || event.payload.pre_seal_ledger_sequence !== previous.sequence
      || event.payload.pre_seal_ledger_head_hash !== previous.event_hash) {
      return failure("LEDGER_HISTORY_INVALID", path, "Terminal seal must immediately bind the exact pre-seal V04 prefix.");
    }
  }
  if (event.event_type === "run.paused") {
    const previous = events[index - 1];
    const request = exactReferencedEvent(events, event.payload.request_event_ref);
    if (previous?.event_type !== "run.fence-advanced"
      || request?.event_type !== "control.pause-requested"
      || event.payload.quiescent_boundary_sequence !== previous.sequence
      || event.payload.quiescent_boundary_head_hash !== previous.event_hash) {
      return failure("LEDGER_HISTORY_INVALID", path, "Pause must bind its exact request and adjacent fence boundary.");
    }
  }
  if (event.event_type === "execution.attempt-started") {
    const issuedClock = exactReferencedEvent(events, event.payload.issued_clock_ref);
    const clockAttemptRef = issuedClock?.event_type === "run.clock-observed"
      && issuedClock.payload.reason === "run-owner-acquisition"
      ? issuedClock.payload.attempt_ref
      : null;
    const clockOwnerRef = issuedClock?.event_type === "run.clock-observed"
      && issuedClock.payload.reason === "run-owner-acquisition"
      ? issuedClock.payload.owner_lease_ref
      : null;
    const resumeRequest = event.payload.resume_request_event_ref === null
      ? null
      : exactReferencedEvent(events, event.payload.resume_request_event_ref);
    const clockIsAdjacent = event.payload.attempt_ordinal === 1
      ? issuedClock?.sequence === event.sequence - 1
      : resumeRequest?.event_type === "recovery.resume-requested"
        && resumeRequest.sequence === event.sequence - 1
        && issuedClock?.sequence === resumeRequest.sequence - 1;
    if (issuedClock?.event_type !== "run.clock-observed"
      || issuedClock.payload.reason !== "run-owner-acquisition"
      || issuedClock.payload.use_ref !== event.payload.run_owner_lease_id
      || issuedClock.payload.boot_id_hash !== event.payload.boot_id_hash
      || issuedClock.payload.monotonic_clock_id !== event.payload.monotonic_clock_id
      || issuedClock.payload.elapsed_ms >= event.payload.deadline_elapsed_ms
      || clockAttemptRef !== null
      || clockOwnerRef !== null
      || !clockIsAdjacent) {
      return failure("LEDGER_HISTORY_INVALID", `${path}.issued_clock_ref`, "Attempt start must bind its exact prospective run-owner acquisition clock.");
    }
    if (event.payload.attempt_ordinal === 1) {
      const boundary = events[event.payload.source_boundary_sequence - 1];
      if (boundary?.event_type !== "run.started" || boundary.event_hash !== event.payload.source_boundary_head_hash) {
        return failure("LEDGER_HISTORY_INVALID", path, "Initial attempt must bind the exact run.started boundary.");
      }
    } else {
      const request = event.payload.resume_request_event_ref === null
        ? null
        : exactReferencedEvent(events, event.payload.resume_request_event_ref);
      const prior = event.payload.previous_attempt_event_ref === null
        ? null
        : exactReferencedEvent(events, event.payload.previous_attempt_event_ref);
      if (request?.event_type !== "recovery.resume-requested" || prior?.event_type !== "execution.attempt-started") {
        return failure("LEDGER_HISTORY_INVALID", path, "Recovery attempt must name exact prior attempt and resume request events.");
      }
      if (event.payload.repository_state_hash !== request.payload.repository_state_hash) {
        return failure("LEDGER_HISTORY_INVALID", `${path}.repository_state_hash`, "Recovery attempt must copy the pending request repository state hash exactly.");
      }
    }
  }
  if (event.event_type === "task.execution-non-entry-acknowledged") {
    const admission = exactReferencedEvent(events, event.payload.admission_ref);
    const attempt = exactReferencedEvent(events, event.payload.attempt_event_ref);
    const admissionPayload = admission?.event_type === "task.action-admitted"
      ? admission.payload as unknown as { action_id: string; task_ref: string; attempt_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>; fence_epoch: number }
      : null;
    if (admission?.event_type !== "task.action-admitted"
      || attempt?.event_type !== "execution.attempt-started"
      || admissionPayload === null
      || admissionPayload.action_id !== event.payload.action_id
      || admissionPayload.task_ref !== event.payload.task_ref
      || !sameLedgerRef(admissionPayload.attempt_event_ref, event.payload.attempt_event_ref)
      || admissionPayload.fence_epoch !== event.payload.fence_epoch) {
      return failure("LEDGER_HISTORY_INVALID", path, "Non-entry acknowledgement must bind the exact admitted action, attempt, task, and fence.");
    }
  }
  if (event.event_type === "process.termination-attempted") {
    const trigger = exactReferencedEvent(events, event.payload.trigger_event_ref);
    if ((event.payload.trigger === "abort" && trigger?.event_type !== "control.abort-requested")
      || (event.payload.trigger === "quarantine" && trigger?.event_type !== "run.quarantined")) {
      return failure("LEDGER_HISTORY_INVALID", `${path}.trigger_event_ref`, "Termination trigger must name the exact matching abort or quarantine event.");
    }
    if (event.payload.trigger === "reconciliation") {
      const acknowledgement = trigger?.event_type === "task.execution-non-entry-acknowledged" ? trigger : null;
      if (acknowledgement === null
        || !sameLedgerRef(acknowledgement.payload.admission_ref, event.payload.action_admission_event_ref)
        || acknowledgement.payload.adapter_invocation_id !== event.payload.adapter_invocation_id
        || acknowledgement.payload.host_identity_hash !== event.payload.host_identity_hash
        || acknowledgement.payload.boot_id_hash !== event.payload.boot_id_hash
        || acknowledgement.payload.unit_name_hash !== event.payload.unit_name_hash
        || acknowledgement.payload.cgroup_path_hash !== event.payload.cgroup_path_hash) {
        return failure("LEDGER_HISTORY_INVALID", `${path}.trigger_event_ref`, "Reconciliation termination must bind the exact matching non-entry acknowledgement and execution identity.");
      }
    }
  }
  if (event.event_type === "task.action-outcome-reconciled"
    && event.payload.reconciliation_status === "proven-non-start") {
    const admission = exactReferencedEvent(events, event.payload.admission_ref);
    const acknowledgement = exactReferencedEvent(events, event.payload.non_entry_ack_event_ref);
    const termination = exactReferencedEvent(events, event.payload.process_cannot_continue_ref);
    const admissionPayload = admission?.event_type === "task.action-admitted"
      ? admission.payload as unknown as { action_id: string; task_ref: string; attempt_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>; fence_epoch: number }
      : null;
    if (admission?.event_type !== "task.action-admitted"
      || acknowledgement?.event_type !== "task.execution-non-entry-acknowledged"
      || termination?.event_type !== "process.termination-attempted"
      || termination.payload.trigger !== "reconciliation"
      || !sameLedgerRef(termination.payload.trigger_event_ref, event.payload.non_entry_ack_event_ref)
      || admissionPayload === null
      || acknowledgement.sequence >= termination.sequence
      || admissionPayload.action_id !== event.payload.action_id
      || admissionPayload.task_ref !== event.payload.task_ref
      || !sameLedgerRef(admissionPayload.attempt_event_ref, event.payload.attempt_event_ref)
      || admissionPayload.fence_epoch !== event.payload.fence_epoch
      || acknowledgement.payload.action_id !== event.payload.action_id
      || acknowledgement.payload.task_ref !== event.payload.task_ref
      || !sameLedgerRef(acknowledgement.payload.admission_ref, event.payload.admission_ref)
      || !sameLedgerRef(acknowledgement.payload.attempt_event_ref, event.payload.attempt_event_ref)
      || acknowledgement.payload.adapter_invocation_id !== event.payload.adapter_invocation_id
      || acknowledgement.payload.adapter_ref !== event.payload.adapter_ref
      || acknowledgement.payload.adapter_version_hash !== event.payload.adapter_version_hash
      || acknowledgement.payload.fence_epoch !== event.payload.fence_epoch
      || !sameLedgerRef(termination.payload.action_admission_event_ref, event.payload.admission_ref)
      || termination.payload.adapter_invocation_id !== acknowledgement.payload.adapter_invocation_id
      || termination.payload.host_identity_hash !== acknowledgement.payload.host_identity_hash
      || termination.payload.boot_id_hash !== acknowledgement.payload.boot_id_hash
      || termination.payload.unit_name_hash !== acknowledgement.payload.unit_name_hash
      || termination.payload.cgroup_path_hash !== acknowledgement.payload.cgroup_path_hash
      || termination.payload.observed_outcome !== "terminated") {
      return failure("LEDGER_HISTORY_INVALID", path, "Proven non-start must bind one exact acknowledgement and later terminated process observation.");
    }
    const contradiction = events
      .slice(admission.sequence, index)
      .find((candidate) => candidate.sequence !== acknowledgement.sequence && actionFactMatches(candidate, event.payload.action_id));
    if (contradiction !== undefined) {
      return failure("LEDGER_HISTORY_INVALID", path, "Proven non-start contradicts an existing execution, result, progress, effect, reconciliation, or settlement fact.");
    }
  }
  if (event.event_type === "effect.outcome" && event.source === "integrity" && event.payload.outcome === "not-committed") {
    const reconciliation = event.payload.reconciliation_event_ref === null
      ? null
      : exactReferencedEvent(events, event.payload.reconciliation_event_ref);
    const admission = reconciliation?.event_type === "task.action-outcome-reconciled"
      && reconciliation.payload.reconciliation_status === "proven-non-start"
      ? exactReferencedEvent(events, reconciliation.payload.admission_ref)
      : null;
    const sideEffectRefs = admission?.event_type === "task.action-admitted"
      ? (admission.payload as unknown as { side_effect_refs: readonly string[] }).side_effect_refs
      : null;
    if (reconciliation?.event_type !== "task.action-outcome-reconciled"
      || reconciliation.payload.reconciliation_status !== "proven-non-start"
      || admission?.event_type !== "task.action-admitted"
      || sideEffectRefs === null
      || event.payload.action_id !== reconciliation.payload.action_id
      || event.payload.task_ref !== reconciliation.payload.task_ref
      || !sideEffectRefs.includes(event.payload.effect_ref)) {
      return failure("LEDGER_HISTORY_INVALID", path, "Integrity non-commit must bind a proven non-start reconciliation and one admitted effect.");
    }
  }
  if (event.event_type === "ownership.lease-acquired") {
    const attempt = exactReferencedEvent(events, event.payload.attempt_event_ref);
    const clock = exactReferencedEvent(events, event.payload.issued_clock_ref);
    if (attempt?.event_type !== "execution.attempt-started"
      || clock?.event_type !== "run.clock-observed"
      || clock.payload.reason !== "owner-acquisition"
      || clock.payload.use_ref !== event.payload.owner_lease_id
      || clock.payload.attempt_ref === null
      || clock.payload.owner_lease_ref === null
      || !sameLedgerRef(clock.payload.attempt_ref, event.payload.attempt_event_ref)
      || !sameLedgerRef(clock.payload.owner_lease_ref, {
        ledger_sequence: attempt.sequence,
        event_hash: attempt.event_hash,
      })
      || clock.payload.boot_id_hash !== event.payload.boot_id_hash
      || clock.payload.monotonic_clock_id !== event.payload.monotonic_clock_id) {
      return failure("LEDGER_HISTORY_INVALID", `${path}.attempt_event_ref`, "Owner lease must name an execution attempt.");
    }
  }
  if (event.event_type === "ownership.lease-heartbeat-recorded") {
    const ownerRef = event.payload.owner_lease_event_ref;
    const owner = exactReferencedEvent(events, ownerRef);
    const clock = exactReferencedEvent(events, event.payload.observation_clock_ref);
    const ownerId = owner?.event_type === "execution.attempt-started"
      ? owner.payload.run_owner_lease_id
      : owner?.event_type === "ownership.lease-acquired" ? owner.payload.owner_lease_id : null;
    const attemptRef = owner?.event_type === "execution.attempt-started"
      ? { ledger_sequence: owner.sequence, event_hash: owner.event_hash }
      : owner?.event_type === "ownership.lease-acquired" ? owner.payload.attempt_event_ref : null;
    if (ownerId === null || attemptRef === null
      || clock?.event_type !== "run.clock-observed"
      || clock.payload.reason !== "owner-heartbeat"
      || clock.payload.use_ref !== ownerId
      || !sameLedgerRef(clock.payload.attempt_ref, attemptRef)
      || !sameLedgerRef(clock.payload.owner_lease_ref, ownerRef)
      || clock.payload.boot_id_hash !== event.payload.boot_id_hash
      || clock.payload.monotonic_clock_id !== event.payload.monotonic_clock_id
      || clock.payload.elapsed_ms >= event.payload.previous_deadline_elapsed_ms) {
      return failure("LEDGER_HISTORY_INVALID", path, "Heartbeat must bind a same-domain pre-deadline owner-heartbeat clock observation.");
    }
  }
  if (event.event_type === "ownership.lease-released") {
    const ownerRef = event.payload.owner_lease_event_ref;
    const owner = exactReferencedEvent(events, ownerRef);
    const clock = exactReferencedEvent(events, event.payload.release_clock_ref);
    const ownerId = owner?.event_type === "execution.attempt-started"
      ? owner.payload.run_owner_lease_id
      : owner?.event_type === "ownership.lease-acquired" ? owner.payload.owner_lease_id : null;
    const attemptRef = owner?.event_type === "execution.attempt-started"
      ? { ledger_sequence: owner.sequence, event_hash: owner.event_hash }
      : owner?.event_type === "ownership.lease-acquired" ? owner.payload.attempt_event_ref : null;
    if (ownerId === null || attemptRef === null
      || clock?.event_type !== "run.clock-observed"
      || clock.payload.reason !== "owner-release"
      || clock.payload.use_ref !== ownerId
      || !sameLedgerRef(clock.payload.attempt_ref, attemptRef)
      || !sameLedgerRef(clock.payload.owner_lease_ref, ownerRef)) {
      return failure("LEDGER_HISTORY_INVALID", path, "Release must bind the exact owner-release clock observation.");
    }
  }
  if (event.event_type === "control.pause-requested") {
    const clock = exactReferencedEvent(events, event.payload.request_clock_ref);
    if (clock?.event_type !== "run.clock-observed"
      || clock.payload.reason !== "pause-request"
      || clock.payload.use_ref !== event.payload.request_id
      || !sameLedgerRef(clock.payload.attempt_ref, event.payload.attempt_event_ref)
      || !sameLedgerRef(clock.payload.owner_lease_ref, event.payload.run_owner_lease_ref)) {
      return failure("LEDGER_HISTORY_INVALID", path, "Pause request must bind its exact pause-request clock observation.");
    }
  }
  if (event.event_type === "recovery.resume-requested") {
    const clock = exactReferencedEvent(events, event.payload.request_clock_ref);
    if (clock?.event_type !== "run.clock-observed"
      || clock.payload.reason !== "recovery-request"
      || clock.payload.use_ref !== event.payload.request_id
      || !sameLedgerRef(clock.payload.attempt_ref, event.payload.previous_attempt_event_ref)
      || !sameLedgerRef(clock.payload.owner_lease_ref, event.payload.previous_attempt_event_ref)) {
      return failure("LEDGER_HISTORY_INVALID", path, "Recovery request must bind its exact recovery-request clock observation.");
    }
  }
  if (event.event_type === "run.compaction-recorded") {
    const first = exactReferencedEvent(events, event.payload.source_first_event_ref);
    const last = exactReferencedEvent(events, event.payload.source_last_event_ref);
    const prefix = events[event.payload.source_prefix_sequence - 1];
    if (first === null || last === null
      || first.sequence > last.sequence
      || last.sequence > event.payload.source_prefix_sequence
      || prefix?.event_hash !== event.payload.source_prefix_head_hash) {
      return failure("LEDGER_HISTORY_INVALID", path, "Compaction must bind an exact ordered source range and prefix head.");
    }
  }
  return null;
}

function validateHistory(events: readonly RuntimeEventV04Value[]): HistoryResult {
  const first = events[0];
  if (first?.event_type !== "run.initialized") {
    return failure("LEDGER_HISTORY_INVALID", "event[0]", "A V04 primary ledger must begin with run.initialized.");
  }
  const eventIds = new Set<string>();
  const earlier = new Set<string>();
  for (const [index, event] of events.entries()) {
    if (event.sequence !== index + 1) {
      return failure("LEDGER_HASH_CHAIN_INVALID", `event[${index}].sequence`, `Expected contiguous sequence ${index + 1}.`);
    }
    const expectedPrevious = index === 0 ? null : events[index - 1]!.event_hash;
    if (event.previous_event_hash !== expectedPrevious) {
      return failure("LEDGER_HASH_CHAIN_INVALID", `event[${index}].previous_event_hash`, "previous_event_hash does not match the prior event.");
    }
    const { event_hash: eventHash, ...preimage } = event;
    if (hashCanonical(preimage) !== eventHash) {
      return failure("LEDGER_HASH_CHAIN_INVALID", `event[${index}].event_hash`, "event_hash does not match the RFC 8785 event preimage.");
    }
    if (event.run_id !== first.run_id) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].run_id`, "Every event must belong to the initialized run.");
    }
    if (eventIds.has(event.event_id)) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].event_id`, "event_id must be unique in the run.");
    }
    eventIds.add(event.event_id);
    const payload = event.payload as unknown as Record<string, unknown>;
    if (typeof payload.plan_hash === "string" && payload.plan_hash !== first.payload.plan_hash) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.plan_hash`, "Copied plan_hash must equal the initialized plan.");
    }
    const refs: Array<{ sequence: number; eventHash: string; path: string }> = [];
    collectLedgerRefs(event.payload, `event[${index}].payload`, refs);
    for (const ref of refs) {
      if (ref.sequence >= event.sequence || !earlier.has(refKey(ref.sequence, ref.eventHash))) {
        return failure("LEDGER_HISTORY_INVALID", ref.path, "Ledger reference must resolve to an exact earlier V04 event.");
      }
    }
    const specific = validateV04SpecificHistory(events, index);
    if (specific !== null) return specific;
    earlier.add(refKey(event.sequence, event.event_hash));
  }
  const reduction = reduceRuntimeEventPrefixV04(events);
  if (!reduction.ok) return failure("LEDGER_TRANSITION_INVALID", reduction.path, reduction.message);
  return { ok: true, state: reduction.state, runId: first.run_id, planHash: first.payload.plan_hash };
}

function validateEvents(input: readonly unknown[]):
  | Readonly<{ ok: true; events: readonly RuntimeEventV04Value[]; state: RuntimeStateV04; runId: string; planHash: string }>
  | Extract<RuntimeLedgerInspectionV04, { ok: false }> {
  const events: RuntimeEventV04Value[] = [];
  for (const [index, value] of input.entries()) {
    const parsed = RuntimeEventV04.safeParse(value);
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
  const history = validateHistory(events);
  return history.ok
    ? { ok: true, events, state: history.state, runId: history.runId, planHash: history.planHash }
    : history;
}

function captureBytes(input: unknown): Uint8Array | null {
  try {
    if (!(input instanceof Uint8Array) || Object.getPrototypeOf(input) !== Uint8Array.prototype) return null;
    if (input.byteLength === 0 || input.byteLength > MAX_LEDGER_BYTES || input.buffer instanceof SharedArrayBuffer) return null;
    return new Uint8Array(input);
  } catch {
    return null;
  }
}

export function inspectRuntimeLedgerV04(input: unknown): RuntimeLedgerInspectionV04 {
  const bytes = captureBytes(input);
  if (bytes === null) return failure("LEDGER_SYNTAX_INVALID", "(root)", "Runtime ledger input must be an owned Uint8Array byte view.");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return failure("LEDGER_SYNTAX_INVALID", "(root)", "Runtime ledger bytes must be valid UTF-8.");
  }
  if (!text.endsWith("\n")) return failure("LEDGER_SYNTAX_INVALID", "(root)", "A bounded V04 ledger must be newline-terminated.");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.length > MAX_EVENTS
    || lines.some((line) => line.length === 0 || Buffer.byteLength(line, "utf8") > MAX_EVENT_BYTES)) {
    return failure("LEDGER_SYNTAX_INVALID", "(root)", "Every bounded JSONL line must contain exactly one event.");
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
  const parsed = validateEvents(values);
  if (!parsed.ok) return parsed;
  const frozenEvents = freezeDeep(parsed.events.map((event) => freezeDeep(event)));
  const lineByteLengths = freezeDeep(lines.map((line) => Buffer.byteLength(line, "utf8") + 1));
  const ledger = freezeDeep({
    run_id: parsed.runId,
    plan_hash: parsed.planHash,
    events: frozenEvents,
    sequence: frozenEvents.length,
    head_hash: frozenEvents.at(-1)!.event_hash,
    ledger_bytes_hash: hashRawBytes(bytes),
    ledger_byte_length: bytes.byteLength,
    line_byte_lengths: lineByteLengths,
    sealed: frozenEvents.at(-1)?.event_type === "run.terminal-sealed",
    state: parsed.state,
  }) as unknown as ValidatedRuntimeLedgerV04;
  validatedRuntimeLedgersV04.add(ledger);
  return { ok: true, ledger, state: parsed.state };
}
