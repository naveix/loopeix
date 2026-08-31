import type { RuntimeEventV04Value } from "../schema/runtime-v04.js";

type LedgerRefV04 = Readonly<{ ledger_sequence: number; event_hash: string }>;
type RuntimeAttemptModeV04 = "ordinary" | "reconciliation-only" | "compensation-continuation";

export type RuntimeRunStateV04 =
  | "initialized"
  | "running"
  | "paused"
  | "quarantine-required"
  | "quarantined"
  | "held"
  | "aborting"
  | "sealed";

export type RuntimeOwnerLeaseV04 = Readonly<{
  owner_lease_id: string;
  lease_event_ref: LedgerRefV04;
  scope: "run" | "task" | "integrator";
  scope_ref: string;
  parent_run_owner_lease_id: string | null;
  attempt_event_ref: LedgerRefV04;
  fence_epoch: number;
  deadline_elapsed_ms: number;
  boot_id_hash: string;
  monotonic_clock_id: string;
  heartbeat_ordinal: number;
  active: boolean;
  released: boolean;
}>;

export type RuntimePendingResumeRequestV04 = Readonly<{
  request_id: string;
  event_ref: LedgerRefV04;
  mode: "ordinary" | "reconciliation-only" | "compensation-continuation";
  resume_nonce_hash: string;
  previous_attempt_event_ref: LedgerRefV04;
  source_boundary_sequence: number;
  source_boundary_head_hash: string;
}>;

export type RuntimeStateV04 = Readonly<{
  state: RuntimeRunStateV04;
  started: boolean;
  abort_requested: boolean;
  terminal_freeze_entered: boolean;
  terminal_sealed: boolean;
  current_attempt_ordinal: number | null;
  current_attempt_event_ref: LedgerRefV04 | null;
  current_attempt_mode: RuntimeAttemptModeV04 | null;
  current_fence_epoch: number;
  active_run_owner: RuntimeOwnerLeaseV04 | null;
  subordinate_owner_leases: readonly RuntimeOwnerLeaseV04[];
  pending_resume_request: RuntimePendingResumeRequestV04 | null;
  consumed_resume_request_ids: readonly string[];
  consumed_resume_nonce_hashes: readonly string[];
  in_flight_action_ids: readonly string[];
}>;

export type RuntimeStateReductionResultV04 =
  | Readonly<{ ok: true; state: RuntimeStateV04 }>
  | Readonly<{ ok: false; path: string; message: string }>;

type MutableOwnerLease = {
  -readonly [K in keyof RuntimeOwnerLeaseV04]: RuntimeOwnerLeaseV04[K];
};

function fail(index: number, message: string): RuntimeStateReductionResultV04 {
  return { ok: false, path: `event[${index}]`, message };
}

function refOf(event: RuntimeEventV04Value): LedgerRefV04 {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function refKey(ref: LedgerRefV04): string {
  return `${ref.ledger_sequence}\0${ref.event_hash}`;
}

function sameRef(left: LedgerRefV04 | null, right: LedgerRefV04 | null): boolean {
  return left === null || right === null
    ? left === right
    : left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

function actionAdmissionBindings(payload: unknown): Readonly<{
  action_id: string;
  attempt_event_ref: LedgerRefV04;
  parent_run_owner_lease_id: string;
  fence_epoch: number;
}> | null {
  if (typeof payload !== "object" || payload === null) return null;
  const record = payload as Record<string, unknown>;
  const attemptRef = record.attempt_event_ref;
  if (typeof record.action_id !== "string"
    || typeof record.parent_run_owner_lease_id !== "string"
    || !Number.isSafeInteger(record.fence_epoch)
    || typeof attemptRef !== "object"
    || attemptRef === null) return null;
  const refRecord = attemptRef as Record<string, unknown>;
  if (!Number.isSafeInteger(refRecord.ledger_sequence) || typeof refRecord.event_hash !== "string") return null;
  return {
    action_id: record.action_id,
    attempt_event_ref: {
      ledger_sequence: refRecord.ledger_sequence as number,
      event_hash: refRecord.event_hash,
    },
    parent_run_owner_lease_id: record.parent_run_owner_lease_id,
    fence_epoch: record.fence_epoch as number,
  };
}

function compensationAdmissionBindings(payload: unknown): Readonly<{
  action_id: string;
  lease_event_ref: LedgerRefV04;
}> | null {
  if (typeof payload !== "object" || payload === null) return null;
  const record = payload as Record<string, unknown>;
  const leaseRef = record.lease_event_ref;
  if (typeof record.action_id !== "string" || typeof leaseRef !== "object" || leaseRef === null) return null;
  const refRecord = leaseRef as Record<string, unknown>;
  if (!Number.isSafeInteger(refRecord.ledger_sequence) || typeof refRecord.event_hash !== "string") return null;
  return {
    action_id: record.action_id,
    lease_event_ref: {
      ledger_sequence: refRecord.ledger_sequence as number,
      event_hash: refRecord.event_hash,
    },
  };
}

const RESTRICTED_SHARED_EVENT_TYPES = new Set<RuntimeEventV04Value["event_type"]>([
  "run.clock-observed",
  "control.pause-requested",
  "control.abort-requested",
  "run.fence-advanced",
  "run.paused",
  "integrity.observation-rejected",
  "run.quarantined",
  "authority.grant-revoked",
  "ownership.lease-heartbeat-recorded",
  "ownership.lease-released",
  "run.terminal-freeze-entered",
  "run.terminal-freeze-revised",
  "run.compensation-requested",
  "run.compensation-request-revised",
  "run.compensation-candidate-escalated",
  "run.terminal-sealed",
  "recovery.resume-requested",
  "execution.attempt-started",
]);

const RECONCILIATION_EVIDENCE_EVENT_TYPES = new Set<RuntimeEventV04Value["event_type"]>([
  "evidence.recorded",
  "observation.manual-recorded",
  "claim.recorded",
  "finding.recorded",
  "process.termination-attempted",
  "task.execution-non-entry-acknowledged",
  "task.action-outcome-reconciled",
  "effect.outcome",
  "task.action-settled",
]);

const COMPENSATION_VERIFICATION_EVENT_TYPES = new Set<RuntimeEventV04Value["event_type"]>([
  "gate.result-required",
  "gate.result-recorded",
  "evaluation.result-required",
  "evaluation.result-recorded",
  "evidence.recorded",
  "observation.manual-recorded",
  "claim.recorded",
  "finding.recorded",
  "waiver.recorded",
  "record.redaction-derivative-recorded",
  "record.custody-state-recorded",
  "record.export-decision-recorded",
  "run.compensation-phase-entered",
  "compensation.settled",
  "ownership.lease-acquired",
]);

function restrictedAttemptModeViolation(
  mode: RuntimeAttemptModeV04,
  event: RuntimeEventV04Value,
  compensationLeaseRefs: ReadonlySet<string>,
  compensationActionIds: ReadonlySet<string>,
  compensationAdmissionRefs: ReadonlySet<string>,
): string | null {
  if (mode === "ordinary" || RESTRICTED_SHARED_EVENT_TYPES.has(event.event_type)) return null;
  if (mode === "reconciliation-only") {
    if (RECONCILIATION_EVIDENCE_EVENT_TYPES.has(event.event_type)) return null;
    if (event.event_type === "compensation.settled" && event.payload.status === "unable") return null;
    return `Event ${event.event_type} is not permitted in a reconciliation-only attempt.`;
  }
  if (COMPENSATION_VERIFICATION_EVENT_TYPES.has(event.event_type)) return null;
  if (event.event_type === "approval.recommendation-recorded") {
    return event.payload.phase === "compensation"
      ? null
      : "A compensation-continuation recommendation must be compensation-scoped.";
  }
  if (event.event_type === "policy.decision-recorded") {
    return event.payload.phase === "compensation"
      ? null
      : "A compensation-continuation policy decision must be compensation-scoped.";
  }
  if (event.event_type === "lease.issued") {
    return event.payload.phase === "compensation"
      ? null
      : "A compensation-continuation lease must be compensation-scoped.";
  }
  if (event.event_type === "limit.admission-blocked") {
    return event.payload.phase === "compensation"
      ? null
      : "A compensation-continuation admission refusal must be compensation-scoped.";
  }
  if (event.event_type === "task.action-admitted") {
    const admission = compensationAdmissionBindings(event.payload);
    return admission !== null && compensationLeaseRefs.has(refKey(admission.lease_event_ref))
      ? null
      : "A compensation-continuation action admission must name a compensation lease.";
  }
  if (event.event_type === "artifact.recorded") {
    return compensationActionIds.has(event.payload.producer_action_id)
      ? null
      : "An artifact in compensation-continuation must be produced by a compensation action.";
  }
  if (event.event_type === "process.termination-attempted") {
    return compensationAdmissionRefs.has(refKey(event.payload.action_admission_event_ref))
      ? null
      : "A termination observation in compensation-continuation must name a compensation action admission.";
  }
  if (event.event_type === "tool.call-admitted" || event.event_type === "artifact.write-admitted"
    || event.event_type === "task.execution-started" || event.event_type === "task.execution-completed"
    || event.event_type === "task.execution-failed" || event.event_type === "task.action-outcome-unknown"
    || event.event_type === "task.execution-non-entry-acknowledged"
    || event.event_type === "task.action-outcome-reconciled" || event.event_type === "effect.outcome"
    || event.event_type === "task.action-settled") {
    return compensationActionIds.has(event.payload.action_id)
      ? null
      : `Event ${event.event_type} is not scoped to a compensation action.`;
  }
  return `Event ${event.event_type} is not permitted in a compensation-continuation attempt.`;
}

export function reduceRuntimeEventPrefixV04(
  events: readonly RuntimeEventV04Value[],
): RuntimeStateReductionResultV04 {
  let state: RuntimeRunStateV04 = "initialized";
  let started = false;
  let abortRequested = false;
  let terminalFreezeEntered = false;
  let terminalSealed = false;
  let currentAttemptOrdinal: number | null = null;
  let currentAttemptEventRef: LedgerRefV04 | null = null;
  let currentAttemptMode: RuntimeAttemptModeV04 | null = null;
  let currentFenceEpoch = 0;
  let activeRunOwner: MutableOwnerLease | null = null;
  let pendingResumeRequest: RuntimePendingResumeRequestV04 | null = null;
  let pendingPauseRequestRef: LedgerRefV04 | null = null;
  let lastFencePreviousEpoch: number | null = null;
  let lastFenceOwnerRefs: readonly LedgerRefV04[] = [];
  const subordinateLeases = new Map<string, MutableOwnerLease>();
  const leasesByEventRef = new Map<string, MutableOwnerLease>();
  const consumedRequestIds = new Set<string>();
  const consumedNonces = new Set<string>();
  const seenRequestIds = new Set<string>();
  const seenNonces = new Set<string>();
  const inFlight = new Set<string>();
  const compensationLeaseRefs = new Set<string>();
  const compensationActionIds = new Set<string>();
  const compensationAdmissionRefs = new Set<string>();
  const byRef = new Map<string, RuntimeEventV04Value>();
  const admissionsByAction = new Map<string, Extract<RuntimeEventV04Value, { event_type: "task.action-admitted" }>>();
  const nonEntryAcknowledgements = new Map<string, Extract<RuntimeEventV04Value, { event_type: "task.execution-non-entry-acknowledged" }>>();
  const contradictoryActionFacts = new Set<string>();
  const provenNonStartByAction = new Map<string, Extract<RuntimeEventV04Value, { event_type: "task.action-outcome-reconciled" }>>();
  let runStartedRef: LedgerRefV04 | null = null;

  for (const [index, event] of events.entries()) {
    const eventRef = refOf(event);
    if (index === 0) {
      if (event.event_type !== "run.initialized") return fail(index, "A V04 ledger must begin with run.initialized.");
      currentFenceEpoch = event.payload.initial_fence_epoch;
      byRef.set(refKey(eventRef), event);
      continue;
    }
    if (state === "sealed") return fail(index, "No event may follow a terminal seal.");
    if (state === "quarantine-required" && event.event_type !== "run.quarantined") {
      return fail(index, "integrity.observation-rejected must be followed immediately by its exact quarantine event.");
    }
    if (pendingResumeRequest !== null && [
      "lease.issued",
      "task.action-admitted",
      "tool.call-admitted",
      "artifact.write-admitted",
      "task.execution-started",
      "task.execution-completed",
      "task.progress-fact-recorded",
      "task.execution-failed",
      "artifact.recorded",
      "loop.attempt-completed",
      "task.progress-observed",
      "run.compaction-recorded",
      "run.compensation-phase-entered",
    ].includes(event.event_type)) {
      return fail(index, "No work event is permitted while a recovery request remains pending.");
    }
    if (currentAttemptMode !== null) {
      const violation = restrictedAttemptModeViolation(
        currentAttemptMode,
        event,
        compensationLeaseRefs,
        compensationActionIds,
        compensationAdmissionRefs,
      );
      if (violation !== null) return fail(index, violation);
    }

    switch (event.event_type) {
      case "run.initialized":
        return fail(index, "run.initialized may appear only once at sequence 1.");
      case "run.started":
        if (started || state !== "initialized") return fail(index, "run.started requires one initialized run.");
        started = true;
        state = "running";
        runStartedRef = eventRef;
        break;
      case "recovery.resume-requested": {
        if (currentAttemptEventRef === null || pendingResumeRequest !== null) {
          return fail(index, "A recovery request requires one current attempt and no pending recovery request.");
        }
        if (!sameRef(event.payload.previous_attempt_event_ref, currentAttemptEventRef)) {
          return fail(index, "Recovery request must name the exact current attempt.");
        }
        if (seenRequestIds.has(event.payload.request_id) || seenNonces.has(event.payload.resume_nonce_hash)) {
          return fail(index, "Recovery request IDs and nonces must be run-wide unique.");
        }
        seenRequestIds.add(event.payload.request_id);
        seenNonces.add(event.payload.resume_nonce_hash);
        pendingResumeRequest = freezeDeep({
          request_id: event.payload.request_id,
          event_ref: eventRef,
          mode: event.payload.mode,
          resume_nonce_hash: event.payload.resume_nonce_hash,
          previous_attempt_event_ref: event.payload.previous_attempt_event_ref,
          source_boundary_sequence: event.payload.source_boundary_sequence,
          source_boundary_head_hash: event.payload.source_boundary_head_hash,
        });
        break;
      }
      case "execution.attempt-started": {
        const payload = event.payload;
        if (!started) return fail(index, "An execution attempt requires run.started.");
        if (currentAttemptOrdinal === null) {
          if (payload.attempt_ordinal !== 1
            || payload.previous_attempt_event_ref !== null
            || payload.resume_request_event_ref !== null
            || payload.resume_nonce_hash !== null
            || payload.previous_fence_epoch !== 0
            || payload.fence_epoch !== 0
            || runStartedRef === null
            || payload.source_boundary_sequence !== runStartedRef.ledger_sequence
            || payload.source_boundary_head_hash !== runStartedRef.event_hash) {
            return fail(index, "Initial attempt must bind ordinal one, fence zero, and the exact run.started boundary.");
          }
        } else {
          const pending = pendingResumeRequest;
          if (pending === null) return fail(index, "A recovery attempt requires one pending recovery request.");
          if (payload.attempt_ordinal !== currentAttemptOrdinal + 1) return fail(index, "Recovery attempt ordinal must advance exactly once.");
          if (!sameRef(payload.previous_attempt_event_ref, currentAttemptEventRef)
            || !sameRef(payload.resume_request_event_ref, pending.event_ref)
            || payload.resume_nonce_hash !== pending.resume_nonce_hash
            || payload.source_boundary_sequence !== pending.source_boundary_sequence
            || payload.source_boundary_head_hash !== pending.source_boundary_head_hash) {
            return fail(index, "Recovery attempt must consume the exact pending request and durable boundary.");
          }
          if (payload.previous_fence_epoch !== currentFenceEpoch
            || currentFenceEpoch >= Number.MAX_SAFE_INTEGER
            || payload.fence_epoch !== currentFenceEpoch + 1) {
            return fail(index, "Recovery attempt fence must advance exactly once.");
          }
          consumedRequestIds.add(pending.request_id);
          consumedNonces.add(pending.resume_nonce_hash);
          pendingResumeRequest = null;
          if (activeRunOwner !== null) activeRunOwner.active = false;
          for (const lease of subordinateLeases.values()) lease.active = false;
        }
        currentAttemptOrdinal = payload.attempt_ordinal;
        currentAttemptEventRef = eventRef;
        currentAttemptMode = payload.mode;
        compensationLeaseRefs.clear();
        compensationActionIds.clear();
        compensationAdmissionRefs.clear();
        currentFenceEpoch = payload.fence_epoch;
        activeRunOwner = {
          owner_lease_id: payload.run_owner_lease_id,
          lease_event_ref: eventRef,
          scope: "run",
          scope_ref: event.run_id,
          parent_run_owner_lease_id: null,
          attempt_event_ref: eventRef,
          fence_epoch: payload.fence_epoch,
          deadline_elapsed_ms: payload.deadline_elapsed_ms,
          boot_id_hash: payload.boot_id_hash,
          monotonic_clock_id: payload.monotonic_clock_id,
          heartbeat_ordinal: 0,
          active: true,
          released: false,
        };
        leasesByEventRef.set(refKey(eventRef), activeRunOwner);
        state = "running";
        break;
      }
      case "ownership.lease-acquired": {
        if (pendingResumeRequest !== null) return fail(index, "No work is admitted while a pending recovery request exists.");
        if (state !== "running" || activeRunOwner === null || !activeRunOwner.active || currentAttemptEventRef === null) {
          return fail(index, "A subordinate owner lease requires one active run owner.");
        }
        const payload = event.payload;
        if (payload.parent_run_owner_lease_id !== activeRunOwner.owner_lease_id
          || !sameRef(payload.attempt_event_ref, currentAttemptEventRef)
          || payload.fence_epoch !== currentFenceEpoch
          || payload.boot_id_hash !== activeRunOwner.boot_id_hash
          || payload.monotonic_clock_id !== activeRunOwner.monotonic_clock_id
          || payload.deadline_elapsed_ms > activeRunOwner.deadline_elapsed_ms) {
          return fail(index, "Subordinate owner lease must bind the active attempt, parent, fence, domain, and deadline.");
        }
        if (subordinateLeases.has(payload.owner_lease_id)) return fail(index, "Owner lease IDs must be unique.");
        const lease: MutableOwnerLease = {
          owner_lease_id: payload.owner_lease_id,
          lease_event_ref: eventRef,
          scope: payload.scope,
          scope_ref: payload.scope_ref,
          parent_run_owner_lease_id: payload.parent_run_owner_lease_id,
          attempt_event_ref: payload.attempt_event_ref,
          fence_epoch: payload.fence_epoch,
          deadline_elapsed_ms: payload.deadline_elapsed_ms,
          boot_id_hash: payload.boot_id_hash,
          monotonic_clock_id: payload.monotonic_clock_id,
          heartbeat_ordinal: 0,
          active: true,
          released: false,
        };
        subordinateLeases.set(payload.owner_lease_id, lease);
        leasesByEventRef.set(refKey(eventRef), lease);
        break;
      }
      case "ownership.lease-heartbeat-recorded": {
        const lease = leasesByEventRef.get(refKey(event.payload.owner_lease_event_ref));
        if (lease === undefined || !lease.active || lease.released) return fail(index, "Heartbeat requires the exact active owner lease.");
        if (event.payload.fence_epoch !== currentFenceEpoch
          || lease.fence_epoch !== currentFenceEpoch
          || event.payload.boot_id_hash !== lease.boot_id_hash
          || event.payload.monotonic_clock_id !== lease.monotonic_clock_id
          || event.payload.heartbeat_ordinal !== lease.heartbeat_ordinal + 1
          || event.payload.previous_deadline_elapsed_ms !== lease.deadline_elapsed_ms
          || event.payload.deadline_elapsed_ms <= lease.deadline_elapsed_ms) {
          return fail(index, "Heartbeat must extend the exact current lease in its fence and clock domain.");
        }
        lease.heartbeat_ordinal = event.payload.heartbeat_ordinal;
        lease.deadline_elapsed_ms = event.payload.deadline_elapsed_ms;
        break;
      }
      case "ownership.lease-released": {
        const lease = leasesByEventRef.get(refKey(event.payload.owner_lease_event_ref));
        if (lease === undefined || !lease.active || lease.released) return fail(index, "Release requires the exact active owner lease.");
        if (event.payload.fence_epoch !== currentFenceEpoch) return fail(index, "Release fence must equal the current fence.");
        lease.active = false;
        lease.released = true;
        break;
      }
      case "control.pause-requested":
        if (currentAttemptEventRef === null || activeRunOwner === null || !activeRunOwner.active
          || !sameRef(event.payload.attempt_event_ref, currentAttemptEventRef)
          || !sameRef(event.payload.run_owner_lease_ref, activeRunOwner.lease_event_ref)
          || event.payload.fence_epoch !== currentFenceEpoch) {
          return fail(index, "Pause request must bind the active attempt, run owner, and fence.");
        }
        pendingPauseRequestRef = eventRef;
        break;
      case "run.fence-advanced":
        if (currentAttemptEventRef === null
          || !sameRef(event.payload.attempt_ref, currentAttemptEventRef)
          || event.payload.previous_fence_epoch !== currentFenceEpoch
          || currentFenceEpoch >= Number.MAX_SAFE_INTEGER
          || event.payload.fence_epoch !== currentFenceEpoch + 1) {
          return fail(index, "Fence advance must bind the current attempt and advance exactly once.");
        }
        lastFencePreviousEpoch = currentFenceEpoch;
        lastFenceOwnerRefs = event.payload.owner_lease_refs;
        currentFenceEpoch = event.payload.fence_epoch;
        for (const ownerRef of event.payload.owner_lease_refs) {
          const lease = leasesByEventRef.get(refKey(ownerRef));
          if (lease === undefined || !lease.active) return fail(index, "Fence advance must invalidate exact active owner leases.");
          lease.active = false;
        }
        break;
      case "task.action-admitted": {
        const admission = actionAdmissionBindings(event.payload);
        if (admission === null) return fail(index, "Action admission payload bindings are invalid.");
        if (pendingResumeRequest !== null) return fail(index, "No action is admitted while a pending recovery request exists.");
        if (state !== "running" || currentAttemptEventRef === null || activeRunOwner === null || !activeRunOwner.active
          || !sameRef(admission.attempt_event_ref, currentAttemptEventRef)
          || admission.parent_run_owner_lease_id !== activeRunOwner.owner_lease_id
          || admission.fence_epoch !== currentFenceEpoch) {
          return fail(index, "Action admission requires the active attempt, run owner, and fence.");
        }
        if (inFlight.has(admission.action_id)) return fail(index, "An action may enter in-flight state only once.");
        inFlight.add(admission.action_id);
        admissionsByAction.set(admission.action_id, event);
        break;
      }
      case "task.execution-non-entry-acknowledged": {
        const admission = admissionsByAction.get(event.payload.action_id);
        const admissionPayload = admission?.payload as unknown as {
          task_ref: string; attempt_event_ref: LedgerRefV04; fence_epoch: number;
        } | undefined;
        if (admission === undefined
          || nonEntryAcknowledgements.has(event.payload.action_id)
          || admissionPayload === undefined
          || !sameRef(event.payload.admission_ref, refOf(admission))
          || admissionPayload.task_ref !== event.payload.task_ref
          || !sameRef(admissionPayload.attempt_event_ref, event.payload.attempt_event_ref)
          || admissionPayload.fence_epoch !== event.payload.fence_epoch
          || contradictoryActionFacts.has(event.payload.action_id)) {
          return fail(index, "Non-entry acknowledgement must bind one contradiction-free admitted action, attempt, task, and fence.");
        }
        nonEntryAcknowledgements.set(event.payload.action_id, event);
        break;
      }
      case "process.termination-attempted": {
        const trigger = byRef.get(refKey(event.payload.trigger_event_ref));
        if ((event.payload.trigger === "abort" && trigger?.event_type !== "control.abort-requested")
          || (event.payload.trigger === "quarantine" && trigger?.event_type !== "run.quarantined")) {
          return fail(index, "Termination trigger must name the exact matching abort or quarantine event.");
        }
        if (event.payload.trigger === "reconciliation") {
          if (trigger?.event_type !== "task.execution-non-entry-acknowledged"
            || !sameRef(trigger.payload.admission_ref, event.payload.action_admission_event_ref)
            || trigger.payload.adapter_invocation_id !== event.payload.adapter_invocation_id
            || trigger.payload.host_identity_hash !== event.payload.host_identity_hash
            || trigger.payload.boot_id_hash !== event.payload.boot_id_hash
            || trigger.payload.unit_name_hash !== event.payload.unit_name_hash
            || trigger.payload.cgroup_path_hash !== event.payload.cgroup_path_hash) {
            return fail(index, "Reconciliation termination must bind the exact matching non-entry acknowledgement and execution identity.");
          }
        }
        break;
      }
      case "task.action-outcome-reconciled": {
        if (event.payload.reconciliation_status === "outcome-remains-unknown") {
          contradictoryActionFacts.add(event.payload.action_id);
          break;
        }
        const admission = admissionsByAction.get(event.payload.action_id);
        const admissionPayload = admission?.payload as unknown as {
          task_ref: string; attempt_event_ref: LedgerRefV04; fence_epoch: number;
        } | undefined;
        const acknowledgement = byRef.get(refKey(event.payload.non_entry_ack_event_ref));
        const termination = byRef.get(refKey(event.payload.process_cannot_continue_ref));
        if (admission === undefined
          || acknowledgement?.event_type !== "task.execution-non-entry-acknowledged"
          || termination?.event_type !== "process.termination-attempted"
          || termination.payload.trigger !== "reconciliation"
          || !sameRef(termination.payload.trigger_event_ref, event.payload.non_entry_ack_event_ref)
          || admissionPayload === undefined
          || acknowledgement.sequence >= termination.sequence
          || !sameRef(event.payload.admission_ref, refOf(admission))
          || admissionPayload.task_ref !== event.payload.task_ref
          || !sameRef(admissionPayload.attempt_event_ref, event.payload.attempt_event_ref)
          || admissionPayload.fence_epoch !== event.payload.fence_epoch
          || acknowledgement.payload.action_id !== event.payload.action_id
          || acknowledgement.payload.task_ref !== event.payload.task_ref
          || !sameRef(acknowledgement.payload.admission_ref, event.payload.admission_ref)
          || !sameRef(acknowledgement.payload.attempt_event_ref, event.payload.attempt_event_ref)
          || acknowledgement.payload.adapter_invocation_id !== event.payload.adapter_invocation_id
          || acknowledgement.payload.adapter_ref !== event.payload.adapter_ref
          || acknowledgement.payload.adapter_version_hash !== event.payload.adapter_version_hash
          || acknowledgement.payload.fence_epoch !== event.payload.fence_epoch
          || !sameRef(termination.payload.action_admission_event_ref, event.payload.admission_ref)
          || termination.payload.adapter_invocation_id !== acknowledgement.payload.adapter_invocation_id
          || termination.payload.host_identity_hash !== acknowledgement.payload.host_identity_hash
          || termination.payload.boot_id_hash !== acknowledgement.payload.boot_id_hash
          || termination.payload.unit_name_hash !== acknowledgement.payload.unit_name_hash
          || termination.payload.cgroup_path_hash !== acknowledgement.payload.cgroup_path_hash
          || termination.payload.observed_outcome !== "terminated"
          || contradictoryActionFacts.has(event.payload.action_id)) {
          return fail(index, "Proven non-start contradicts prior facts or lacks an exact acknowledgement and later terminated process observation.");
        }
        provenNonStartByAction.set(event.payload.action_id, event);
        break;
      }
      case "task.execution-started":
      case "task.execution-completed":
      case "task.execution-failed":
      case "task.progress-fact-recorded":
      case "task.action-outcome-unknown":
        contradictoryActionFacts.add(event.payload.action_id);
        break;
      case "effect.outcome": {
        const proven = provenNonStartByAction.get(event.payload.action_id);
        if (proven === undefined) {
          contradictoryActionFacts.add(event.payload.action_id);
          break;
        }
        const admission = admissionsByAction.get(event.payload.action_id);
        const sideEffectRefs = admission?.payload === undefined
          ? null
          : (admission.payload as unknown as { side_effect_refs: readonly string[] }).side_effect_refs;
        if (event.source !== "integrity"
          || event.payload.outcome !== "not-committed"
          || event.payload.reconciliation_event_ref === null
          || !sameRef(event.payload.reconciliation_event_ref, refOf(proven))
          || event.payload.task_ref !== proven.payload.task_ref
          || admission === undefined
          || sideEffectRefs === null
          || !sideEffectRefs.includes(event.payload.effect_ref)) {
          return fail(index, "Proven non-start effects must be integrity-authored non-commits bound to the exact reconciliation.");
        }
        break;
      }
      case "task.action-settled": {
        const proven = provenNonStartByAction.get(event.payload.action_id);
        if (proven !== undefined) {
          const admission = admissionsByAction.get(event.payload.action_id);
          const sideEffectRefs = admission?.payload === undefined
            ? null
            : (admission.payload as unknown as { side_effect_refs: readonly string[] }).side_effect_refs;
          const effectRefs = new Set<string>();
          for (const outcome of event.payload.effect_outcomes) {
            const outcomeEvent = byRef.get(refKey(outcome.outcome_event_ref));
            if (outcome.outcome !== "not-committed"
              || outcomeEvent?.event_type !== "effect.outcome"
              || outcomeEvent.source !== "integrity"
              || outcomeEvent.payload.reconciliation_event_ref === null
              || !sameRef(outcomeEvent.payload.reconciliation_event_ref, refOf(proven))) {
              return fail(index, "Proven non-start settlement must bind only its exact integrity non-commit effects.");
            }
            effectRefs.add(outcome.effect_ref);
          }
          if (admission === undefined
            || sideEffectRefs === null
            || !sameRef(event.payload.terminal_event_ref, refOf(proven))
            || event.payload.task_ref !== proven.payload.task_ref
            || effectRefs.size !== sideEffectRefs.length
            || sideEffectRefs.some((effectRef: string) => !effectRefs.has(effectRef))) {
            return fail(index, "Proven non-start settlement must close the exact action and every admitted effect.");
          }
        }
        if (!inFlight.delete(event.payload.action_id)) return fail(index, "Action settlement requires an in-flight action.");
        break;
      }
      case "run.paused":
        if (state !== "running" || inFlight.size !== 0) return fail(index, "run.paused requires a running quiescent boundary.");
        if (pendingPauseRequestRef === null
          || !sameRef(event.payload.request_event_ref, pendingPauseRequestRef)
          || !sameRef(event.payload.attempt_event_ref, currentAttemptEventRef)
          || lastFencePreviousEpoch !== event.payload.previous_fence_epoch
          || event.payload.fence_epoch !== currentFenceEpoch
          || event.payload.quiescent_boundary_sequence !== event.sequence - 1
          || event.payload.quiescent_boundary_head_hash !== event.previous_event_hash
          || event.payload.invalidated_owner_lease_refs.length !== lastFenceOwnerRefs.length
          || event.payload.invalidated_owner_lease_refs.some((ref, refIndex) => !sameRef(ref, lastFenceOwnerRefs[refIndex] ?? null))) {
          return fail(index, "run.paused must bind its exact request, fence, boundary, and invalidated owners.");
        }
        state = "paused";
        pendingPauseRequestRef = null;
        break;
      case "integrity.observation-rejected":
        if (!started || (state !== "running" && state !== "paused")) return fail(index, "Rejected observation requires a started active run.");
        state = "quarantine-required";
        break;
      case "run.quarantined":
        if (state !== "quarantine-required") return fail(index, "run.quarantined requires the adjacent rejected observation.");
        state = "quarantined";
        break;
      case "authority.grant-revoked":
        if (state !== "aborting" && state !== "quarantined") state = "held";
        break;
      case "control.abort-requested":
        abortRequested = true;
        if (state !== "quarantined") state = "aborting";
        break;
      case "run.terminal-freeze-entered":
      case "run.terminal-freeze-revised":
        terminalFreezeEntered = true;
        break;
      case "run.terminal-sealed":
        if (!terminalFreezeEntered) return fail(index, "Terminal seal requires a preceding terminal freeze.");
        if (inFlight.size !== 0) return fail(index, "Terminal seal requires no unresolved in-flight action.");
        if (event.payload.previous_fence_epoch !== currentFenceEpoch
          || currentFenceEpoch >= Number.MAX_SAFE_INTEGER
          || event.payload.fence_epoch !== currentFenceEpoch + 1) {
          return fail(index, "Terminal seal must advance the current fence exactly once.");
        }
        currentFenceEpoch = event.payload.fence_epoch;
        if (activeRunOwner !== null) activeRunOwner.active = false;
        for (const lease of subordinateLeases.values()) lease.active = false;
        terminalSealed = true;
        state = "sealed";
        break;
      default:
        break;
    }
    if (currentAttemptMode === "compensation-continuation") {
      if (event.event_type === "lease.issued" && event.payload.phase === "compensation") {
        compensationLeaseRefs.add(refKey(eventRef));
      } else if (event.event_type === "task.action-admitted") {
        const admission = compensationAdmissionBindings(event.payload);
        if (admission !== null) {
          compensationActionIds.add(admission.action_id);
          compensationAdmissionRefs.add(refKey(eventRef));
        }
      }
    }
    byRef.set(refKey(eventRef), event);
  }

  const output: RuntimeStateV04 = {
    state,
    started,
    abort_requested: abortRequested,
    terminal_freeze_entered: terminalFreezeEntered,
    terminal_sealed: terminalSealed,
    current_attempt_ordinal: currentAttemptOrdinal,
    current_attempt_event_ref: currentAttemptEventRef,
    current_attempt_mode: currentAttemptMode,
    current_fence_epoch: currentFenceEpoch,
    active_run_owner: activeRunOwner,
    subordinate_owner_leases: [...subordinateLeases.values()].sort((left, right) => left.owner_lease_id.localeCompare(right.owner_lease_id)),
    pending_resume_request: pendingResumeRequest,
    consumed_resume_request_ids: [...consumedRequestIds].sort(),
    consumed_resume_nonce_hashes: [...consumedNonces].sort(),
    in_flight_action_ids: [...inFlight].sort(),
  };
  return { ok: true, state: freezeDeep(output) };
}
