import { z } from "zod";

import { LedgerRefV02 } from "../schema/runtime.js";
import {
  isValidatedRuntimePlanV03,
  type ValidatedRuntimePlanV03,
} from "./project-plan-v03.js";
import {
  inspectCapturedRuntimeRecoveryRequestV04,
  RuntimeRecoveryRequestIntentV04,
  type RuntimeRecoveryRequestIntentV04Value,
} from "./runtime-recovery-authorization-v04.js";
import {
  evaluateRuntimeLimitAccountingV04,
  projectRuntimeLimitCountersV04,
  type RuntimeLimitAccountingValueV04,
  type RuntimeLimitCountersV04Value,
} from "./runtime-limit-accounting-v04.js";
import type { ValidatedRuntimeLedgerV04 } from "./runtime-ledger-v04.js";
import {
  isValidatedRunManifestPairV04,
  type ValidatedRunManifestV04,
} from "./runtime-manifest-v04.js";
import {
  validateRuntimeSummaryForRecoveryV04,
  type ValidatedSummaryArtifactV01,
} from "./runtime-summary-v04.js";

const nonNegativeSafeInteger = z.number().int().nonnegative().refine(Number.isSafeInteger);
const positiveSafeInteger = nonNegativeSafeInteger.positive();

const OwnerStatusV04 = z.discriminatedUnion("status", [
  z.object({
    status: z.literal("absent"),
    evidence_refs: z.tuple([]),
  }).strict(),
  z.object({
    status: z.literal("current"),
    owner_lease_event_ref: LedgerRefV02,
    evidence_refs: z.array(LedgerRefV02).min(1),
  }).strict(),
  z.object({
    status: z.literal("ambiguous"),
    ambiguous_reason: z.enum([
      "heartbeat-at-deadline",
      "same-boot-clock-mismatch",
      "cross-boot-process-proof-missing",
      "stale-owner-proof-missing",
    ]),
    owner_lease_event_ref: LedgerRefV02,
    evidence_refs: z.array(LedgerRefV02).min(1),
  }).strict(),
  z.object({
    status: z.literal("proven-stale"),
    stale_reason: z.enum([
      "same-domain-deadline-reached",
      "cross-boot-process-cannot-continue",
    ]),
    owner_lease_event_ref: LedgerRefV02,
    evidence_refs: z.array(LedgerRefV02).min(1),
  }).strict(),
]);

export type RuntimeRecoveryModeV04 =
  | "ordinary"
  | "reconciliation-only"
  | "compensation-continuation";

export type RuntimeRecoveryRefusalReasonV04 =
  | "run-terminal-sealed"
  | "post-seal-source"
  | "run-quarantined"
  | "owner-current"
  | "owner-ambiguous"
  | "owner-unproven-stale"
  | "pending-resume-request"
  | "resume-fence-mismatch"
  | "resume-request-id-reused"
  | "resume-nonce-reused"
  | "double-resume"
  | "plan-hash-drift"
  | "input-hash-drift"
  | "recovery-policy-hash-drift"
  | "authority-envelope-hash-drift"
  | "repository-boundary-drift"
  | "summary-lineage-drift"
  | "execution-attempts-exhausted"
  | "elapsed-budget-exhausted"
  | "process-runtime-exhausted"
  | "output-budget-exhausted"
  | "worker-budget-exhausted"
  | "token-budget-exhausted"
  | "cost-budget-exhausted"
  | "no-eligible-durable-boundary"
  | "ordinary-blocked-by-unresolved-action"
  | "compensation-blocked-by-unresolved-action"
  | "reconciliation-target-required"
  | "reconciliation-target-mismatch"
  | "reconciliation-proof-not-authorized"
  | "compensation-boundary-mismatch";

export type RuntimeRecoveryResumeBoundaryV04 = Readonly<{
  source_boundary_sequence: number;
  source_boundary_head_hash: string;
  source_manifest_hash: string;
  attempt_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  fence_epoch: number;
}>;

export type RuntimeRecoveryRequestProjectionV04 = Readonly<{
  request_id: string;
  mode: RuntimeRecoveryModeV04;
  resume_nonce_hash: string;
  previous_attempt_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  source_boundary_sequence: number;
  source_boundary_head_hash: string;
  source_manifest_hash: string;
  plan_hash: string;
  input_hash: string;
  recovery_policy_hash: string;
  authority_envelope_hash: string;
  repository_state_hash: string;
  target_action_admission_ref: Readonly<{ ledger_sequence: number; event_hash: string }> | null;
  compensation_phase_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }> | null;
}>;

export type RuntimeRecoveryEligibilityDecisionV04 = Readonly<{
  disposition: "eligible";
  mode: RuntimeRecoveryModeV04;
  resume_boundary: RuntimeRecoveryResumeBoundaryV04;
  request_projection: RuntimeRecoveryRequestProjectionV04;
  next_attempt_ordinal: number;
  next_fence_epoch: number;
  counters: RuntimeLimitCountersV04Value;
  limit_projection: RuntimeLimitAccountingValueV04;
  validated_summary: ValidatedSummaryArtifactV01 | null;
}>;

export type RuntimeRecoveryRefusalDecisionV04 = Readonly<{
  disposition: "refused";
  precedence: 2 | 3 | 4 | 5 | 6 | 7;
  reason_code: RuntimeRecoveryRefusalReasonV04;
}>;

export type RuntimeRecoveryDecisionV04 =
  | RuntimeRecoveryEligibilityDecisionV04
  | RuntimeRecoveryRefusalDecisionV04;

export type RuntimeRecoveryResultV04 =
  | Readonly<{ ok: true; decision: RuntimeRecoveryDecisionV04 }>
  | Readonly<{ ok: false; reason: "INVALID_RUNTIME_RECOVERY_INPUT" }>;

type LedgerRef = z.infer<typeof LedgerRefV02>;
type OwnerStatus = z.infer<typeof OwnerStatusV04>;
type RecoveryRequestIntent = RuntimeRecoveryRequestIntentV04Value;

const INVALID_RECOVERY = Object.freeze({
  ok: false,
  reason: "INVALID_RUNTIME_RECOVERY_INPUT",
} as const);

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

function exactObject<T extends readonly string[]>(
  value: unknown,
  keys: T,
): Record<T[number], unknown> | null {
  try {
    if (typeof value !== "object" || value === null || Object.getPrototypeOf(value) !== Object.prototype) return null;
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.keys(descriptors).sort().join("\0") !== [...keys].sort().join("\0")) return null;
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true) {
        return null;
      }
    }
    return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value])) as Record<T[number], unknown>;
  } catch {
    return null;
  }
}

function sameRef(left: LedgerRef, right: LedgerRef): boolean {
  return left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function eventAt(ledger: ValidatedRuntimeLedgerV04, ref: LedgerRef): (typeof ledger.events)[number] | null {
  const event = ledger.events[ref.ledger_sequence - 1];
  return event?.event_hash === ref.event_hash ? event : null;
}

function toRef(event: { sequence: number; event_hash: string }): LedgerRef {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function currentAttemptEvent(ledger: ValidatedRuntimeLedgerV04) {
  const ref = ledger.state.current_attempt_event_ref;
  if (ref === null) return null;
  const event = eventAt(ledger, ref);
  return event?.event_type === "execution.attempt-started" ? event : null;
}

function currentBoundary(ledger: ValidatedRuntimeLedgerV04): LedgerRef | null {
  const head = ledger.events.at(-1);
  return head === undefined ? null : toRef(head);
}

function expectedRepositoryStateHash(
  plan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
): string {
  const settlement = [...ledger.events].reverse().find(
    (event) => event.event_type === "task.action-settled",
  );
  return settlement?.event_type === "task.action-settled"
    ? settlement.payload.repository_post_state_hash
    : plan.plan.authority_subject.repository.initial_state.repository_state_hash;
}

function validateSummary(
  summary: unknown,
  plan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
  manifest: ValidatedRunManifestV04,
): ValidatedSummaryArtifactV01 | null | "invalid" | "drift" {
  if (summary === null) return null;
  const validated = validateRuntimeSummaryForRecoveryV04({
    inspected_summary: summary,
    validated_plan: plan,
    ledger,
    manifest,
  });
  if (validated.ok) return validated.validated_summary;
  return validated.reason === "SUMMARY_INVALIDATED" ? "drift" : "invalid";
}

function unresolvedAdmissions(ledger: ValidatedRuntimeLedgerV04): readonly LedgerRef[] {
  const settled = new Set<string>();
  for (const event of ledger.events) {
    if (event.event_type === "task.action-settled") settled.add(event.payload.action_id);
  }
  const unresolved: LedgerRef[] = [];
  for (const event of ledger.events) {
    if (event.event_type !== "task.action-admitted") continue;
    const actionId = (event.payload as Readonly<{ action_id: string }>).action_id;
    if (!ledger.state.in_flight_action_ids.includes(actionId)) continue;
    if (settled.has(actionId)) continue;
    unresolved.push(toRef(event));
  }
  return unresolved;
}

function latestCompensationPhaseRef(ledger: ValidatedRuntimeLedgerV04): LedgerRef | null {
  const event = [...ledger.events].reverse().find((row) => row.event_type === "run.compensation-phase-entered");
  return event === undefined ? null : toRef(event);
}

function validateOwnerStatus(
  ledger: ValidatedRuntimeLedgerV04,
  ownerStatus: OwnerStatus,
): true | RuntimeRecoveryResultV04 {
  const activeOwner = ledger.state.active_run_owner?.active === true
    ? ledger.state.active_run_owner.lease_event_ref
    : null;
  if (ownerStatus.status === "absent") {
    return activeOwner === null
      ? true
      : { ok: true, decision: { disposition: "refused", precedence: 4, reason_code: "owner-unproven-stale" } };
  }
  if (ownerStatus.evidence_refs.some((ref) => eventAt(ledger, ref) === null)) return INVALID_RECOVERY;
  if (eventAt(ledger, ownerStatus.owner_lease_event_ref) === null) return INVALID_RECOVERY;
  if (activeOwner === null || !sameRef(activeOwner, ownerStatus.owner_lease_event_ref)) return INVALID_RECOVERY;
  if (ownerStatus.status === "current") {
    return { ok: true, decision: { disposition: "refused", precedence: 4, reason_code: "owner-current" } };
  }
  if (ownerStatus.status === "ambiguous") {
    return { ok: true, decision: { disposition: "refused", precedence: 4, reason_code: "owner-ambiguous" } };
  }
  return true;
}

function limitProjection(
  plan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
  manifest: ValidatedRunManifestV04,
  mode: RuntimeRecoveryModeV04,
): Readonly<{ counters: RuntimeLimitCountersV04Value; projection: RuntimeLimitAccountingValueV04 }> | null {
  const counters = projectRuntimeLimitCountersV04({
    validated_plan: plan,
    ledger,
    manifest,
  });
  if (!counters.ok) return null;
  const projection = evaluateRuntimeLimitAccountingV04({
    plan: plan.plan,
    phase: mode === "compensation-continuation" ? "compensation" : "work",
    consumed: {
      ...counters.value,
      active_workers: 0,
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
  if (!projection.ok) return null;
  return { counters: counters.value, projection: projection.value };
}

function limitRefusal(projection: RuntimeLimitAccountingValueV04): RuntimeRecoveryRefusalDecisionV04 | null {
  if (projection.execution_attempts_exhausted) {
    return { disposition: "refused", precedence: 6, reason_code: "execution-attempts-exhausted" };
  }
  if (projection.exhausted_limit_refs.includes("max-elapsed-ms")) {
    return { disposition: "refused", precedence: 6, reason_code: "elapsed-budget-exhausted" };
  }
  if (projection.exhausted_limit_refs.includes("max-output-bytes")) {
    return { disposition: "refused", precedence: 6, reason_code: "output-budget-exhausted" };
  }
  if (projection.exhausted_limit_refs.includes("max-workers")) {
    return { disposition: "refused", precedence: 6, reason_code: "worker-budget-exhausted" };
  }
  if (projection.exhausted_limit_refs.includes("max-tokens")) {
    return { disposition: "refused", precedence: 6, reason_code: "token-budget-exhausted" };
  }
  if (projection.exhausted_limit_refs.includes("max-cost")) {
    return { disposition: "refused", precedence: 6, reason_code: "cost-budget-exhausted" };
  }
  return null;
}

function buildEligibleDecision(
  ledger: ValidatedRuntimeLedgerV04,
  manifest: ValidatedRunManifestV04,
  requestProjection: RuntimeRecoveryRequestProjectionV04,
  counters: RuntimeLimitCountersV04Value,
  projection: RuntimeLimitAccountingValueV04,
  summary: ValidatedSummaryArtifactV01 | null,
): RuntimeRecoveryEligibilityDecisionV04 | null {
  const attempt = currentAttemptEvent(ledger);
  const boundary = currentBoundary(ledger);
  if (attempt === null || boundary === null) return null;
  const nextAttemptOrdinal = attempt.payload.attempt_ordinal + 1;
  const nextFenceEpoch = ledger.state.current_fence_epoch + 1;
  if (!Number.isSafeInteger(nextAttemptOrdinal) || !Number.isSafeInteger(nextFenceEpoch)) return null;
  return freezeDeep({
    disposition: "eligible",
    mode: requestProjection.mode,
    resume_boundary: {
      source_boundary_sequence: requestProjection.source_boundary_sequence,
      source_boundary_head_hash: requestProjection.source_boundary_head_hash,
      source_manifest_hash: requestProjection.source_manifest_hash,
      attempt_event_ref: requestProjection.previous_attempt_event_ref,
      fence_epoch: ledger.state.current_fence_epoch,
    },
    request_projection: requestProjection,
    next_attempt_ordinal: nextAttemptOrdinal,
    next_fence_epoch: nextFenceEpoch,
    counters,
    limit_projection: projection,
    validated_summary: summary,
  });
}

function driftRefusal(
  plan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
  requestProjection: RuntimeRecoveryRequestProjectionV04,
): RuntimeRecoveryRefusalDecisionV04 | null {
  const attempt = currentAttemptEvent(ledger);
  if (attempt === null) return null;
  if (attempt.payload.plan_hash !== plan.plan_hash || requestProjection.plan_hash !== plan.plan_hash) {
    return { disposition: "refused", precedence: 5, reason_code: "plan-hash-drift" };
  }
  if (
    attempt.payload.input_hash !== plan.plan.runtime_input_hash
    || requestProjection.input_hash !== plan.plan.runtime_input_hash
  ) {
    return { disposition: "refused", precedence: 5, reason_code: "input-hash-drift" };
  }
  if (
    attempt.payload.recovery_policy_hash !== plan.plan.runtime_recovery_policy_hash
    || requestProjection.recovery_policy_hash !== plan.plan.runtime_recovery_policy_hash
  ) {
    return { disposition: "refused", precedence: 5, reason_code: "recovery-policy-hash-drift" };
  }
  if (requestProjection.authority_envelope_hash !== attempt.payload.authority_envelope_hash) {
    return { disposition: "refused", precedence: 5, reason_code: "authority-envelope-hash-drift" };
  }
  if (requestProjection.repository_state_hash !== expectedRepositoryStateHash(plan, ledger)) {
    return { disposition: "refused", precedence: 5, reason_code: "repository-boundary-drift" };
  }
  return null;
}

function projectFreshRequest(
  ledger: ValidatedRuntimeLedgerV04,
  manifest: ValidatedRunManifestV04,
  request: RecoveryRequestIntent,
  repositoryStateHash: string,
): RuntimeRecoveryRequestProjectionV04 | null {
  const attempt = currentAttemptEvent(ledger);
  const boundary = currentBoundary(ledger);
  if (attempt === null || boundary === null) return null;
  return freezeDeep({
    request_id: request.request_id,
    mode: request.requested_mode,
    resume_nonce_hash: request.resume_nonce_hash,
    previous_attempt_event_ref: toRef(attempt),
    source_boundary_sequence: boundary.ledger_sequence,
    source_boundary_head_hash: boundary.event_hash,
    source_manifest_hash: manifest.manifest_hash,
    plan_hash: attempt.payload.plan_hash,
    input_hash: attempt.payload.input_hash,
    recovery_policy_hash: attempt.payload.recovery_policy_hash,
    authority_envelope_hash: request.authority_envelope_hash,
    repository_state_hash: repositoryStateHash,
    target_action_admission_ref: request.target_action_admission_ref,
    compensation_phase_event_ref: request.compensation_phase_event_ref,
  });
}

function projectPendingRequest(
  ledger: ValidatedRuntimeLedgerV04,
  pendingRequest: Extract<(typeof ledger.events)[number], { event_type: "recovery.resume-requested" }>,
): RuntimeRecoveryRequestProjectionV04 {
  return freezeDeep({
    request_id: pendingRequest.payload.request_id,
    mode: pendingRequest.payload.mode,
    resume_nonce_hash: pendingRequest.payload.resume_nonce_hash,
    previous_attempt_event_ref: pendingRequest.payload.previous_attempt_event_ref,
    source_boundary_sequence: pendingRequest.payload.source_boundary_sequence,
    source_boundary_head_hash: pendingRequest.payload.source_boundary_head_hash,
    source_manifest_hash: pendingRequest.payload.source_manifest_hash,
    plan_hash: pendingRequest.payload.plan_hash,
    input_hash: pendingRequest.payload.input_hash,
    recovery_policy_hash: pendingRequest.payload.recovery_policy_hash,
    authority_envelope_hash: pendingRequest.payload.authority_envelope_hash,
    repository_state_hash: pendingRequest.payload.repository_state_hash,
    target_action_admission_ref: pendingRequest.payload.target_action_admission_ref,
    compensation_phase_event_ref: pendingRequest.payload.compensation_phase_event_ref,
  });
}

function decideRecovery(
  ledger: ValidatedRuntimeLedgerV04,
  manifest: ValidatedRunManifestV04,
  plan: ValidatedRuntimePlanV03,
  ownerStatus: OwnerStatus,
  requestProjection: RuntimeRecoveryRequestProjectionV04,
  summary: ValidatedSummaryArtifactV01 | null | "drift",
  allowedPendingRequestRef: LedgerRef | null,
  reconciliationAuthorized: boolean,
): RuntimeRecoveryResultV04 {
  if (manifest.run_state === "sealed" || ledger.sealed || ledger.state.terminal_sealed) {
    return { ok: true, decision: { disposition: "refused", precedence: 2, reason_code: "run-terminal-sealed" } };
  }
  if (ledger.state.state === "quarantine-required" || ledger.state.state === "quarantined" || manifest.run_state === "quarantined") {
    return { ok: true, decision: { disposition: "refused", precedence: 3, reason_code: "run-quarantined" } };
  }
  if (ledger.state.pending_resume_request !== null) {
    if (allowedPendingRequestRef === null || !sameRef(ledger.state.pending_resume_request.event_ref, allowedPendingRequestRef)) {
      return { ok: true, decision: { disposition: "refused", precedence: 4, reason_code: "pending-resume-request" } };
    }
  }
  if (ledger.state.consumed_resume_request_ids.includes(requestProjection.request_id)) {
    return { ok: true, decision: { disposition: "refused", precedence: 4, reason_code: "resume-request-id-reused" } };
  }
  if (ledger.state.consumed_resume_nonce_hashes.includes(requestProjection.resume_nonce_hash)) {
    return { ok: true, decision: { disposition: "refused", precedence: 4, reason_code: "resume-nonce-reused" } };
  }
  const ownerDecision = validateOwnerStatus(ledger, ownerStatus);
  if (allowedPendingRequestRef === null && ownerDecision !== true) return ownerDecision;
  const driftDecision = driftRefusal(plan, ledger, requestProjection);
  if (driftDecision !== null) return { ok: true, decision: driftDecision };
  if (summary === "drift") {
    return { ok: true, decision: { disposition: "refused", precedence: 5, reason_code: "summary-lineage-drift" } };
  }
  const limits = limitProjection(plan, ledger, manifest, requestProjection.mode);
  if (limits === null) return INVALID_RECOVERY;
  const limitDecision = limitRefusal(limits.projection);
  if (limitDecision !== null) return { ok: true, decision: limitDecision };
  const attempt = currentAttemptEvent(ledger);
  if (attempt === null) {
    return { ok: true, decision: { disposition: "refused", precedence: 7, reason_code: "no-eligible-durable-boundary" } };
  }
  const unresolved = unresolvedAdmissions(ledger);
  if (requestProjection.mode === "ordinary" && unresolved.length > 0) {
    return {
      ok: true,
      decision: { disposition: "refused", precedence: 7, reason_code: "ordinary-blocked-by-unresolved-action" },
    };
  }
  if (requestProjection.mode === "compensation-continuation" && unresolved.length > 0) {
    return {
      ok: true,
      decision: { disposition: "refused", precedence: 7, reason_code: "compensation-blocked-by-unresolved-action" },
    };
  }
  if (requestProjection.mode === "reconciliation-only") {
    if (requestProjection.target_action_admission_ref === null) {
      return {
        ok: true,
        decision: { disposition: "refused", precedence: 7, reason_code: "reconciliation-target-required" },
      };
    }
    if (!unresolved.some((ref) => sameRef(ref, requestProjection.target_action_admission_ref!))) {
      return {
        ok: true,
        decision: { disposition: "refused", precedence: 7, reason_code: "reconciliation-target-mismatch" },
      };
    }
    if (!reconciliationAuthorized) {
      return {
        ok: true,
        decision: { disposition: "refused", precedence: 7, reason_code: "reconciliation-proof-not-authorized" },
      };
    }
  }
  if (requestProjection.mode === "compensation-continuation") {
    const phaseRef = latestCompensationPhaseRef(ledger);
    if (requestProjection.compensation_phase_event_ref === null
      || phaseRef === null
      || !sameRef(requestProjection.compensation_phase_event_ref, phaseRef)) {
      return {
        ok: true,
        decision: { disposition: "refused", precedence: 7, reason_code: "compensation-boundary-mismatch" },
      };
    }
  }
  const eligible = buildEligibleDecision(
    ledger,
    manifest,
    requestProjection,
    limits.counters,
    limits.projection,
    summary,
  );
  return eligible === null ? INVALID_RECOVERY : { ok: true, decision: eligible };
}

export function planRuntimeRecoveryV04(input: unknown): RuntimeRecoveryResultV04 {
  try {
    const exact = exactObject(input, ["ledger", "manifest", "plan", "owner_status", "request", "summary"]);
    if (exact === null
      || !isValidatedRuntimePlanV03(exact.plan)
      || !isValidatedRunManifestPairV04(exact.manifest, exact.ledger)) {
      return INVALID_RECOVERY;
    }
    const ownerStatus = OwnerStatusV04.safeParse(exact.owner_status);
    const binding = inspectCapturedRuntimeRecoveryRequestV04(exact.request);
    if (!ownerStatus.success || binding === null) return INVALID_RECOVERY;
    const plan = exact.plan as ValidatedRuntimePlanV03;
    const ledger = exact.ledger as ValidatedRuntimeLedgerV04;
    const manifest = exact.manifest as ValidatedRunManifestV04;
    if (plan.run_id !== ledger.run_id
      || ledger.run_id !== manifest.run_id
      || plan.plan_hash !== ledger.plan_hash
      || ledger.plan_hash !== manifest.plan_hash
      || plan.plan.run_id !== ledger.run_id
      || binding.validated_plan !== plan
      || binding.ledger !== ledger
      || binding.manifest !== manifest
      || binding.source_boundary_sequence !== ledger.sequence
      || binding.source_boundary_head_hash !== ledger.head_hash
      || binding.source_manifest_hash !== manifest.manifest_hash) {
      return INVALID_RECOVERY;
    }
    const summary = validateSummary(exact.summary, plan, ledger, manifest);
    if (summary === "invalid") return INVALID_RECOVERY;
    const requestProjection = projectFreshRequest(
      ledger,
      manifest,
      binding.request,
      binding.current_repository_state_hash,
    );
    if (requestProjection === null) {
      return { ok: true, decision: { disposition: "refused", precedence: 7, reason_code: "no-eligible-durable-boundary" } };
    }
    return decideRecovery(
      ledger,
      manifest,
      plan,
      ownerStatus.data,
      requestProjection,
      summary,
      null,
      true,
    );
  } catch {
    return INVALID_RECOVERY;
  }
}

/** Read-only recovery projection. Its raw request can never authorize reconciliation or C2 writes. */
export function projectRuntimeRecoveryAdviceV04(input: unknown): RuntimeRecoveryResultV04 {
  try {
    const exact = exactObject(input, ["ledger", "manifest", "plan", "owner_status", "request", "summary"]);
    if (exact === null
      || !isValidatedRuntimePlanV03(exact.plan)
      || !isValidatedRunManifestPairV04(exact.manifest, exact.ledger)) {
      return INVALID_RECOVERY;
    }
    const ownerStatus = OwnerStatusV04.safeParse(exact.owner_status);
    const request = RuntimeRecoveryRequestIntentV04.safeParse(exact.request);
    if (!ownerStatus.success || !request.success) return INVALID_RECOVERY;
    const plan = exact.plan as ValidatedRuntimePlanV03;
    const ledger = exact.ledger as ValidatedRuntimeLedgerV04;
    const manifest = exact.manifest as ValidatedRunManifestV04;
    if (plan.run_id !== ledger.run_id
      || ledger.run_id !== manifest.run_id
      || plan.plan_hash !== ledger.plan_hash
      || ledger.plan_hash !== manifest.plan_hash
      || plan.plan.run_id !== ledger.run_id) {
      return INVALID_RECOVERY;
    }
    const summary = validateSummary(exact.summary, plan, ledger, manifest);
    if (summary === "invalid") return INVALID_RECOVERY;
    const requestProjection = projectFreshRequest(
      ledger,
      manifest,
      request.data,
      expectedRepositoryStateHash(plan, ledger),
    );
    if (requestProjection === null) {
      return { ok: true, decision: { disposition: "refused", precedence: 7, reason_code: "no-eligible-durable-boundary" } };
    }
    return decideRecovery(ledger, manifest, plan, ownerStatus.data, requestProjection, summary, null, false);
  } catch {
    return INVALID_RECOVERY;
  }
}

export function validatePendingRuntimeRecoveryV04(input: unknown): RuntimeRecoveryResultV04 {
  try {
    const exact = exactObject(input, ["ledger", "manifest", "plan", "owner_status", "pending_request_event_ref", "summary"]);
    if (exact === null
      || !isValidatedRuntimePlanV03(exact.plan)
      || !isValidatedRunManifestPairV04(exact.manifest, exact.ledger)) {
      return INVALID_RECOVERY;
    }
    const ownerStatus = OwnerStatusV04.safeParse(exact.owner_status);
    const pendingRef = LedgerRefV02.safeParse(exact.pending_request_event_ref);
    if (!ownerStatus.success || !pendingRef.success) return INVALID_RECOVERY;
    const plan = exact.plan as ValidatedRuntimePlanV03;
    const ledger = exact.ledger as ValidatedRuntimeLedgerV04;
    const manifest = exact.manifest as ValidatedRunManifestV04;
    if (plan.run_id !== ledger.run_id
      || ledger.run_id !== manifest.run_id
      || plan.plan_hash !== ledger.plan_hash
      || ledger.plan_hash !== manifest.plan_hash) {
      return INVALID_RECOVERY;
    }
    const summary = validateSummary(exact.summary, plan, ledger, manifest);
    if (summary === "invalid") return INVALID_RECOVERY;
    const pendingEvent = eventAt(ledger, pendingRef.data);
    const currentPending = ledger.state.pending_resume_request;
    if (pendingEvent?.event_type !== "recovery.resume-requested"
      || currentPending === null
      || !sameRef(currentPending.event_ref, pendingRef.data)) {
      return { ok: true, decision: { disposition: "refused", precedence: 4, reason_code: "double-resume" } };
    }
    const requestProjection = projectPendingRequest(ledger, pendingEvent);
    return decideRecovery(ledger, manifest, plan, ownerStatus.data, requestProjection, summary, pendingRef.data, true);
  } catch {
    return INVALID_RECOVERY;
  }
}
