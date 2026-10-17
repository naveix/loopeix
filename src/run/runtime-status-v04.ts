import { z } from "zod";

import { hashCanonical } from "../hash.js";
import type {
  ProgressEvaluationV02Value,
} from "../schema/runtime.js";
import { LedgerRefV02 } from "../schema/runtime.js";
import {
  isValidatedRuntimePlanV03,
  type ValidatedRuntimePlanV03,
} from "./project-plan-v03.js";
import {
  deriveProgressV02ForRuntime,
} from "./progress-evaluator.js";
import {
  projectRuntimeRecoveryAdviceV04,
  validatePendingRuntimeRecoveryV04,
  type RuntimeRecoveryDecisionV04,
  type RuntimeRecoveryModeV04,
  type RuntimeRecoveryRefusalReasonV04,
} from "./runtime-recovery-v04.js";
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
  isInspectedSummaryArtifactV01,
  validateRuntimeSummaryForRecoveryV04,
  type InspectedSummaryArtifactV01,
  type SummaryInvalidationReasonV04,
} from "./runtime-summary-v04.js";

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

type LedgerRef = z.infer<typeof LedgerRefV02>;
type OwnerStatus = z.infer<typeof OwnerStatusV04>;

export type RuntimeStatusSummaryStateV04 =
  | Readonly<{ status: "absent" }>
  | Readonly<{
      status: "valid";
      summary_id: string;
      attempt_id: string;
      source_prefix_sequence: number;
      source_prefix_head_hash: string;
    }>
  | Readonly<{ status: "invalid"; reason: SummaryInvalidationReasonV04 }>;

export type RuntimeStatusNextActionV04 =
  | Readonly<{
      disposition: "resume";
      mode: RuntimeRecoveryModeV04;
      reason_code: "eligible";
      target_action_admission_ref: LedgerRef | null;
      compensation_phase_event_ref: LedgerRef | null;
      request_projection: Readonly<{
        request_id: string;
        previous_attempt_event_ref: LedgerRef;
        source_boundary_sequence: number;
        source_boundary_head_hash: string;
        source_manifest_hash: string;
      }>;
    }>
  | Readonly<{
      disposition: "resume-pending";
      mode: RuntimeRecoveryModeV04;
      reason_code: "pending-resume-request-valid";
      pending_request_event_ref: LedgerRef;
    }>
  | Readonly<{
      disposition: "hold";
      reason_code: RuntimeRecoveryRefusalReasonV04 | SummaryInvalidationReasonV04;
      target_action_admission_ref: LedgerRef | null;
      compensation_phase_event_ref: LedgerRef | null;
    }>;

export type RuntimeStatusV04 = Readonly<{
  schema_version: "0.4";
  run: Readonly<{
    run_id: string;
    state: ValidatedRunManifestV04["run_state"];
    phase: "work" | "compensation";
    terminal: Readonly<{
      sealed: boolean;
      outcome: "completed" | "held" | "blocked" | "failed" | "stalled" | "exhausted" | "aborted" | null;
      pending_outcome: string | null;
      seal_event_ref: LedgerRef | null;
    }>;
  }>;
  plan: Readonly<{
    schema_version: "0.3";
    plan_hash: string;
    recovery_policy_hash: string | null;
  }>;
  integrity: Readonly<{
    ledger_sequence: number;
    ledger_head_hash: string;
    ledger_bytes_hash: string;
    manifest_hash: string;
    manifest_projection_event_ref: LedgerRef;
    pair_status: "matched";
  }>;
  attempt: Readonly<{
    current_attempt_ordinal: number | null;
    current_attempt_event_ref: LedgerRef | null;
    history: readonly Readonly<{
      attempt_id: string;
      attempt_ordinal: number;
      attempt_event_ref: LedgerRef;
      mode: RuntimeRecoveryModeV04;
      previous_attempt_event_ref: LedgerRef | null;
      resume_request_event_ref: LedgerRef | null;
      run_owner_lease_id: string;
      deadline_elapsed_ms: number;
      fence_epoch: number;
      current: boolean;
    }>[];
  }>;
  fence: Readonly<{
    current_fence_epoch: number;
  }>;
  owner: Readonly<{
    status: OwnerStatus["status"];
    reason: string | null;
    evidence_refs: readonly LedgerRef[];
    owner_lease_event_ref: LedgerRef | null;
    current_owner: Readonly<{
      owner_lease_id: string;
      scope: "run" | "task" | "integrator";
      scope_ref: string;
      deadline_elapsed_ms: number;
      heartbeat_ordinal: number;
      active: boolean;
      released: boolean;
      fence_epoch: number;
    }> | null;
    heartbeat_state: "absent" | "current" | "ambiguous" | "proven-stale";
    lease_deadline_state: "no-owner" | "open" | "ambiguous" | "reached";
  }>;
  actions: Readonly<{
    in_flight_action_refs: readonly Readonly<{
      action_id: string;
      task_ref: string;
      admission_ref: LedgerRef;
      attempt_event_ref: LedgerRef;
    }>[];
    outcome_unknown_action_refs: readonly Readonly<{
      action_id: string;
      task_ref: string;
      admission_ref: LedgerRef;
      status_event_ref: LedgerRef;
      reconciliation_status: "outcome-unknown" | "outcome-remains-unknown";
    }>[];
  }>;
  limits: Readonly<{
    counters: RuntimeLimitCountersV04Value;
    remaining: RuntimeLimitAccountingValueV04["remaining"];
    exhausted_limit_refs: readonly string[];
    execution_attempts_exhausted: boolean;
  }>;
  progress: Readonly<{
    evaluation: ProgressEvaluationV02Value;
    stalled: boolean;
    stalled_observation_refs: readonly string[];
    target_reached_refs: readonly string[];
  }>;
  summary: RuntimeStatusSummaryStateV04;
  next_action: RuntimeStatusNextActionV04;
}>;

export type RuntimeStatusResultV04 =
  | Readonly<{ ok: true; status: RuntimeStatusV04 }>
  | Readonly<{ ok: false; reason: "INVALID_RUNTIME_STATUS_INPUT" }>;

const INVALID_STATUS = Object.freeze({
  ok: false,
  reason: "INVALID_RUNTIME_STATUS_INPUT",
} as const);

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

function exactStatusInput(input: unknown): Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  owner_status: OwnerStatus;
  summary: InspectedSummaryArtifactV01 | null;
}> | null {
  try {
    if (typeof input !== "object" || input === null || Object.getPrototypeOf(input) !== Object.prototype) return null;
    if (Reflect.ownKeys(input).some((key) => typeof key !== "string")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const keys = Object.keys(descriptors).sort().join("\0");
    const withSummary = ["ledger", "manifest", "owner_status", "summary", "validated_plan"].sort().join("\0");
    const withoutSummary = ["ledger", "manifest", "owner_status", "validated_plan"].sort().join("\0");
    if (keys !== withSummary && keys !== withoutSummary) return null;
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true) {
        return null;
      }
    }
    const parsedOwner = OwnerStatusV04.safeParse(descriptors.owner_status?.value);
    if (!parsedOwner.success) return null;
    const summaryValue = Object.hasOwn(descriptors, "summary") ? descriptors.summary!.value : null;
    if (summaryValue !== null && !isInspectedSummaryArtifactV01(summaryValue)) return null;
    return {
      validated_plan: descriptors.validated_plan!.value as ValidatedRuntimePlanV03,
      ledger: descriptors.ledger!.value as ValidatedRuntimeLedgerV04,
      manifest: descriptors.manifest!.value as ValidatedRunManifestV04,
      owner_status: parsedOwner.data,
      summary: summaryValue as InspectedSummaryArtifactV01 | null,
    };
  } catch {
    return null;
  }
}

function sameRef(left: LedgerRef | null, right: LedgerRef | null): boolean {
  return left === null || right === null
    ? left === right
    : left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function refOf(event: Readonly<{ sequence: number; event_hash: string }>): LedgerRef {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function phaseAtHead(ledger: ValidatedRuntimeLedgerV04): "work" | "compensation" {
  return ledger.events.some((event) => event.event_type === "run.compensation-phase-entered")
    ? "compensation"
    : "work";
}

function latestPendingTerminal(ledger: ValidatedRuntimeLedgerV04): string | null {
  const pending = [...ledger.events].reverse().find((event) =>
    event.event_type === "run.compensation-candidate-escalated"
    || event.event_type === "run.compensation-phase-entered");
  return pending?.payload.pending_terminal ?? null;
}

function attemptHistory(ledger: ValidatedRuntimeLedgerV04) {
  return ledger.events
    .filter((event) => event.event_type === "execution.attempt-started")
    .map((event) => freezeDeep({
      attempt_id: event.payload.attempt_id,
      attempt_ordinal: event.payload.attempt_ordinal,
      attempt_event_ref: refOf(event),
      mode: event.payload.mode,
      previous_attempt_event_ref: event.payload.previous_attempt_event_ref,
      resume_request_event_ref: event.payload.resume_request_event_ref,
      run_owner_lease_id: event.payload.run_owner_lease_id,
      deadline_elapsed_ms: event.payload.deadline_elapsed_ms,
      fence_epoch: event.payload.fence_epoch,
      current: sameRef(ledger.state.current_attempt_event_ref, refOf(event)),
    }));
}

function ownerProjection(ownerStatus: OwnerStatus, ledger: ValidatedRuntimeLedgerV04): RuntimeStatusV04["owner"] {
  const currentOwner = ledger.state.active_run_owner;
  const reason = ownerStatus.status === "ambiguous"
    ? ownerStatus.ambiguous_reason
    : ownerStatus.status === "proven-stale"
      ? ownerStatus.stale_reason
      : null;
  return freezeDeep({
    status: ownerStatus.status,
    reason,
    evidence_refs: ownerStatus.evidence_refs,
    owner_lease_event_ref: ownerStatus.status === "absent" ? null : ownerStatus.owner_lease_event_ref,
    current_owner: currentOwner === null
      ? null
      : {
          owner_lease_id: currentOwner.owner_lease_id,
          scope: currentOwner.scope,
          scope_ref: currentOwner.scope_ref,
          deadline_elapsed_ms: currentOwner.deadline_elapsed_ms,
          heartbeat_ordinal: currentOwner.heartbeat_ordinal,
          active: currentOwner.active,
          released: currentOwner.released,
          fence_epoch: currentOwner.fence_epoch,
        },
    heartbeat_state: ownerStatus.status,
    lease_deadline_state: ownerStatus.status === "absent"
      ? "no-owner"
      : ownerStatus.status === "current"
        ? "open"
        : ownerStatus.status === "ambiguous"
          ? "ambiguous"
          : "reached",
  });
}

function actionAdmissionFields(payload: unknown): Readonly<{
  action_id: string;
  task_ref: string;
  attempt_event_ref: LedgerRef;
}> | null {
  if (typeof payload !== "object" || payload === null) return null;
  const record = payload as Record<string, unknown>;
  const attemptRef = record.attempt_event_ref;
  if (typeof record.action_id !== "string"
    || typeof record.task_ref !== "string"
    || typeof attemptRef !== "object"
    || attemptRef === null) return null;
  const refRecord = attemptRef as Record<string, unknown>;
  if (!Number.isSafeInteger(refRecord.ledger_sequence) || typeof refRecord.event_hash !== "string") return null;
  return {
    action_id: record.action_id,
    task_ref: record.task_ref,
    attempt_event_ref: {
      ledger_sequence: refRecord.ledger_sequence as number,
      event_hash: refRecord.event_hash,
    },
  };
}

function actionRefMap(ledger: ValidatedRuntimeLedgerV04) {
  return new Map(
    ledger.events
      .flatMap((event) => {
        if (event.event_type !== "task.action-admitted") return [];
        const admission = actionAdmissionFields(event.payload);
        if (admission === null) return [];
        return [[
          admission.action_id,
          freezeDeep({
            action_id: admission.action_id,
            task_ref: admission.task_ref,
            admission_ref: refOf(event),
            attempt_event_ref: admission.attempt_event_ref,
          }),
        ] as const];
      }),
  );
}

function inFlightActions(ledger: ValidatedRuntimeLedgerV04): RuntimeStatusV04["actions"]["in_flight_action_refs"] {
  const admissions = actionRefMap(ledger);
  return freezeDeep(
    ledger.state.in_flight_action_ids
      .map((actionId) => admissions.get(actionId))
      .filter((value): value is NonNullable<typeof value> => value !== undefined),
  );
}

function outcomeUnknownActions(ledger: ValidatedRuntimeLedgerV04): RuntimeStatusV04["actions"]["outcome_unknown_action_refs"] {
  const admissions = actionRefMap(ledger);
  const settled = new Set(
    ledger.events
      .filter((event) => event.event_type === "task.action-settled")
      .map((event) => event.payload.action_id),
  );
  const latestUnknown = new Map<string, RuntimeStatusV04["actions"]["outcome_unknown_action_refs"][number]>();
  for (const event of ledger.events) {
    if (event.event_type !== "task.action-outcome-unknown" && event.event_type !== "task.action-outcome-reconciled") continue;
    const actionId = event.payload.action_id;
    const admission = admissions.get(actionId);
    if (admission === undefined || settled.has(actionId)) continue;
    if (event.event_type === "task.action-outcome-reconciled" && event.payload.reconciliation_status === "proven-non-start") {
      latestUnknown.delete(actionId);
      continue;
    }
    latestUnknown.set(actionId, freezeDeep({
      action_id: actionId,
      task_ref: admission.task_ref,
      admission_ref: admission.admission_ref,
      status_event_ref: refOf(event),
      reconciliation_status: event.event_type === "task.action-outcome-unknown"
        ? "outcome-unknown"
        : "outcome-remains-unknown",
    }));
  }
  return freezeDeep([...latestUnknown.values()].sort((left, right) =>
    left.admission_ref.ledger_sequence - right.admission_ref.ledger_sequence));
}

function progressProjection(
  validatedPlan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
  counters: RuntimeLimitCountersV04Value,
): Readonly<{
  evaluation: ProgressEvaluationV02Value;
  stalled: boolean;
  stalled_observation_refs: readonly string[];
  target_reached_refs: readonly string[];
}> | null {
  const result = deriveProgressV02ForRuntime({
    run_id: ledger.run_id,
    plan_hash: ledger.plan_hash,
    plan: validatedPlan.plan,
    ledger_sequence: ledger.sequence,
    ledger_head_hash: ledger.head_hash,
    completed_loop_attempts: counters.loop_attempts,
    observations: ledger.events.filter((event) => event.event_type === "task.progress-observed"),
    events: ledger.events,
  } as unknown as Parameters<typeof deriveProgressV02ForRuntime>[0]);
  if (!result.ok) return null;
  const stalled = result.value.observations.filter((row) => row.stalled).map((row) => row.ref);
  const reached = result.value.observations.filter((row) => row.target_reached).map((row) => row.ref);
  return freezeDeep({
    evaluation: result.value,
    stalled: stalled.length > 0,
    stalled_observation_refs: stalled,
    target_reached_refs: reached,
  });
}

function summaryProjection(
  summary: InspectedSummaryArtifactV01 | null,
  validatedPlan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
  manifest: ValidatedRunManifestV04,
): RuntimeStatusSummaryStateV04 {
  if (summary === null) return Object.freeze({ status: "absent" });
  const validated = validateRuntimeSummaryForRecoveryV04({
    inspected_summary: summary,
    validated_plan: validatedPlan,
    ledger,
    manifest,
  });
  if (!validated.ok) {
    return validated.reason === "SUMMARY_INVALIDATED"
      ? Object.freeze({ status: "invalid", reason: validated.invalidation_reason })
      : Object.freeze({ status: "invalid", reason: "source-head-mismatch" });
  }
  return freezeDeep({
    status: "valid",
    summary_id: validated.summary.summary_id,
    attempt_id: validated.summary.attempt_id,
    source_prefix_sequence: validated.summary.source_prefix_sequence,
    source_prefix_head_hash: validated.summary.source_prefix_head_hash,
  });
}

function deterministicProbeRequestId(ledger: ValidatedRuntimeLedgerV04): string {
  const seen = new Set(
    ledger.events
      .filter((event) => event.event_type === "recovery.resume-requested")
      .map((event) => event.payload.request_id),
  );
  for (let ordinal = 1; ordinal < 10_000; ordinal += 1) {
    const candidate = `request_status_probe_s41_${ordinal}`;
    if (!seen.has(candidate) && !ledger.state.consumed_resume_request_ids.includes(candidate)) return candidate;
  }
  return "request_status_probe_s41_overflow";
}

function deterministicProbeNonce(ledger: ValidatedRuntimeLedgerV04, mode: RuntimeRecoveryModeV04, target: LedgerRef | null): string {
  return hashCanonical({
    purpose: "runtime-status-v04-probe",
    head_hash: ledger.head_hash,
    head_sequence: ledger.sequence,
    mode,
    target,
  });
}

function eligibleDecision(
  decision: RuntimeRecoveryDecisionV04,
): Extract<RuntimeRecoveryDecisionV04, { disposition: "eligible" }> | null {
  return decision.disposition === "eligible" ? decision : null;
}

function refusedDecision(
  decision: RuntimeRecoveryDecisionV04,
): Extract<RuntimeRecoveryDecisionV04, { disposition: "refused" }> | null {
  return decision.disposition === "refused" ? decision : null;
}

function holdDecision(
  reason_code: RuntimeRecoveryRefusalReasonV04 | SummaryInvalidationReasonV04,
  target_action_admission_ref: LedgerRef | null,
  compensation_phase_event_ref: LedgerRef | null,
): RuntimeStatusNextActionV04 {
  return freezeDeep({
    disposition: "hold",
    reason_code,
    target_action_admission_ref,
    compensation_phase_event_ref,
  });
}

function nextAction(
  validatedPlan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
  manifest: ValidatedRunManifestV04,
  ownerStatus: OwnerStatus,
  summary: InspectedSummaryArtifactV01 | null,
  summaryState: RuntimeStatusSummaryStateV04,
  unknownActions: RuntimeStatusV04["actions"]["outcome_unknown_action_refs"],
): RuntimeStatusNextActionV04 | null {
  if (manifest.run_state === "sealed" || ledger.sealed || ledger.state.terminal_sealed) {
    return holdDecision("run-terminal-sealed", null, null);
  }
  if (ledger.state.state === "quarantine-required" || ledger.state.state === "quarantined" || manifest.run_state === "quarantined") {
    return holdDecision("run-quarantined", null, null);
  }
  if (ledger.state.pending_resume_request !== null) {
    const pending = validatePendingRuntimeRecoveryV04({
      ledger,
      manifest,
      plan: validatedPlan,
      owner_status: ownerStatus,
      pending_request_event_ref: ledger.state.pending_resume_request.event_ref,
      summary,
    });
    if (!pending.ok) return null;
    const eligible = eligibleDecision(pending.decision);
    const refused = refusedDecision(pending.decision);
    return eligible !== null
      ? freezeDeep({
          disposition: "resume-pending",
          mode: eligible.mode,
          reason_code: "pending-resume-request-valid",
          pending_request_event_ref: ledger.state.pending_resume_request.event_ref,
        })
      : refused === null ? null : holdDecision(refused.reason_code, null, null);
  }

  if (summaryState.status === "invalid") return holdDecision(summaryState.reason, null, null);
  if (ledger.state.current_attempt_event_ref === null) {
    return holdDecision("no-eligible-durable-boundary", null, null);
  }

  const phase = phaseAtHead(ledger);
  const target = unknownActions[0]?.admission_ref ?? null;
  const mode: RuntimeRecoveryModeV04 = phase === "compensation"
    ? "compensation-continuation"
    : target === null ? "ordinary" : "reconciliation-only";
  const compensationPhaseEventRef = phase === "compensation"
    ? refOf([...ledger.events].reverse().find((event) => event.event_type === "run.compensation-phase-entered")!)
    : null;
  const request = {
    request_id: deterministicProbeRequestId(ledger),
    requested_mode: mode,
    resume_nonce_hash: deterministicProbeNonce(ledger, mode, target),
    authority_envelope_hash: currentAttemptAuthorityEnvelopeHash(ledger),
    target_action_admission_ref: mode === "reconciliation-only" ? target : null,
    compensation_phase_event_ref: mode === "compensation-continuation" ? compensationPhaseEventRef : null,
  } as const;
  const planned = projectRuntimeRecoveryAdviceV04({
    ledger,
    manifest,
    plan: validatedPlan,
    owner_status: ownerStatus,
    request,
    summary,
  });
  if (!planned.ok) return null;
  const eligible = eligibleDecision(planned.decision);
  const refused = refusedDecision(planned.decision);
  if (eligible !== null) {
    return freezeDeep({
      disposition: "resume",
      mode: eligible.mode,
      reason_code: "eligible",
      target_action_admission_ref: eligible.request_projection.target_action_admission_ref,
      compensation_phase_event_ref: eligible.request_projection.compensation_phase_event_ref,
      request_projection: {
        request_id: eligible.request_projection.request_id,
        previous_attempt_event_ref: eligible.request_projection.previous_attempt_event_ref,
        source_boundary_sequence: eligible.request_projection.source_boundary_sequence,
        source_boundary_head_hash: eligible.request_projection.source_boundary_head_hash,
        source_manifest_hash: eligible.request_projection.source_manifest_hash,
      },
    });
  }
  return refused === null ? null : holdDecision(refused.reason_code, target, compensationPhaseEventRef);
}

function currentAttemptAuthorityEnvelopeHash(ledger: ValidatedRuntimeLedgerV04): string {
  const event = ledger.events.findLast((row) => row.event_type === "execution.attempt-started");
  if (event === undefined) return `sha256:${"0".repeat(64)}`;
  return event.payload.authority_envelope_hash;
}

export function projectRuntimeStatusV04(input: unknown): RuntimeStatusResultV04 {
  const exact = exactStatusInput(input);
  if (exact === null
    || !isValidatedRuntimePlanV03(exact.validated_plan)
    || !isValidatedRunManifestPairV04(exact.manifest, exact.ledger)) {
    return INVALID_STATUS;
  }
  const { validated_plan: validatedPlan, ledger, manifest, owner_status: ownerStatus, summary } = exact;
  if (validatedPlan.run_id !== ledger.run_id
    || ledger.run_id !== manifest.run_id
    || validatedPlan.plan_hash !== ledger.plan_hash
    || ledger.plan_hash !== manifest.plan_hash
    || validatedPlan.plan.run_id !== ledger.run_id) {
    return INVALID_STATUS;
  }

  const counters = projectRuntimeLimitCountersV04({
    validated_plan: validatedPlan,
    ledger,
    manifest,
  });
  if (!counters.ok) return INVALID_STATUS;

  const phase = phaseAtHead(ledger);
  const limitProjection = evaluateRuntimeLimitAccountingV04({
    plan: validatedPlan.plan,
    phase,
    consumed: counters.value,
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
  if (!limitProjection.ok) return INVALID_STATUS;

  const progress = progressProjection(validatedPlan, ledger, counters.value);
  if (progress === null) return INVALID_STATUS;
  const summaryState = summaryProjection(summary, validatedPlan, ledger, manifest);
  const unknownActions = outcomeUnknownActions(ledger);
  const next = nextAction(validatedPlan, ledger, manifest, ownerStatus, summary, summaryState, unknownActions);
  if (next === null) return INVALID_STATUS;

  const terminal = manifest.terminal;
  const status = freezeDeep({
    schema_version: "0.4" as const,
    run: {
      run_id: ledger.run_id,
      state: manifest.run_state,
      phase,
      terminal: {
        sealed: manifest.run_state === "sealed",
        outcome: terminal?.outcome ?? null,
        pending_outcome: latestPendingTerminal(ledger),
        seal_event_ref: terminal?.seal_event_ref ?? null,
      },
    },
    plan: {
      schema_version: "0.3" as const,
      plan_hash: validatedPlan.plan_hash,
      recovery_policy_hash: ledger.events.findLast((event) => event.event_type === "execution.attempt-started")?.payload.recovery_policy_hash ?? null,
    },
    integrity: {
      ledger_sequence: ledger.sequence,
      ledger_head_hash: ledger.head_hash,
      ledger_bytes_hash: ledger.ledger_bytes_hash,
      manifest_hash: manifest.manifest_hash,
      manifest_projection_event_ref: manifest.projection_event_ref,
      pair_status: "matched" as const,
    },
    attempt: {
      current_attempt_ordinal: ledger.state.current_attempt_ordinal,
      current_attempt_event_ref: ledger.state.current_attempt_event_ref,
      history: attemptHistory(ledger),
    },
    fence: {
      current_fence_epoch: ledger.state.current_fence_epoch,
    },
    owner: ownerProjection(ownerStatus, ledger),
    actions: {
      in_flight_action_refs: inFlightActions(ledger),
      outcome_unknown_action_refs: unknownActions,
    },
    limits: {
      counters: counters.value,
      remaining: limitProjection.value.remaining,
      exhausted_limit_refs: limitProjection.value.exhausted_limit_refs,
      execution_attempts_exhausted: limitProjection.value.execution_attempts_exhausted,
    },
    progress,
    summary: summaryState,
    next_action: next,
  }) satisfies RuntimeStatusV04;

  return { ok: true, status };
}
