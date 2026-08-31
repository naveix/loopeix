import { z } from "zod";

import { hashCanonical } from "../hash.js";
import { LedgerRefV02 } from "../schema/runtime.js";
import { Hash } from "../schema/scalars.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import {
  isValidatedRuntimePlanV03,
  type ValidatedRuntimePlanV03,
} from "./project-plan-v03.js";
import {
  HumanAuthorizationProofV02,
  isCapturedAuthorityTrustContextV02,
  verifyHumanAuthorizationProofV02,
  type CapturedAuthorityTrustContextForS36V02,
} from "./runtime-record-admission-v02.js";
import {
  isValidatedRuntimeLedgerV04,
  type ValidatedRuntimeLedgerV04,
} from "./runtime-ledger-v04.js";
import {
  isValidatedRunManifestPairV04,
  type ValidatedRunManifestV04,
} from "./runtime-manifest-v04.js";
import {
  consumeApprovedRepositoryObservationV02,
  type ApprovedRepositoryObservationV02,
} from "./repository-observation-v02.js";

export const RuntimeRecoveryRequestIntentV04 = z.discriminatedUnion("requested_mode", [
  z.object({
    request_id: MachineIdV02,
    requested_mode: z.literal("ordinary"),
    resume_nonce_hash: Hash,
    authority_envelope_hash: Hash,
    target_action_admission_ref: z.null(),
    compensation_phase_event_ref: z.null(),
  }).strict(),
  z.object({
    request_id: MachineIdV02,
    requested_mode: z.literal("reconciliation-only"),
    resume_nonce_hash: Hash,
    authority_envelope_hash: Hash,
    target_action_admission_ref: LedgerRefV02,
    compensation_phase_event_ref: z.null(),
  }).strict(),
  z.object({
    request_id: MachineIdV02,
    requested_mode: z.literal("compensation-continuation"),
    resume_nonce_hash: Hash,
    authority_envelope_hash: Hash,
    target_action_admission_ref: z.null(),
    compensation_phase_event_ref: LedgerRefV02,
  }).strict(),
]);

export type RuntimeRecoveryRequestIntentV04Value = Readonly<
  z.infer<typeof RuntimeRecoveryRequestIntentV04>
>;

const RuntimeRecoveryAuthorizationInputV04 = z.object({
  trust_context: z.custom<CapturedAuthorityTrustContextForS36V02>(
    isCapturedAuthorityTrustContextV02,
  ),
  authorization_proof: HumanAuthorizationProofV02,
  validated_plan: z.custom<ValidatedRuntimePlanV03>(isValidatedRuntimePlanV03),
  ledger: z.custom<ValidatedRuntimeLedgerV04>(isValidatedRuntimeLedgerV04),
  manifest: z.custom<ValidatedRunManifestV04>(
    (value) => typeof value === "object" && value !== null,
  ),
  repository_observation: z.custom<ApprovedRepositoryObservationV02>(
    (value) => typeof value === "object" && value !== null,
  ),
  request: RuntimeRecoveryRequestIntentV04,
}).strict();

const RISK_TIER_RANK = Object.freeze({
  T0: 0,
  T1: 1,
  T2: 2,
  T3a: 3,
  T3b: 4,
  T3c: 5,
  T3d: 6,
  T4: 7,
} as const);

type LedgerRef = Readonly<z.infer<typeof LedgerRefV02>>;

export type RuntimeRecoveryAuthorizationSubjectV04 = Readonly<{
  purpose: "runtime-recovery-request-v04";
  schema_version: "0.4";
  run_id: string;
  plan_hash: string;
  runtime_input_hash: string;
  runtime_recovery_policy_hash: string;
  current_repository_state_hash: string;
  source_boundary_sequence: number;
  source_boundary_head_hash: string;
  source_manifest_hash: string;
  request_id: string;
  mode: RuntimeRecoveryRequestIntentV04Value["requested_mode"];
  resume_nonce_hash: string;
  authority_envelope_hash: string;
  target_action_admission_ref: LedgerRef | null;
  compensation_phase_event_ref: LedgerRef | null;
}>;

export type RuntimeRecoveryAuthorizationScopeV04 = Readonly<{
  purpose: "runtime-recovery-scope-v04";
  schema_version: "0.4";
  operation: "resume";
  run_id: string;
  plan_hash: string;
  runtime_input_hash: string;
  runtime_recovery_policy_hash: string;
  current_repository_state_hash: string;
  mode: RuntimeRecoveryRequestIntentV04Value["requested_mode"];
  authority_envelope_hash: string;
  target_action_admission_ref: LedgerRef | null;
  compensation_phase_event_ref: LedgerRef | null;
}>;

export type CapturedRuntimeRecoveryRequestBindingV04 = Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  run_id: string;
  plan_hash: string;
  current_repository_state_hash: string;
  expected_repository_state_hash: string;
  source_boundary_sequence: number;
  source_boundary_head_hash: string;
  source_manifest_hash: string;
  current_attempt_event_ref: LedgerRef;
  request: RuntimeRecoveryRequestIntentV04Value;
  authorization_subject_hash: string;
  action_scope_hash: string;
  authorization_id: string;
  authority_ref: string;
  proof_record_hash: string;
  revocation_epoch: number;
  expires_at: string;
  approved_risk_tier: keyof typeof RISK_TIER_RANK;
}>;

class CapturedRuntimeRecoveryRequestTokenV04 {
  readonly #capturedRuntimeRecoveryRequestV04 = true;

  private constructor() {
    void this.#capturedRuntimeRecoveryRequestV04;
    Object.freeze(this);
  }

  static create(): CapturedRuntimeRecoveryRequestTokenV04 {
    return new CapturedRuntimeRecoveryRequestTokenV04();
  }
}

export type CapturedRuntimeRecoveryRequestV04 = CapturedRuntimeRecoveryRequestTokenV04;

export type CaptureRuntimeRecoveryRequestResultV04 =
  | Readonly<{ ok: true; value: CapturedRuntimeRecoveryRequestV04 }>
  | Readonly<{
      ok: false;
      error: "RUNTIME_RECOVERY_REQUEST_AUTHORIZATION_INVALID";
    }>;

const capturedRecoveryRequests = new WeakMap<
  object,
  CapturedRuntimeRecoveryRequestBindingV04
>();

const INVALID_CAPTURE = Object.freeze({
  ok: false,
  error: "RUNTIME_RECOVERY_REQUEST_AUTHORIZATION_INVALID",
} as const);

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function cloneRequest(
  request: RuntimeRecoveryRequestIntentV04Value,
): RuntimeRecoveryRequestIntentV04Value {
  return deepFreeze(structuredClone(request));
}

function referenceAt(
  ledger: ValidatedRuntimeLedgerV04,
  reference: LedgerRef,
) {
  const event = ledger.events[reference.ledger_sequence - 1];
  return event?.event_hash === reference.event_hash ? event : null;
}

function currentAttempt(
  ledger: ValidatedRuntimeLedgerV04,
): Readonly<{
  event_ref: LedgerRef;
  authority_envelope_hash: string;
  plan_hash: string;
  input_hash: string;
  recovery_policy_hash: string;
}> | null {
  const reference = ledger.state.current_attempt_event_ref;
  if (reference === null) return null;
  const event = referenceAt(ledger, reference);
  if (event?.event_type !== "execution.attempt-started") return null;
  return {
    event_ref: deepFreeze(structuredClone(reference)),
    authority_envelope_hash: event.payload.authority_envelope_hash,
    plan_hash: event.payload.plan_hash,
    input_hash: event.payload.input_hash,
    recovery_policy_hash: event.payload.recovery_policy_hash,
  };
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

function requestReferencesAreValid(
  ledger: ValidatedRuntimeLedgerV04,
  request: RuntimeRecoveryRequestIntentV04Value,
): boolean {
  if (request.requested_mode === "reconciliation-only") {
    const target = referenceAt(ledger, request.target_action_admission_ref);
    return target?.event_type === "task.action-admitted"
      && ledger.state.in_flight_action_ids.includes(
        (target.payload as Readonly<{ action_id: string }>).action_id,
      );
  }
  if (request.requested_mode === "compensation-continuation") {
    return referenceAt(ledger, request.compensation_phase_event_ref)?.event_type
      === "run.compensation-phase-entered";
  }
  return true;
}

function subjectPreimage(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  request: RuntimeRecoveryRequestIntentV04Value;
  repository_observation: ApprovedRepositoryObservationV02;
}>): RuntimeRecoveryAuthorizationSubjectV04 | null {
  const head = input.ledger.events.at(-1);
  if (head === undefined) return null;
  return {
    purpose: "runtime-recovery-request-v04",
    schema_version: "0.4",
    run_id: input.validated_plan.run_id,
    plan_hash: input.validated_plan.plan_hash,
    runtime_input_hash: input.validated_plan.plan.runtime_input_hash,
    runtime_recovery_policy_hash: input.validated_plan.plan.runtime_recovery_policy_hash,
    current_repository_state_hash: input.repository_observation.repository_state_hash,
    source_boundary_sequence: head.sequence,
    source_boundary_head_hash: head.event_hash,
    source_manifest_hash: input.manifest.manifest_hash,
    request_id: input.request.request_id,
    mode: input.request.requested_mode,
    resume_nonce_hash: input.request.resume_nonce_hash,
    authority_envelope_hash: input.request.authority_envelope_hash,
    target_action_admission_ref: input.request.target_action_admission_ref,
    compensation_phase_event_ref: input.request.compensation_phase_event_ref,
  };
}

function scopePreimage(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  request: RuntimeRecoveryRequestIntentV04Value;
  repository_observation: ApprovedRepositoryObservationV02;
}>): RuntimeRecoveryAuthorizationScopeV04 {
  return {
    purpose: "runtime-recovery-scope-v04",
    schema_version: "0.4",
    operation: "resume",
    run_id: input.validated_plan.run_id,
    plan_hash: input.validated_plan.plan_hash,
    runtime_input_hash: input.validated_plan.plan.runtime_input_hash,
    runtime_recovery_policy_hash: input.validated_plan.plan.runtime_recovery_policy_hash,
    current_repository_state_hash: input.repository_observation.repository_state_hash,
    mode: input.request.requested_mode,
    authority_envelope_hash: input.request.authority_envelope_hash,
    target_action_admission_ref: input.request.target_action_admission_ref,
    compensation_phase_event_ref: input.request.compensation_phase_event_ref,
  };
}

/** RFC 8785 canonical hash of the exact S41 recovery authorization subject. */
export function hashRuntimeRecoveryAuthorizationSubjectV04(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  request: RuntimeRecoveryRequestIntentV04Value;
  repository_observation: ApprovedRepositoryObservationV02;
}>): string | null {
  if (!isValidatedRuntimePlanV03(input.validated_plan)
    || !isValidatedRunManifestPairV04(input.manifest, input.ledger)) return null;
  const preimage = subjectPreimage(input);
  return preimage === null ? null : hashCanonical(preimage);
}

/** RFC 8785 canonical hash of the exact S41 recovery operation scope. */
export function hashRuntimeRecoveryActionScopeV04(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  request: RuntimeRecoveryRequestIntentV04Value;
  repository_observation: ApprovedRepositoryObservationV02;
}>): string | null {
  if (!isValidatedRuntimePlanV03(input.validated_plan)) return null;
  return hashCanonical(scopePreimage(input));
}

/**
 * Converts a verified S36 human authorization proof into a non-forgeable S41
 * recovery-request capability bound to one exact durable V04 source boundary.
 */
export function captureRuntimeRecoveryRequestV04(
  input: unknown,
): CaptureRuntimeRecoveryRequestResultV04 {
  try {
    const parsed = RuntimeRecoveryAuthorizationInputV04.safeParse(input);
    if (!parsed.success) return INVALID_CAPTURE;
    const value = parsed.data;
    const { validated_plan: plan, ledger, manifest, repository_observation: repositoryObservation, request } = value;
    if (!isValidatedRunManifestPairV04(manifest, ledger)
      || plan.run_id !== ledger.run_id
      || plan.run_id !== manifest.run_id
      || plan.plan_hash !== ledger.plan_hash
      || plan.plan_hash !== manifest.plan_hash
      || manifest.ledger_sequence !== ledger.sequence
      || manifest.ledger_head_hash !== ledger.head_hash) return INVALID_CAPTURE;
    const attempt = currentAttempt(ledger);
    const head = ledger.events.at(-1);
    if (attempt === null
      || head === undefined
      || attempt.plan_hash !== plan.plan_hash
      || attempt.input_hash !== plan.plan.runtime_input_hash
      || attempt.recovery_policy_hash !== plan.plan.runtime_recovery_policy_hash
      || request.authority_envelope_hash !== attempt.authority_envelope_hash
      || !requestReferencesAreValid(ledger, request)) return INVALID_CAPTURE;
    const observedRepository = consumeApprovedRepositoryObservationV02(repositoryObservation);
    if (observedRepository === null
      || observedRepository.repository_state_hash !== repositoryObservation.repository_state_hash) {
      return INVALID_CAPTURE;
    }
    const expectedRepositoryHash = expectedRepositoryStateHash(plan, ledger);
    const proof = value.authorization_proof;
    const authorizationSubjectHash = hashRuntimeRecoveryAuthorizationSubjectV04({
      validated_plan: plan,
      ledger,
      manifest,
      request,
      repository_observation: repositoryObservation,
    });
    const actionScopeHash = hashRuntimeRecoveryActionScopeV04({
      validated_plan: plan,
      request,
      repository_observation: repositoryObservation,
    });
    if (authorizationSubjectHash === null
      || actionScopeHash === null
      || !verifyHumanAuthorizationProofV02(value.trust_context, proof).ok
      || proof.run_id !== plan.run_id
      || proof.plan_hash !== plan.plan_hash
      || RISK_TIER_RANK[proof.approved_risk_tier] < RISK_TIER_RANK.T1
      || proof.authorization_subject_hash !== authorizationSubjectHash
      || proof.action_scope_hash !== actionScopeHash) return INVALID_CAPTURE;

    const storedRequest = cloneRequest(request);
    const binding = deepFreeze({
      validated_plan: plan,
      ledger,
      manifest,
      run_id: plan.run_id,
      plan_hash: plan.plan_hash,
      current_repository_state_hash: observedRepository.repository_state_hash,
      expected_repository_state_hash: expectedRepositoryHash,
      source_boundary_sequence: head.sequence,
      source_boundary_head_hash: head.event_hash,
      source_manifest_hash: manifest.manifest_hash,
      current_attempt_event_ref: attempt.event_ref,
      request: storedRequest,
      authorization_subject_hash: authorizationSubjectHash,
      action_scope_hash: actionScopeHash,
      authorization_id: proof.authorization_id,
      authority_ref: proof.authenticated_principal_ref,
      proof_record_hash: proof.record_hash,
      revocation_epoch: proof.revocation_epoch,
      expires_at: proof.expires_at,
      approved_risk_tier: proof.approved_risk_tier,
    }) satisfies CapturedRuntimeRecoveryRequestBindingV04;
    const capability = CapturedRuntimeRecoveryRequestTokenV04.create();
    capturedRecoveryRequests.set(capability, binding);
    return Object.freeze({ ok: true, value: capability });
  } catch {
    return INVALID_CAPTURE;
  }
}

function copyCapturedBinding(
  binding: CapturedRuntimeRecoveryRequestBindingV04,
): CapturedRuntimeRecoveryRequestBindingV04 {
  return deepFreeze({
    ...binding,
    current_attempt_event_ref: structuredClone(binding.current_attempt_event_ref),
    request: structuredClone(binding.request),
  });
}

/** Package-internal, non-consuming bridge for planning before mutation. */
export function inspectCapturedRuntimeRecoveryRequestV04(
  capability: unknown,
): CapturedRuntimeRecoveryRequestBindingV04 | null {
  if ((typeof capability !== "object" && typeof capability !== "function")
    || capability === null) return null;
  const binding = capturedRecoveryRequests.get(capability);
  return binding === undefined ? null : copyCapturedBinding(binding);
}

/** Package-internal exactly-once bridge for the durable recovery writer. */
export function consumeCapturedRuntimeRecoveryRequestV04(
  capability: unknown,
): CapturedRuntimeRecoveryRequestBindingV04 | null {
  if ((typeof capability !== "object" && typeof capability !== "function")
    || capability === null) return null;
  const binding = capturedRecoveryRequests.get(capability);
  if (binding === undefined) return null;
  capturedRecoveryRequests.delete(capability);
  return copyCapturedBinding(binding);
}
