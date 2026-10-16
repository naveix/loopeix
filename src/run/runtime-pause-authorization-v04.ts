import { z } from "zod";

import { hashCanonical } from "../hash.js";
import { LedgerRefV02 } from "../schema/runtime.js";
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

const RuntimePauseRequestV04 = z.object({
  request_id: MachineIdV02,
}).strict();

type RuntimePauseRequestV04Value = Readonly<z.infer<typeof RuntimePauseRequestV04>>;
type LedgerRef = Readonly<z.infer<typeof LedgerRefV02>>;

const RuntimePauseAuthorizationInputV04 = z.object({
  trust_context: z.custom<CapturedAuthorityTrustContextForS36V02>(
    isCapturedAuthorityTrustContextV02,
  ),
  authorization_proof: HumanAuthorizationProofV02,
  validated_plan: z.custom<ValidatedRuntimePlanV03>(isValidatedRuntimePlanV03),
  ledger: z.custom<ValidatedRuntimeLedgerV04>(isValidatedRuntimeLedgerV04),
  manifest: z.custom<ValidatedRunManifestV04>(
    (value) => typeof value === "object" && value !== null,
  ),
  request: RuntimePauseRequestV04,
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

export type RuntimePauseAuthorizationSubjectV04 = Readonly<{
  purpose: "runtime-pause-request-v04";
  schema_version: "0.4";
  run_id: string;
  plan_hash: string;
  runtime_input_hash: string;
  runtime_recovery_policy_hash: string;
  source_boundary_sequence: number;
  source_boundary_head_hash: string;
  source_manifest_hash: string;
  request_id: string;
  requested_by: "operator";
  reason_code: "operator-request";
  current_attempt_event_ref: LedgerRef;
  run_owner_lease_event_ref: LedgerRef;
  current_fence_epoch: number;
  authority_envelope_hash: string;
}>;

export type RuntimePauseAuthorizationScopeV04 = Readonly<{
  purpose: "runtime-pause-scope-v04";
  schema_version: "0.4";
  operation: "pause";
  run_id: string;
  plan_hash: string;
  runtime_input_hash: string;
  runtime_recovery_policy_hash: string;
  request_id: string;
  requested_by: "operator";
  reason_code: "operator-request";
  current_attempt_event_ref: LedgerRef;
  run_owner_lease_event_ref: LedgerRef;
  current_fence_epoch: number;
  authority_envelope_hash: string;
}>;

export type CapturedRuntimePauseRequestBindingV04 = Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  run_id: string;
  plan_hash: string;
  runtime_input_hash: string;
  runtime_recovery_policy_hash: string;
  source_boundary_sequence: number;
  source_boundary_head_hash: string;
  source_manifest_hash: string;
  current_attempt_event_ref: LedgerRef;
  run_owner_lease_event_ref: LedgerRef;
  current_fence_epoch: number;
  authority_envelope_hash: string;
  request: Readonly<{
    request_id: string;
    requested_by: "operator";
    reason_code: "operator-request";
  }>;
  authorization_subject_hash: string;
  action_scope_hash: string;
  authorization_id: string;
  authority_ref: string;
  proof_record_hash: string;
  revocation_epoch: number;
  expires_at: string;
  approved_risk_tier: keyof typeof RISK_TIER_RANK;
}>;

class CapturedRuntimePauseRequestTokenV04 {
  readonly #capturedRuntimePauseRequestV04 = true;

  private constructor() {
    void this.#capturedRuntimePauseRequestV04;
    Object.freeze(this);
  }

  static create(): CapturedRuntimePauseRequestTokenV04 {
    return new CapturedRuntimePauseRequestTokenV04();
  }
}

export type CapturedRuntimePauseRequestV04 = CapturedRuntimePauseRequestTokenV04;

export type CaptureRuntimePauseRequestResultV04 =
  | Readonly<{ ok: true; value: CapturedRuntimePauseRequestV04 }>
  | Readonly<{ ok: false; error: "RUNTIME_PAUSE_REQUEST_AUTHORIZATION_INVALID" }>;

const capturedPauseRequests = new WeakMap<object, CapturedRuntimePauseRequestBindingV04>();
const INVALID_CAPTURE = Object.freeze({
  ok: false,
  error: "RUNTIME_PAUSE_REQUEST_AUTHORIZATION_INVALID",
} as const);

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

function refEquals(left: LedgerRef, right: LedgerRef): boolean {
  return left.ledger_sequence === right.ledger_sequence
    && left.event_hash === right.event_hash;
}

function isExactDataRecord(value: unknown, keys: readonly string[]): boolean {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    if (Object.getOwnPropertySymbols(value).length !== 0) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const names = Object.keys(descriptors).sort();
    if (names.length !== keys.length
      || names.some((name, index) => name !== [...keys].sort()[index])) return false;
    return Object.values(descriptors).every(
      (descriptor) => "value" in descriptor && descriptor.get === undefined && descriptor.set === undefined,
    );
  } catch {
    return false;
  }
}

function currentAttempt(input: Readonly<{
  ledger: ValidatedRuntimeLedgerV04;
  validated_plan: ValidatedRuntimePlanV03;
}>): Readonly<{
  event_ref: LedgerRef;
  authority_envelope_hash: string;
}> | null {
  const reference = input.ledger.state.current_attempt_event_ref;
  if (reference === null) return null;
  const event = input.ledger.events[reference.ledger_sequence - 1];
  if (event?.event_hash !== reference.event_hash
    || event.event_type !== "execution.attempt-started"
    || event.payload.plan_hash !== input.validated_plan.plan_hash
    || event.payload.input_hash !== input.validated_plan.plan.runtime_input_hash
    || event.payload.recovery_policy_hash !== input.validated_plan.plan.runtime_recovery_policy_hash) {
    return null;
  }
  return {
    event_ref: freezeDeep(structuredClone(reference)),
    authority_envelope_hash: event.payload.authority_envelope_hash,
  };
}

function hasPendingPause(ledger: ValidatedRuntimeLedgerV04): boolean {
  let latestRequest = -1;
  let latestCompletion = -1;
  ledger.events.forEach((event, index) => {
    if (event.event_type === "control.pause-requested") latestRequest = index;
    if (event.event_type === "run.paused") latestCompletion = index;
  });
  return latestRequest > latestCompletion;
}

function boundFacts(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
}>): Readonly<{
  attempt_ref: LedgerRef;
  owner_ref: LedgerRef;
  fence_epoch: number;
  authority_envelope_hash: string;
  head_sequence: number;
  head_hash: string;
  manifest_hash: string;
}> | null {
  const { validated_plan: plan, ledger, manifest } = input;
  if (!isValidatedRuntimePlanV03(plan)
    || !isValidatedRunManifestPairV04(manifest, ledger)
    || plan.run_id !== ledger.run_id
    || plan.run_id !== manifest.run_id
    || plan.plan_hash !== ledger.plan_hash
    || plan.plan_hash !== manifest.plan_hash
    || ledger.state.state !== "running"
    || ledger.state.terminal_sealed
    || ledger.state.pending_resume_request !== null
    || hasPendingPause(ledger)) return null;
  const attempt = currentAttempt({ ledger, validated_plan: plan });
  const owner = ledger.state.active_run_owner;
  const head = ledger.events.at(-1);
  if (attempt === null
    || owner === null
    || !owner.active
    || owner.released
    || head === undefined
    || !refEquals(owner.attempt_event_ref, attempt.event_ref)
    || !refEquals(owner.lease_event_ref, attempt.event_ref)
    || owner.fence_epoch !== ledger.state.current_fence_epoch) return null;
  return {
    attempt_ref: attempt.event_ref,
    owner_ref: freezeDeep(structuredClone(owner.lease_event_ref)),
    fence_epoch: ledger.state.current_fence_epoch,
    authority_envelope_hash: attempt.authority_envelope_hash,
    head_sequence: head.sequence,
    head_hash: head.event_hash,
    manifest_hash: manifest.manifest_hash,
  };
}

function subjectPreimage(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  request: RuntimePauseRequestV04Value;
}>): RuntimePauseAuthorizationSubjectV04 | null {
  const facts = boundFacts(input);
  if (facts === null) return null;
  return {
    purpose: "runtime-pause-request-v04",
    schema_version: "0.4",
    run_id: input.validated_plan.run_id,
    plan_hash: input.validated_plan.plan_hash,
    runtime_input_hash: input.validated_plan.plan.runtime_input_hash,
    runtime_recovery_policy_hash: input.validated_plan.plan.runtime_recovery_policy_hash,
    source_boundary_sequence: facts.head_sequence,
    source_boundary_head_hash: facts.head_hash,
    source_manifest_hash: facts.manifest_hash,
    request_id: input.request.request_id,
    requested_by: "operator",
    reason_code: "operator-request",
    current_attempt_event_ref: facts.attempt_ref,
    run_owner_lease_event_ref: facts.owner_ref,
    current_fence_epoch: facts.fence_epoch,
    authority_envelope_hash: facts.authority_envelope_hash,
  };
}

function scopePreimage(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  request: RuntimePauseRequestV04Value;
}>): RuntimePauseAuthorizationScopeV04 | null {
  const facts = boundFacts(input);
  if (facts === null) return null;
  return {
    purpose: "runtime-pause-scope-v04",
    schema_version: "0.4",
    operation: "pause",
    run_id: input.validated_plan.run_id,
    plan_hash: input.validated_plan.plan_hash,
    runtime_input_hash: input.validated_plan.plan.runtime_input_hash,
    runtime_recovery_policy_hash: input.validated_plan.plan.runtime_recovery_policy_hash,
    request_id: input.request.request_id,
    requested_by: "operator",
    reason_code: "operator-request",
    current_attempt_event_ref: facts.attempt_ref,
    run_owner_lease_event_ref: facts.owner_ref,
    current_fence_epoch: facts.fence_epoch,
    authority_envelope_hash: facts.authority_envelope_hash,
  };
}

/** RFC 8785 canonical hash of one exact operator pause request boundary. */
export function hashRuntimePauseAuthorizationSubjectV04(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  request: RuntimePauseRequestV04Value;
}>): string | null {
  try {
    const parsedRequest = RuntimePauseRequestV04.safeParse(input.request);
    if (!parsedRequest.success) return null;
    const preimage = subjectPreimage({ ...input, request: parsedRequest.data });
    return preimage === null ? null : hashCanonical(preimage);
  } catch {
    return null;
  }
}

/** RFC 8785 canonical hash of the exact pause operation scope. */
export function hashRuntimePauseActionScopeV04(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  request: RuntimePauseRequestV04Value;
}>): string | null {
  try {
    const parsedRequest = RuntimePauseRequestV04.safeParse(input.request);
    if (!parsedRequest.success) return null;
    const preimage = scopePreimage({ ...input, request: parsedRequest.data });
    return preimage === null ? null : hashCanonical(preimage);
  } catch {
    return null;
  }
}

/** Captures one verified operator pause proof as a package-private opaque capability. */
export function captureRuntimePauseRequestV04(
  input: unknown,
): CaptureRuntimePauseRequestResultV04 {
  try {
    if (!isExactDataRecord(input, [
      "trust_context",
      "authorization_proof",
      "validated_plan",
      "ledger",
      "manifest",
      "request",
    ])) return INVALID_CAPTURE;
    const untrusted = input as Readonly<Record<string, unknown>>;
    if (!isExactDataRecord(untrusted.request, ["request_id"])) return INVALID_CAPTURE;
    const parsed = RuntimePauseAuthorizationInputV04.safeParse(input);
    if (!parsed.success) return INVALID_CAPTURE;
    const value = parsed.data;
    const facts = boundFacts(value);
    if (facts === null) return INVALID_CAPTURE;
    const subjectHash = hashRuntimePauseAuthorizationSubjectV04(value);
    const scopeHash = hashRuntimePauseActionScopeV04(value);
    const proof = value.authorization_proof;
    if (subjectHash === null
      || scopeHash === null
      || !verifyHumanAuthorizationProofV02(value.trust_context, proof).ok
      || proof.run_id !== value.validated_plan.run_id
      || proof.plan_hash !== value.validated_plan.plan_hash
      || RISK_TIER_RANK[proof.approved_risk_tier] < RISK_TIER_RANK.T1
      || proof.authorization_subject_hash !== subjectHash
      || proof.action_scope_hash !== scopeHash) return INVALID_CAPTURE;

    const binding = freezeDeep({
      validated_plan: value.validated_plan,
      ledger: value.ledger,
      manifest: value.manifest,
      run_id: value.validated_plan.run_id,
      plan_hash: value.validated_plan.plan_hash,
      runtime_input_hash: value.validated_plan.plan.runtime_input_hash,
      runtime_recovery_policy_hash: value.validated_plan.plan.runtime_recovery_policy_hash,
      source_boundary_sequence: facts.head_sequence,
      source_boundary_head_hash: facts.head_hash,
      source_manifest_hash: facts.manifest_hash,
      current_attempt_event_ref: facts.attempt_ref,
      run_owner_lease_event_ref: facts.owner_ref,
      current_fence_epoch: facts.fence_epoch,
      authority_envelope_hash: facts.authority_envelope_hash,
      request: {
        request_id: value.request.request_id,
        requested_by: "operator",
        reason_code: "operator-request",
      },
      authorization_subject_hash: subjectHash,
      action_scope_hash: scopeHash,
      authorization_id: proof.authorization_id,
      authority_ref: proof.authenticated_principal_ref,
      proof_record_hash: proof.record_hash,
      revocation_epoch: proof.revocation_epoch,
      expires_at: proof.expires_at,
      approved_risk_tier: proof.approved_risk_tier,
    }) satisfies CapturedRuntimePauseRequestBindingV04;
    const capability = CapturedRuntimePauseRequestTokenV04.create();
    capturedPauseRequests.set(capability, binding);
    return Object.freeze({ ok: true, value: capability });
  } catch {
    return INVALID_CAPTURE;
  }
}

function copyBinding(
  binding: CapturedRuntimePauseRequestBindingV04,
): CapturedRuntimePauseRequestBindingV04 {
  return freezeDeep({
    ...binding,
    current_attempt_event_ref: structuredClone(binding.current_attempt_event_ref),
    run_owner_lease_event_ref: structuredClone(binding.run_owner_lease_event_ref),
    request: structuredClone(binding.request),
  });
}

/** Package-internal, non-consuming bridge for planning and safe pre-write retries. */
export function inspectCapturedRuntimePauseRequestV04(
  capability: unknown,
): CapturedRuntimePauseRequestBindingV04 | null {
  if ((typeof capability !== "object" && typeof capability !== "function")
    || capability === null) return null;
  const binding = capturedPauseRequests.get(capability);
  return binding === undefined ? null : copyBinding(binding);
}

/** Package-internal exactly-once bridge for the eventual durable pause writer. */
export function consumeCapturedRuntimePauseRequestV04(
  capability: unknown,
): CapturedRuntimePauseRequestBindingV04 | null {
  if ((typeof capability !== "object" && typeof capability !== "function")
    || capability === null) return null;
  const binding = capturedPauseRequests.get(capability);
  if (binding === undefined) return null;
  capturedPauseRequests.delete(capability);
  return copyBinding(binding);
}
