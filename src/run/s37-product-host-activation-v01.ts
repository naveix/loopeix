import { isProxy } from "node:util/types";

import { z } from "zod";

import { hashCanonical, hashRawBytes } from "../hash.js";
import { Hash, IsoTimestamp, MachineId } from "../schema/scalars.js";
import {
  HumanAuthorizationProofV02,
  verifyHumanAuthorizationProofV02,
  type CapturedAuthorityTrustContextForS36V02,
  type HumanAuthorizationProofV02Value,
} from "./runtime-record-admission-v02.js";
import {
  consumeAuthorizedS37LinuxLaunchQualificationV03,
  type AuthorizedS37LinuxLaunchQualificationV03,
} from "./s37-linux-launch-qualification-v03.js";
import { parseS37ProductHostInstallBundleV01 } from "./s37-product-host-contract-v03.js";
import {
  beginS37ProductHostAuthoritySessionV01,
  closeS37ProductHostActivationStoreSessionV01,
  commitS37ProductHostActivationEventV01,
  inspectS37ProductHostActivationStoreSessionV01,
  reconcileS37ProductHostActivationStoreV01 as reconcileStore,
  captureS37ProductHostActivationStoreV01,
  disposeS37ProductHostActivationStoreV01,
  type S37ProductHostActivationStoreSessionV01,
} from "./s37-product-host-activation-store-v01.js";

const ActivationId = z.string().regex(/^activation_[a-f0-9]{64}$/u);
const safePositive = z.number().int().positive().refine(Number.isSafeInteger);
const safeNonnegative = z.number().int().nonnegative().refine(Number.isSafeInteger);
const Operation = z.enum(["install-and-launch", "transition-and-launch", "launch-stable"]);
const RiskT4 = z.literal("T4");
const ExactUtcSecond = IsoTimestamp.refine((value) => new Date(Date.parse(value)).toISOString().replace(".000Z", "Z") === value);
const QualificationIntentV01 = z.object({
  schema_version: z.literal("s37-product-host-qualification-intent-v01"),
  product_profile: z.literal("s37-local-product-inert-v03"),
  anchor_subject_hash: Hash,
  anchor_generation: safePositive,
  runtime_profile_hash: Hash,
  launch_nonce: Hash,
  requested_at: ExactUtcSecond,
  expires_at: ExactUtcSecond,
  intent_hash: Hash,
}).strict();
const LocalProofRequestV02 = z.object({
  authorization_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  authorization_subject_hash: Hash,
  authenticated_principal_ref: MachineId,
  action_scope_hash: Hash,
  approved_risk_tier: RiskT4,
  operator_key_id: MachineId,
  approval_nonce: Hash,
  issued_at: ExactUtcSecond,
  expires_at: ExactUtcSecond,
  revocation_epoch: safeNonnegative,
}).strict();

const PrelaunchRevalidationFields = z.object({
  schema_version: z.literal("s37-product-host-prelaunch-authorization-revalidation-v01"),
  activation_id: ActivationId,
  event_four_hash: Hash,
  action_scope_hash: Hash,
  proof_record_hash: Hash,
  authorization_statement_hash: Hash,
  authenticated_principal_ref: MachineId,
  operator_key_id: MachineId,
  approved_risk_tier: RiskT4,
  revocation_epoch: safeNonnegative,
  qualification_intent_hash: Hash,
  qualification_hash: Hash,
  conformance_receipt_hash: Hash,
  anchor_generation: safePositive,
  anchor_hash: Hash,
  artifact_set_hash: Hash,
  controller_identity_hash: Hash,
  broker_profile_hash: Hash,
  boot_id_hash: Hash,
  fence_epoch: safePositive,
  revalidated_at: IsoTimestamp,
  valid_until: IsoTimestamp,
}).strict();

const PrelaunchRevalidation = PrelaunchRevalidationFields.extend({
  prelaunch_authorization_revalidation_hash: Hash,
}).strict();

const FinalObservationFields = z.object({
  schema_version: z.literal("s37-product-host-final-observation-v01"),
  activation_id: ActivationId,
  activation_request_hash: Hash,
  event_four_hash: Hash,
  anchor_generation: safePositive,
  anchor_hash: Hash,
  boot_id_hash: Hash,
  host_tuple_hash: Hash,
  systemd_run_hash: Hash,
  runtime_profile_hash: Hash,
  artifact_set_hash: Hash,
  controller_uid: safePositive,
  primary_gid: safePositive,
  controller_identity_hash: Hash,
  broker_profile_hash: Hash,
  conformance_receipt_hash: Hash,
  qualification_hash: Hash,
  unit_name_hash: Hash,
  cgroup_path_hash: Hash,
  prelaunch_authorization_revalidation_hash: Hash,
  prelaunch_authorization_valid_until: IsoTimestamp,
  prelaunch_absence_observation_hash: Hash,
  fence_epoch: safePositive,
  observed_at: IsoTimestamp,
}).strict();

const FinalObservation = FinalObservationFields.extend({ final_observation_hash: Hash }).strict();

const BrokerRequestFields = z.object({
  schema_version: z.literal("s37-product-host-broker-request-v01"),
  activation_id: ActivationId,
  activation_request_hash: Hash,
  operation: Operation,
  event_four_hash: Hash,
  anchor_generation: safePositive,
  anchor_hash: Hash,
  boot_id_hash: Hash,
  fence_epoch: safePositive,
  runtime_profile_hash: Hash,
  artifact_set_hash: Hash,
  controller_uid: safePositive,
  primary_gid: safePositive,
  controller_identity_hash: Hash,
  qualification_hash: Hash,
  final_observation_hash: Hash,
  conformance_receipt_hash: Hash,
  broker_profile_hash: Hash,
  systemd_run_hash: Hash,
  supervisor_hash: Hash,
  bwrap_hash: Hash,
  probe_hash: Hash,
  seccomp_policy_hash: Hash,
  unit_name: z.string().min(1),
  cgroup_path: z.string().min(1),
  command: z.string().min(1),
  argv: z.array(z.string()).readonly(),
  cwd: z.string().min(1),
  environment: z.record(z.string(), z.string()),
  stdio: z.tuple([z.literal("ignore"), z.literal("ignore"), z.literal("ignore")]),
  no_retry: z.literal(true),
  broker_deadline_ms: z.literal(5_000),
  prelaunch_authorization_valid_until: IsoTimestamp,
}).strict();

const BrokerRequest = BrokerRequestFields.extend({ broker_request_hash: Hash }).strict();

const LaunchAdmissionFields = z.object({
  schema_version: z.literal("s37-product-host-launch-admission-v01"),
  activation_id: ActivationId,
  activation_request_hash: Hash,
  operation: Operation,
  event_one_hash: Hash,
  event_two_hash: Hash,
  event_three_hash: Hash,
  event_four_hash: Hash,
  authorization_nonce_record_hash: Hash,
  launch_nonce_record_hash: Hash,
  qualification_nonce_record_hash: Hash,
  anchor_generation: safePositive,
  anchor_hash: Hash,
  boot_id_hash: Hash,
  controller_uid: safePositive,
  primary_gid: safePositive,
  controller_identity_hash: Hash,
  fence_epoch: safePositive,
  qualification_intent_hash: Hash,
  activation_decision_facts_hash: Hash,
  decision_input_hash: Hash,
  decision_simulation_hash: Hash,
  lease_simulation_hash: Hash,
  qualification_request_hash: Hash,
  qualification_hash: Hash,
  prelaunch_authorization_revalidation_hash: Hash,
  prelaunch_authorization_valid_until: IsoTimestamp,
  final_observation_hash: Hash,
  conformance_receipt_hash: Hash,
  broker_profile_hash: Hash,
  broker_request_hash: Hash,
}).strict();

const LaunchAdmission = LaunchAdmissionFields.extend({ launch_admission_hash: Hash }).strict();

const PostCommitRevalidationFields = z.object({
  schema_version: z.literal("s37-product-host-post-commit-authorization-revalidation-v01"),
  activation_id: ActivationId,
  event_five_hash: Hash,
  manifest_hash: Hash,
  prelaunch_authorization_revalidation_hash: Hash,
  action_scope_hash: Hash,
  proof_record_hash: Hash,
  authorization_statement_hash: Hash,
  authenticated_principal_ref: MachineId,
  operator_key_id: MachineId,
  approved_risk_tier: RiskT4,
  revocation_epoch: safeNonnegative,
  anchor_generation: safePositive,
  anchor_hash: Hash,
  artifact_set_hash: Hash,
  controller_identity_hash: Hash,
  broker_profile_hash: Hash,
  boot_id_hash: Hash,
  fence_epoch: safePositive,
  conformance_receipt_hash: Hash,
  qualification_hash: Hash,
  revalidated_at: IsoTimestamp,
  valid_until: IsoTimestamp,
}).strict();

const PostCommitRevalidation = PostCommitRevalidationFields.extend({
  post_commit_authorization_revalidation_hash: Hash,
}).strict();

type Prelaunch = z.infer<typeof PrelaunchRevalidation>;
type FinalObservationValue = z.infer<typeof FinalObservation>;
type BrokerRequestValue = z.infer<typeof BrokerRequest>;
type LaunchAdmissionValue = z.infer<typeof LaunchAdmission>;
type PostCommit = z.infer<typeof PostCommitRevalidation>;

export type ClosedS37ActivationOutcomeV01 = Readonly<
  | { ok: true; outcome: "COMPLETED"; activation_id: string; evidence_hash: string }
  | { ok: false; outcome: "NOT_STARTED" | "NOT_COMMITTED" | "RECOVERY_REQUIRED" | "OUTCOME_UNKNOWN"; activation_id: string | null; evidence_hash: string | null }
>;

class AuthorizedS37ProductHostLaunchTokenV01 {
  readonly #brand = true;
  private constructor() { void this.#brand; Object.freeze(this); }
  static create(): AuthorizedS37ProductHostLaunchTokenV01 { return new AuthorizedS37ProductHostLaunchTokenV01(); }
}

export type AuthorizedS37ProductHostLaunchV01 = AuthorizedS37ProductHostLaunchTokenV01;

type LaunchAuthorizationBinding = Readonly<{
  proof: HumanAuthorizationProofV02Value;
  action_scope_hash: string;
  anchor_subject_hash: string;
}>;

const launchAuthorizations = new WeakMap<object, LaunchAuthorizationBinding>();

export function authorizeS37ProductHostLaunchV01(input: Readonly<{
  trust_context: CapturedAuthorityTrustContextForS36V02;
  authorization_proof: unknown;
  action_scope_hash: string;
  anchor_subject_hash: string;
}>): Readonly<{ ok: true; value: AuthorizedS37ProductHostLaunchV01 }> | Readonly<{ ok: false; error: "LAUNCH_AUTHORIZATION_INVALID" }> {
  try {
    const proof = HumanAuthorizationProofV02.safeParse(input.authorization_proof);
    if (!proof.success || proof.data.approved_risk_tier !== "T4"
      || proof.data.action_scope_hash !== input.action_scope_hash
      || proof.data.authorization_subject_hash !== input.anchor_subject_hash
      || !Hash.safeParse(input.action_scope_hash).success || !Hash.safeParse(input.anchor_subject_hash).success
      || !verifyHumanAuthorizationProofV02(input.trust_context, proof.data).ok) {
      return Object.freeze({ ok: false, error: "LAUNCH_AUTHORIZATION_INVALID" });
    }
    const value = AuthorizedS37ProductHostLaunchTokenV01.create();
    launchAuthorizations.set(value, Object.freeze({
      proof: Object.freeze(structuredClone(proof.data)),
      action_scope_hash: input.action_scope_hash,
      anchor_subject_hash: input.anchor_subject_hash,
    }));
    return Object.freeze({ ok: true, value });
  } catch {
    return Object.freeze({ ok: false, error: "LAUNCH_AUTHORIZATION_INVALID" });
  }
}

export type S37ProductHostLaunchPermitMaterialV01 = Readonly<{
  activation_id: string;
  fence_epoch: number;
  event_five_hash: string;
  manifest_hash: string;
  launch_admission_hash: string;
  broker_request_hash: string;
  conformance_receipt_hash: string;
  post_commit_authorization_revalidation_hash: string;
  post_commit_authorization_valid_until: string;
  admission: LaunchAdmissionValue;
  broker_request: BrokerRequestValue;
  post_commit_revalidation: PostCommit;
}>;

export type S37ProductHostPermitHandoffV01<TPermit extends object> = Readonly<{
  mint(material: S37ProductHostLaunchPermitMaterialV01): TPermit | null;
}>;

export type S37ProductHostPostCommitRecaptureV01 = Readonly<{
  trust_context: CapturedAuthorityTrustContextForS36V02;
  revalidation: unknown;
}>;

function selfHashValid<T extends Record<string, unknown>>(
  value: T,
  hashKey: keyof T,
  purpose: string,
  wrapper: string,
): boolean {
  const { [hashKey]: claimed, ...fields } = value;
  return claimed === hashCanonical({ purpose, [wrapper]: fields });
}

function sameProof(record: Prelaunch | PostCommit, binding: LaunchAuthorizationBinding): boolean {
  const proof = binding.proof;
  return record.action_scope_hash === binding.action_scope_hash
    && record.proof_record_hash === proof.record_hash
    && record.authorization_statement_hash === proof.authorization_statement_hash
    && record.authenticated_principal_ref === proof.authenticated_principal_ref
    && record.operator_key_id === proof.operator_key_id
    && record.approved_risk_tier === proof.approved_risk_tier
    && record.revocation_epoch === proof.revocation_epoch;
}

function activeAt(now: string, issuedAt: string, expiresAt: string): boolean {
  const current = Date.parse(now);
  return Date.parse(issuedAt) <= current && current < Date.parse(expiresAt);
}

function prelaunchCrossValid(
  prelaunch: Prelaunch,
  finalObservation: FinalObservationValue,
  brokerRequest: BrokerRequestValue,
  admission: LaunchAdmissionValue,
  binding: LaunchAuthorizationBinding,
  qualification: Readonly<Record<string, unknown>>,
  session: Exclude<ReturnType<typeof inspectS37ProductHostActivationStoreSessionV01>, { ok: false }>,
): boolean {
  const qualificationHash = qualification.qualification_hash;
  const qualificationIssuedAt = qualification.issued_at;
  const qualificationExpiresAt = qualification.expires_at;
  if (typeof qualificationHash !== "string" || typeof qualificationIssuedAt !== "string" || typeof qualificationExpiresAt !== "string") return false;
  return selfHashValid(prelaunch, "prelaunch_authorization_revalidation_hash", prelaunch.schema_version, "revalidation")
    && selfHashValid(finalObservation, "final_observation_hash", finalObservation.schema_version, "observation")
    && selfHashValid(brokerRequest, "broker_request_hash", brokerRequest.schema_version, "request")
    && selfHashValid(admission, "launch_admission_hash", admission.schema_version, "admission")
    && sameProof(prelaunch, binding)
    && prelaunch.activation_id === session.activation_id
    && prelaunch.fence_epoch === session.fence_epoch
    && prelaunch.event_four_hash === session.previous_event_hash
    && prelaunch.qualification_hash === qualificationHash
    && activeAt(prelaunch.revalidated_at, binding.proof.issued_at, binding.proof.expires_at)
    && activeAt(prelaunch.revalidated_at, qualificationIssuedAt, qualificationExpiresAt)
    && Date.parse(prelaunch.revalidated_at) < Date.parse(prelaunch.valid_until)
    && Date.parse(prelaunch.valid_until) <= Date.parse(binding.proof.expires_at)
    && Date.parse(prelaunch.valid_until) <= Date.parse(qualificationExpiresAt)
    && finalObservation.activation_id === prelaunch.activation_id
    && finalObservation.event_four_hash === prelaunch.event_four_hash
    && finalObservation.anchor_generation === prelaunch.anchor_generation
    && finalObservation.anchor_hash === prelaunch.anchor_hash
    && finalObservation.boot_id_hash === prelaunch.boot_id_hash
    && finalObservation.artifact_set_hash === prelaunch.artifact_set_hash
    && finalObservation.controller_identity_hash === prelaunch.controller_identity_hash
    && finalObservation.broker_profile_hash === prelaunch.broker_profile_hash
    && finalObservation.conformance_receipt_hash === prelaunch.conformance_receipt_hash
    && finalObservation.qualification_hash === prelaunch.qualification_hash
    && finalObservation.prelaunch_authorization_revalidation_hash === prelaunch.prelaunch_authorization_revalidation_hash
    && finalObservation.prelaunch_authorization_valid_until === prelaunch.valid_until
    && finalObservation.fence_epoch === prelaunch.fence_epoch
    && Date.parse(prelaunch.revalidated_at) <= Date.parse(finalObservation.observed_at)
    && Date.parse(finalObservation.observed_at) < Date.parse(prelaunch.valid_until)
    && brokerRequest.activation_id === finalObservation.activation_id
    && brokerRequest.activation_request_hash === finalObservation.activation_request_hash
    && brokerRequest.event_four_hash === finalObservation.event_four_hash
    && brokerRequest.anchor_generation === finalObservation.anchor_generation
    && brokerRequest.anchor_hash === finalObservation.anchor_hash
    && brokerRequest.boot_id_hash === finalObservation.boot_id_hash
    && brokerRequest.fence_epoch === finalObservation.fence_epoch
    && brokerRequest.artifact_set_hash === finalObservation.artifact_set_hash
    && brokerRequest.controller_uid === finalObservation.controller_uid
    && brokerRequest.primary_gid === finalObservation.primary_gid
    && brokerRequest.controller_identity_hash === finalObservation.controller_identity_hash
    && brokerRequest.qualification_hash === finalObservation.qualification_hash
    && brokerRequest.final_observation_hash === finalObservation.final_observation_hash
    && brokerRequest.conformance_receipt_hash === finalObservation.conformance_receipt_hash
    && brokerRequest.broker_profile_hash === finalObservation.broker_profile_hash
    && brokerRequest.systemd_run_hash === finalObservation.systemd_run_hash
    && brokerRequest.prelaunch_authorization_valid_until === prelaunch.valid_until
    && admission.activation_id === brokerRequest.activation_id
    && admission.activation_request_hash === brokerRequest.activation_request_hash
    && admission.operation === brokerRequest.operation
    && admission.event_four_hash === brokerRequest.event_four_hash
    && admission.anchor_generation === brokerRequest.anchor_generation
    && admission.anchor_hash === brokerRequest.anchor_hash
    && admission.boot_id_hash === brokerRequest.boot_id_hash
    && admission.controller_uid === brokerRequest.controller_uid
    && admission.primary_gid === brokerRequest.primary_gid
    && admission.controller_identity_hash === brokerRequest.controller_identity_hash
    && admission.fence_epoch === brokerRequest.fence_epoch
    && admission.qualification_hash === brokerRequest.qualification_hash
    && admission.prelaunch_authorization_revalidation_hash === prelaunch.prelaunch_authorization_revalidation_hash
    && admission.prelaunch_authorization_valid_until === prelaunch.valid_until
    && admission.final_observation_hash === brokerRequest.final_observation_hash
    && admission.conformance_receipt_hash === brokerRequest.conformance_receipt_hash
    && admission.broker_profile_hash === brokerRequest.broker_profile_hash
    && admission.broker_request_hash === brokerRequest.broker_request_hash;
}

export async function commitS37ProductHostLaunchAdmissionV01<TPermit extends object>(input: Readonly<{
  session: S37ProductHostActivationStoreSessionV01;
  launch_authorization: AuthorizedS37ProductHostLaunchV01;
  qualification_authorization: AuthorizedS37LinuxLaunchQualificationV03;
  prelaunch_trust_context: CapturedAuthorityTrustContextForS36V02;
  prelaunch_revalidation: unknown;
  final_observation: unknown;
  broker_request: unknown;
  launch_admission: unknown;
  post_commit_recapture: (evidence: Readonly<{ event_five_hash: string; manifest_hash: string }>) => S37ProductHostPostCommitRecaptureV01;
  permit_handoff: S37ProductHostPermitHandoffV01<TPermit>;
}>): Promise<Readonly<{ ok: true; permit: TPermit; event_five_hash: string; manifest_hash: string }>
  | Readonly<{ ok: false; outcome: "RECOVERY_REQUIRED" | "OUTCOME_UNKNOWN"; error: string }>> {
  const session = inspectS37ProductHostActivationStoreSessionV01(input.session);
  const binding = launchAuthorizations.get(input.launch_authorization);
  const prelaunch = PrelaunchRevalidation.safeParse(input.prelaunch_revalidation);
  const finalObservation = FinalObservation.safeParse(input.final_observation);
  const brokerRequest = BrokerRequest.safeParse(input.broker_request);
  const admission = LaunchAdmission.safeParse(input.launch_admission);
  if (!session.ok || binding === undefined || !prelaunch.success || !finalObservation.success
    || !brokerRequest.success || !admission.success || session.next_sequence % 7 !== 5
    || !verifyHumanAuthorizationProofV02(input.prelaunch_trust_context, binding.proof).ok) {
    return Object.freeze({ ok: false, outcome: "RECOVERY_REQUIRED", error: "PRELAUNCH_REVALIDATION_INVALID" });
  }
  const qualification = consumeAuthorizedS37LinuxLaunchQualificationV03(input.qualification_authorization);
  if (qualification === null) {
    return Object.freeze({ ok: false, outcome: "RECOVERY_REQUIRED", error: "LAUNCH_ADMISSION_INVALID" });
  }
  // From this point the qualification is irreversibly consumed. Burn the T4
  // launch authority in the same synchronous segment so no failure can make a
  // second admission attempt possible.
  launchAuthorizations.delete(input.launch_authorization);
  if (!prelaunchCrossValid(
    prelaunch.data, finalObservation.data, brokerRequest.data, admission.data, binding,
    qualification.qualification as unknown as Readonly<Record<string, unknown>>, session,
  )) return Object.freeze({ ok: false, outcome: "RECOVERY_REQUIRED", error: "LAUNCH_ADMISSION_INVALID" });
  let committed: Awaited<ReturnType<typeof commitS37ProductHostActivationEventV01>>;
  try {
    committed = await commitS37ProductHostActivationEventV01(input.session, {
      operation: admission.data.operation,
      event_type: "activation.launch-admitted",
      anchor_generation: admission.data.anchor_generation,
      anchor_hash: admission.data.anchor_hash,
      controller_uid: admission.data.controller_uid,
      payload: {
        launch_admission_hash: admission.data.launch_admission_hash,
        qualification_hash: admission.data.qualification_hash,
        prelaunch_authorization_revalidation_hash: admission.data.prelaunch_authorization_revalidation_hash,
        final_observation_hash: admission.data.final_observation_hash,
        broker_request_hash: admission.data.broker_request_hash,
      },
    });
  } catch {
    return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_EVENT_FIVE_AMBIGUOUS" });
  }
  if (!committed.ok) return Object.freeze({
    ok: false,
    outcome: committed.outcome === "OUTCOME_UNKNOWN" ? "OUTCOME_UNKNOWN" : "RECOVERY_REQUIRED",
    error: committed.error,
  });
  let captured: S37ProductHostPostCommitRecaptureV01;
  try { captured = input.post_commit_recapture({ event_five_hash: committed.event_hash, manifest_hash: committed.manifest_hash }); }
  catch { return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "POST_COMMIT_REVALIDATION_INVALID" }); }
  const postCommit = PostCommitRevalidation.safeParse(captured.revalidation);
  if (!postCommit.success || !selfHashValid(postCommit.data, "post_commit_authorization_revalidation_hash", postCommit.data.schema_version, "revalidation")
    || !sameProof(postCommit.data, binding) || !verifyHumanAuthorizationProofV02(captured.trust_context, binding.proof).ok
    || postCommit.data.activation_id !== admission.data.activation_id
    || postCommit.data.event_five_hash !== committed.event_hash || postCommit.data.manifest_hash !== committed.manifest_hash
    || postCommit.data.prelaunch_authorization_revalidation_hash !== prelaunch.data.prelaunch_authorization_revalidation_hash
    || postCommit.data.anchor_generation !== admission.data.anchor_generation || postCommit.data.anchor_hash !== admission.data.anchor_hash
    || postCommit.data.artifact_set_hash !== prelaunch.data.artifact_set_hash
    || postCommit.data.controller_identity_hash !== admission.data.controller_identity_hash
    || postCommit.data.broker_profile_hash !== admission.data.broker_profile_hash
    || postCommit.data.boot_id_hash !== admission.data.boot_id_hash || postCommit.data.fence_epoch !== admission.data.fence_epoch
    || postCommit.data.conformance_receipt_hash !== admission.data.conformance_receipt_hash
    || postCommit.data.qualification_hash !== admission.data.qualification_hash
    || Date.parse(postCommit.data.revalidated_at) < Date.parse(finalObservation.data.observed_at)
    || Date.parse(postCommit.data.revalidated_at) >= Date.parse(postCommit.data.valid_until)
    || Date.parse(postCommit.data.valid_until) > Date.parse(prelaunch.data.valid_until)
    || !activeAt(postCommit.data.revalidated_at, binding.proof.issued_at, binding.proof.expires_at)) {
    return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "POST_COMMIT_REVALIDATION_INVALID" });
  }
  const material = Object.freeze({
    activation_id: admission.data.activation_id,
    fence_epoch: admission.data.fence_epoch,
    event_five_hash: committed.event_hash,
    manifest_hash: committed.manifest_hash,
    launch_admission_hash: admission.data.launch_admission_hash,
    broker_request_hash: brokerRequest.data.broker_request_hash,
    conformance_receipt_hash: admission.data.conformance_receipt_hash,
    post_commit_authorization_revalidation_hash: postCommit.data.post_commit_authorization_revalidation_hash,
    post_commit_authorization_valid_until: postCommit.data.valid_until,
    admission: Object.freeze(structuredClone(admission.data)),
    broker_request: Object.freeze(structuredClone(brokerRequest.data)),
    post_commit_revalidation: Object.freeze(structuredClone(postCommit.data)),
  });
  let permit: TPermit | null;
  try { permit = input.permit_handoff.mint(material); }
  catch { permit = null; }
  return permit === null
    ? Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "LAUNCH_PERMIT_UNAVAILABLE" })
    : Object.freeze({ ok: true, permit, event_five_hash: committed.event_hash, manifest_hash: committed.manifest_hash });
}

function closedNotStarted(): ClosedS37ActivationOutcomeV01 {
  return Object.freeze({ ok: false, outcome: "NOT_STARTED", activation_id: null, evidence_hash: null });
}

function captureOwnedBytes(value: unknown): Uint8Array | null {
  try {
    if (typeof value !== "object" || value === null || isProxy(value)
      || !(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype
      || ["buffer", "byteLength", "byteOffset", "length"].some((key) => Object.hasOwn(value, key))
      || value.byteLength === 0 || value.byteLength > 65_536
      || !(value.buffer instanceof ArrayBuffer) || value.buffer.resizable || value.byteOffset !== 0
      || value.byteLength !== value.buffer.byteLength) return null;
    return new Uint8Array(value);
  } catch {
    return null;
  }
}

function captureActivationInput(value: unknown, withBundle: boolean): Readonly<{
  bundle_bytes?: Uint8Array;
  proof_request_bytes: Uint8Array;
  qualification_intent_bytes: Uint8Array;
}> | null {
  try {
    if (typeof value !== "object" || value === null || isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const keys = withBundle
      ? ["bundle_bytes", "proof_request_bytes", "qualification_intent_bytes"]
      : ["proof_request_bytes", "qualification_intent_bytes"];
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== keys.length
      || Object.keys(descriptors).join("\0") !== keys.join("\0")) return null;
    const bytes: Record<string, Uint8Array> = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) return null;
      const captured = captureOwnedBytes(descriptor.value);
      if (captured === null) return null;
      bytes[key] = captured;
    }
    const proof = bytes.proof_request_bytes;
    const intent = bytes.qualification_intent_bytes;
    if (proof === undefined || intent === undefined) return null;
    return Object.freeze({
      ...(withBundle ? { bundle_bytes: bytes.bundle_bytes } : {}),
      proof_request_bytes: proof,
      qualification_intent_bytes: intent,
    });
  } catch {
    return null;
  }
}

function exactJson(bytes: Uint8Array): unknown | null {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const parsed: unknown = JSON.parse(text);
    return JSON.stringify(parsed) === text ? parsed : null;
  } catch {
    return null;
  }
}

function activationRequestIdentity(input: Readonly<{
  operation: "install-and-launch" | "transition-and-launch" | "launch-stable";
  bundle_bytes?: Uint8Array;
  proof_request_bytes: Uint8Array;
  qualification_intent_bytes: Uint8Array;
}>): Readonly<{ activation_id: string; activation_request_hash: string }> | null {
  const proof = LocalProofRequestV02.safeParse(exactJson(input.proof_request_bytes));
  const intent = QualificationIntentV01.safeParse(exactJson(input.qualification_intent_bytes));
  if (!proof.success || !intent.success || Date.parse(intent.data.requested_at) >= Date.parse(intent.data.expires_at)
    || Date.parse(intent.data.expires_at) - Date.parse(intent.data.requested_at) > 600_000
    || Date.parse(proof.data.issued_at) >= Date.parse(proof.data.expires_at)
    || proof.data.authorization_subject_hash !== intent.data.anchor_subject_hash
    || intent.data.intent_hash !== hashCanonical({
      purpose: intent.data.schema_version,
      intent: Object.fromEntries(Object.entries(intent.data).filter(([key]) => key !== "intent_hash")),
    })) return null;
  let bundleHash: string | null = null;
  if (input.bundle_bytes !== undefined) {
    const parsed = parseS37ProductHostInstallBundleV01(exactJson(input.bundle_bytes));
    if (!parsed.ok || typeof parsed.value.bundle_hash !== "string") return null;
    bundleHash = parsed.value.bundle_hash;
  }
  const activationRequestHash = hashCanonical({
    purpose: "s37-product-host-activation-request-v01",
    operation: input.operation,
    bundle_hash: bundleHash,
    proof_request_hash: hashRawBytes(input.proof_request_bytes),
    qualification_intent_hash: intent.data.intent_hash,
    action_scope_hash: proof.data.action_scope_hash,
  });
  return Object.freeze({
    activation_id: `activation_${activationRequestHash.slice("sha256:".length)}`,
    activation_request_hash: activationRequestHash,
  });
}

async function custodyGate(identity: Readonly<{
  activation_id: string;
  activation_request_hash: string;
}>): Promise<ClosedS37ActivationOutcomeV01> {
  let begun: Awaited<ReturnType<typeof beginS37ProductHostAuthoritySessionV01>>;
  try { begun = await beginS37ProductHostAuthoritySessionV01(identity); }
  catch {
    return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null });
  }
  if (!begun.ok) return Object.freeze({
    ok: false,
    outcome: begun.outcome,
    activation_id: null,
    evidence_hash: null,
  });
  const closed = await closeS37ProductHostActivationStoreSessionV01(begun.value.session).catch(() => ({
    released: false as const, outcome: "OUTCOME_UNKNOWN" as const,
  }));
  const disposed = await disposeS37ProductHostActivationStoreV01(begun.value.store).catch(() => false);
  if (!closed.released || closed.outcome !== "NOT_STARTED" || !disposed) return Object.freeze({
    ok: false,
    outcome: "OUTCOME_UNKNOWN",
    activation_id: null,
    evidence_hash: null,
  });
  return closedNotStarted();
}

export async function installS37ProductHostV01(input: Readonly<{
  bundle_bytes: Uint8Array;
  proof_request_bytes: Uint8Array;
  qualification_intent_bytes: Uint8Array;
}>): Promise<ClosedS37ActivationOutcomeV01> {
  const captured = captureActivationInput(input, true);
  if (captured === null) return closedNotStarted();
  const identity = activationRequestIdentity({ operation: "install-and-launch", ...captured });
  return identity === null ? closedNotStarted() : custodyGate(identity);
}

export async function transitionS37ProductHostV01(input: Readonly<{
  bundle_bytes: Uint8Array;
  proof_request_bytes: Uint8Array;
  qualification_intent_bytes: Uint8Array;
}>): Promise<ClosedS37ActivationOutcomeV01> {
  const captured = captureActivationInput(input, true);
  if (captured === null) return closedNotStarted();
  const identity = activationRequestIdentity({ operation: "transition-and-launch", ...captured });
  return identity === null ? closedNotStarted() : custodyGate(identity);
}

export async function activateStableS37ProductHostV01(input: Readonly<{
  proof_request_bytes: Uint8Array;
  qualification_intent_bytes: Uint8Array;
}>): Promise<ClosedS37ActivationOutcomeV01> {
  const captured = captureActivationInput(input, false);
  if (captured === null) return closedNotStarted();
  const identity = activationRequestIdentity({ operation: "launch-stable", ...captured });
  return identity === null ? closedNotStarted() : custodyGate(identity);
}

export async function reconcileS37ProductHostActivationV01(): Promise<ClosedS37ActivationOutcomeV01> {
  let captured: Awaited<ReturnType<typeof captureS37ProductHostActivationStoreV01>>;
  try { captured = await captureS37ProductHostActivationStoreV01(); }
  catch { return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null }); }
  if (!captured.ok) return Object.freeze({
    ok: false, outcome: captured.error === "ACTIVATION_PLATFORM_INELIGIBLE" ? "NOT_STARTED" : "OUTCOME_UNKNOWN",
    activation_id: null, evidence_hash: null,
  });
  let outcome: ClosedS37ActivationOutcomeV01;
  try {
    const result = await reconcileStore(captured.store);
    outcome = result.outcome === "COMPLETED"
      ? result.activation_id !== null && result.evidence_hash !== null
        ? Object.freeze({ ok: true, outcome: "COMPLETED", activation_id: result.activation_id, evidence_hash: result.evidence_hash })
        : Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: result.activation_id, evidence_hash: result.evidence_hash })
      : Object.freeze({ ok: false, outcome: result.outcome, activation_id: result.activation_id, evidence_hash: result.evidence_hash });
  } catch {
    outcome = Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null });
  }
  const disposed = await disposeS37ProductHostActivationStoreV01(captured.store).catch(() => false);
  return disposed ? outcome : Object.freeze({
    ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: outcome.activation_id, evidence_hash: outcome.evidence_hash,
  });
}
