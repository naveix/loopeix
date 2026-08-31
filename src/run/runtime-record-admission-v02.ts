import { createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { z, type ZodType } from "zod";

import { canonicalize, hashCanonical, hashRawBytes } from "../hash.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";
import {
  ArtifactRecordV02,
  ActionProposalV02,
  AgencyRecommendationEvidenceRefsV02,
  AuthorityScopeV02,
  LedgerRefV02,
  NonEmptyCanonicalLedgerRefsV02,
  PolicyDecisionRecordedEventV02,
  RedactionDerivativeRecordV02,
  ReviewEvidenceRefsV02,
  TaskResultV02,
  compareRuntimeUtf8BytesV02,
  hashAuthorityScopeV02,
  type RuntimeEventV02Value,
} from "../schema/runtime.js";
import { Hash, RiskTierV1 } from "../schema/scalars.js";
import {
  HumanIdV02 as HumanId,
  IsoTimestampV02 as IsoTimestamp,
  MachineIdV02 as MachineId,
  NonBlankStringV02 as NonBlankString,
} from "../schema/scalars-v02.js";
import {
  authorityPolicyReasonRefIsCompatibleV02,
  resolveAgencyQuorumRequirementV02,
  resolveImmutableActionApprovalPolicyV02,
  resolveS36BuiltInAuthorityDecisionPolicyExtensionV1,
  type AuthorityDecisionPolicyExtensionV1Value,
} from "./action-classifier-policy-v02.js";

const safeInteger = z.number().int().refine(Number.isSafeInteger, { message: "must be a safe integer" });
const RISK_TIER_RANK = Object.freeze({ T0: 0, T1: 1, T2: 2, T3a: 3, T3b: 4, T3c: 5, T3d: 6, T4: 7 } as const);

/** Frozen V02 human-authorization record; package-private authority machinery only. */
export const HumanAuthorizationProofV02 = z.object({
  schema_version: z.literal("0.2"),
  authorization_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  authorization_subject_hash: Hash,
  authenticated_principal_ref: MachineId,
  authentication_context_hash: Hash,
  action_scope_hash: Hash,
  approved_risk_tier: RiskTierV1,
  operator_key_id: MachineId,
  approval_channel: z.enum(["local-ed25519", "platform-authenticated"]),
  approval_nonce: Hash,
  proof_algorithm: z.enum(["ed25519", "platform-authenticated-v01"]),
  authorization_statement_hash: Hash,
  proof_value: NonBlankString,
  issued_at: IsoTimestamp,
  expires_at: IsoTimestamp,
  revocation_epoch: safeInteger.nonnegative(),
  record_hash: Hash,
}).strict().superRefine((proof, ctx) => {
  const validChannelPair =
    (proof.approval_channel === "local-ed25519" && proof.proof_algorithm === "ed25519")
    || (proof.approval_channel === "platform-authenticated"
      && proof.proof_algorithm === "platform-authenticated-v01");
  if (!validChannelPair) {
    ctx.addIssue({
      code: "custom",
      path: ["proof_algorithm"],
      message: "proof algorithm must match approval channel",
    });
  }
  if (Date.parse(proof.issued_at) >= Date.parse(proof.expires_at)) {
    ctx.addIssue({
      code: "custom",
      path: ["expires_at"],
      message: "authorization interval must be non-empty",
    });
  }
  const {
    authorization_statement_hash: _statementHash,
    proof_value: _proofValue,
    record_hash: _recordHash,
    ...statementPreimage
  } = proof;
  if (proof.authorization_statement_hash !== hashCanonical(statementPreimage)) {
    ctx.addIssue({
      code: "custom",
      path: ["authorization_statement_hash"],
      message: "authorization statement hash must match its exact preimage",
    });
  }
  const { record_hash: _ignored, ...recordPreimage } = proof;
  if (proof.record_hash !== hashCanonical(recordPreimage)) {
    ctx.addIssue({ code: "custom", path: ["record_hash"], message: "record hash must match the exact human-authorization preimage" });
  }
});

export type HumanAuthorizationProofV02Value = z.infer<typeof HumanAuthorizationProofV02>;

const CanonicalBase64 = NonBlankString.refine((value) => {
  try {
    return Buffer.from(value, "base64").toString("base64") === value;
  } catch {
    return false;
  }
}, { message: "must be canonical padded RFC 4648 base64" });

const AuthenticationContextV02 = z.object({
  context_version: z.literal("0.1"),
  trust_domain: NonBlankString,
  approval_channel: z.enum(["local-ed25519", "platform-authenticated"]),
  authenticated_principal_ref: MachineId,
  credential_ref: MachineId,
  channel_subject_hash: Hash,
  session_binding_hash: Hash,
  assurance_level: z.enum(["phishing-resistant", "platform-session"]),
}).strict().superRefine((context, refinement) => {
  const valid = context.approval_channel === "local-ed25519"
    ? context.assurance_level === "phishing-resistant"
    : context.assurance_level === "platform-session";
  if (!valid) refinement.addIssue({ code: "custom", path: ["assurance_level"], message: "assurance must match channel" });
});
const OperatorKeyTrustRowV02 = z.object({
  operator_key_id: MachineId,
  authenticated_principal_ref: MachineId,
  trust_domain: NonBlankString,
  public_key_spki_base64: CanonicalBase64,
  effective_from: IsoTimestamp,
  effective_until: IsoTimestamp,
  revoked_at: IsoTimestamp.nullable(),
}).strict();
const PlatformChannelVerifierTrustRowV02 = z.object({
  operator_key_id: MachineId,
  authenticated_principal_ref: MachineId,
  trust_domain: NonBlankString,
  verifier_ref: MachineId,
  verifier_identity_hash: Hash,
  proof_algorithm: z.literal("platform-authenticated-v01"),
  effective_from: IsoTimestamp,
  effective_until: IsoTimestamp,
  revoked_at: IsoTimestamp.nullable(),
}).strict();
const HostProducerKeyTrustRowV02 = z.object({
  signer_key_ref: MachineId,
  authenticated_actor_ref: MachineId,
  trust_domain: NonBlankString,
  public_key_spki_base64: CanonicalBase64,
  allowed_record_kinds: z.union([
    z.tuple([z.literal("agency-recommendation")]),
    z.tuple([z.literal("authority-revocation")]),
    z.tuple([z.literal("agency-recommendation"), z.literal("authority-revocation")]),
  ]),
  effective_from: IsoTimestamp,
  effective_until: IsoTimestamp,
  revoked_at: IsoTimestamp.nullable(),
}).strict();
const AuthorityEpochRowV02 = z.object({
  authenticated_principal_ref: MachineId,
  revocation_epoch: safeInteger.nonnegative(),
  effective_from: IsoTimestamp,
}).strict();
const DurableNonceConsumptionRowV02 = z.object({
  authenticated_principal_ref: MachineId,
  approval_nonce: Hash,
  domain: z.enum(["primary-v02", "administrative-custody-v01"]),
  run_id: MachineId,
  authorization_id: MachineId,
  authorization_statement_hash: Hash,
}).strict();
const AuthorityTrustCaptureInputV02 = z.object({
  observed_at: IsoTimestamp,
  policy_digest: Hash,
  authentication_contexts: z.array(AuthenticationContextV02).min(1),
  operator_keys: z.array(OperatorKeyTrustRowV02).default([]),
  platform_channel_verifiers: z.array(PlatformChannelVerifierTrustRowV02).default([]),
  host_producer_keys: z.array(HostProducerKeyTrustRowV02).default([]),
  authority_epochs: z.array(AuthorityEpochRowV02).min(1),
  durable_nonce_consumptions: z.array(DurableNonceConsumptionRowV02),
}).strict();

type AuthorityTrustSnapshotV02 = z.infer<typeof AuthorityTrustCaptureInputV02> & Readonly<{
  policy_extension_hash: string;
  policy_extension: AuthorityDecisionPolicyExtensionV1Value;
  platform_verifiers?: ReadonlyMap<string, PlatformReceiptVerifierV02>;
}>;
export type CapturedAuthorityTrustContextForS36V02 = Readonly<{
  policy_digest: string;
  readonly __captured_authority_trust_context_s36_v02: unique symbol;
}>;
type TrustResult<T> = Readonly<{ ok: true; value: T }> | Readonly<{ ok: false; error: "AUTHORITY_TRUST_INVALID" }>;
const authorityTrustSnapshots = new WeakMap<object, AuthorityTrustSnapshotV02>();

type PlatformReceiptVerifierInputV02 = Readonly<{
  proof_value: string; authorization_statement_hash: string; operator_key_id: string;
  authenticated_principal_ref: string; authentication_context_hash: string;
  channel_subject_hash: string; session_binding_hash: string; observed_at: string;
}>;
type PlatformReceiptVerifierV02 = (input: PlatformReceiptVerifierInputV02) => Readonly<{ ok: boolean }>;
export type PlatformReceiptVerifierRegistryV02 = Readonly<{ readonly __platform_receipt_verifier_registry_v02: unique symbol }>;
const platformVerifierRegistries = new WeakMap<object, ReadonlyMap<string, PlatformReceiptVerifierV02>>();
export function capturePlatformReceiptVerifierRegistryV02(registrations: readonly Readonly<{
  verifier_ref: string; verifier_identity_hash: string; verify: PlatformReceiptVerifierV02;
}>[]): PlatformReceiptVerifierRegistryV02 {
  const rows = new Map<string, PlatformReceiptVerifierV02>();
  for (const registration of registrations) {
    const ref = MachineId.parse(registration.verifier_ref); const identity = Hash.parse(registration.verifier_identity_hash);
    if (typeof registration.verify !== "function" || rows.has(`${ref}:${identity}`)) throw new TypeError("invalid platform verifier registration");
    rows.set(`${ref}:${identity}`, registration.verify);
  }
  const registry = Object.freeze({}) as PlatformReceiptVerifierRegistryV02;
  platformVerifierRegistries.set(registry, rows);
  return registry;
}

function uniqueBy<T>(rows: readonly T[], identity: (row: T) => string): boolean {
  return new Set(rows.map(identity)).size === rows.length;
}

function isCanonicalOrder(rows: readonly unknown[]): boolean {
  return rows.every((row, index) => index === 0
    || Buffer.from(canonicalize(rows[index - 1])).compare(Buffer.from(canonicalize(row))) < 0);
}

function freezeAuthorityTrustValue<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeAuthorityTrustValue(child);
  return Object.freeze(value);
}

function isEd25519Spki(value: string): boolean {
  try {
    const key = createPublicKey({ key: Buffer.from(value, "base64"), format: "der", type: "spki" });
    return key.asymmetricKeyType === "ed25519"
      && key.export({ format: "der", type: "spki" }).toString("base64") === value;
  } catch {
    return false;
  }
}

export function captureAuthorityTrustContextV02(
  input: unknown,
  capabilities?: Readonly<{ platform_receipt_verifier_registry: PlatformReceiptVerifierRegistryV02 }>,
): TrustResult<CapturedAuthorityTrustContextForS36V02> {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)) return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
    const parsed = AuthorityTrustCaptureInputV02.safeParse(input);
    const extension = parsed.success
      ? resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(parsed.data.policy_digest)
      : null;
    if (!parsed.success || resolveImmutableActionApprovalPolicyV02(parsed.data.policy_digest) === null || extension === null) {
      return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
    }
    const data = { ...structuredClone(parsed.data), policy_extension_hash: extension.extension_hash, policy_extension: extension };
    if (data.operator_keys.length === 0 && data.platform_channel_verifiers.length === 0) {
      return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
    }
    if (!uniqueBy(data.authentication_contexts, (row) => `${row.authenticated_principal_ref}:${row.credential_ref}`)
      || !uniqueBy(data.operator_keys, (row) => row.operator_key_id)
      || !uniqueBy(data.platform_channel_verifiers, (row) => row.operator_key_id)
      || !uniqueBy(data.host_producer_keys, (row) => row.signer_key_ref)
      || !uniqueBy(data.authority_epochs, (row) => `${row.authenticated_principal_ref}:${row.effective_from}`)
      || !uniqueBy(data.durable_nonce_consumptions, (row) => `${row.authenticated_principal_ref}:${row.approval_nonce}`)
      || !isCanonicalOrder(data.authentication_contexts) || !isCanonicalOrder(data.operator_keys)
      || !isCanonicalOrder(data.platform_channel_verifiers) || !isCanonicalOrder(data.host_producer_keys)
      || !isCanonicalOrder(data.authority_epochs) || !isCanonicalOrder(data.durable_nonce_consumptions)) {
      return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
    }
    const verifierRegistry = capabilities === undefined
      ? undefined : platformVerifierRegistries.get(capabilities.platform_receipt_verifier_registry);
    if (data.platform_channel_verifiers.length > 0 && verifierRegistry === undefined) return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
    for (const row of data.platform_channel_verifiers) {
      const context = data.authentication_contexts.find((candidateContext) => candidateContext.credential_ref === row.operator_key_id);
      if (context === undefined || context.approval_channel !== "platform-authenticated"
        || context.authenticated_principal_ref !== row.authenticated_principal_ref || context.trust_domain !== row.trust_domain
        || Date.parse(row.effective_from) >= Date.parse(row.effective_until)
        || !verifierRegistry?.has(`${row.verifier_ref}:${row.verifier_identity_hash}`)) return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
    }
    for (const row of data.host_producer_keys) {
      if (!isEd25519Spki(row.public_key_spki_base64) || Date.parse(row.effective_from) >= Date.parse(row.effective_until)) {
        return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
      }
    }
    (data as AuthorityTrustSnapshotV02 & { platform_verifiers?: ReadonlyMap<string, PlatformReceiptVerifierV02> }).platform_verifiers = verifierRegistry;
    for (const key of data.operator_keys) {
      if (!isEd25519Spki(key.public_key_spki_base64)
        || Date.parse(key.effective_from) >= Date.parse(key.effective_until)
        || (key.revoked_at !== null && Date.parse(key.revoked_at) < Date.parse(key.effective_from))) {
        return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
      }
      const context = data.authentication_contexts.find((candidate) => candidate.credential_ref === key.operator_key_id);
      if (context === undefined || context.authenticated_principal_ref !== key.authenticated_principal_ref
        || context.trust_domain !== key.trust_domain || context.approval_channel !== "local-ed25519") {
        return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
      }
    }
    const context = Object.freeze({ policy_digest: data.policy_digest }) as CapturedAuthorityTrustContextForS36V02;
    authorityTrustSnapshots.set(context, freezeAuthorityTrustValue(data));
    return { ok: true, value: context };
  } catch {
    return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
  }
}

export function capturedAuthorityPolicyExtensionHashV02(
  trust: CapturedAuthorityTrustContextForS36V02,
): string | null {
  return authorityTrustSnapshots.get(trust)?.policy_extension_hash ?? null;
}

export function resolveCapturedAuthorityDecisionPolicyExtensionV02(
  trust: CapturedAuthorityTrustContextForS36V02,
): AuthorityDecisionPolicyExtensionV1Value | null {
  const extension = authorityTrustSnapshots.get(trust)?.policy_extension;
  return extension === undefined ? null : structuredClone(extension);
}

export function isCapturedAuthorityTrustContextV02(value: unknown): value is CapturedAuthorityTrustContextForS36V02 {
  return typeof value === "object" && value !== null && authorityTrustSnapshots.has(value);
}

export type CapturedAuthorityTrustBoundaryV02 = Readonly<{
  observed_at: string;
  policy_digest: string;
  authority_epochs: readonly Readonly<{
    authenticated_principal_ref: string;
    revocation_epoch: number;
  }>[];
}>;

/** Read-only freshness projection; opaque keys, credentials, nonces, and verifier capabilities never leave the capture. */
export function inspectCapturedAuthorityTrustBoundaryV02(
  trust: CapturedAuthorityTrustContextForS36V02,
): CapturedAuthorityTrustBoundaryV02 | null {
  const snapshot = authorityTrustSnapshots.get(trust);
  if (snapshot === undefined) return null;
  const observedAt = Date.parse(snapshot.observed_at);
  const effectiveByPrincipal = new Map<string, z.infer<typeof AuthorityEpochRowV02>>();
  for (const row of snapshot.authority_epochs) {
    const effectiveAt = Date.parse(row.effective_from);
    if (effectiveAt > observedAt) continue;
    const current = effectiveByPrincipal.get(row.authenticated_principal_ref);
    if (current === undefined || Date.parse(current.effective_from) < effectiveAt) {
      effectiveByPrincipal.set(row.authenticated_principal_ref, row);
    }
  }
  const authorityEpochs = [...effectiveByPrincipal.values()]
    .sort((left, right) => compareRuntimeUtf8BytesV02(
      left.authenticated_principal_ref,
      right.authenticated_principal_ref,
    ))
    .map((row) => Object.freeze({
      authenticated_principal_ref: row.authenticated_principal_ref,
      revocation_epoch: row.revocation_epoch,
    }));
  return Object.freeze({
    observed_at: snapshot.observed_at,
    policy_digest: snapshot.policy_digest,
    authority_epochs: Object.freeze(authorityEpochs),
  });
}

export function authenticationContextHashForTrustV02(
  trust: CapturedAuthorityTrustContextForS36V02,
  principalRef: string,
  credentialRef: string,
): string | null {
  const snapshot = authorityTrustSnapshots.get(trust);
  const context = snapshot?.authentication_contexts.find((candidate) =>
    candidate.authenticated_principal_ref === principalRef && candidate.credential_ref === credentialRef);
  return context === undefined ? null : hashCanonical({ purpose: "authentication-context-v02", ...context });
}

type NonceStatusV02 = "reserved" | "already-consumed" | "unavailable";
type NonceReserveV02 = (row: z.infer<typeof DurableNonceConsumptionRowV02>) => Promise<NonceStatusV02>;
export type NonceReservationCapabilityV02 = Readonly<{ readonly __nonce_reservation_capability_v02: unique symbol }>;
const nonceCapabilities = new WeakMap<object, NonceReserveV02>();
export function captureNonceReservationCapabilityV02(reserve: NonceReserveV02): NonceReservationCapabilityV02 {
  if (typeof reserve !== "function") throw new TypeError("nonce reservation operation is required");
  const capability = Object.freeze({}) as NonceReservationCapabilityV02;
  nonceCapabilities.set(capability, reserve);
  return capability;
}

export type Ed25519AuthoritySignerV02 = Readonly<{ key_ref: string; readonly __ed25519_authority_signer_v02: unique symbol }>;
const authoritySigners = new WeakMap<object, ReturnType<typeof createPrivateKey>>();
export function captureEd25519AuthoritySignerV02(keyRef: string, privateKeyPem: string): Ed25519AuthoritySignerV02 {
  const parsedRef = MachineId.parse(keyRef);
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new TypeError("authority signer must be Ed25519");
  const signer = Object.freeze({ key_ref: parsedRef }) as Ed25519AuthoritySignerV02;
  authoritySigners.set(signer, key);
  return signer;
}

export type HostProducerEd25519SignerV02 = Readonly<{ key_ref: string; readonly __host_producer_ed25519_signer_v02: unique symbol }>;
const hostProducerSigners = new WeakMap<object, ReturnType<typeof createPrivateKey>>();
export function captureHostProducerEd25519SignerV02(keyRef: string, privateKeyPem: string): HostProducerEd25519SignerV02 {
  const parsedRef = MachineId.parse(keyRef);
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new TypeError("host producer signer must be Ed25519");
  const signer = Object.freeze({ key_ref: parsedRef }) as HostProducerEd25519SignerV02;
  hostProducerSigners.set(signer, key);
  return signer;
}

const LocalProofRequestV02 = z.object({
  authorization_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  authorization_subject_hash: Hash,
  authenticated_principal_ref: MachineId,
  action_scope_hash: Hash,
  approved_risk_tier: RiskTierV1,
  operator_key_id: MachineId,
  approval_nonce: Hash,
  issued_at: IsoTimestamp,
  expires_at: IsoTimestamp,
  revocation_epoch: safeInteger.nonnegative(),
}).strict();
type ProofError = "AUTHORITY_TRUST_INVALID" | "AUTHENTICATION_CONTEXT_INVALID" | "NONCE_RESERVATION_UNAVAILABLE"
  | "NONCE_ALREADY_CONSUMED" | "NONCE_RESERVATION_FAILED" | "AUTHORITY_PROOF_INVALID" | "SIGNING_FAILED";
type ProofResult = Readonly<{ ok: true; value: HumanAuthorizationProofV02Value }> | Readonly<{ ok: false; error: ProofError }>;

export async function produceLocalHumanAuthorizationProofV02(input: Readonly<{
  trust_context: CapturedAuthorityTrustContextForS36V02;
  nonce_reservation: NonceReservationCapabilityV02;
  signer: Ed25519AuthoritySignerV02;
  request: unknown;
}>): Promise<ProofResult> {
  try {
    const snapshot = authorityTrustSnapshots.get(input.trust_context);
    const reserve = nonceCapabilities.get(input.nonce_reservation);
    const signingKey = authoritySigners.get(input.signer);
    const request = LocalProofRequestV02.safeParse(input.request);
    if (snapshot === undefined) return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
    if (reserve === undefined) return { ok: false, error: "NONCE_RESERVATION_UNAVAILABLE" };
    if (signingKey === undefined || !request.success) return { ok: false, error: "AUTHORITY_PROOF_INVALID" };
    const key = snapshot.operator_keys.find((candidate) => candidate.operator_key_id === request.data.operator_key_id);
    const contextHash = authenticationContextHashForTrustV02(input.trust_context, request.data.authenticated_principal_ref, request.data.operator_key_id);
    const observed = Date.parse(snapshot.observed_at);
    if (key === undefined || contextHash === null || input.signer.key_ref !== key.operator_key_id
      || key.authenticated_principal_ref !== request.data.authenticated_principal_ref
      || Date.parse(request.data.issued_at) > observed || observed >= Date.parse(request.data.expires_at)
      || Date.parse(key.effective_from) > observed || observed >= Date.parse(key.effective_until)
      || (key.revoked_at !== null && Date.parse(key.revoked_at) <= observed)) {
      return { ok: false, error: "AUTHENTICATION_CONTEXT_INVALID" };
    }
    const currentEpoch = [...snapshot.authority_epochs]
      .filter((row) => row.authenticated_principal_ref === request.data.authenticated_principal_ref && Date.parse(row.effective_from) <= observed)
      .sort((left, right) => Date.parse(right.effective_from) - Date.parse(left.effective_from))[0];
    if (currentEpoch?.revocation_epoch !== request.data.revocation_epoch) return { ok: false, error: "AUTHORITY_PROOF_INVALID" };
    const statementPreimage = {
      schema_version: "0.2" as const, ...request.data,
      authentication_context_hash: contextHash,
      approval_channel: "local-ed25519" as const,
      proof_algorithm: "ed25519" as const,
    };
    const authorizationStatementHash = hashCanonical(statementPreimage);
    const nonceRow = DurableNonceConsumptionRowV02.parse({
      authenticated_principal_ref: request.data.authenticated_principal_ref,
      approval_nonce: request.data.approval_nonce,
      domain: "primary-v02",
      run_id: request.data.run_id,
      authorization_id: request.data.authorization_id,
      authorization_statement_hash: authorizationStatementHash,
    });
    const publicKey = createPublicKey(signingKey).export({ type: "spki", format: "der" }).toString("base64");
    if (publicKey !== key.public_key_spki_base64) return { ok: false, error: "SIGNING_FAILED" };
    let reservation: NonceStatusV02;
    try { reservation = await reserve(Object.freeze(nonceRow)); } catch { return { ok: false, error: "NONCE_RESERVATION_FAILED" }; }
    if (reservation === "already-consumed") return { ok: false, error: "NONCE_ALREADY_CONSUMED" };
    if (reservation !== "reserved") return { ok: false, error: "NONCE_RESERVATION_UNAVAILABLE" };
    const proofValue = cryptoSign(null, Buffer.from(authorizationStatementHash, "ascii"), signingKey).toString("base64");
    const withoutRecordHash = { ...statementPreimage, authorization_statement_hash: authorizationStatementHash, proof_value: proofValue };
    const proof = HumanAuthorizationProofV02.safeParse({ ...withoutRecordHash, record_hash: hashCanonical(withoutRecordHash) });
    return proof.success ? { ok: true, value: Object.freeze(proof.data) } : { ok: false, error: "AUTHORITY_PROOF_INVALID" };
  } catch {
    return { ok: false, error: "AUTHORITY_PROOF_INVALID" };
  }
}

export function verifyHumanAuthorizationProofV02(
  trust: CapturedAuthorityTrustContextForS36V02,
  candidate: unknown,
): Readonly<{ ok: true }> | Readonly<{ ok: false; error: "AUTHORITY_PROOF_INVALID" }> {
  try {
    const snapshot = authorityTrustSnapshots.get(trust);
    const proof = HumanAuthorizationProofV02.safeParse(candidate);
    if (snapshot === undefined || !proof.success) return { ok: false, error: "AUTHORITY_PROOF_INVALID" };
    const contextHash = authenticationContextHashForTrustV02(trust, proof.data.authenticated_principal_ref, proof.data.operator_key_id);
    const observed = Date.parse(snapshot.observed_at);
    const epoch = [...snapshot.authority_epochs].filter((row) => row.authenticated_principal_ref === proof.data.authenticated_principal_ref
      && Date.parse(row.effective_from) <= observed).sort((a, b) => Date.parse(b.effective_from) - Date.parse(a.effective_from))[0];
    const nonce = snapshot.durable_nonce_consumptions.find((row) => row.authenticated_principal_ref === proof.data.authenticated_principal_ref
      && row.approval_nonce === proof.data.approval_nonce);
    if (contextHash !== proof.data.authentication_context_hash || epoch?.revocation_epoch !== proof.data.revocation_epoch
      || Date.parse(proof.data.issued_at) > observed || observed >= Date.parse(proof.data.expires_at)
      || nonce === undefined || nonce.domain !== "primary-v02" || nonce.run_id !== proof.data.run_id
      || nonce.authorization_id !== proof.data.authorization_id || nonce.authorization_statement_hash !== proof.data.authorization_statement_hash) {
      return { ok: false, error: "AUTHORITY_PROOF_INVALID" };
    }
    if (proof.data.approval_channel === "local-ed25519") {
      const key = snapshot.operator_keys.find((row) => row.operator_key_id === proof.data.operator_key_id);
      if (key === undefined || Date.parse(key.effective_from) > observed || observed >= Date.parse(key.effective_until)
        || (key.revoked_at !== null && Date.parse(key.revoked_at) <= observed)) return { ok: false, error: "AUTHORITY_PROOF_INVALID" };
      const publicKey = createPublicKey({ key: Buffer.from(key.public_key_spki_base64, "base64"), format: "der", type: "spki" });
      return cryptoVerify(null, Buffer.from(proof.data.authorization_statement_hash, "ascii"), publicKey, Buffer.from(proof.data.proof_value, "base64"))
        ? { ok: true } : { ok: false, error: "AUTHORITY_PROOF_INVALID" };
    }
    const context = snapshot.authentication_contexts.find((row) => row.authenticated_principal_ref === proof.data.authenticated_principal_ref
      && row.credential_ref === proof.data.operator_key_id && row.approval_channel === "platform-authenticated");
    const row = snapshot.platform_channel_verifiers.find((candidate) => candidate.operator_key_id === proof.data.operator_key_id
      && candidate.authenticated_principal_ref === proof.data.authenticated_principal_ref);
    if (context === undefined || row === undefined || Date.parse(row.effective_from) > observed || observed >= Date.parse(row.effective_until)
      || (row.revoked_at !== null && Date.parse(row.revoked_at) <= observed)) return { ok: false, error: "AUTHORITY_PROOF_INVALID" };
    const verifier = snapshot.platform_verifiers?.get(`${row.verifier_ref}:${row.verifier_identity_hash}`);
    if (verifier === undefined) return { ok: false, error: "AUTHORITY_PROOF_INVALID" };
    try {
      return verifier({ proof_value: proof.data.proof_value, authorization_statement_hash: proof.data.authorization_statement_hash,
        operator_key_id: proof.data.operator_key_id, authenticated_principal_ref: proof.data.authenticated_principal_ref,
        authentication_context_hash: proof.data.authentication_context_hash, channel_subject_hash: context.channel_subject_hash,
        session_binding_hash: context.session_binding_hash, observed_at: snapshot.observed_at }).ok
        ? { ok: true } : { ok: false, error: "AUTHORITY_PROOF_INVALID" };
    } catch { return { ok: false, error: "AUTHORITY_PROOF_INVALID" }; }
  } catch {
    return { ok: false, error: "AUTHORITY_PROOF_INVALID" };
  }
}

function eventForLedgerRefV02(events: readonly RuntimeEventV02Value[], ref: z.infer<typeof LedgerRefV02>): RuntimeEventV02Value | undefined {
  return events.find((event) => event.sequence === ref.ledger_sequence && event.event_hash === ref.event_hash);
}

export function verifyAuthorityEnvelopeRecordV02(
  trust: CapturedAuthorityTrustContextForS36V02,
  candidate: unknown,
  recordsByPath: ReadonlyMap<string, unknown>,
  events: readonly RuntimeEventV02Value[],
): Readonly<{ ok: true }> | Readonly<{ ok: false; error: "AUTHORITY_ENVELOPE_INVALID" }> {
  try {
    const envelope = AuthorityEnvelopeV02.safeParse(candidate);
    if (!envelope.success) return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
    const proofRecords = envelope.data.human_authorization_proof_refs.map((ref) => {
      const event = eventForLedgerRefV02(events, ref);
      if (event?.event_type !== "authority.human-authorization-recorded") return null;
      const payload = payloadOf(event); const path = payload.record_path;
      return typeof path === "string" ? recordsByPath.get(path) ?? null : null;
    });
    if (proofRecords.some((proof) => proof === null)) return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
    if (envelope.data.lineage.kind === "root") {
      if (proofRecords.some((proof) => {
        const parsed = HumanAuthorizationProofV02.safeParse(proof);
        return !parsed.success || !verifyHumanAuthorizationProofV02(trust, parsed.data).ok
          || parsed.data.authorization_subject_hash !== envelope.data.authorization_subject_hash
          || parsed.data.run_id !== envelope.data.run_id || parsed.data.plan_hash !== envelope.data.plan_hash
          || parsed.data.action_scope_hash !== envelope.data.action_scope_hash
          || parsed.data.authenticated_principal_ref !== envelope.data.issuer.principal_ref;
      })) return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
      return { ok: true };
    }
    const rootEvent = eventForLedgerRefV02(events, envelope.data.lineage.root_authority_envelope_ref.record_event_ref);
    const parentEvent = eventForLedgerRefV02(events, envelope.data.lineage.parent_authority_envelope_ref.record_event_ref);
    if (rootEvent?.event_type !== "authority.envelope-recorded" || parentEvent?.event_type !== "authority.envelope-recorded") {
      return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
    }
    const rootPath = payloadOf(rootEvent).record_path; const parentPath = payloadOf(parentEvent).record_path;
    const root = typeof rootPath === "string" ? AuthorityEnvelopeV02.safeParse(recordsByPath.get(rootPath)) : null;
    const parent = typeof parentPath === "string" ? AuthorityEnvelopeV02.safeParse(recordsByPath.get(parentPath)) : null;
    if (root === null || parent === null || !root.success || !parent.success || root.data.lineage.kind !== "root"
      || canonicalize(envelope.data.human_authorization_proof_refs) !== canonicalize(root.data.human_authorization_proof_refs)
      || canonicalize(envelope.data.human_authorization_proof_refs) !== canonicalize(parent.data.human_authorization_proof_refs)
      || !scopeStrictSubsetV02(envelope.data.authority_scope, parent.data.authority_scope)
      || envelope.data.issuer.stable_identity_hash !== parent.data.subject.stable_identity_hash
      || envelope.data.run_id !== root.data.run_id || envelope.data.plan_hash !== root.data.plan_hash
      || envelope.data.policy_digest !== root.data.policy_digest) return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
    if (!verifyAuthorityEnvelopeRecordV02(trust, root.data, recordsByPath, events).ok) {
      return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
    }
    return { ok: true };
  } catch { return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" }; }
}

export function verifyAdmittedAuthorityTrustRecordsV02(
  trust: CapturedAuthorityTrustContextForS36V02,
  recordsByPath: ReadonlyMap<string, unknown>,
  events: readonly RuntimeEventV02Value[] = [],
): Readonly<{ ok: true }> | Readonly<{ ok: false; error: "AUTHORITY_TRUST_INVALID" }> {
  try {
    if (!authorityTrustSnapshots.has(trust)) return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
    for (const [path, record] of recordsByPath) {
      if (path.startsWith("authorities/human/") && !verifyHumanAuthorizationProofV02(trust, record).ok) {
        return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
      }
      if (path.startsWith("authorities/envelopes/")
        && !verifyAuthorityEnvelopeRecordV02(trust, record, recordsByPath, events).ok) {
        return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
      }
      if (path.startsWith("authorities/recommendations/") && !verifyAgencyRecommendationRecordV02(trust, record).ok) {
        return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
      }
      if (path.startsWith("authorities/revocations/") && !verifyAuthorityRevocationRecordV02(trust, record).ok) {
        return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
      }
    }
    return { ok: true };
  } catch {
    return { ok: false, error: "AUTHORITY_TRUST_INVALID" };
  }
}

type AuthorityScopeValueV02 = z.infer<typeof AuthorityScopeV02>;
function canonicalSubset(child: readonly unknown[], parent: readonly unknown[]): boolean {
  const allowed = new Set(parent.map(canonicalize));
  return child.every((value) => allowed.has(canonicalize(value)));
}
function selectorContained(child: AuthorityScopeValueV02["resource_selectors"][number], parent: AuthorityScopeValueV02["resource_selectors"][number]): boolean {
  if (child.kind !== parent.kind) return false;
  if (child.kind === "plan-object" || child.kind === "tool") return canonicalize(child) === canonicalize(parent);
  if (child.kind === "workspace-path" && parent.kind === "workspace-path") {
    return child.workspace_root_ref === parent.workspace_root_ref
      && parent.path_prefix_segments.every((segment, index) => child.path_prefix_segments[index] === segment);
  }
  if (child.kind === "network-origin" && parent.kind === "network-origin") {
    return child.origin_ref === parent.origin_ref
      && parent.path_prefix_segments.every((segment, index) => child.path_prefix_segments[index] === segment);
  }
  return child.kind === "connector-resource" && parent.kind === "connector-resource"
    && child.connector_ref === parent.connector_ref && child.account_ref === parent.account_ref
    && parent.resource_prefix_segments.every((segment, index) => child.resource_prefix_segments[index] === segment);
}

function scopeHasRedundantSelectors(scope: AuthorityScopeValueV02): boolean {
  return scope.resource_selectors.some((selector, index) => scope.resource_selectors.some((candidate, candidateIndex) =>
    index !== candidateIndex && selectorContained(selector, candidate)));
}

function scopeCapabilitiesResolve(scope: AuthorityScopeValueV02): boolean {
  const rules = scope.authority_subject.protection.action_approval_policy.classifier_registry.rules;
  return scope.capability_constraints.every((constraint) => rules.some((rule) =>
    rule.rule_hash === constraint.classifier_rule_hash && canonicalize(rule.key) === canonicalize(constraint.classifier_key)));
}

export function scopeStrictSubsetV02(childInput: unknown, parentInput: unknown): boolean {
  try {
    const child = AuthorityScopeV02.safeParse(childInput);
    const parent = AuthorityScopeV02.safeParse(parentInput);
    if (!child.success || !parent.success || canonicalize(child.data.authority_subject) !== canonicalize(parent.data.authority_subject)
      || child.data.action_class !== parent.data.action_class || child.data.resource_selectors.length === 0 || child.data.operations.length === 0
      || scopeHasRedundantSelectors(child.data) || scopeHasRedundantSelectors(parent.data)
      || !scopeCapabilitiesResolve(child.data) || !scopeCapabilitiesResolve(parent.data)
      || !canonicalSubset(child.data.capability_constraints, parent.data.capability_constraints)
      || !child.data.resource_selectors.every((selector) => parent.data.resource_selectors.some((candidate) => selectorContained(selector, candidate)))
      || !canonicalSubset(child.data.operations, parent.data.operations)
      || !canonicalSubset(child.data.side_effect_constraints.allowed_effect_classes, parent.data.side_effect_constraints.allowed_effect_classes)
      || !canonicalSubset(child.data.side_effect_constraints.allowed_effect_refs, parent.data.side_effect_constraints.allowed_effect_refs)
      || !canonicalSubset(child.data.data_constraints.readable_classifications, parent.data.data_constraints.readable_classifications)
      || !canonicalSubset(child.data.data_constraints.exportable_classifications, parent.data.data_constraints.exportable_classifications)
      || !canonicalSubset(child.data.data_constraints.exportable_classifications, child.data.data_constraints.readable_classifications)
      || !canonicalSubset(child.data.data_constraints.sink_refs, parent.data.data_constraints.sink_refs)
      || RISK_TIER_RANK[child.data.max_risk_tier] > RISK_TIER_RANK[parent.data.max_risk_tier]
      || child.data.bounded_constraints.max_delegation_depth !== parent.data.bounded_constraints.max_delegation_depth) return false;
    const requirements = ["require_inspectable", "require_reversible", "require_idempotency_key", "require_compensation"] as const;
    if (requirements.some((key) => parent.data.side_effect_constraints[key] && !child.data.side_effect_constraints[key])) return false;
    const limits = ["max_actions", "max_attempts", "max_tool_calls", "max_output_bytes", "max_elapsed_ms", "max_workers", "max_decisions"] as const;
    if (limits.some((key) => child.data.bounded_constraints[key] > parent.data.bounded_constraints[key])) return false;
    const cc = child.data.bounded_constraints.cost; const pc = parent.data.bounded_constraints.cost;
    if (pc.capture === "not-applicable" && cc.capture !== "not-applicable") return false;
    if (pc.capture === "required" && cc.capture === "required"
      && (cc.cost_currency !== pc.cost_currency || cc.max_cost_minor_units > pc.max_cost_minor_units)) return false;
    const costNarrowed = pc.capture === "required" && (cc.capture === "not-applicable"
      || (cc.capture === "required" && cc.max_cost_minor_units < pc.max_cost_minor_units));
    return child.data.capability_constraints.length < parent.data.capability_constraints.length
      || child.data.resource_selectors.length < parent.data.resource_selectors.length
      || child.data.resource_selectors.some((selector) => parent.data.resource_selectors.some((candidate) =>
        selectorContained(selector, candidate) && canonicalize(selector) !== canonicalize(candidate)))
      || child.data.operations.length < parent.data.operations.length
      || child.data.side_effect_constraints.allowed_effect_classes.length < parent.data.side_effect_constraints.allowed_effect_classes.length
      || child.data.side_effect_constraints.allowed_effect_refs.length < parent.data.side_effect_constraints.allowed_effect_refs.length
      || child.data.data_constraints.readable_classifications.length < parent.data.data_constraints.readable_classifications.length
      || child.data.data_constraints.exportable_classifications.length < parent.data.data_constraints.exportable_classifications.length
      || child.data.data_constraints.sink_refs.length < parent.data.data_constraints.sink_refs.length
      || RISK_TIER_RANK[child.data.max_risk_tier] < RISK_TIER_RANK[parent.data.max_risk_tier]
      || requirements.some((key) => !parent.data.side_effect_constraints[key] && child.data.side_effect_constraints[key])
      || limits.some((key) => child.data.bounded_constraints[key] < parent.data.bounded_constraints[key])
      || costNarrowed;
  } catch { return false; }
}

const AuthorityPrincipalV02 = z.object({
  principal_ref: MachineId,
  stable_identity_hash: Hash,
}).strict();

const RootAuthorityLineageV02 = z.object({
  kind: z.literal("root"),
  root_authority_envelope_ref: z.null(),
  parent_authority_envelope_ref: z.null(),
  delegation: z.null(),
  on_behalf_of_chain: z.tuple([AuthorityPrincipalV02, AuthorityPrincipalV02]),
  delegation_depth: z.literal(0),
}).strict();

const AuthorityEnvelopeDependencyRefV02 = z.object({
  record_kind: z.literal("authority-envelope"),
  record_id: MachineId,
  record_event_ref: LedgerRefV02,
}).strict();

const DelegatedAuthorityLineageV02 = z.object({
  kind: z.literal("delegated"),
  root_authority_envelope_ref: AuthorityEnvelopeDependencyRefV02,
  parent_authority_envelope_ref: AuthorityEnvelopeDependencyRefV02,
  delegation: z.object({
    delegated_by: AuthorityPrincipalV02,
    delegated_to: AuthorityPrincipalV02,
    parent_scope_hash: Hash,
    child_scope_hash: Hash,
    delegated_at: IsoTimestamp,
  }).strict(),
  on_behalf_of_chain: z.tuple([AuthorityPrincipalV02, AuthorityPrincipalV02, AuthorityPrincipalV02]),
  delegation_depth: z.literal(1),
}).strict();

/** Frozen V02 authority-envelope record; package-private authority machinery only. */
export const AuthorityEnvelopeV02 = z.object({
  schema_version: z.literal("0.2"),
  authority_envelope_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  policy_digest: Hash,
  subject: AuthorityPrincipalV02,
  issuer: AuthorityPrincipalV02,
  authorization_subject_hash: Hash,
  human_authorization_proof_refs: NonEmptyCanonicalLedgerRefsV02,
  authority_scope: AuthorityScopeV02,
  action_scope_hash: Hash,
  lineage: z.discriminatedUnion("kind", [RootAuthorityLineageV02, DelegatedAuthorityLineageV02]),
  issued_at: IsoTimestamp,
  expires_at: IsoTimestamp,
  revocation_epoch: safeInteger.nonnegative(),
  record_hash: Hash,
}).strict().superRefine((envelope, ctx) => {
  if (envelope.policy_digest !== envelope.authority_scope.authority_subject.policy_digest) {
    ctx.addIssue({ code: "custom", path: ["policy_digest"], message: "policy digest must match the authority subject" });
  }
  const scopeHashValid = envelope.action_scope_hash === hashAuthorityScopeV02(envelope.authority_scope)
    || envelope.action_scope_hash === hashCanonical(envelope.authority_scope);
  if (!scopeHashValid) {
    ctx.addIssue({ code: "custom", path: ["action_scope_hash"], message: "action scope hash must match the complete authority scope" });
  }
  const delegationMode = envelope.authority_scope.authority_subject.protection.delegation_mode;
  const maxDelegationDepth = envelope.authority_scope.bounded_constraints.max_delegation_depth;
  const delegationPolicyCoherent = (delegationMode === "none" && maxDelegationDepth === 0)
    || (delegationMode === "strict-subset-once" && maxDelegationDepth === 1);
  if (!delegationPolicyCoherent || (envelope.lineage.kind === "delegated" && maxDelegationDepth !== 1)) {
    ctx.addIssue({ code: "custom", path: ["authority_scope", "bounded_constraints", "max_delegation_depth"], message: "delegation mode and maximum depth must agree with lineage role" });
  }
  const chain = envelope.lineage.on_behalf_of_chain;
  const stableIdentityHashes = chain.map((principal) => principal.stable_identity_hash);
  if (new Set(stableIdentityHashes).size !== stableIdentityHashes.length) {
    ctx.addIssue({ code: "custom", path: ["lineage", "on_behalf_of_chain"], message: "lineage stable identities must be unique" });
  }
  if (envelope.lineage.kind === "root") {
    if (canonicalize(chain[0]) !== canonicalize(envelope.issuer)
      || canonicalize(chain[1]) !== canonicalize(envelope.subject)
      || envelope.issuer.stable_identity_hash === envelope.subject.stable_identity_hash) {
      ctx.addIssue({ code: "custom", path: ["lineage", "on_behalf_of_chain"], message: "root lineage must be the distinct issuer and subject" });
    }
  } else {
    if (canonicalize(chain[1]) !== canonicalize(envelope.issuer)
      || canonicalize(chain[2]) !== canonicalize(envelope.subject)
      || canonicalize(envelope.lineage.delegation.delegated_by) !== canonicalize(envelope.issuer)
      || canonicalize(envelope.lineage.delegation.delegated_to) !== canonicalize(envelope.subject)
      || envelope.lineage.delegation.child_scope_hash !== envelope.action_scope_hash
      || canonicalize(envelope.lineage.root_authority_envelope_ref)
        !== canonicalize(envelope.lineage.parent_authority_envelope_ref)) {
      ctx.addIssue({ code: "custom", path: ["lineage"], message: "delegated lineage must bind root chain, parent issuer, child subject, and child scope" });
    }
  }
  if (Date.parse(envelope.issued_at) >= Date.parse(envelope.expires_at)) {
    ctx.addIssue({ code: "custom", path: ["expires_at"], message: "authority interval must be non-empty" });
  }
  const expectedAuthorizationSubjectHash = hashCanonical({
    purpose: "authority-envelope-subject-v02",
    schema_version: envelope.schema_version,
    authority_envelope_id: envelope.authority_envelope_id,
    run_id: envelope.run_id,
    plan_hash: envelope.plan_hash,
    policy_digest: envelope.policy_digest,
    subject: envelope.subject,
    issuer: envelope.issuer,
    action_scope_hash: envelope.action_scope_hash,
    lineage: envelope.lineage,
    issued_at: envelope.issued_at,
    expires_at: envelope.expires_at,
    revocation_epoch: envelope.revocation_epoch,
  });
  if (envelope.authorization_subject_hash !== expectedAuthorizationSubjectHash) {
    ctx.addIssue({ code: "custom", path: ["authorization_subject_hash"], message: "authorization subject hash must match the exact envelope subject preimage" });
  }
  const { record_hash: _ignored, ...recordPreimage } = envelope;
  if (envelope.record_hash !== hashCanonical(recordPreimage)) {
    ctx.addIssue({ code: "custom", path: ["record_hash"], message: "record hash must match the exact authority-envelope preimage" });
  }
});

export type AuthorityEnvelopeV02Value = z.infer<typeof AuthorityEnvelopeV02>;

const RootAuthorityEnvelopeProducerInputV02 = z.object({
  schema_version: z.literal("0.2"),
  authority_envelope_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  policy_digest: Hash,
  subject: AuthorityPrincipalV02,
  issuer: AuthorityPrincipalV02,
  authority_scope: AuthorityScopeV02,
  issued_at: IsoTimestamp,
  expires_at: IsoTimestamp,
  revocation_epoch: safeInteger.nonnegative(),
}).strict();

export function authorityEnvelopeSubjectHashV02(input: unknown): string | null {
  const parsed = RootAuthorityEnvelopeProducerInputV02.safeParse(input);
  if (!parsed.success) return null;
  const actionScopeHash = hashAuthorityScopeV02(parsed.data.authority_scope);
  const lineage = {
    kind: "root" as const,
    root_authority_envelope_ref: null,
    parent_authority_envelope_ref: null,
    delegation: null,
    on_behalf_of_chain: [parsed.data.issuer, parsed.data.subject] as const,
    delegation_depth: 0 as const,
  };
  return hashCanonical({
    purpose: "authority-envelope-subject-v02",
    schema_version: parsed.data.schema_version,
    authority_envelope_id: parsed.data.authority_envelope_id,
    run_id: parsed.data.run_id,
    plan_hash: parsed.data.plan_hash,
    policy_digest: parsed.data.policy_digest,
    subject: parsed.data.subject,
    issuer: parsed.data.issuer,
    action_scope_hash: actionScopeHash,
    lineage,
    issued_at: parsed.data.issued_at,
    expires_at: parsed.data.expires_at,
    revocation_epoch: parsed.data.revocation_epoch,
  });
}

type ProofWithRefV02 = Readonly<{ proof_ref: z.infer<typeof LedgerRefV02>; proof: HumanAuthorizationProofV02Value }>;
export function constructRootAuthorityEnvelopeV02(input: Readonly<{
  trust_context: CapturedAuthorityTrustContextForS36V02;
  envelope: unknown;
  human_authorization_proofs: readonly ProofWithRefV02[];
}>): Readonly<{ ok: true; value: AuthorityEnvelopeV02Value }>
  | Readonly<{ ok: false; error: "AUTHORITY_ENVELOPE_INVALID" }> {
  try {
    const envelope = RootAuthorityEnvelopeProducerInputV02.safeParse(input.envelope);
    const snapshot = authorityTrustSnapshots.get(input.trust_context);
    if (!envelope.success || snapshot === undefined || input.human_authorization_proofs.length === 0
      || envelope.data.policy_digest !== snapshot.policy_digest
      || envelope.data.policy_digest !== envelope.data.authority_scope.authority_subject.policy_digest
      || envelope.data.issuer.stable_identity_hash === envelope.data.subject.stable_identity_hash) {
      return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
    }
    const authorizationSubjectHash = authorityEnvelopeSubjectHashV02(envelope.data);
    if (authorizationSubjectHash === null) return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
    const proofRefs: z.infer<typeof LedgerRefV02>[] = [];
    const principalRefs = new Set<string>();
    for (const row of input.human_authorization_proofs) {
      const proofRef = LedgerRefV02.safeParse(row.proof_ref);
      if (!proofRef.success || !verifyHumanAuthorizationProofV02(input.trust_context, row.proof).ok
        || row.proof.authorization_subject_hash !== authorizationSubjectHash
        || row.proof.run_id !== envelope.data.run_id || row.proof.plan_hash !== envelope.data.plan_hash
        || row.proof.action_scope_hash !== hashAuthorityScopeV02(envelope.data.authority_scope)
        || row.proof.authenticated_principal_ref !== envelope.data.issuer.principal_ref
        || RISK_TIER_RANK[row.proof.approved_risk_tier] < RISK_TIER_RANK[envelope.data.authority_scope.max_risk_tier]
        || Date.parse(row.proof.issued_at) > Date.parse(envelope.data.issued_at)
        || Date.parse(row.proof.expires_at) < Date.parse(envelope.data.expires_at)
        || principalRefs.has(row.proof.authenticated_principal_ref)) {
        return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
      }
      principalRefs.add(row.proof.authenticated_principal_ref);
      proofRefs.push(proofRef.data);
    }
    proofRefs.sort((left, right) => left.ledger_sequence - right.ledger_sequence
      || Buffer.from(left.event_hash).compare(Buffer.from(right.event_hash)));
    const actionScopeHash = hashAuthorityScopeV02(envelope.data.authority_scope);
    const lineage = {
      kind: "root" as const, root_authority_envelope_ref: null, parent_authority_envelope_ref: null,
      delegation: null, on_behalf_of_chain: [envelope.data.issuer, envelope.data.subject] as const, delegation_depth: 0 as const,
    };
    const withoutRecordHash = {
      ...envelope.data, authorization_subject_hash: authorizationSubjectHash,
      human_authorization_proof_refs: proofRefs as [z.infer<typeof LedgerRefV02>, ...z.infer<typeof LedgerRefV02>[]],
      action_scope_hash: actionScopeHash, lineage,
    };
    const record = AuthorityEnvelopeV02.safeParse({ ...withoutRecordHash, record_hash: hashCanonical(withoutRecordHash) });
    return record.success ? { ok: true, value: Object.freeze(record.data) } : { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
  } catch {
    return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
  }
}

const DelegatedEnvelopeProducerInputV02 = z.object({
  schema_version: z.literal("0.2"), authority_envelope_id: MachineId,
  subject: AuthorityPrincipalV02, authority_scope: AuthorityScopeV02,
  issued_at: IsoTimestamp, expires_at: IsoTimestamp,
  root_ref: AuthorityEnvelopeDependencyRefV02, parent_ref: AuthorityEnvelopeDependencyRefV02,
}).strict();

export function constructDelegatedAuthorityEnvelopeV02(input: Readonly<{
  trust_context: CapturedAuthorityTrustContextForS36V02;
  root: AuthorityEnvelopeV02Value;
  parent: AuthorityEnvelopeV02Value;
  child: unknown;
  inherited_proofs: readonly ProofWithRefV02[];
}>): Readonly<{ ok: true; value: AuthorityEnvelopeV02Value }> | Readonly<{ ok: false; error: "AUTHORITY_ENVELOPE_INVALID" }> {
  try {
    const root = AuthorityEnvelopeV02.safeParse(input.root); const parent = AuthorityEnvelopeV02.safeParse(input.parent);
    const child = DelegatedEnvelopeProducerInputV02.safeParse(input.child);
    if (!root.success || !parent.success || !child.success || root.data.lineage.kind !== "root"
      || parent.data.authority_envelope_id !== root.data.authority_envelope_id
      || !scopeStrictSubsetV02(child.data.authority_scope, parent.data.authority_scope)
      || root.data.authority_scope.authority_subject.protection.delegation_mode !== "strict-subset-once"
      || child.data.issued_at < parent.data.issued_at || child.data.expires_at > parent.data.expires_at
      || canonicalize(child.data.root_ref) !== canonicalize(child.data.parent_ref)
      || child.data.root_ref.record_id !== root.data.authority_envelope_id
      || input.inherited_proofs.length !== root.data.human_authorization_proof_refs.length) {
      return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
    }
    const refs = input.inherited_proofs.map((row) => row.proof_ref);
    if (canonicalize(refs) !== canonicalize(root.data.human_authorization_proof_refs)
      || input.inherited_proofs.some((row) => !verifyHumanAuthorizationProofV02(input.trust_context, row.proof).ok
        || row.proof.authorization_subject_hash !== root.data.authorization_subject_hash
        || Date.parse(row.proof.expires_at) < Date.parse(child.data.expires_at))) {
      return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
    }
    const lineage = {
      kind: "delegated" as const, root_authority_envelope_ref: child.data.root_ref,
      parent_authority_envelope_ref: child.data.parent_ref,
      delegation: { delegated_by: parent.data.subject, delegated_to: child.data.subject,
        parent_scope_hash: parent.data.action_scope_hash, child_scope_hash: hashAuthorityScopeV02(child.data.authority_scope),
        delegated_at: child.data.issued_at },
      on_behalf_of_chain: [root.data.issuer, root.data.subject, child.data.subject] as const,
      delegation_depth: 1 as const,
    };
    const base = {
      schema_version: "0.2" as const, authority_envelope_id: child.data.authority_envelope_id,
      run_id: root.data.run_id, plan_hash: root.data.plan_hash, policy_digest: root.data.policy_digest,
      subject: child.data.subject, issuer: parent.data.subject, human_authorization_proof_refs: refs,
      authority_scope: child.data.authority_scope, action_scope_hash: hashAuthorityScopeV02(child.data.authority_scope),
      lineage, issued_at: child.data.issued_at, expires_at: child.data.expires_at, revocation_epoch: 0,
    };
    const authorization_subject_hash = hashCanonical({
      purpose: "authority-envelope-subject-v02",
      schema_version: base.schema_version,
      authority_envelope_id: base.authority_envelope_id,
      run_id: base.run_id,
      plan_hash: base.plan_hash,
      policy_digest: base.policy_digest,
      subject: base.subject,
      issuer: base.issuer,
      action_scope_hash: base.action_scope_hash,
      lineage: base.lineage,
      issued_at: base.issued_at,
      expires_at: base.expires_at,
      revocation_epoch: base.revocation_epoch,
    });
    const withoutRecordHash = { ...base, authorization_subject_hash };
    const record = AuthorityEnvelopeV02.safeParse({ ...withoutRecordHash, record_hash: hashCanonical(withoutRecordHash) });
    return record.success ? { ok: true, value: Object.freeze(record.data) } : { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" };
  } catch { return { ok: false, error: "AUTHORITY_ENVELOPE_INVALID" }; }
}

const PolicyReasonCodeRefV02 = z.object({
  policy_digest: Hash,
  declaration_ref: HumanId,
}).strict();

const AgencyRecommendationConditionV02 = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("require-gate-pass"), gate_ref: HumanId }).strict(),
  z.object({ kind: z.literal("require-evaluation-pass"), evaluation_ref: HumanId }).strict(),
  z.object({ kind: z.literal("require-evidence"), requirement_ref: HumanId }).strict(),
  z.object({ kind: z.literal("reduce-expiry"), expires_at: IsoTimestamp }).strict(),
]);

const HostProducerAttestationV02 = z.object({
  signer_key_ref: MachineId,
  signature_algorithm: z.literal("ed25519"),
  statement_hash: Hash,
  signature_value: NonBlankString,
}).strict();

type ActionProposalV02Value = z.infer<typeof ActionProposalV02>;
type ProposalConstructionResultV02 = Readonly<{ ok: true; value: ActionProposalV02Value }>
  | Readonly<{ ok: false; error: "ACTION_PROPOSAL_INVALID" }>;

const PROPOSAL_DERIVED_FIELDS_V02 = new Set([
  "on_behalf_of_chain_hash", "authorized_change_set_hash", "normalized_dispatch_hash",
  "action_scope_hash", "classification_binding", "policy_action_kind",
  "action_approval_class", "action_proposal_hash",
]);

function plainRecordV02(input: unknown): Record<string, unknown> | null {
  return typeof input === "object" && input !== null && !Array.isArray(input)
    ? input as Record<string, unknown>
    : null;
}

function resolveProposalClassificationV02(input: Record<string, unknown>) {
  const scopeResult = AuthorityScopeV02.safeParse(input.action_scope);
  const dispatch = plainRecordV02(input.normalized_dispatch);
  const changeSet = plainRecordV02(input.authorized_change_set);
  const dataFlow = plainRecordV02(input.data_flow);
  const budgetDelta = plainRecordV02(input.budget_delta);
  const cost = plainRecordV02(budgetDelta?.cost);
  if (!scopeResult.success || dispatch === null || changeSet === null || dataFlow === null || cost === null) return null;
  const scope = scopeResult.data;
  const policyDigest = scope.authority_subject.policy_digest;
  const policy = resolveImmutableActionApprovalPolicyV02(policyDigest);
  if (policy === null
    || canonicalize(policy) !== canonicalize(scope.authority_subject.protection.action_approval_policy)) return null;
  const repositoryIntent = changeSet.transition_mode === "read-only" && changeSet.mode === "no-change"
    ? "none"
    : changeSet.mode === "path-set" ? "workspace-edit"
      : changeSet.mode === "head-only" || changeSet.mode === "head-and-path-set" ? "commit" : null;
  const costMode = cost.capture === "required" ? "metered" : cost.capture === "not-applicable" ? "none" : null;
  if (repositoryIntent === null || costMode === null) return null;
  const matchingConstraints = scope.capability_constraints.filter(({ classifier_key: key }) =>
    key.action_class === input.action_class
    && key.dispatch_kind === dispatch.kind
    && key.adapter_ref === dispatch.adapter_ref
    && key.adapter_version_hash === dispatch.adapter_version_hash
    && key.capability_ref === dispatch.capability_ref
    && key.capability_definition_hash === dispatch.capability_definition_hash
    && key.operation === dispatch.operation
    && key.effective_risk_tier === input.effective_risk_tier
    && key.data_access_mode === dataFlow.data_access_mode
    && key.repository_transition_intent === repositoryIntent
    && key.cost_mode === costMode
    && key.effect_classes.every((effect) => scope.side_effect_constraints.allowed_effect_classes.includes(effect))
    && (!scope.side_effect_constraints.require_inspectable || key.all_effects_inspectable)
    && (!scope.side_effect_constraints.require_reversible || key.all_effects_reversible));
  if (matchingConstraints.length !== 1) return null;
  const constraint = matchingConstraints[0]!;
  const matchingRules = policy.classifier_registry.rules.filter((rule) =>
    rule.rule_hash === constraint.classifier_rule_hash
    && canonicalize(rule.key) === canonicalize(constraint.classifier_key));
  if (matchingRules.length !== 1) return null;
  const rule = matchingRules[0]!;
  const entry = policy.entries.find((candidate) => candidate.action_kind === rule.policy_action_kind);
  if (entry === undefined || entry.approval_class !== rule.action_approval_class
    || entry.classifier_rule_hash !== rule.rule_hash) return null;
  return { scope, policy, rule };
}

/** Constructs one frozen proposal from admitted normalized facts; derived authority fields are never caller-controlled. */
export function constructActionProposalV02(input: unknown): ProposalConstructionResultV02 {
  try {
    const source = plainRecordV02(input);
    if (source === null || Object.keys(source).some((key) => PROPOSAL_DERIVED_FIELDS_V02.has(key)
      || /(?:instruction|prompt|command|source_body|raw_text)/u.test(key))) {
      return { ok: false, error: "ACTION_PROPOSAL_INVALID" };
    }
    const classification = resolveProposalClassificationV02(source);
    const dataFlow = plainRecordV02(source.data_flow);
    if (classification === null || dataFlow === null) return { ok: false, error: "ACTION_PROPOSAL_INVALID" };
    const scope = classification.scope;
    const dispatch = source.normalized_dispatch as Record<string, unknown>;
    if (!scope.operations.includes(dispatch.operation as never)
      || !scope.resource_selectors.some((selector) => canonicalize(selector) === canonicalize(dispatch.target))
      || (dispatch.destination !== null && !scope.resource_selectors.some((selector) => canonicalize(selector) === canonicalize(dispatch.destination)))
      || RISK_TIER_RANK[source.effective_risk_tier as keyof typeof RISK_TIER_RANK] > RISK_TIER_RANK[scope.max_risk_tier]
      || !((dataFlow.readable_classifications as unknown[]) ?? []).every((value) => scope.data_constraints.readable_classifications.includes(value as string))
      || !((dataFlow.exportable_classifications as unknown[]) ?? []).every((value) => scope.data_constraints.exportable_classifications.includes(value as string))
      || !((dataFlow.sink_refs as unknown[]) ?? []).every((value) => scope.data_constraints.sink_refs.includes(value as string))) {
      return { ok: false, error: "ACTION_PROPOSAL_INVALID" };
    }
    const chainHash = hashCanonical({ purpose: "action-on-behalf-of-chain-v02", on_behalf_of_chain: source.on_behalf_of_chain });
    const changeSetHash = hashCanonical({ purpose: "authorized-repository-change-set-v02", ...(source.authorized_change_set as Record<string, unknown>) });
    const dispatchHash = hashCanonical({ purpose: "normalized-action-dispatch-v02", ...dispatch });
    const flowWithHash = {
      ...dataFlow,
      data_flow_hash: hashCanonical({
        purpose: "action-data-flow-v02",
        readable_classifications: dataFlow.readable_classifications,
        exportable_classifications: dataFlow.exportable_classifications,
        sink_refs: dataFlow.sink_refs,
        data_access_mode: dataFlow.data_access_mode,
      }),
    };
    const proposalWithoutHash = {
      ...source,
      on_behalf_of_chain_hash: chainHash,
      authorized_change_set_hash: changeSetHash,
      normalized_dispatch_hash: dispatchHash,
      action_scope_hash: hashAuthorityScopeV02(scope),
      classification_binding: {
        classifier_input_hash: hashCanonical({ purpose: "action-classifier-input-v1", key: classification.rule.key }),
        classifier_registry_hash: classification.policy.classifier_registry.registry_hash,
        classifier_rule_hash: classification.rule.rule_hash,
      },
      policy_action_kind: classification.rule.policy_action_kind,
      action_approval_class: classification.rule.action_approval_class,
      data_flow: flowWithHash,
    };
    const parsed = ActionProposalV02.safeParse({
      ...proposalWithoutHash,
      action_proposal_hash: hashCanonical({ purpose: "action-proposal-v02", ...proposalWithoutHash }),
    });
    return parsed.success
      ? { ok: true, value: freezeAuthorityTrustValue(parsed.data) }
      : { ok: false, error: "ACTION_PROPOSAL_INVALID" };
  } catch {
    return { ok: false, error: "ACTION_PROPOSAL_INVALID" };
  }
}

const ReviewerEvidenceExtractionV02 = z.object({
  evidence_ref: z.object({
    record_kind: z.enum(["evidence", "human-authorization"]),
    record_id: MachineId,
    record_event_ref: LedgerRefV02,
  }).strict(),
  source_selector_hash: Hash,
  source_content_hash: Hash,
  extracted_fact_hashes: z.array(Hash).min(1),
  provenance_hash: Hash,
  source_trust: z.enum(["trusted", "authenticated", "untrusted"]),
  sensitivity: z.enum(["public", "internal", "confidential", "restricted"]),
  uncertainty: z.enum(["none", "bounded", "material"]),
}).strict();

const ReviewerViewV02 = z.object({
  action_proposal_id: MachineId,
  action_proposal_hash: Hash,
  target: z.unknown(),
  destination: z.unknown().nullable(),
  capability_ref: HumanId,
  capability_definition_hash: Hash,
  operation: NonBlankString,
  effect_classes: z.array(NonBlankString),
  effect_refs: z.array(z.object({ task_ref: HumanId, effect_ref: HumanId }).strict()),
  data_access_mode: NonBlankString,
  readable_classifications: z.array(NonBlankString),
  exportable_classifications: z.array(NonBlankString),
  sink_refs: z.array(MachineId),
  effective_risk_tier: RiskTierV1,
  budget_delta_hash: Hash,
  evidence_extractions: z.array(ReviewerEvidenceExtractionV02),
  source_transformation_hash: Hash,
  reviewer_view_hash: Hash,
}).strict();
export type ReviewerViewV02Value = z.infer<typeof ReviewerViewV02>;

/** Projects a proposal into an instruction-free, hash-bound reviewer surface. */
export function constructReviewerViewV02(input: unknown): Readonly<{ ok: true; value: ReviewerViewV02Value }>
  | Readonly<{ ok: false; error: "REVIEWER_VIEW_INVALID" }> {
  try {
    const source = plainRecordV02(input);
    const proposalResult = ActionProposalV02.safeParse(source?.action_proposal);
    const evidenceResult = z.array(ReviewerEvidenceExtractionV02).safeParse(source?.evidence_extractions);
    if (source === null || Object.keys(source).some((key) => !["action_proposal", "evidence_extractions"].includes(key))
      || !proposalResult.success || !evidenceResult.success) return { ok: false, error: "REVIEWER_VIEW_INVALID" };
    const proposal = proposalResult.data;
    const classification = resolveProposalClassificationV02(proposal as unknown as Record<string, unknown>);
    if (classification === null) return { ok: false, error: "REVIEWER_VIEW_INVALID" };
    const sourceTransformationHash = hashCanonical({
      purpose: "reviewer-view-source-transformation-v02",
      action_proposal_hash: proposal.action_proposal_hash,
      normalized_dispatch_hash: proposal.normalized_dispatch_hash,
      action_scope_hash: proposal.action_scope_hash,
      data_flow_hash: proposal.data_flow.data_flow_hash,
      evidence_extractions: evidenceResult.data,
    });
    const withoutHash = {
      action_proposal_id: proposal.action_proposal_id,
      action_proposal_hash: proposal.action_proposal_hash,
      target: proposal.normalized_dispatch.target,
      destination: proposal.normalized_dispatch.destination,
      capability_ref: proposal.normalized_dispatch.capability_ref,
      capability_definition_hash: proposal.normalized_dispatch.capability_definition_hash,
      operation: proposal.normalized_dispatch.operation,
      effect_classes: classification.rule.key.effect_classes,
      effect_refs: proposal.side_effect_refs,
      data_access_mode: proposal.data_flow.data_access_mode,
      readable_classifications: proposal.data_flow.readable_classifications,
      exportable_classifications: proposal.data_flow.exportable_classifications,
      sink_refs: proposal.data_flow.sink_refs,
      effective_risk_tier: proposal.effective_risk_tier,
      budget_delta_hash: hashCanonical({ purpose: "action-budget-delta-v02", ...proposal.budget_delta }),
      evidence_extractions: evidenceResult.data,
      source_transformation_hash: sourceTransformationHash,
    };
    const parsed = ReviewerViewV02.safeParse({
      ...withoutHash,
      reviewer_view_hash: hashCanonical({ purpose: "reviewer-view-v02", ...withoutHash }),
    });
    return parsed.success
      ? { ok: true, value: freezeAuthorityTrustValue(parsed.data) }
      : { ok: false, error: "REVIEWER_VIEW_INVALID" };
  } catch {
    return { ok: false, error: "REVIEWER_VIEW_INVALID" };
  }
}

function canonicalArray<T>(schema: z.ZodType<T>, label: string, minimum = 0) {
  return z.array(schema).min(minimum).superRefine((values, ctx) => {
    for (let index = 1; index < values.length; index += 1) {
      if (Buffer.from(canonicalize(values[index - 1]!)).compare(Buffer.from(canonicalize(values[index]!))) >= 0) {
        ctx.addIssue({ code: "custom", path: [index], message: `${label} must be unique and RFC 8785 sorted` });
      }
    }
  });
}

const CanonicalEvidenceIndependenceKeysV02 = canonicalArray(Hash, "evidence independence keys", 1);
const NonEmptyCanonicalPolicyReasonRefsV02 = canonicalArray(PolicyReasonCodeRefV02, "policy reason refs", 1);

/** Frozen V02 agency-recommendation record; signature verification requires captured host trust. */
export const AgencyRecommendationRecordV02 = z.object({
  schema_version: z.literal("0.2"),
  recommendation_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  task_ref: HumanId,
  phase: z.enum(["work", "compensation"]),
  compensation_ref: HumanId.nullable(),
  action_proposal: ActionProposalV02,
  action_proposal_id: MachineId,
  action_proposal_hash: Hash,
  proposer_actor_ref: MachineId,
  proposer_stable_identity_hash: Hash,
  action_actor_ref: MachineId,
  action_actor_stable_identity_hash: Hash,
  on_behalf_of_chain_hash: Hash,
  repository_root_ref: MachineId,
  repository_base_ref_identity_hash: Hash,
  repository_pre_state_hash: Hash,
  authorized_change_set_hash: Hash,
  normalized_dispatch_hash: Hash,
  action_scope: AuthorityScopeV02,
  action_scope_hash: Hash,
  action_class: z.enum(["task", "tool", "artifact-write"]),
  classifier_input_hash: Hash,
  classifier_registry_hash: Hash,
  classifier_rule_hash: Hash,
  data_flow_hash: Hash,
  policy_action_kind: z.enum(["authenticated-read", "network-read", "reversible-workspace-edit"]),
  action_approval_class: z.literal("agency"),
  recommendation_subject_hash: Hash,
  quorum_requirement_hash: Hash,
  policy_digest: Hash,
  reviewed_through_ref: LedgerRefV02,
  evidence_refs: AgencyRecommendationEvidenceRefsV02,
  evidence_independence_keys: CanonicalEvidenceIndependenceKeysV02,
  evaluator_role_ref: HumanId,
  evaluator_actor_ref: MachineId,
  evaluator_stable_identity_hash: Hash,
  evaluator_authentication_context_hash: Hash,
  decision: z.enum(["allow", "allow_with_conditions", "deny", "escalate", "abort"]),
  conditions: z.array(AgencyRecommendationConditionV02),
  reason_codes: NonEmptyCanonicalPolicyReasonRefsV02,
  issued_at: IsoTimestamp,
  expires_at: IsoTimestamp,
  producer_attestation: HostProducerAttestationV02,
  record_hash: Hash,
}).strict().superRefine((recommendation, ctx) => {
  const proposal = recommendation.action_proposal;
  const copiedBindingsMatch = recommendation.run_id === proposal.run_id
    && recommendation.plan_hash === proposal.plan_hash
    && recommendation.task_ref === proposal.task_ref
    && recommendation.phase === proposal.phase
    && recommendation.compensation_ref === proposal.compensation_ref
    && recommendation.action_proposal_id === proposal.action_proposal_id
    && recommendation.action_proposal_hash === proposal.action_proposal_hash
    && recommendation.proposer_actor_ref === proposal.proposer_actor_ref
    && recommendation.proposer_stable_identity_hash === proposal.proposer_stable_identity_hash
    && recommendation.action_actor_ref === proposal.action_actor_ref
    && recommendation.action_actor_stable_identity_hash === proposal.action_actor_stable_identity_hash
    && recommendation.on_behalf_of_chain_hash === proposal.on_behalf_of_chain_hash
    && recommendation.repository_root_ref === proposal.repository_root_ref
    && recommendation.repository_base_ref_identity_hash === proposal.repository_base_ref_identity_hash
    && recommendation.repository_pre_state_hash === proposal.repository_pre_state_hash
    && recommendation.authorized_change_set_hash === proposal.authorized_change_set_hash
    && recommendation.normalized_dispatch_hash === proposal.normalized_dispatch_hash
    && canonicalize(recommendation.action_scope) === canonicalize(proposal.action_scope)
    && recommendation.action_scope_hash === proposal.action_scope_hash
    && recommendation.action_class === proposal.action_class
    && recommendation.classifier_input_hash === proposal.classification_binding.classifier_input_hash
    && recommendation.classifier_registry_hash === proposal.classification_binding.classifier_registry_hash
    && recommendation.classifier_rule_hash === proposal.classification_binding.classifier_rule_hash
    && recommendation.data_flow_hash === proposal.data_flow.data_flow_hash
    && recommendation.policy_action_kind === proposal.policy_action_kind
    && recommendation.action_approval_class === proposal.action_approval_class;
  if (!copiedBindingsMatch) {
    ctx.addIssue({ code: "custom", message: "recommendation bindings must exactly copy the action proposal" });
  }
  if ((recommendation.phase === "compensation") !== (recommendation.compensation_ref !== null)) {
    ctx.addIssue({ code: "custom", path: ["compensation_ref"], message: "compensation ref must be present exactly in compensation phase" });
  }
  if ((recommendation.decision === "allow_with_conditions") !== (recommendation.conditions.length > 0)) {
    ctx.addIssue({ code: "custom", path: ["conditions"], message: "conditions must be non-empty exactly for conditional allow" });
  }
  if (recommendation.evaluator_stable_identity_hash === recommendation.proposer_stable_identity_hash
    || recommendation.evaluator_stable_identity_hash === recommendation.action_actor_stable_identity_hash) {
    ctx.addIssue({ code: "custom", path: ["evaluator_stable_identity_hash"], message: "evaluator must be independent from proposer and action actor" });
  }
  if (recommendation.reason_codes.some((reason) => reason.policy_digest !== recommendation.policy_digest)) {
    ctx.addIssue({ code: "custom", path: ["reason_codes"], message: "reason refs must copy the recommendation policy digest" });
  }
  if (Date.parse(recommendation.issued_at) >= Date.parse(recommendation.expires_at)) {
    ctx.addIssue({ code: "custom", path: ["expires_at"], message: "recommendation interval must be non-empty" });
  }
  const expectedSubjectHash = hashCanonical({
    purpose: "agency-recommendation-subject-v02",
    run_id: recommendation.run_id, plan_hash: recommendation.plan_hash,
    task_ref: recommendation.task_ref, phase: recommendation.phase,
    compensation_ref: recommendation.compensation_ref,
    action_proposal_id: recommendation.action_proposal_id,
    action_proposal_hash: recommendation.action_proposal_hash,
    proposer_actor_ref: recommendation.proposer_actor_ref,
    proposer_stable_identity_hash: recommendation.proposer_stable_identity_hash,
    action_actor_ref: recommendation.action_actor_ref,
    action_actor_stable_identity_hash: recommendation.action_actor_stable_identity_hash,
    on_behalf_of_chain_hash: recommendation.on_behalf_of_chain_hash,
    repository_root_ref: recommendation.repository_root_ref,
    repository_base_ref_identity_hash: recommendation.repository_base_ref_identity_hash,
    repository_pre_state_hash: recommendation.repository_pre_state_hash,
    authorized_change_set_hash: recommendation.authorized_change_set_hash,
    normalized_dispatch_hash: recommendation.normalized_dispatch_hash,
    action_scope_hash: recommendation.action_scope_hash,
    action_class: recommendation.action_class,
    classifier_input_hash: recommendation.classifier_input_hash,
    classifier_registry_hash: recommendation.classifier_registry_hash,
    classifier_rule_hash: recommendation.classifier_rule_hash,
    data_flow_hash: recommendation.data_flow_hash,
    policy_action_kind: recommendation.policy_action_kind,
    action_approval_class: recommendation.action_approval_class,
    quorum_requirement_hash: recommendation.quorum_requirement_hash,
    policy_digest: recommendation.policy_digest,
    reviewed_through_ref: recommendation.reviewed_through_ref,
  });
  if (recommendation.recommendation_subject_hash !== expectedSubjectHash) {
    ctx.addIssue({ code: "custom", path: ["recommendation_subject_hash"], message: "recommendation subject hash must match its exact preimage" });
  }
  const { record_hash: _recordHash, producer_attestation, ...recordWithoutAttestation } = recommendation;
  const attestationPreimage = {
    ...recordWithoutAttestation,
    producer_attestation: {
      signer_key_ref: producer_attestation.signer_key_ref,
      signature_algorithm: producer_attestation.signature_algorithm,
    },
  };
  if (producer_attestation.statement_hash !== hashCanonical(attestationPreimage)) {
    ctx.addIssue({ code: "custom", path: ["producer_attestation", "statement_hash"], message: "producer statement hash must match the exact attestation preimage" });
  }
  const { record_hash: _ignored, ...recordPreimage } = recommendation;
  if (recommendation.record_hash !== hashCanonical(recordPreimage)) {
    ctx.addIssue({ code: "custom", path: ["record_hash"], message: "record hash must match the exact agency-recommendation preimage" });
  }
});

export type AgencyRecommendationRecordV02Value = z.infer<typeof AgencyRecommendationRecordV02>;

const AgencyRecommendationProductionRequestV02 = z.object({
  recommendation_id: MachineId, reviewed_through_ref: LedgerRefV02,
  evidence_refs: AgencyRecommendationEvidenceRefsV02,
  evidence_independence_keys: CanonicalEvidenceIndependenceKeysV02,
  evidence_producer_stable_identity_hashes: canonicalArray(Hash, "evidence producer roots", 1),
  evaluator_role_ref: HumanId, evaluator_actor_ref: MachineId, evaluator_stable_identity_hash: Hash,
  decision: z.enum(["allow", "allow_with_conditions", "deny", "escalate", "abort"]),
  conditions: z.array(AgencyRecommendationConditionV02),
  reason_declaration_refs: canonicalArray(HumanId, "reason declaration refs", 1),
  issued_at: IsoTimestamp, expires_at: IsoTimestamp,
}).strict();

/** Produces one non-authoritative reviewer recommendation through a captured host signing capability. */
export function produceAgencyRecommendationRecordV02(input: Readonly<{
  trust_context: CapturedAuthorityTrustContextForS36V02; signer: HostProducerEd25519SignerV02;
  action_proposal: unknown; reviewer_view: unknown; request: unknown;
}>): Readonly<{ ok: true; value: AgencyRecommendationRecordV02Value }>
  | Readonly<{ ok: false; error: "AUTHORITY_RECOMMENDATION_INVALID" }> {
  try {
    const snapshot = authorityTrustSnapshots.get(input.trust_context);
    const signingKey = hostProducerSigners.get(input.signer);
    const proposal = ActionProposalV02.safeParse(input.action_proposal);
    const view = ReviewerViewV02.safeParse(input.reviewer_view);
    const request = AgencyRecommendationProductionRequestV02.safeParse(input.request);
    if (snapshot === undefined || signingKey === undefined || !proposal.success || !view.success || !request.success
      || proposal.data.action_approval_class !== "agency"
      || view.data.action_proposal_id !== proposal.data.action_proposal_id
      || view.data.action_proposal_hash !== proposal.data.action_proposal_hash) return { ok: false, error: "AUTHORITY_RECOMMENDATION_INVALID" };
    const rebuiltView = constructReviewerViewV02({ action_proposal: proposal.data, evidence_extractions: view.data.evidence_extractions });
    if (!rebuiltView.ok || rebuiltView.value.reviewer_view_hash !== view.data.reviewer_view_hash) return { ok: false, error: "AUTHORITY_RECOMMENDATION_INVALID" };
    const quorum = resolveAgencyQuorumRequirementV02({
      policy_digest: snapshot.policy_digest, action_class: proposal.data.action_class,
      policy_action_kind: proposal.data.policy_action_kind, action_approval_class: proposal.data.action_approval_class,
    });
    const issued = Date.parse(request.data.issued_at); const expires = Date.parse(request.data.expires_at); const observed = Date.parse(snapshot.observed_at);
    if (quorum === null || proposal.data.action_scope.authority_subject.policy_digest !== snapshot.policy_digest
      || !(quorum.requirement.required_reviewer_role_refs as readonly string[]).includes(request.data.evaluator_role_ref)
      || request.data.evaluator_stable_identity_hash === proposal.data.proposer_stable_identity_hash
      || request.data.evaluator_stable_identity_hash === proposal.data.action_actor_stable_identity_hash
      || request.data.evidence_producer_stable_identity_hashes.includes(request.data.evaluator_stable_identity_hash)
      || request.data.evidence_refs.length < quorum.requirement.minimum_evidence_roots_per_recommendation
      || request.data.evidence_independence_keys.length < quorum.requirement.minimum_evidence_roots_per_recommendation
      || issued > observed || observed >= expires || expires - issued > quorum.requirement.max_recommendation_ttl_ms
      || (request.data.decision === "allow_with_conditions") !== (request.data.conditions.length > 0)
      || request.data.reason_declaration_refs.some((ref) => !authorityPolicyReasonRefIsCompatibleV02(snapshot.policy_digest, ref, "agency-recommendation", request.data.decision))) {
      return { ok: false, error: "AUTHORITY_RECOMMENDATION_INVALID" };
    }
    const trustedKey = snapshot.host_producer_keys.find((row) => row.signer_key_ref === input.signer.key_ref
      && row.authenticated_actor_ref === request.data.evaluator_actor_ref && (row.allowed_record_kinds as readonly string[]).includes("agency-recommendation"));
    const contextHash = authenticationContextHashForTrustV02(input.trust_context, request.data.evaluator_actor_ref, input.signer.key_ref);
    if (trustedKey === undefined || contextHash === null
      || createPublicKey(signingKey).export({ type: "spki", format: "der" }).toString("base64") !== trustedKey.public_key_spki_base64
      || Date.parse(trustedKey.effective_from) > issued || issued >= Date.parse(trustedKey.effective_until)
      || (trustedKey.revoked_at !== null && Date.parse(trustedKey.revoked_at) <= issued)) return { ok: false, error: "AUTHORITY_RECOMMENDATION_INVALID" };
    const value = proposal.data; const binding = value.classification_binding;
    const copied = {
      run_id: value.run_id, plan_hash: value.plan_hash, task_ref: value.task_ref, phase: value.phase, compensation_ref: value.compensation_ref,
      action_proposal_id: value.action_proposal_id, action_proposal_hash: value.action_proposal_hash,
      proposer_actor_ref: value.proposer_actor_ref, proposer_stable_identity_hash: value.proposer_stable_identity_hash,
      action_actor_ref: value.action_actor_ref, action_actor_stable_identity_hash: value.action_actor_stable_identity_hash,
      on_behalf_of_chain_hash: value.on_behalf_of_chain_hash, repository_root_ref: value.repository_root_ref,
      repository_base_ref_identity_hash: value.repository_base_ref_identity_hash, repository_pre_state_hash: value.repository_pre_state_hash,
      authorized_change_set_hash: value.authorized_change_set_hash, normalized_dispatch_hash: value.normalized_dispatch_hash,
      action_scope_hash: value.action_scope_hash, action_class: value.action_class,
      classifier_input_hash: binding.classifier_input_hash, classifier_registry_hash: binding.classifier_registry_hash,
      classifier_rule_hash: binding.classifier_rule_hash, data_flow_hash: value.data_flow.data_flow_hash,
      policy_action_kind: value.policy_action_kind, action_approval_class: "agency" as const,
    };
    const reviewedPolicy = { quorum_requirement_hash: quorum.quorum_requirement_hash, policy_digest: snapshot.policy_digest, reviewed_through_ref: request.data.reviewed_through_ref };
    const base = {
      schema_version: "0.2" as const, recommendation_id: request.data.recommendation_id,
      ...copied, action_proposal: value, action_scope: value.action_scope,
      recommendation_subject_hash: hashCanonical({ purpose: "agency-recommendation-subject-v02", ...copied, ...reviewedPolicy }),
      ...reviewedPolicy, evidence_refs: request.data.evidence_refs, evidence_independence_keys: request.data.evidence_independence_keys,
      evaluator_role_ref: request.data.evaluator_role_ref, evaluator_actor_ref: request.data.evaluator_actor_ref,
      evaluator_stable_identity_hash: request.data.evaluator_stable_identity_hash, evaluator_authentication_context_hash: contextHash,
      decision: request.data.decision, conditions: request.data.conditions,
      reason_codes: request.data.reason_declaration_refs.map((declaration_ref) => ({ policy_digest: snapshot.policy_digest, declaration_ref })),
      issued_at: request.data.issued_at, expires_at: request.data.expires_at,
    };
    const header = { signer_key_ref: input.signer.key_ref, signature_algorithm: "ed25519" as const };
    const statementHash = hashCanonical({ ...base, producer_attestation: header });
    const producer_attestation = { ...header, statement_hash: statementHash, signature_value: cryptoSign(null, Buffer.from(statementHash, "ascii"), signingKey).toString("base64") };
    const withoutHash = { ...base, producer_attestation };
    const parsed = AgencyRecommendationRecordV02.safeParse({ ...withoutHash, record_hash: hashCanonical(withoutHash) });
    return parsed.success ? { ok: true, value: freezeAuthorityTrustValue(parsed.data) } : { ok: false, error: "AUTHORITY_RECOMMENDATION_INVALID" };
  } catch { return { ok: false, error: "AUTHORITY_RECOMMENDATION_INVALID" }; }
}

const AuthorityRevocationProductionRequestV02 = z.object({
  revocation_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  target: z.unknown(),
  previous_revocation_epoch: safeInteger.nonnegative(),
  revocation_epoch: safeInteger.positive(),
  effective_prefix_ref: LedgerRefV02,
  reason_code: z.enum([
    "operator-revoked",
    "authority-expired",
    "scope-invalidated",
    "policy-changed",
    "principal-revoked",
    "compromise-suspected",
  ]),
  evidence_refs: ReviewEvidenceRefsV02,
  revoker_identity_ref: MachineId,
  revoker_stable_identity_hash: Hash,
  revoked_at: IsoTimestamp,
}).strict();

/** Produces one strict authority-revocation record through a captured host signing capability. */
export function produceAuthorityRevocationRecordV02(input: Readonly<{
  trust_context: CapturedAuthorityTrustContextForS36V02;
  signer: HostProducerEd25519SignerV02;
  request: unknown;
}>): Readonly<{ ok: true; value: AuthorityRevocationRecordV02Value }>
  | Readonly<{ ok: false; error: "AUTHORITY_REVOCATION_INVALID" }> {
  try {
    const snapshot = authorityTrustSnapshots.get(input.trust_context);
    const signingKey = hostProducerSigners.get(input.signer);
    const request = AuthorityRevocationProductionRequestV02.safeParse(input.request);
    if (snapshot === undefined || signingKey === undefined || !request.success) {
      return { ok: false, error: "AUTHORITY_REVOCATION_INVALID" };
    }
    const target = AuthorityRevocationTargetV02.safeParse(request.data.target);
    if (!target.success) {
      return { ok: false, error: "AUTHORITY_REVOCATION_INVALID" };
    }
    const revokedAt = Date.parse(request.data.revoked_at);
    const observed = Date.parse(snapshot.observed_at);
    const trustedKey = snapshot.host_producer_keys.find((row) => row.signer_key_ref === input.signer.key_ref
      && row.authenticated_actor_ref === request.data.revoker_identity_ref
      && (row.allowed_record_kinds as readonly string[]).includes("authority-revocation"));
    const contextHash = authenticationContextHashForTrustV02(
      input.trust_context,
      request.data.revoker_identity_ref,
      input.signer.key_ref,
    );
    if (trustedKey === undefined || contextHash === null
      || createPublicKey(signingKey).export({ type: "spki", format: "der" }).toString("base64") !== trustedKey.public_key_spki_base64
      || revokedAt > observed
      || Date.parse(trustedKey.effective_from) > revokedAt
      || revokedAt >= Date.parse(trustedKey.effective_until)
      || (trustedKey.revoked_at !== null && Date.parse(trustedKey.revoked_at) <= revokedAt)) {
      return { ok: false, error: "AUTHORITY_REVOCATION_INVALID" };
    }
    const revoker_kind = request.data.reason_code === "operator-revoked"
      ? "operator" as const
      : "policy-enforcement-point" as const;
    const base = {
      schema_version: "0.2" as const,
      revocation_id: request.data.revocation_id,
      run_id: request.data.run_id,
      plan_hash: request.data.plan_hash,
      target: target.data,
      previous_revocation_epoch: request.data.previous_revocation_epoch,
      revocation_epoch: request.data.revocation_epoch,
      effective_prefix_ref: request.data.effective_prefix_ref,
      reason_code: request.data.reason_code,
      evidence_refs: request.data.evidence_refs,
      revoker_kind,
      revoker_identity_ref: request.data.revoker_identity_ref,
      revoker_stable_identity_hash: request.data.revoker_stable_identity_hash,
      revoker_authentication_context_hash: contextHash,
      policy_digest: snapshot.policy_digest,
      revoked_at: request.data.revoked_at,
    };
    const header = {
      signer_key_ref: input.signer.key_ref,
      signature_algorithm: "ed25519" as const,
    };
    const statementHash = hashCanonical({
      ...base,
      producer_attestation: header,
    });
    const producer_attestation = {
      ...header,
      statement_hash: statementHash,
      signature_value: cryptoSign(null, Buffer.from(statementHash, "ascii"), signingKey).toString("base64"),
    };
    const withoutHash = { ...base, producer_attestation };
    const parsed = AuthorityRevocationRecordV02.safeParse({
      ...withoutHash,
      record_hash: hashCanonical(withoutHash),
    });
    return parsed.success
      ? { ok: true, value: freezeAuthorityTrustValue(parsed.data) }
      : { ok: false, error: "AUTHORITY_REVOCATION_INVALID" };
  } catch {
    return { ok: false, error: "AUTHORITY_REVOCATION_INVALID" };
  }
}

const AuthorityRevocationTargetV02 = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("authority-envelope"),
    target_ref: z.object({
      record_kind: z.literal("authority-envelope"),
      record_id: MachineId,
      record_event_ref: LedgerRefV02,
    }).strict(),
    target_scope_hash: Hash,
  }).strict(),
  z.object({
    kind: z.literal("gate-waiver-authority"),
    target_ref: z.object({
      record_kind: z.literal("gate-waiver-authority"),
      record_id: MachineId,
      record_event_ref: LedgerRefV02,
    }).strict(),
    target_scope_hash: Hash,
  }).strict(),
]);

function compareLedgerRefsV02(left: z.infer<typeof LedgerRefV02>, right: z.infer<typeof LedgerRefV02>): number {
  if (left.ledger_sequence !== right.ledger_sequence) {
    return left.ledger_sequence < right.ledger_sequence ? -1 : 1;
  }
  return Buffer.from(left.event_hash).compare(Buffer.from(right.event_hash));
}

/** Frozen V02 authority-revocation record; history and trust validation stay outside the record parser. */
export const AuthorityRevocationRecordV02 = z.object({
  schema_version: z.literal("0.2"),
  revocation_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  target: AuthorityRevocationTargetV02,
  previous_revocation_epoch: safeInteger.nonnegative(),
  revocation_epoch: safeInteger.positive(),
  effective_prefix_ref: LedgerRefV02,
  reason_code: z.enum([
    "operator-revoked",
    "authority-expired",
    "scope-invalidated",
    "policy-changed",
    "principal-revoked",
    "compromise-suspected",
  ]),
  evidence_refs: ReviewEvidenceRefsV02,
  revoker_kind: z.enum(["operator", "policy-enforcement-point"]),
  revoker_identity_ref: MachineId,
  revoker_stable_identity_hash: Hash,
  revoker_authentication_context_hash: Hash,
  policy_digest: Hash,
  revoked_at: IsoTimestamp,
  producer_attestation: HostProducerAttestationV02,
  record_hash: Hash,
}).strict().superRefine((revocation, ctx) => {
  const operatorRevocation = revocation.reason_code === "operator-revoked";
  const expectedRevokerKind = operatorRevocation ? "operator" : "policy-enforcement-point";
  if (revocation.revoker_kind !== expectedRevokerKind) {
    ctx.addIssue({ code: "custom", path: ["revoker_kind"], message: "revoker kind must match the revocation reason" });
  }
  if (revocation.previous_revocation_epoch >= Number.MAX_SAFE_INTEGER
    || revocation.revocation_epoch !== revocation.previous_revocation_epoch + 1) {
    ctx.addIssue({ code: "custom", path: ["revocation_epoch"], message: "revocation epoch must increment by exactly one without overflow" });
  }
  for (const [index, evidenceRef] of revocation.evidence_refs.entries()) {
    const prefixOrder = compareLedgerRefsV02(evidenceRef.record_event_ref, revocation.effective_prefix_ref);
    if (prefixOrder > 0 || (prefixOrder === 0 && canonicalize(evidenceRef.record_event_ref) !== canonicalize(revocation.effective_prefix_ref))) {
      ctx.addIssue({ code: "custom", path: ["evidence_refs", index], message: "evidence must resolve at or before the effective prefix" });
    }
    if (evidenceRef.record_kind === "authority-revocation" && evidenceRef.record_id === revocation.revocation_id) {
      ctx.addIssue({ code: "custom", path: ["evidence_refs", index], message: "revocation evidence cannot depend on the revocation itself" });
    }
  }
  const { record_hash: _recordHash, producer_attestation, ...recordWithoutAttestation } = revocation;
  const { statement_hash: _statementHash, signature_value: _signatureValue, ...attestationPreimage } = producer_attestation;
  if (producer_attestation.statement_hash !== hashCanonical({
    ...recordWithoutAttestation,
    producer_attestation: attestationPreimage,
  })) {
    ctx.addIssue({ code: "custom", path: ["producer_attestation", "statement_hash"], message: "producer statement hash must match the exact attestation preimage" });
  }
  const { record_hash: _ignored, ...recordPreimage } = revocation;
  if (revocation.record_hash !== hashCanonical(recordPreimage)) {
    ctx.addIssue({ code: "custom", path: ["record_hash"], message: "record hash must match the exact authority-revocation preimage" });
  }
});

export type AuthorityRevocationRecordV02Value = z.infer<typeof AuthorityRevocationRecordV02>;

function verifyProducerAttestationV02(
  trust: CapturedAuthorityTrustContextForS36V02,
  recordKind: "agency-recommendation" | "authority-revocation",
  actorRef: string,
  authenticationContextHash: string,
  attestation: z.infer<typeof HostProducerAttestationV02>,
  effectiveAt: string,
  expiresAt: string | null,
): boolean {
  try {
    const snapshot = authorityTrustSnapshots.get(trust); if (snapshot === undefined) return false;
    const key = snapshot.host_producer_keys.find((row) => row.signer_key_ref === attestation.signer_key_ref
      && row.authenticated_actor_ref === actorRef && (row.allowed_record_kinds as readonly string[]).includes(recordKind));
    const contextHash = authenticationContextHashForTrustV02(trust, actorRef, attestation.signer_key_ref);
    const observed = Date.parse(snapshot.observed_at); const effective = Date.parse(effectiveAt);
    if (key === undefined || contextHash !== authenticationContextHash
      || effective > observed || (expiresAt !== null && observed >= Date.parse(expiresAt))
      || Date.parse(key.effective_from) > effective || effective >= Date.parse(key.effective_until)
      || (key.revoked_at !== null && Date.parse(key.revoked_at) <= effective)) return false;
    const publicKey = createPublicKey({ key: Buffer.from(key.public_key_spki_base64, "base64"), format: "der", type: "spki" });
    return cryptoVerify(null, Buffer.from(attestation.statement_hash, "ascii"), publicKey, Buffer.from(attestation.signature_value, "base64"));
  } catch { return false; }
}

export function verifyAgencyRecommendationRecordV02(
  trust: CapturedAuthorityTrustContextForS36V02,
  candidate: unknown,
): Readonly<{ ok: true }> | Readonly<{ ok: false; error: "AUTHORITY_RECOMMENDATION_INVALID" }> {
  const record = AgencyRecommendationRecordV02.safeParse(candidate);
  return record.success && verifyProducerAttestationV02(trust, "agency-recommendation", record.data.evaluator_actor_ref,
    record.data.evaluator_authentication_context_hash, record.data.producer_attestation, record.data.issued_at, record.data.expires_at)
    ? { ok: true } : { ok: false, error: "AUTHORITY_RECOMMENDATION_INVALID" };
}

export function verifyAuthorityRevocationRecordV02(
  trust: CapturedAuthorityTrustContextForS36V02,
  candidate: unknown,
): Readonly<{ ok: true }> | Readonly<{ ok: false; error: "AUTHORITY_REVOCATION_INVALID" }> {
  const record = AuthorityRevocationRecordV02.safeParse(candidate);
  return record.success && verifyProducerAttestationV02(trust, "authority-revocation", record.data.revoker_identity_ref,
    record.data.revoker_authentication_context_hash, record.data.producer_attestation, record.data.revoked_at, null)
    ? { ok: true } : { ok: false, error: "AUTHORITY_REVOCATION_INVALID" };
}

const PolicyDecisionProducerRequestV02 = z.object({
  policy_decision_id: MachineId,
  authority_envelope_ref: z.object({
    record_kind: z.literal("authority-envelope"),
    record_id: MachineId,
    record_event_ref: LedgerRefV02,
  }).strict(),
  reviewed_through_ref: LedgerRefV02,
  recommendation_event_refs: z.array(LedgerRefV02),
  compensation_evidence_refs: z.array(LedgerRefV02).default([]),
  issued_at: IsoTimestamp,
  expires_at: IsoTimestamp,
}).strict();

export type SimulatedAuthorityLeaseV02 = Readonly<{
  lease_version: "0.1";
  action_proposal_hash: string;
  authority_envelope_ref: z.infer<typeof PolicyDecisionProducerRequestV02.shape.authority_envelope_ref>;
  policy_decision_id: string;
  issued_at: string;
  expires_at: string;
  invalidation_fingerprint: string;
}>;

function exactOrSubsetScopeV02(candidate: z.infer<typeof AuthorityScopeV02>, container: z.infer<typeof AuthorityScopeV02>): boolean {
  return hashAuthorityScopeV02(candidate) === hashAuthorityScopeV02(container)
    || canonicalize(candidate) === canonicalize(container)
    || scopeStrictSubsetV02(candidate, container);
}

function uniqueLedgerRefsV02(refs: readonly z.infer<typeof LedgerRefV02>[]): boolean {
  return refs.every((ref, index) => index === 0 || compareLedgerRefsV02(refs[index - 1]!, ref) < 0);
}

function canonicalHashListV02(values: readonly string[]): readonly string[] {
  return Object.freeze([...values].sort(compareRuntimeUtf8BytesV02));
}

function decisionReasonCodesV02(
  policyDigest: string,
  declarationRef: string,
): readonly Readonly<{ policy_digest: string; declaration_ref: string }>[] {
  return Object.freeze([{ policy_digest: policyDigest, declaration_ref: declarationRef }]);
}

function policyDecisionPayloadCandidateV02(
  proposal: ActionProposalV02Value,
  request: z.infer<typeof PolicyDecisionProducerRequestV02>,
  branch: Readonly<{
    quorum_requirement_hash: string | null;
    recommendation_event_refs: readonly z.infer<typeof LedgerRefV02>[];
    condition_hashes: readonly string[];
    failed_condition_hashes: readonly string[];
    decision: "allow" | "deny" | "escalate" | "abort" | "hold";
    decision_disposition: "lease-eligible" | "proposal-final" | "human-exception-required" | "abort-run" | "redecide-after-prefix-change" | "non-resumable";
    reason_codes: readonly Readonly<{ policy_digest: string; declaration_ref: string }>[];
    evidence_refs: readonly z.infer<typeof LedgerRefV02>[];
  }>,
  revocationEpoch: number,
) {
  return {
    policy_decision_id: request.policy_decision_id,
    run_id: proposal.run_id,
    plan_hash: proposal.plan_hash,
    task_ref: proposal.task_ref,
    phase: proposal.phase,
    compensation_ref: proposal.compensation_ref,
    authority_envelope_ref: request.authority_envelope_ref,
    action_proposal: proposal,
    action_proposal_id: proposal.action_proposal_id,
    action_proposal_hash: proposal.action_proposal_hash,
    action_actor_ref: proposal.action_actor_ref,
    action_actor_stable_identity_hash: proposal.action_actor_stable_identity_hash,
    on_behalf_of_chain_hash: proposal.on_behalf_of_chain_hash,
    repository_root_ref: proposal.repository_root_ref,
    repository_base_ref_identity_hash: proposal.repository_base_ref_identity_hash,
    repository_pre_state_hash: proposal.repository_pre_state_hash,
    authorized_change_set_hash: proposal.authorized_change_set_hash,
    normalized_dispatch_hash: proposal.normalized_dispatch_hash,
    action_scope_hash: proposal.action_scope_hash,
    action_class: proposal.action_class,
    classifier_input_hash: proposal.classification_binding.classifier_input_hash,
    classifier_registry_hash: proposal.classification_binding.classifier_registry_hash,
    classifier_rule_hash: proposal.classification_binding.classifier_rule_hash,
    data_flow_hash: proposal.data_flow.data_flow_hash,
    policy_action_kind: proposal.policy_action_kind,
    action_approval_class: proposal.action_approval_class,
    reviewed_through_ref: request.reviewed_through_ref,
    quorum_requirement_hash: branch.quorum_requirement_hash,
    recommendation_event_refs: branch.recommendation_event_refs,
    condition_hashes: branch.condition_hashes,
    failed_condition_hashes: branch.failed_condition_hashes,
    decision: branch.decision,
    decision_disposition: branch.decision_disposition,
    policy_digest: proposal.action_scope.authority_subject.policy_digest,
    reason_codes: branch.reason_codes,
    evidence_refs: branch.evidence_refs,
    issued_at: request.issued_at,
    expires_at: request.expires_at,
    revocation_epoch: revocationEpoch,
  };
}

function wrapPolicyDecisionEventV02(
  payload: ReturnType<typeof policyDecisionPayloadCandidateV02>,
  authorityRef: string,
  riskTier: string,
) {
  const preimage = {
    schema_version: "0.2" as const,
    event_id: "policy_decision_preview",
    run_id: payload.run_id,
    sequence: 1,
    recorded_at: payload.issued_at,
    event_type: "policy.decision-recorded" as const,
    source: "policy-enforcement-point" as const,
    authority_ref: authorityRef,
    risk_tier: riskTier,
    related_ids: [],
    previous_event_hash: null,
    payload,
  };
  return Object.freeze({ ...preimage, event_hash: hashCanonical(preimage) });
}

function simulatedLeaseFingerprintV02(payload: ReturnType<typeof policyDecisionPayloadCandidateV02>): string {
  return hashCanonical({
    purpose: "s36-simulated-lease-v02",
    policy_decision_id: payload.policy_decision_id,
    authority_envelope_ref: payload.authority_envelope_ref,
    action_proposal_hash: payload.action_proposal_hash,
    action_scope_hash: payload.action_scope_hash,
    repository_root_ref: payload.repository_root_ref,
    repository_base_ref_identity_hash: payload.repository_base_ref_identity_hash,
    repository_pre_state_hash: payload.repository_pre_state_hash,
    normalized_dispatch_hash: payload.normalized_dispatch_hash,
    classifier_input_hash: payload.classifier_input_hash,
    classifier_registry_hash: payload.classifier_registry_hash,
    classifier_rule_hash: payload.classifier_rule_hash,
    data_flow_hash: payload.data_flow_hash,
    policy_digest: payload.policy_digest,
    reviewed_through_ref: payload.reviewed_through_ref,
    recommendation_event_refs: payload.recommendation_event_refs,
    condition_hashes: payload.condition_hashes,
    failed_condition_hashes: payload.failed_condition_hashes,
    revocation_epoch: payload.revocation_epoch,
    expires_at: payload.expires_at,
  });
}

/** Evaluates one pure S36 policy branch and emits no durable records or side effects. */
export function producePolicyDecisionV02(input: Readonly<{
  trust_context: CapturedAuthorityTrustContextForS36V02;
  authority_envelope: unknown;
  action_proposal: unknown;
  recommendations: readonly Readonly<{ recommendation_ref: z.infer<typeof LedgerRefV02>; recommendation: unknown }>[];
  request: unknown;
}>): Readonly<{ ok: true; value: ReturnType<typeof policyDecisionPayloadCandidateV02> }>
  | Readonly<{ ok: false; error: "POLICY_DECISION_INVALID" }> {
  try {
    const snapshot = authorityTrustSnapshots.get(input.trust_context);
    const envelope = AuthorityEnvelopeV02.safeParse(input.authority_envelope);
    const proposal = ActionProposalV02.safeParse(input.action_proposal);
    const request = PolicyDecisionProducerRequestV02.safeParse(input.request);
    if (snapshot === undefined || !envelope.success || !proposal.success || !request.success
      || proposal.data.run_id !== envelope.data.run_id
      || proposal.data.plan_hash !== envelope.data.plan_hash
      || proposal.data.action_scope.authority_subject.policy_digest !== snapshot.policy_digest
      || proposal.data.action_scope.authority_subject.policy_digest !== envelope.data.policy_digest) {
      return { ok: false, error: "POLICY_DECISION_INVALID" };
    }
    const issuedAt = Date.parse(request.data.issued_at);
    const expiresAt = Date.parse(request.data.expires_at);
    const observedAt = Date.parse(snapshot.observed_at);
    if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)
      || issuedAt > observedAt || observedAt >= expiresAt
      || request.data.authority_envelope_ref.record_id !== envelope.data.authority_envelope_id
      || canonicalize(request.data.authority_envelope_ref.record_event_ref) === canonicalize(request.data.reviewed_through_ref)
      || !exactOrSubsetScopeV02(proposal.data.action_scope, envelope.data.authority_scope)
      || Date.parse(envelope.data.issued_at) > observedAt || observedAt >= Date.parse(envelope.data.expires_at)) {
      return { ok: false, error: "POLICY_DECISION_INVALID" };
    }

    const branch = (() => {
      if (proposal.data.action_approval_class === "blocked") {
        return {
          quorum_requirement_hash: null,
          recommendation_event_refs: Object.freeze([]) as readonly z.infer<typeof LedgerRefV02>[],
          condition_hashes: Object.freeze([]) as readonly string[],
          failed_condition_hashes: Object.freeze([]) as readonly string[],
          decision: "hold" as const,
          decision_disposition: "non-resumable" as const,
          reason_codes: decisionReasonCodesV02(snapshot.policy_digest, "decision-blocked-hold"),
          evidence_refs: Object.freeze([]) as readonly z.infer<typeof LedgerRefV02>[],
        };
      }
      if (proposal.data.action_approval_class === "human_exception") {
        return {
          quorum_requirement_hash: null,
          recommendation_event_refs: Object.freeze([]) as readonly z.infer<typeof LedgerRefV02>[],
          condition_hashes: Object.freeze([]) as readonly string[],
          failed_condition_hashes: Object.freeze([]) as readonly string[],
          decision: "hold" as const,
          decision_disposition: "non-resumable" as const,
          reason_codes: decisionReasonCodesV02(snapshot.policy_digest, "decision-human-exception-hold"),
          evidence_refs: Object.freeze([]) as readonly z.infer<typeof LedgerRefV02>[],
        };
      }
      if (proposal.data.action_approval_class === "automatic") {
        return {
          quorum_requirement_hash: null,
          recommendation_event_refs: Object.freeze([]) as readonly z.infer<typeof LedgerRefV02>[],
          condition_hashes: Object.freeze([]) as readonly string[],
          failed_condition_hashes: Object.freeze([]) as readonly string[],
          decision: "allow" as const,
          decision_disposition: "lease-eligible" as const,
          reason_codes: decisionReasonCodesV02(snapshot.policy_digest, "decision-automatic-allow"),
          evidence_refs: Object.freeze([]) as readonly z.infer<typeof LedgerRefV02>[],
        };
      }

      const quorum = resolveAgencyQuorumRequirementV02({
        policy_digest: snapshot.policy_digest,
        action_class: proposal.data.action_class,
        policy_action_kind: proposal.data.policy_action_kind,
        action_approval_class: proposal.data.action_approval_class,
      });
      if (quorum === null) return null;
      if (proposal.data.phase === "compensation" && proposal.data.compensation_ref !== null) {
        return {
          quorum_requirement_hash: null,
          recommendation_event_refs: Object.freeze([]) as readonly z.infer<typeof LedgerRefV02>[],
          condition_hashes: Object.freeze([]) as readonly string[],
          failed_condition_hashes: Object.freeze([]) as readonly string[],
          decision: "hold" as const,
          decision_disposition: "non-resumable" as const,
          reason_codes: decisionReasonCodesV02(snapshot.policy_digest, "decision-compensation-safety-hold"),
          evidence_refs: Object.freeze([...request.data.compensation_evidence_refs]) as readonly z.infer<typeof LedgerRefV02>[],
        };
      }

      const validRecommendations = input.recommendations
        .map((row) => {
          const recommendation = AgencyRecommendationRecordV02.safeParse(row.recommendation);
          return recommendation.success
            && verifyAgencyRecommendationRecordV02(input.trust_context, recommendation.data).ok
            && recommendation.data.action_proposal_hash === proposal.data.action_proposal_hash
            && recommendation.data.reviewed_through_ref.ledger_sequence === request.data.reviewed_through_ref.ledger_sequence
            && recommendation.data.reviewed_through_ref.event_hash === request.data.reviewed_through_ref.event_hash
            && compareLedgerRefsV02(row.recommendation_ref, request.data.reviewed_through_ref) > 0
            && Date.parse(recommendation.data.issued_at) <= issuedAt
            && issuedAt < Date.parse(recommendation.data.expires_at)
            ? { recommendation_ref: row.recommendation_ref, recommendation: recommendation.data }
            : null;
        })
        .filter((row): row is { recommendation_ref: z.infer<typeof LedgerRefV02>; recommendation: AgencyRecommendationRecordV02Value } => row !== null)
        .sort((left, right) => compareLedgerRefsV02(left.recommendation_ref, right.recommendation_ref));
      const recommendationRefs = Object.freeze(validRecommendations.map(({ recommendation_ref }) => recommendation_ref));
      const evidenceRefs = Object.freeze(
        validRecommendations.flatMap(({ recommendation }) => recommendation.evidence_refs.map((ref) => ref.record_event_ref))
          .sort(compareLedgerRefsV02)
          .filter((ref, index, values) => index === 0 || compareLedgerRefsV02(values[index - 1]!, ref) !== 0),
      );
      const uniqueReviewerRoots = new Set(validRecommendations.map(({ recommendation }) => recommendation.evaluator_stable_identity_hash));
      const allowRecommendations = validRecommendations.filter(({ recommendation }) => recommendation.decision === "allow");
      const allowRoles = new Set(allowRecommendations.map(({ recommendation }) => recommendation.evaluator_role_ref));
      const conditionalConditions = canonicalHashListV02(
        validRecommendations.flatMap(({ recommendation }) =>
          recommendation.decision === "allow_with_conditions" ? recommendation.conditions.map((condition) => hashCanonical(condition)) : []),
      );
      if (!uniqueLedgerRefsV02(recommendationRefs)) return null;
      if (conditionalConditions.length > 0) {
        return {
          quorum_requirement_hash: quorum.quorum_requirement_hash,
          recommendation_event_refs: recommendationRefs,
          condition_hashes: conditionalConditions,
          failed_condition_hashes: conditionalConditions,
          decision: "hold" as const,
          decision_disposition: "redecide-after-prefix-change" as const,
          reason_codes: decisionReasonCodesV02(snapshot.policy_digest, "decision-agency-condition-hold"),
          evidence_refs: evidenceRefs,
        };
      }
      const completeAllowQuorum =
        allowRecommendations.length >= quorum.requirement.minimum_allow_recommendations
        && uniqueReviewerRoots.size >= quorum.requirement.minimum_independent_reviewer_roots
        && (quorum.requirement.required_reviewer_role_refs as readonly string[]).every((role) => allowRoles.has(role))
        && evidenceRefs.length >= quorum.requirement.minimum_evidence_roots_per_recommendation;
      if (!completeAllowQuorum) {
        return {
          quorum_requirement_hash: quorum.quorum_requirement_hash,
          recommendation_event_refs: recommendationRefs,
          condition_hashes: Object.freeze([]) as readonly string[],
          failed_condition_hashes: Object.freeze([]) as readonly string[],
          decision: "hold" as const,
          decision_disposition: "non-resumable" as const,
          reason_codes: decisionReasonCodesV02(snapshot.policy_digest, "decision-agency-quorum-hold"),
          evidence_refs: evidenceRefs,
        };
      }
      const dominant = validRecommendations.find(({ recommendation }) => recommendation.decision === "abort")
        ?? validRecommendations.find(({ recommendation }) => recommendation.decision === "deny")
        ?? validRecommendations.find(({ recommendation }) => recommendation.decision === "escalate");
      if (dominant !== undefined) {
        const mapping = dominant.recommendation.decision === "abort"
          ? { decision: "abort" as const, decision_disposition: "abort-run" as const, reason: "decision-agency-abort" }
          : dominant.recommendation.decision === "deny"
            ? { decision: "deny" as const, decision_disposition: "proposal-final" as const, reason: "decision-agency-deny" }
            : { decision: "escalate" as const, decision_disposition: "human-exception-required" as const, reason: "decision-agency-escalate" };
        return {
          quorum_requirement_hash: quorum.quorum_requirement_hash,
          recommendation_event_refs: recommendationRefs,
          condition_hashes: Object.freeze([]) as readonly string[],
          failed_condition_hashes: Object.freeze([]) as readonly string[],
          decision: mapping.decision,
          decision_disposition: mapping.decision_disposition,
          reason_codes: decisionReasonCodesV02(snapshot.policy_digest, mapping.reason),
          evidence_refs: evidenceRefs,
        };
      }
      return {
        quorum_requirement_hash: quorum.quorum_requirement_hash,
        recommendation_event_refs: recommendationRefs,
        condition_hashes: Object.freeze([]) as readonly string[],
        failed_condition_hashes: Object.freeze([]) as readonly string[],
        decision: "allow" as const,
        decision_disposition: "lease-eligible" as const,
        reason_codes: decisionReasonCodesV02(snapshot.policy_digest, "decision-agency-allow"),
        evidence_refs: evidenceRefs,
      };
    })();

    if (branch === null) return { ok: false, error: "POLICY_DECISION_INVALID" };
    const payload = policyDecisionPayloadCandidateV02(proposal.data, request.data, branch, envelope.data.revocation_epoch);
    const parsed = PolicyDecisionRecordedEventV02.safeParse(
      wrapPolicyDecisionEventV02(payload, envelope.data.issuer.principal_ref, proposal.data.effective_risk_tier),
    );
    return parsed.success ? { ok: true, value: freezeAuthorityTrustValue(payload) } : { ok: false, error: "POLICY_DECISION_INVALID" };
  } catch {
    return { ok: false, error: "POLICY_DECISION_INVALID" };
  }
}

/** Emits one in-memory S36 lease slot from an allow branch; it is preview-only and not durable. */
export function simulatePolicyDecisionLeaseV02(input: Readonly<{ decision: unknown }>): Readonly<{ ok: true; value: SimulatedAuthorityLeaseV02 }>
  | Readonly<{ ok: false; error: "SIMULATED_LEASE_INVALID" }> {
  try {
    const payload = PolicyDecisionProducerRequestV02.shape.authority_envelope_ref.safeParse(
      (input.decision as { authority_envelope_ref?: unknown })?.authority_envelope_ref,
    );
    const decision = input.decision as ReturnType<typeof policyDecisionPayloadCandidateV02> | null;
    if (decision === null || !payload.success || decision.decision !== "allow" || decision.decision_disposition !== "lease-eligible") {
      return { ok: false, error: "SIMULATED_LEASE_INVALID" };
    }
    return {
      ok: true,
      value: Object.freeze({
        lease_version: "0.1",
        action_proposal_hash: decision.action_proposal_hash,
        authority_envelope_ref: payload.data,
        policy_decision_id: decision.policy_decision_id,
        issued_at: decision.issued_at,
        expires_at: decision.expires_at,
        invalidation_fingerprint: simulatedLeaseFingerprintV02(decision),
      }),
    };
  } catch {
    return { ok: false, error: "SIMULATED_LEASE_INVALID" };
  }
}


export type RuntimeRecordAdmissionReasonV02 =
  | "RUNTIME_RECORD_MISSING"
  | "RUNTIME_RECORD_HASH_INVALID"
  | "RUNTIME_RECORD_SCHEMA_INVALID"
  | "RUNTIME_SCHEMA_INVENTORY_INVALID";

export type RuntimeRecordAdmissionInputV02 = Readonly<{
  events: readonly RuntimeEventV02Value[];
  run_id: string;
  plan_hash: string;
  record_bytes_by_path: ReadonlyMap<string, Uint8Array>;
  raw_hash_by_path: ReadonlyMap<string, string>;
}>;

export type RuntimeRecordAdmissionValueV02 = Readonly<{
  records_by_path: ReadonlyMap<string, unknown>;
  content_bytes_by_path: ReadonlyMap<string, Uint8Array>;
  ordered_paths: readonly string[];
}>;

export type RuntimeRecordAdmissionResultV02 =
  | Readonly<{ ok: true; value: RuntimeRecordAdmissionValueV02 }>
  | Readonly<{ ok: false; reason: RuntimeRecordAdmissionReasonV02 }>;

type RecordBinding = Readonly<{
  path: string;
  hash: string;
  id: string;
  event: RuntimeEventV02Value;
  schema: ZodType | null;
  event_record_field_paths?: Readonly<Record<string, readonly string[]>>;
  event_record_field_values?: Readonly<Record<string, (record: Record<string, unknown>) => unknown>>;
  content: Readonly<{ path: string; hash: string; size: number }> | null;
}>;

type BindingDerivationResult =
  | Readonly<{ ok: true; bindings: readonly RecordBinding[] }>
  | Readonly<{ ok: false; reason: "RUNTIME_SCHEMA_INVENTORY_INVALID" }>;

type RegistryRow = Readonly<{
  event_type: RuntimeEventV02Value["event_type"];
  id_field: string;
  event_path_field: string;
  event_hash_field: string;
  path_for_id: (id: string) => string;
  schema: ZodType | null;
  event_record_field_paths?: Readonly<Record<string, readonly string[]>>;
  event_record_field_values?: Readonly<Record<string, (record: Record<string, unknown>) => unknown>>;
  content_fields?: Readonly<{
    path: string;
    hash: string;
    size: string;
    path_for_id?: (id: string) => string;
  }>;
}>;

const row = (
  event_type: RegistryRow["event_type"],
  id_field: string,
  event_path_field: string,
  event_hash_field: string,
  prefix: string,
  schema: ZodType | null = null,
  content_fields?: RegistryRow["content_fields"],
  event_record_field_paths?: RegistryRow["event_record_field_paths"],
  event_record_field_values?: RegistryRow["event_record_field_values"],
): RegistryRow => ({
  event_type,
  id_field,
  event_path_field,
  event_hash_field,
  path_for_id: (id) => `${prefix}/${id}.json`,
  schema,
  ...(content_fields === undefined ? {} : { content_fields }),
  ...(event_record_field_paths === undefined ? {} : { event_record_field_paths }),
  ...(event_record_field_values === undefined ? {} : { event_record_field_values }),
});

/** Closed primary-runtime record/content registry; absent from the package root. */
export const RUNTIME_RECORD_FAMILY_REGISTRY_V02: readonly RegistryRow[] = Object.freeze([
  row("artifact.recorded", "artifact_ref", "artifact_record_path", "artifact_record_hash", "artifacts/records", ArtifactRecordV02,
    { path: "artifact_path", hash: "content_hash", size: "size_bytes" }),
  row("record.redaction-derivative-recorded", "derivative_ref", "derivative_record_path", "derivative_record_hash", "custody/derivatives/pre-seal", RedactionDerivativeRecordV02,
    { path: "derivative_content_path", hash: "derivative_content_hash", size: "derivative_size_bytes",
      path_for_id: (id) => `custody/derivatives/pre-seal/${id}.bin` }),
  row("task.execution-completed", "result_id", "result_path", "result_hash", "task-results", TaskResultV02),
  row("task.execution-failed", "result_id", "result_path", "result_hash", "task-results", TaskResultV02),
  row("evidence.recorded", "evidence_id", "record_path", "record_hash", "evidence/records", null,
    { path: "content_path", hash: "content_hash", size: "size_bytes",
      path_for_id: (id) => `evidence/content/${id}.bin` }),
  row("authority.human-authorization-recorded", "authorization_id", "record_path", "record_hash", "authorities/human", HumanAuthorizationProofV02),
  row("authority.envelope-recorded", "authority_envelope_id", "record_path", "record_hash", "authorities/envelopes", AuthorityEnvelopeV02, undefined, {
    subject_ref: ["subject", "principal_ref"],
    issuer_principal_ref: ["issuer", "principal_ref"],
    action_class: ["authority_scope", "action_class"],
    max_risk_tier: ["authority_scope", "max_risk_tier"],
    delegation_depth: ["lineage", "delegation_depth"],
  }),
  row("authority.waiver-recorded", "authority_record_id", "record_path", "record_hash", "authorities/gate-waivers"),
  row("approval.recommendation-recorded", "recommendation_id", "record_path", "record_hash", "authorities/recommendations",
    AgencyRecommendationRecordV02, undefined, {
      signer_key_ref: ["producer_attestation", "signer_key_ref"],
      statement_hash: ["producer_attestation", "statement_hash"],
    }, {
      condition_hashes: (record) => ((record.conditions as readonly unknown[]) ?? [])
        .map((condition) => hashCanonical(condition))
        .sort(compareRuntimeUtf8BytesV02),
    }),
  row("authority.grant-revoked", "revocation_id", "record_path", "record_hash", "authorities/revocations",
    AuthorityRevocationRecordV02, undefined, {
      signer_key_ref: ["producer_attestation", "signer_key_ref"],
      statement_hash: ["producer_attestation", "statement_hash"],
    }),
  row("observation.manual-recorded", "observation_id", "record_path", "record_hash", "observations"),
  row("record.export-decision-recorded", "decision_id", "record_path", "record_hash", "export-decisions"),
  row("claim.recorded", "claim_id", "record_path", "record_hash", "claims"),
  row("finding.recorded", "finding_id", "record_path", "record_hash", "findings"),
  row("waiver.recorded", "waiver_id", "record_path", "record_hash", "waivers"),
  row("gate.result-recorded", "result_id", "record_path", "record_hash", "gates"),
  row("evaluation.result-recorded", "result_id", "record_path", "record_hash", "evaluations"),
]);

const REGISTRY_BY_EVENT = new Map(RUNTIME_RECORD_FAMILY_REGISTRY_V02.map((entry) => [entry.event_type, entry]));

function fail(reason: RuntimeRecordAdmissionReasonV02): RuntimeRecordAdmissionResultV02 {
  return { ok: false, reason };
}

function payloadOf(event: RuntimeEventV02Value): Record<string, unknown> {
  return event.payload as unknown as Record<string, unknown>;
}

function strictPayloadRecordSchema(payload: Record<string, unknown>): ZodType {
  const shape = Object.fromEntries(["schema_version", ...Object.keys(payload)].map((key) => [key, z.unknown()]));
  return z.object(shape).strict();
}

function deriveBindings(events: readonly RuntimeEventV02Value[]): BindingDerivationResult {
  const bindings: RecordBinding[] = [];
  const ownedPaths = new Set<string>();
  for (const event of events) {
    const registry = REGISTRY_BY_EVENT.get(event.event_type);
    if (registry === undefined) continue;
    const payload = payloadOf(event);
    const id = payload[registry.id_field];
    const path = payload[registry.event_path_field];
    const hash = payload[registry.event_hash_field];
    if (typeof id !== "string" || typeof path !== "string" || typeof hash !== "string"
      || path !== registry.path_for_id(id) || ownedPaths.has(path)) {
      return { ok: false, reason: "RUNTIME_SCHEMA_INVENTORY_INVALID" };
    }
    ownedPaths.add(path);

    let content: RecordBinding["content"] = null;
    if (registry.content_fields !== undefined) {
      const contentPath = payload[registry.content_fields.path];
      const contentHash = payload[registry.content_fields.hash];
      const contentSize = payload[registry.content_fields.size];
      const allNull = contentPath === null && contentHash === null && contentSize === null;
      if (!allNull) {
        if (typeof contentPath !== "string" || typeof contentHash !== "string"
          || !Number.isSafeInteger(contentSize) || (contentSize as number) < 0 || ownedPaths.has(contentPath)
          || (registry.content_fields.path_for_id !== undefined
            && contentPath !== registry.content_fields.path_for_id(id))) {
          return { ok: false, reason: "RUNTIME_SCHEMA_INVENTORY_INVALID" };
        }
        ownedPaths.add(contentPath);
        content = { path: contentPath, hash: contentHash, size: contentSize as number };
      }
    }
    bindings.push({
      path, hash, id, event, schema: registry.schema, content,
      ...(registry.event_record_field_paths === undefined
        ? {}
        : { event_record_field_paths: registry.event_record_field_paths }),
      ...(registry.event_record_field_values === undefined
        ? {}
        : { event_record_field_values: registry.event_record_field_values }),
    });
  }
  return { ok: true, bindings };
}

function valueAtPath(record: Record<string, unknown>, path: readonly string[]): unknown {
  let value: unknown = record;
  for (const segment of path) {
    if (typeof value !== "object" || value === null || Array.isArray(value) || !Object.hasOwn(value, segment)) {
      return undefined;
    }
    value = (value as Record<string, unknown>)[segment];
  }
  return value;
}

function selectedEventBindingsMatch(record: Record<string, unknown>, binding: RecordBinding): boolean {
  const payload = payloadOf(binding.event);
  for (const [key, eventValue] of Object.entries(payload)) {
    const derivedValue = binding.event_record_field_values?.[key];
    const mappedPath = binding.event_record_field_paths?.[key];
    if (derivedValue !== undefined) {
      if (canonicalize(derivedValue(record)) !== canonicalize(eventValue)) return false;
    } else if (mappedPath !== undefined) {
      if (canonicalize(valueAtPath(record, mappedPath)) !== canonicalize(eventValue)) return false;
    } else if (Object.hasOwn(record, key) && canonicalize(record[key]) !== canonicalize(eventValue)) {
      return false;
    }
  }
  if (Object.hasOwn(record, "run_id") && record.run_id !== binding.event.run_id) return false;
  return true;
}

export function admitRuntimeRecordsV02(
  input: RuntimeRecordAdmissionInputV02,
): RuntimeRecordAdmissionResultV02 {
  try {
    if (input.events.some((event) => event.run_id !== input.run_id)) {
      return fail("RUNTIME_RECORD_SCHEMA_INVALID");
    }
    const derived = deriveBindings(input.events);
    if (!derived.ok) return derived;
    const bindings = derived.bindings;
    const expectedPaths = new Set(bindings.flatMap((binding) => [binding.path, ...(binding.content === null ? [] : [binding.content.path])]));
    for (const path of expectedPaths) {
      if (!input.record_bytes_by_path.has(path)) return fail("RUNTIME_RECORD_MISSING");
    }
    if (input.record_bytes_by_path.size !== expectedPaths.size
      || [...input.record_bytes_by_path.keys()].some((path) => !expectedPaths.has(path))
      || input.raw_hash_by_path.size !== expectedPaths.size
      || [...input.raw_hash_by_path.keys()].some((path) => !expectedPaths.has(path))) {
      return fail("RUNTIME_SCHEMA_INVENTORY_INVALID");
    }

    const records = new Map<string, unknown>();
    const contents = new Map<string, Uint8Array>();
    for (const binding of [...bindings].sort((left, right) => compareRuntimeUtf8BytesV02(left.path, right.path))) {
      const bytes = input.record_bytes_by_path.get(binding.path)!;
      if (input.raw_hash_by_path.get(binding.path) !== hashRawBytes(bytes)) return fail("RUNTIME_RECORD_HASH_INVALID");
      const decoded = decodeStructuredDocumentV02(bytes, "json");
      if (!decoded.ok || typeof decoded.value !== "object" || decoded.value === null || Array.isArray(decoded.value)) {
        return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      }
      const record = decoded.value as Record<string, unknown>;
      const schema = binding.schema ?? strictPayloadRecordSchema(payloadOf(binding.event));
      if (record.schema_version !== "0.2" || typeof record.record_hash !== "string") return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      const { record_hash: recordHash, ...preimage } = record;
      if (recordHash !== hashCanonical(preimage) || recordHash !== binding.hash) return fail("RUNTIME_RECORD_HASH_INVALID");
      if (!schema.safeParse(record).success) return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      if (Object.hasOwn(record, "run_id") && record.run_id !== input.run_id) return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      if (Object.hasOwn(record, "plan_hash") && record.plan_hash !== input.plan_hash) return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      if (!selectedEventBindingsMatch(record, binding)) return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      records.set(binding.path, Object.freeze(record));

      if (binding.content !== null) {
        const contentBytes = input.record_bytes_by_path.get(binding.content.path)!;
        const rawHash = hashRawBytes(contentBytes);
        if (input.raw_hash_by_path.get(binding.content.path) !== rawHash
          || rawHash !== binding.content.hash || contentBytes.byteLength !== binding.content.size) {
          return fail("RUNTIME_RECORD_HASH_INVALID");
        }
        contents.set(binding.content.path, new Uint8Array(contentBytes));
      }
    }

    const orderedPaths = Object.freeze([...expectedPaths].sort(compareRuntimeUtf8BytesV02));
    return {
      ok: true,
      value: Object.freeze({ records_by_path: records, content_bytes_by_path: contents, ordered_paths: orderedPaths }),
    };
  } catch {
    return fail("RUNTIME_RECORD_SCHEMA_INVALID");
  }
}
