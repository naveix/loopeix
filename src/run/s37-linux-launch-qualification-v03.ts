import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import { z } from "zod";

import { Hash } from "../schema/scalars.js";
import { MachineIdV02 as MachineId } from "../schema/scalars-v02.js";
import {
  revalidateSimulatedAuthorityLeaseV02,
  simulateAuthorityDecisionV02,
  type AuthorityDecisionSimulationValueV02,
  type SimulatedAuthorityLeaseV02,
} from "./action-classifier-policy-v02.js";
import {
  canonicalV03,
  hashCanonicalV03,
  parseS37LinuxLaunchQualificationV03,
  parseS37LocalProductHostAnchorV03,
  parseS37ProductHostQualificationRequestV01,
  qualificationSigningBytesV03,
  qualificationStatementHashV03,
  verifyS37LinuxLaunchQualificationSignatureV03,
} from "./s37-product-host-contract-v03.js";

const exactUtcSecond = z.iso.datetime({ offset: false, local: false, precision: 0 });
const safeGeneration = z.number().int().positive().refine(Number.isSafeInteger);
const DENY_ROWS = Object.freeze([
  "ambient-credentials", "child-process", "durable-state", "environment",
  "filesystem-write", "network", "output-limits", "retry", "stdin",
  "timeout", "tool-server", "unknown-outcome",
] as const);

const QualificationIssuerV03 = z.object({
  key_ref: MachineId,
  algorithm: z.literal("ed25519"),
  public_key_spki_base64: z.string(),
  public_key_spki_sha256: Hash,
}).strict();

const AnchorFieldsV03 = z.object({
  anchor_hash: Hash,
  generation: safeGeneration,
  runtime_profile_hash: Hash,
  host: z.unknown(),
  artifacts: z.unknown(),
  qualification_issuer: QualificationIssuerV03,
}).loose();

const QualificationRequestFieldsV01 = z.object({
  anchor_hash: Hash,
  anchor_generation: safeGeneration,
  runtime_profile_hash: Hash,
  action_proposal_hash: Hash,
  decision_input_hash: Hash,
  decision_simulation_hash: Hash,
  lease_simulation_hash: Hash,
  launch_nonce: Hash,
  requested_at: exactUtcSecond,
  expires_at: exactUtcSecond,
  request_hash: Hash,
}).loose();

const PhaseBRootsV03 = z.object({
  manifest_sha256: Hash,
  readiness_evidence_sha256: Hash,
  readiness_envelope_sha256: Hash,
  conformance_evidence_sha256: Hash,
  receipt_hash: Hash,
}).strict();

const DenyWitnessV03 = z.object({
  row: z.enum(DENY_ROWS),
  witness_sha256: Hash,
}).strict();

const QualificationObservationV03 = z.object({
  observed_at: exactUtcSecond,
  boot_id_hash: Hash,
  host: z.unknown(),
  runtime_profile_hash: Hash,
  phase_b: PhaseBRootsV03,
  artifacts: z.unknown(),
  deny_witnesses: z.array(DenyWitnessV03).length(DENY_ROWS.length),
}).strict();

const DecisionInputFieldsV02 = z.object({
  proposal: z.object({ action_proposal_hash: Hash }).loose(),
}).loose();

const SimulatedLeaseFieldsV02 = z.object({
  durable: z.literal(false),
  single_use_slot: z.literal(0),
  action_proposal_hash: Hash,
  invalidation_fingerprint: Hash,
  lease_simulation_hash: Hash,
}).strict();

const QualificationFieldsV03 = z.object({
  anchor_hash: Hash,
  anchor_generation: safeGeneration,
  boot_id_hash: Hash,
  host: z.unknown(),
  observed_at: exactUtcSecond,
  runtime_profile_hash: Hash,
  phase_b: PhaseBRootsV03,
  artifacts: z.unknown(),
  deny_witnesses: z.array(DenyWitnessV03).length(DENY_ROWS.length),
  request_hash: Hash,
  decision_input_hash: Hash,
  decision_simulation_hash: Hash,
  lease_simulation_hash: Hash,
  action_proposal_hash: Hash,
  launch_nonce: Hash,
  issued_at: exactUtcSecond,
  expires_at: exactUtcSecond,
  qualification_hash: Hash,
}).loose();

const IssueInputV03 = z.object({
  anchor: z.unknown(),
  qualification_request: z.unknown(),
  decision_input: z.unknown(),
  decision: z.unknown(),
  simulated_lease: z.unknown(),
}).strict();

const AdmitInputV03 = IssueInputV03.extend({
  qualification: z.unknown(),
  observation: z.unknown(),
}).strict();

export type S37QualificationObservationV03 = Readonly<z.infer<typeof QualificationObservationV03>>;
export type S37LinuxLaunchQualificationV03 = Readonly<z.infer<typeof QualificationFieldsV03>>;

class CapturedS37QualificationIssuerSignerTokenV03 {
  readonly #capturedS37QualificationIssuerSignerV03 = true;

  private constructor() {
    void this.#capturedS37QualificationIssuerSignerV03;
    Object.freeze(this);
  }

  static create(): CapturedS37QualificationIssuerSignerTokenV03 {
    return new CapturedS37QualificationIssuerSignerTokenV03();
  }
}

export type CapturedS37QualificationIssuerSignerV03 = CapturedS37QualificationIssuerSignerTokenV03;

type SignerSnapshotV03 = Readonly<{
  key_ref: string;
  private_key: KeyObject;
  public_key_spki_base64: string;
  public_key_spki_sha256: string;
}>;

const signerSnapshots = new WeakMap<object, SignerSnapshotV03>();

export function captureS37QualificationIssuerSignerV03(
  keyRef: string,
  privateKeyPem: string,
): CapturedS37QualificationIssuerSignerV03 {
  const parsedRef = MachineId.parse(keyRef);
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new TypeError("qualification signer must be Ed25519");
  const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const token = CapturedS37QualificationIssuerSignerTokenV03.create();
  signerSnapshots.set(token, Object.freeze({
    key_ref: parsedRef,
    private_key: privateKey,
    public_key_spki_base64: publicKey.toString("base64"),
    public_key_spki_sha256: `sha256:${createHash("sha256").update(publicKey).digest("hex")}`,
  }));
  return token;
}

class CapturedS37QualificationBootObserverTokenV03 {
  readonly #capturedS37QualificationBootObserverV03 = true;

  private constructor() {
    void this.#capturedS37QualificationBootObserverV03;
    Object.freeze(this);
  }

  static create(): CapturedS37QualificationBootObserverTokenV03 {
    return new CapturedS37QualificationBootObserverTokenV03();
  }
}

export type CapturedS37QualificationBootObserverV03 = CapturedS37QualificationBootObserverTokenV03;
type QualificationObserverV03 = () => unknown;
const bootObservers = new WeakMap<object, QualificationObserverV03>();

export function captureS37QualificationBootObserverV03(
  observe: QualificationObserverV03,
): CapturedS37QualificationBootObserverV03 {
  if (typeof observe !== "function") throw new TypeError("qualification boot observer is required");
  const token = CapturedS37QualificationBootObserverTokenV03.create();
  bootObservers.set(token, observe);
  return token;
}

export type IssueS37LinuxLaunchQualificationResultV03 =
  | Readonly<{ ok: true; value: S37LinuxLaunchQualificationV03 }>
  | Readonly<{ ok: false; error: "QUALIFICATION_ISSUANCE_INVALID" }>;

function issueInvalid(): Readonly<{ ok: false; error: "QUALIFICATION_ISSUANCE_INVALID" }> {
  return Object.freeze({ ok: false, error: "QUALIFICATION_ISSUANCE_INVALID" });
}

function admissionInvalid(): Readonly<{ ok: false; error: "QUALIFICATION_ADMISSION_INVALID" }> {
  return Object.freeze({ ok: false, error: "QUALIFICATION_ADMISSION_INVALID" });
}

function exactEqual(left: unknown, right: unknown): boolean {
  const a = canonicalV03(left);
  const b = canonicalV03(right);
  return a.ok && b.ok && a.value === b.value;
}

function canonicalClone(value: unknown): unknown | null {
  const canonical = canonicalV03(value);
  if (!canonical.ok) return null;
  try {
    const clone: unknown = JSON.parse(canonical.value);
    return clone;
  } catch {
    return null;
  }
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

type ValidatedFactsV03 = Readonly<{
  decision_input: unknown;
  decision: AuthorityDecisionSimulationValueV02;
  simulated_lease: SimulatedAuthorityLeaseV02;
  action_proposal_hash: string;
  decision_input_hash: string;
}>;

function validateDecisionFacts(
  decisionInputCandidate: unknown,
  decisionCandidate: unknown,
  leaseCandidate: unknown,
): ValidatedFactsV03 | null {
  const inputFields = DecisionInputFieldsV02.safeParse(decisionInputCandidate);
  const lease = SimulatedLeaseFieldsV02.safeParse(leaseCandidate);
  const recomputed = simulateAuthorityDecisionV02(decisionInputCandidate);
  if (!inputFields.success || !lease.success || !recomputed.ok
    || recomputed.value.simulated_lease === null
    || !exactEqual(recomputed.value, decisionCandidate)
    || !exactEqual(recomputed.value.simulated_lease, lease.data)
    || !revalidateSimulatedAuthorityLeaseV02(lease.data, decisionInputCandidate).ok) return null;
  const decisionInputHash = hashCanonicalV03({
    purpose: "s37-product-host-decision-input-v01",
    decision_input: decisionInputCandidate,
  });
  const clonedInput = canonicalClone(decisionInputCandidate);
  if (!decisionInputHash.ok || clonedInput === null) return null;
  return deepFreeze({
    decision_input: clonedInput,
    decision: recomputed.value,
    simulated_lease: lease.data,
    action_proposal_hash: inputFields.data.proposal.action_proposal_hash,
    decision_input_hash: decisionInputHash.value,
  });
}

function validatedAnchorAndRequest(anchorCandidate: unknown, requestCandidate: unknown) {
  const parsedAnchor = parseS37LocalProductHostAnchorV03(anchorCandidate);
  const parsedRequest = parseS37ProductHostQualificationRequestV01(requestCandidate);
  if (!parsedAnchor.ok || !parsedRequest.ok) return null;
  const anchorFields = AnchorFieldsV03.safeParse(parsedAnchor.value);
  const requestFields = QualificationRequestFieldsV01.safeParse(parsedRequest.value);
  if (!anchorFields.success || !requestFields.success) return null;
  return Object.freeze({
    anchor: parsedAnchor.value,
    anchor_fields: anchorFields.data,
    request: parsedRequest.value,
    request_fields: requestFields.data,
  });
}

function requestMatchesFacts(
  anchor: z.infer<typeof AnchorFieldsV03>,
  request: z.infer<typeof QualificationRequestFieldsV01>,
  facts: ValidatedFactsV03,
): boolean {
  return request.anchor_hash === anchor.anchor_hash
    && request.anchor_generation === anchor.generation
    && request.runtime_profile_hash === anchor.runtime_profile_hash
    && request.action_proposal_hash === facts.action_proposal_hash
    && request.decision_input_hash === facts.decision_input_hash
    && request.decision_simulation_hash === facts.decision.decision_simulation_hash
    && request.lease_simulation_hash === facts.simulated_lease.lease_simulation_hash;
}

function observationOrderValid(observation: z.infer<typeof QualificationObservationV03>): boolean {
  return observation.deny_witnesses.every((witness, index) => witness.row === DENY_ROWS[index]);
}

function exactSecond(ms: number): string | null {
  if (!Number.isFinite(ms) || ms % 1_000 !== 0) return null;
  return new Date(ms).toISOString().replace(".000Z", "Z");
}

export function issueS37LinuxLaunchQualificationV03(
  input: unknown,
  capabilities: Readonly<{
    signer: CapturedS37QualificationIssuerSignerV03;
    boot_observer: CapturedS37QualificationBootObserverV03;
  }>,
): IssueS37LinuxLaunchQualificationResultV03 {
  try {
    const parsedInput = IssueInputV03.safeParse(input);
    if (!parsedInput.success) return issueInvalid();
    const signer = signerSnapshots.get(capabilities.signer);
    const observe = bootObservers.get(capabilities.boot_observer);
    const records = validatedAnchorAndRequest(parsedInput.data.anchor, parsedInput.data.qualification_request);
    const facts = validateDecisionFacts(
      parsedInput.data.decision_input,
      parsedInput.data.decision,
      parsedInput.data.simulated_lease,
    );
    if (signer === undefined || observe === undefined || records === null || facts === null
      || !requestMatchesFacts(records.anchor_fields, records.request_fields, facts)) return issueInvalid();
    const issuer = records.anchor_fields.qualification_issuer;
    if (issuer.key_ref !== signer.key_ref || issuer.algorithm !== "ed25519"
      || issuer.public_key_spki_base64 !== signer.public_key_spki_base64
      || issuer.public_key_spki_sha256 !== signer.public_key_spki_sha256) return issueInvalid();

    const first = QualificationObservationV03.safeParse(observe());
    if (!first.success || !observationOrderValid(first.data)
      || first.data.runtime_profile_hash !== records.anchor_fields.runtime_profile_hash
      || !exactEqual(first.data.host, records.anchor_fields.host)
      || !exactEqual(first.data.artifacts, records.anchor_fields.artifacts)) return issueInvalid();
    const issuedAtMs = Date.parse(first.data.observed_at);
    const requestedAtMs = Date.parse(records.request_fields.requested_at);
    const requestExpiresAtMs = Date.parse(records.request_fields.expires_at);
    const expiresAtMs = Math.min(issuedAtMs + 30_000, requestExpiresAtMs);
    const expiresAt = exactSecond(expiresAtMs);
    if (requestedAtMs > issuedAtMs || issuedAtMs >= requestExpiresAtMs || expiresAt === null || issuedAtMs >= expiresAtMs) {
      return issueInvalid();
    }

    const unsigned = {
      schema_version: "s37-linux-launch-qualification-v03",
      product_profile: "s37-local-product-inert-v03",
      anchor_hash: records.anchor_fields.anchor_hash,
      anchor_generation: records.anchor_fields.generation,
      boot_id_hash: first.data.boot_id_hash,
      host: first.data.host,
      observed_at: first.data.observed_at,
      runtime_profile_hash: first.data.runtime_profile_hash,
      phase_b: first.data.phase_b,
      artifacts: first.data.artifacts,
      deny_witnesses: first.data.deny_witnesses,
      request_hash: records.request_fields.request_hash,
      decision_input_hash: facts.decision_input_hash,
      decision_simulation_hash: facts.decision.decision_simulation_hash,
      lease_simulation_hash: facts.simulated_lease.lease_simulation_hash,
      action_proposal_hash: facts.action_proposal_hash,
      launch_nonce: records.request_fields.launch_nonce,
      issued_at: first.data.observed_at,
      expires_at: expiresAt,
    };
    const header = { issuer_key_ref: signer.key_ref, signature_algorithm: "ed25519" };
    const statement = qualificationStatementHashV03(unsigned, header);
    const signingBytes = qualificationSigningBytesV03(unsigned, header);
    if (!statement.ok || !signingBytes.ok) return issueInvalid();
    const attestation = {
      ...header,
      statement_hash: statement.value,
      signature_value: cryptoSign(null, signingBytes.value, signer.private_key).toString("base64"),
    };
    const withoutHash = { ...unsigned, attestation };
    const qualificationHash = hashCanonicalV03({
      purpose: "s37-linux-launch-qualification-v03",
      ...withoutHash,
    });
    if (!qualificationHash.ok) return issueInvalid();
    const completed = { ...withoutHash, qualification_hash: qualificationHash.value };
    const verified = verifyS37LinuxLaunchQualificationSignatureV03(completed, issuer);
    const second = QualificationObservationV03.safeParse(observe());
    if (!verified.ok || !second.success || second.data.boot_id_hash !== first.data.boot_id_hash) return issueInvalid();
    const narrowed = QualificationFieldsV03.safeParse(verified.value);
    return narrowed.success
      ? Object.freeze({ ok: true, value: deepFreeze(narrowed.data) })
      : issueInvalid();
  } catch {
    return issueInvalid();
  }
}

class AuthorizedS37LinuxLaunchQualificationTokenV03 {
  readonly #authorizedS37LinuxLaunchQualificationV03 = true;

  private constructor() {
    void this.#authorizedS37LinuxLaunchQualificationV03;
    Object.freeze(this);
  }

  static create(): AuthorizedS37LinuxLaunchQualificationTokenV03 {
    return new AuthorizedS37LinuxLaunchQualificationTokenV03();
  }
}

export type AuthorizedS37LinuxLaunchQualificationV03 = AuthorizedS37LinuxLaunchQualificationTokenV03;

export type S37AuthorizedLinuxLaunchQualificationBindingV03 = Readonly<{
  qualification: S37LinuxLaunchQualificationV03;
  anchor: Readonly<Record<string, unknown>>;
  qualification_request: Readonly<Record<string, unknown>>;
  decision_input: unknown;
  decision: AuthorityDecisionSimulationValueV02;
  simulated_lease: SimulatedAuthorityLeaseV02;
  observation: S37QualificationObservationV03;
}>;

export type AdmitS37LinuxLaunchQualificationResultV03 =
  | Readonly<{ ok: true; value: AuthorizedS37LinuxLaunchQualificationV03 }>
  | Readonly<{ ok: false; error: "QUALIFICATION_ADMISSION_INVALID" }>;

const qualificationBindings = new WeakMap<object, S37AuthorizedLinuxLaunchQualificationBindingV03>();
const reservedQualificationHashes = new Set<string>();

export function admitS37LinuxLaunchQualificationV03(input: unknown): AdmitS37LinuxLaunchQualificationResultV03 {
  try {
    const parsedInput = AdmitInputV03.safeParse(input);
    if (!parsedInput.success) return admissionInvalid();
    const records = validatedAnchorAndRequest(parsedInput.data.anchor, parsedInput.data.qualification_request);
    const facts = validateDecisionFacts(
      parsedInput.data.decision_input,
      parsedInput.data.decision,
      parsedInput.data.simulated_lease,
    );
    const qualification = parseS37LinuxLaunchQualificationV03(parsedInput.data.qualification);
    const observation = QualificationObservationV03.safeParse(parsedInput.data.observation);
    if (records === null || facts === null || !qualification.ok || !observation.success
      || !observationOrderValid(observation.data)
      || !requestMatchesFacts(records.anchor_fields, records.request_fields, facts)) return admissionInvalid();
    const verified = verifyS37LinuxLaunchQualificationSignatureV03(
      qualification.value,
      records.anchor_fields.qualification_issuer,
    );
    const narrowed = QualificationFieldsV03.safeParse(verified.ok ? verified.value : null);
    if (!verified.ok || !narrowed.success) return admissionInvalid();
    const value = narrowed.data;
    const observedAtMs = Date.parse(observation.data.observed_at);
    const expiresAtMs = Date.parse(value.expires_at);
    if (reservedQualificationHashes.has(value.qualification_hash)
      || expiresAtMs - observedAtMs < 15_000
      || observedAtMs < Date.parse(value.observed_at)
      || observedAtMs >= Date.parse(records.request_fields.expires_at)
      || value.anchor_hash !== records.anchor_fields.anchor_hash
      || value.anchor_generation !== records.anchor_fields.generation
      || value.request_hash !== records.request_fields.request_hash
      || value.decision_input_hash !== facts.decision_input_hash
      || value.decision_simulation_hash !== facts.decision.decision_simulation_hash
      || value.lease_simulation_hash !== facts.simulated_lease.lease_simulation_hash
      || value.action_proposal_hash !== facts.action_proposal_hash
      || value.launch_nonce !== records.request_fields.launch_nonce
      || value.boot_id_hash !== observation.data.boot_id_hash
      || value.runtime_profile_hash !== observation.data.runtime_profile_hash
      || !exactEqual(value.host, observation.data.host)
      || !exactEqual(value.artifacts, observation.data.artifacts)
      || !exactEqual(value.phase_b, observation.data.phase_b)
      || !exactEqual(value.deny_witnesses, observation.data.deny_witnesses)
      || !exactEqual(observation.data.host, records.anchor_fields.host)
      || !exactEqual(observation.data.artifacts, records.anchor_fields.artifacts)
      || observation.data.runtime_profile_hash !== records.anchor_fields.runtime_profile_hash) return admissionInvalid();

    const qualificationValue = deepFreeze(narrowed.data);
    const binding = deepFreeze({
      qualification: qualificationValue,
      anchor: records.anchor,
      qualification_request: records.request,
      decision_input: facts.decision_input,
      decision: facts.decision,
      simulated_lease: facts.simulated_lease,
      observation: observation.data,
    });
    const capability = AuthorizedS37LinuxLaunchQualificationTokenV03.create();
    reservedQualificationHashes.add(value.qualification_hash);
    qualificationBindings.set(capability, binding);
    return Object.freeze({ ok: true, value: capability });
  } catch {
    return admissionInvalid();
  }
}

export function consumeAuthorizedS37LinuxLaunchQualificationV03(
  capability: unknown,
): S37AuthorizedLinuxLaunchQualificationBindingV03 | null {
  if ((typeof capability !== "object" && typeof capability !== "function") || capability === null) return null;
  const binding = qualificationBindings.get(capability);
  if (binding === undefined) return null;
  qualificationBindings.delete(capability);
  return binding;
}
