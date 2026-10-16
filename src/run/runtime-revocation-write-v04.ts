import { isProxy } from "node:util/types";

import { z } from "zod";

import { canonicalize, hashCanonical, hashRawBytes } from "../hash.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../schema/runtime-v04.js";
import { Hash } from "../schema/scalars.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import {
  isValidatedRuntimePlanV03,
  inspectRuntimePlanV03,
  type ValidatedRuntimePlanV03,
} from "./project-plan-v03.js";
import {
  consumeRuntimeClockObservationV04,
  type CapturedRuntimeClockObservationV04,
} from "./runtime-clock-observation-v04.js";
import {
  closeRuntimeFileStoreSessionV04,
  commitRuntimeFileStoreSessionV04,
  commitRuntimeRecordFileStoreSessionV04,
  openRuntimeFileStoreSessionV04,
  readRuntimeFileStoreSessionSnapshotV04,
  type CapturedRuntimeFileStoreV04,
  type RuntimeFileStoreSessionSnapshotV04,
  type RuntimeFileStoreSessionV04,
} from "./runtime-file-store-v04.js";
import {
  inspectRuntimeLedgerV04,
  type ValidatedRuntimeLedgerV04,
} from "./runtime-ledger-v04.js";
import {
  buildRunManifestV04,
  captureValidatedRunManifestFileV04,
  inspectRunManifestV04,
  isValidatedRunManifestPairV04,
  type ValidatedRunManifestV04,
} from "./runtime-manifest-v04.js";
import { reduceRuntimeEventPrefixV04 } from "./runtime-state-reducer-v04.js";
import {
  AuthorityRevocationRecordV02,
  isCapturedAuthorityTrustContextV02,
  produceAuthorityRevocationRecordV02,
  type AuthorityRevocationRecordV02Value,
  type CapturedAuthorityTrustContextForS36V02,
  type HostProducerEd25519SignerV02,
} from "./runtime-record-admission-v02.js";

type LedgerRef = Readonly<{ ledger_sequence: number; event_hash: string }>;

const RuntimeRevocationTargetRefV04 = z.discriminatedUnion("record_kind", [
  z.object({
    record_kind: z.literal("authority-envelope"),
    record_id: MachineIdV02,
    record_event_ref: z.object({
      ledger_sequence: z.number().int().positive().refine(Number.isSafeInteger),
      event_hash: Hash,
    }).strict(),
  }).strict(),
  z.object({
    record_kind: z.literal("gate-waiver-authority"),
    record_id: MachineIdV02,
    record_event_ref: z.object({
      ledger_sequence: z.number().int().positive().refine(Number.isSafeInteger),
      event_hash: Hash,
    }).strict(),
  }).strict(),
]);

const RuntimeRevocationCaptureRequestV04 = z.object({
  event_id: MachineIdV02,
  revocation_id: MachineIdV02,
  target_ref: RuntimeRevocationTargetRefV04,
  reason_code: z.enum([
    "operator-revoked",
    "authority-expired",
    "scope-invalidated",
    "policy-changed",
    "principal-revoked",
    "compromise-suspected",
  ]),
  evidence_refs: z.array(z.object({
    record_kind: z.string().min(1),
    record_id: z.string().min(1),
    record_event_ref: z.object({
      ledger_sequence: z.number().int().positive().refine(Number.isSafeInteger),
      event_hash: Hash,
    }).strict(),
  }).strict()).min(1),
  revoker_identity_ref: MachineIdV02,
  revoker_stable_identity_hash: Hash,
}).strict();

const RuntimeRevocationCaptureInputV04 = z.object({
  trust_context: z.custom<CapturedAuthorityTrustContextForS36V02>(),
  signer: z.custom<HostProducerEd25519SignerV02>(),
  validated_plan: z.custom<ValidatedRuntimePlanV03>(),
  ledger: z.custom<ValidatedRuntimeLedgerV04>(),
  manifest: z.custom<ValidatedRunManifestV04>(),
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  request: RuntimeRevocationCaptureRequestV04,
}).strict();

const RuntimeRevocationWriteInputV04 = z.object({
  captured_request: z.custom<CapturedRuntimeAuthorityRevocationV04>(),
}).strict();

const ContinueRuntimeRevocationWriteInputV04 = z.object({
  pending_revocation_event_ref: z.object({
    ledger_sequence: z.number().int().positive().refine(Number.isSafeInteger),
    event_hash: Hash,
  }).strict(),
}).strict();

type RevocationBinding = Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  source_boundary_sequence: number;
  source_boundary_head_hash: string;
  source_manifest_hash: string;
  current_fence_epoch: number;
  current_attempt_event_ref: LedgerRef;
  invalidated_owner_lease_refs: readonly LedgerRef[];
  revocation_event: RuntimeEventV04Value;
  fence_event: RuntimeEventV04Value;
  record: AuthorityRevocationRecordV02Value;
  record_path: string;
  record_bytes: Uint8Array;
}>;

class CapturedRuntimeAuthorityRevocationTokenV04 {
  readonly #brand = true;
  private constructor() { void this.#brand; Object.freeze(this); }
  static create(): CapturedRuntimeAuthorityRevocationTokenV04 { return new CapturedRuntimeAuthorityRevocationTokenV04(); }
}

const capturedRevocations = new WeakMap<object, RevocationBinding>();

export type CapturedRuntimeAuthorityRevocationV04 = CapturedRuntimeAuthorityRevocationTokenV04;

export type CaptureRuntimeAuthorityRevocationResultV04 =
  | Readonly<{ ok: true; value: CapturedRuntimeAuthorityRevocationV04 }>
  | Readonly<{ ok: false; error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" }>;

export type RuntimeAuthorityRevocationWriteResultV04 =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      revocation_event_ref: LedgerRef;
      fence_event_ref: LedgerRef;
      ledger_bytes_hash: string;
      manifest_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "REVOCATION_COMMITTED_FENCE_NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_REVOCATION_INPUT_INVALID"
        | "RUNTIME_REVOCATION_AUTHORIZATION_INVALID"
        | "RUNTIME_REVOCATION_PREFIX_INVALID"
        | "RUNTIME_REVOCATION_NOT_COMMITTED"
        | "RUNTIME_REVOCATION_FENCE_NOT_COMMITTED"
        | "RUNTIME_REVOCATION_OUTCOME_UNKNOWN";
      revocation_event_ref?: LedgerRef;
    }>;

type InspectedStore = Readonly<{
  snapshot: RuntimeFileStoreSessionSnapshotV04;
  plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
}>;

function exactPlainObject(value: unknown, keys: readonly string[]): boolean {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value) || isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).some((key) => typeof key !== "string")) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return Object.keys(descriptors).sort().join("\0") === [...keys].sort().join("\0")
      && Object.values(descriptors).every((descriptor) => "value" in descriptor
        && descriptor.get === undefined && descriptor.set === undefined && descriptor.enumerable === true);
  } catch { return false; }
}

function refOf(event: Readonly<{ sequence: number; event_hash: string }>): LedgerRef {
  return Object.freeze({ ledger_sequence: event.sequence, event_hash: event.event_hash });
}

function sameRef(left: LedgerRef, right: LedgerRef): boolean {
  return left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function sameRefs(left: readonly LedgerRef[], right: readonly LedgerRef[]): boolean {
  return left.length === right.length && left.every((ref, index) => sameRef(ref, right[index]!));
}

function maximumObservedElapsed(ledger: ValidatedRuntimeLedgerV04): number {
  return ledger.events.reduce((maximum, row) => row.event_type === "run.clock-observed"
    ? Math.max(maximum, row.payload.elapsed_ms) : maximum, 0);
}

function eventAtRef(
  ledger: ValidatedRuntimeLedgerV04,
  reference: LedgerRef,
): RuntimeEventV04Value | null {
  const row = ledger.events[reference.ledger_sequence - 1];
  return row?.event_hash === reference.event_hash ? row : null;
}

function targetFromLedger(
  ledger: ValidatedRuntimeLedgerV04,
  targetRef: z.infer<typeof RuntimeRevocationTargetRefV04>,
): z.infer<typeof AuthorityRevocationRecordV02.shape.target> | null {
  const targetEvent = eventAtRef(ledger, targetRef.record_event_ref);
  if (targetRef.record_kind === "authority-envelope") {
    if (targetEvent?.event_type !== "authority.envelope-recorded"
      || targetEvent.payload.authority_envelope_id !== targetRef.record_id) {
      return null;
    }
    return Object.freeze({
      kind: "authority-envelope",
      target_ref: targetRef,
      target_scope_hash: targetEvent.payload.action_scope_hash,
    });
  }
  if (targetEvent?.event_type !== "authority.waiver-recorded"
    || targetEvent.payload.authority_record_id !== targetRef.record_id) {
    return null;
  }
  return Object.freeze({
    kind: "gate-waiver-authority",
    target_ref: targetRef,
    target_scope_hash: targetEvent.payload.action_scope_hash,
  });
}

function priorRevocationEpoch(
  ledger: ValidatedRuntimeLedgerV04,
  target: z.infer<typeof AuthorityRevocationRecordV02.shape.target>,
): number | null {
  const baseEvent = eventAtRef(ledger, target.target_ref.record_event_ref);
  if (baseEvent === null) return null;
  const baseEpoch = typeof (baseEvent.payload as Record<string, unknown>).revocation_epoch === "number"
    ? (baseEvent.payload as Record<string, unknown>).revocation_epoch as number
    : 0;
  let previous = baseEpoch;
  for (const row of ledger.events) {
    if (row.event_type !== "authority.grant-revoked") continue;
    if (row.payload.target.kind !== target.kind) continue;
    const priorRef = row.payload.target.target_ref;
    if (priorRef.record_kind !== target.target_ref.record_kind
      || priorRef.record_id !== target.target_ref.record_id
      || !sameRef(priorRef.record_event_ref, target.target_ref.record_event_ref)) continue;
    previous = row.payload.revocation_epoch;
  }
  return previous;
}

function eventPayloadFromRecord(record: AuthorityRevocationRecordV02Value, recordBytes: Uint8Array) {
  const { schema_version: _schemaVersion, producer_attestation, ...copied } = record;
  return Object.freeze({
    ...copied,
    record_path: `authorities/revocations/${record.revocation_id}.json`,
    record_hash: hashRawBytes(recordBytes),
    signer_key_ref: producer_attestation.signer_key_ref,
    statement_hash: producer_attestation.statement_hash,
  });
}

function recordBytesFromRecord(record: AuthorityRevocationRecordV02Value): Uint8Array {
  return new TextEncoder().encode(`${canonicalize(record)}\n`);
}

function appendLedgerBytes(source: Uint8Array, event: RuntimeEventV04Value): Uint8Array {
  const tail = new TextEncoder().encode(`${JSON.stringify(event)}\n`);
  const joined = new Uint8Array(source.byteLength + tail.byteLength);
  joined.set(source);
  joined.set(tail, source.byteLength);
  return joined;
}

function event(
  prior: readonly RuntimeEventV04Value[],
  eventId: string,
  recordedAt: string,
  eventType: RuntimeEventV04Value["event_type"],
  source: RuntimeEventV04Value["source"],
  authorityRef: string | null,
  riskTier: RuntimeEventV04Value["risk_tier"],
  payload: unknown,
): RuntimeEventV04Value | null {
  const preimage = {
    schema_version: "0.4" as const,
    event_id: eventId,
    run_id: prior[0]!.run_id,
    sequence: prior.length + 1,
    recorded_at: recordedAt,
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

function ownerRefs(ledger: ValidatedRuntimeLedgerV04): readonly LedgerRef[] | null {
  const reduced = reduceRuntimeEventPrefixV04(ledger.events);
  if (!reduced.ok || reduced.state.active_run_owner?.active !== true || reduced.state.current_attempt_event_ref === null) {
    return null;
  }
  return Object.freeze([
    reduced.state.active_run_owner.lease_event_ref,
    ...reduced.state.subordinate_owner_leases.filter((row) => row.active).map((row) => row.lease_event_ref),
  ].map((row) => Object.freeze({ ...row })));
}

function currentAttemptRef(ledger: ValidatedRuntimeLedgerV04): LedgerRef | null {
  const reduced = reduceRuntimeEventPrefixV04(ledger.events);
  if (!reduced.ok || reduced.state.current_attempt_event_ref === null) return null;
  return Object.freeze({ ...reduced.state.current_attempt_event_ref });
}

function currentFenceEpoch(ledger: ValidatedRuntimeLedgerV04): number | null {
  const reduced = reduceRuntimeEventPrefixV04(ledger.events);
  return reduced.ok ? reduced.state.current_fence_epoch : null;
}

function capturedFilesWithLedger(snapshot: RuntimeFileStoreSessionSnapshotV04, ledgerBytes: Uint8Array) {
  return snapshot.captured_files.map((file) => Object.freeze({
    path: file.path,
    family: file.family,
    required: file.required,
    mode: file.path === "ledger.jsonl" ? 384 as const : file.mode,
    bytes: file.path === "ledger.jsonl" ? new Uint8Array(ledgerBytes)
      : file.bytes === null ? null : new Uint8Array(file.bytes),
  }));
}

function inspectStore(session: RuntimeFileStoreSessionV04): InspectedStore | null {
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
    || plan.validated_plan.run_id !== manifest.ledger.run_id
    || plan.validated_plan.plan_hash !== manifest.ledger.plan_hash) return null;
  return Object.freeze({
    snapshot: read.snapshot,
    plan: plan.validated_plan,
    ledger: manifest.ledger,
    manifest: manifest.validated_manifest,
  });
}

function matchesBinding(binding: RevocationBinding, inspected: InspectedStore): boolean {
  const attempt = inspected.ledger.state.current_attempt_event_ref;
  return binding.validated_plan.run_id === inspected.plan.run_id
    && binding.validated_plan.plan_hash === inspected.plan.plan_hash
    && binding.source_boundary_sequence === inspected.ledger.sequence
    && binding.source_boundary_head_hash === inspected.ledger.head_hash
    && binding.source_manifest_hash === inspected.manifest.manifest_hash
    && binding.current_fence_epoch === inspected.ledger.state.current_fence_epoch
    && attempt !== null
    && sameRef(binding.current_attempt_event_ref, attempt)
    && sameRefs(binding.invalidated_owner_lease_refs, ownerRefs(inspected.ledger) ?? []);
}

function nextState(
  inspected: InspectedStore,
  events: readonly RuntimeEventV04Value[],
  persistedRecord: Readonly<{ path: string; bytes: Uint8Array }> | null,
) {
  const ledgerBytes = events.reduce((bytes, eventValue) => appendLedgerBytes(bytes, eventValue), inspected.snapshot.ledger_bytes);
  const checked = inspectRuntimeLedgerV04(ledgerBytes);
  if (!checked.ok) return null;
  const includesRecord = persistedRecord !== null
    && !inspected.snapshot.captured_files.some((file) => file.path === persistedRecord.path);
  const manifest = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: inspected.manifest.created_at,
    captured_files: [
      ...capturedFilesWithLedger(inspected.snapshot, ledgerBytes),
      ...(includesRecord && persistedRecord !== null
        ? [Object.freeze({
            path: persistedRecord.path,
            family: "record" as const,
            required: true,
            mode: 384 as const,
            bytes: new Uint8Array(persistedRecord.bytes),
          })]
        : []),
    ],
  });
  return manifest.ok ? Object.freeze({
    ledger_bytes: ledgerBytes,
    manifest_bytes: manifest.bytes,
  }) : null;
}

function inspectCapturedRevocation(value: unknown): RevocationBinding | null {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return null;
  return capturedRevocations.get(value) ?? null;
}

function consumeCapturedRevocation(value: unknown): RevocationBinding | null {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return null;
  const binding = capturedRevocations.get(value);
  if (binding === undefined) return null;
  capturedRevocations.delete(value);
  return binding;
}

function continuationFailure(
  classification: Extract<RuntimeAuthorityRevocationWriteResultV04, { ok: false }>["classification"],
  error: Extract<RuntimeAuthorityRevocationWriteResultV04, { ok: false }>["error"],
  revocationEventRef?: LedgerRef,
): RuntimeAuthorityRevocationWriteResultV04 {
  return Object.freeze({
    ok: false,
    classification,
    error,
    ...(revocationEventRef === undefined ? {} : { revocation_event_ref: revocationEventRef }),
  });
}

function continuationFenceEvent(
  inspected: InspectedStore,
  revocationEvent: RuntimeEventV04Value,
): RuntimeEventV04Value | null {
  const revocationId = typeof revocationEvent.payload === "object"
    && revocationEvent.payload !== null
    && "revocation_id" in revocationEvent.payload
    && typeof revocationEvent.payload.revocation_id === "string"
    ? revocationEvent.payload.revocation_id
    : null;
  const attemptRef = currentAttemptRef(inspected.ledger);
  const fenceEpoch = currentFenceEpoch(inspected.ledger);
  const invalidatedOwnerLeaseRefs = ownerRefs(inspected.ledger);
  if (revocationId === null
    || attemptRef === null
    || fenceEpoch === null
    || invalidatedOwnerLeaseRefs === null
    || fenceEpoch >= Number.MAX_SAFE_INTEGER) {
    return null;
  }
  return event(
    inspected.ledger.events,
    `event_fence_${revocationId}`,
    revocationEvent.recorded_at,
    "run.fence-advanced",
    "policy-enforcement-point",
    revocationEvent.authority_ref,
    revocationEvent.risk_tier,
    {
      previous_fence_epoch: fenceEpoch,
      fence_epoch: fenceEpoch + 1,
      reason: "authority-revoked",
      evidence_refs: [refOf(revocationEvent)],
      attempt_ref: attemptRef,
      owner_lease_refs: invalidatedOwnerLeaseRefs,
    },
  );
}

function validatedRevocationEventRecord(
  inspected: InspectedStore,
  revocationEvent: RuntimeEventV04Value,
): Readonly<{
    path: string;
    hash: string;
    record: AuthorityRevocationRecordV02Value;
  }> | null {
  const payload = revocationEvent.payload;
  if (typeof payload !== "object" || payload === null) return null;
  const {
    record_path: recordPath,
    record_hash: recordHash,
    revocation_id: revocationId,
    run_id: runId,
    plan_hash: planHash,
    signer_key_ref: signerKeyRef,
    statement_hash: statementHash,
  } = payload as Record<string, unknown>;
  if (typeof recordPath !== "string"
    || typeof recordHash !== "string"
    || typeof revocationId !== "string"
    || typeof runId !== "string"
    || typeof planHash !== "string"
    || typeof signerKeyRef !== "string"
    || typeof statementHash !== "string") {
    return null;
  }
  const captured = captureValidatedRunManifestFileV04(inspected.manifest, recordPath);
  if (!captured.ok || captured.bytes === null || hashRawBytes(captured.bytes) !== recordHash) {
    return null;
  }
  let candidate: unknown;
  try {
    candidate = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)) as unknown;
  } catch {
    return null;
  }
  const parsed = AuthorityRevocationRecordV02.safeParse(candidate);
  if (!parsed.success
    || parsed.data.revocation_id !== revocationId
    || parsed.data.run_id !== runId
    || parsed.data.plan_hash !== planHash
    || parsed.data.producer_attestation.signer_key_ref !== signerKeyRef
    || parsed.data.producer_attestation.statement_hash !== statementHash) {
    return null;
  }
  return Object.freeze({
    path: recordPath,
    hash: recordHash,
    record: parsed.data,
  });
}

export function captureRuntimeAuthorityRevocationV04(input: unknown): CaptureRuntimeAuthorityRevocationResultV04 {
  try {
    const parsed = RuntimeRevocationCaptureInputV04.safeParse(input);
    if (!parsed.success
      || !isCapturedAuthorityTrustContextV02(parsed.data.trust_context)
      || !isValidatedRuntimePlanV03(parsed.data.validated_plan)
      || !isValidatedRunManifestPairV04(parsed.data.manifest, parsed.data.ledger)) {
      return Object.freeze({ ok: false, error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" });
    }
    if (parsed.data.validated_plan.run_id !== parsed.data.ledger.run_id
      || parsed.data.ledger.run_id !== parsed.data.manifest.run_id
      || parsed.data.validated_plan.plan_hash !== parsed.data.ledger.plan_hash
      || parsed.data.ledger.plan_hash !== parsed.data.manifest.plan_hash) {
      return Object.freeze({ ok: false, error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" });
    }
    const head = parsed.data.ledger.events.at(-1);
    const target = targetFromLedger(parsed.data.ledger, parsed.data.request.target_ref);
    const previousRevocationEpoch = target === null ? null : priorRevocationEpoch(parsed.data.ledger, target);
    const attemptRef = currentAttemptRef(parsed.data.ledger);
    const fenceEpoch = currentFenceEpoch(parsed.data.ledger);
    const invalidatedOwnerLeaseRefs = ownerRefs(parsed.data.ledger);
    if (head === undefined
      || parsed.data.ledger.state.terminal_sealed
      || previousRevocationEpoch === null
      || attemptRef === null
      || invalidatedOwnerLeaseRefs === null
      || fenceEpoch === null
      || previousRevocationEpoch >= Number.MAX_SAFE_INTEGER) {
      return Object.freeze({ ok: false, error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" });
    }
    const clock = consumeRuntimeClockObservationV04(parsed.data.observation);
    if (clock === null
      || Date.parse(clock.observed_at) < Date.parse(head.recorded_at)
      || clock.elapsed_ms < maximumObservedElapsed(parsed.data.ledger)) {
      return Object.freeze({ ok: false, error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" });
    }
    const record = produceAuthorityRevocationRecordV02({
      trust_context: parsed.data.trust_context,
      signer: parsed.data.signer,
      request: {
        revocation_id: parsed.data.request.revocation_id,
        run_id: parsed.data.validated_plan.run_id,
        plan_hash: parsed.data.validated_plan.plan_hash,
        target,
        previous_revocation_epoch: previousRevocationEpoch,
        revocation_epoch: previousRevocationEpoch + 1,
        effective_prefix_ref: refOf(head),
        reason_code: parsed.data.request.reason_code,
        evidence_refs: parsed.data.request.evidence_refs,
        revoker_identity_ref: parsed.data.request.revoker_identity_ref,
        revoker_stable_identity_hash: parsed.data.request.revoker_stable_identity_hash,
        revoked_at: clock.observed_at,
      },
    });
    if (!record.ok) return Object.freeze({ ok: false, error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" });
    const recordPath = `authorities/revocations/${record.value.revocation_id}.json`;
    const recordBytes = recordBytesFromRecord(record.value);
    const preimage = {
      schema_version: "0.4" as const,
      event_id: parsed.data.request.event_id,
      run_id: parsed.data.validated_plan.run_id,
      sequence: parsed.data.ledger.sequence + 1,
      recorded_at: clock.observed_at,
      event_type: "authority.grant-revoked" as const,
      source: record.value.revoker_kind,
      authority_ref: record.value.revoker_identity_ref,
      risk_tier: "T4" as const,
      related_ids: [],
      previous_event_hash: head.event_hash,
      payload: eventPayloadFromRecord(record.value, recordBytes),
    };
    const revocationEvent = RuntimeEventV04.safeParse({
      ...preimage,
      event_hash: hashCanonical(preimage),
    });
    if (!revocationEvent.success) {
      return Object.freeze({ ok: false, error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" });
    }
    const fenceEvent = event(
      [...parsed.data.ledger.events, revocationEvent.data],
      `event_fence_${parsed.data.request.revocation_id}`,
      clock.observed_at,
      "run.fence-advanced",
      "policy-enforcement-point",
      record.value.revoker_identity_ref,
      "T4",
      {
        previous_fence_epoch: fenceEpoch,
        fence_epoch: fenceEpoch + 1,
        reason: "authority-revoked",
        evidence_refs: [{
          ledger_sequence: parsed.data.ledger.sequence + 1,
          event_hash: revocationEvent.success ? revocationEvent.data.event_hash : "",
        }],
        attempt_ref: attemptRef,
        owner_lease_refs: invalidatedOwnerLeaseRefs,
      },
    );
    if (fenceEvent === null) {
      return Object.freeze({ ok: false, error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" });
    }
    const token = CapturedRuntimeAuthorityRevocationTokenV04.create();
    capturedRevocations.set(token, Object.freeze({
      validated_plan: parsed.data.validated_plan,
      source_boundary_sequence: parsed.data.ledger.sequence,
      source_boundary_head_hash: parsed.data.ledger.head_hash,
      source_manifest_hash: parsed.data.manifest.manifest_hash,
      current_fence_epoch: fenceEpoch,
      current_attempt_event_ref: attemptRef,
      invalidated_owner_lease_refs: invalidatedOwnerLeaseRefs,
      revocation_event: revocationEvent.data,
      fence_event: fenceEvent,
      record: record.value,
      record_path: recordPath,
      record_bytes: recordBytes,
    }));
    return Object.freeze({ ok: true, value: token });
  } catch {
    return Object.freeze({ ok: false, error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" });
  }
}

export async function revokeRuntimeAuthorityV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<RuntimeAuthorityRevocationWriteResultV04> {
  if (!exactPlainObject(input, ["captured_request"])) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_REVOCATION_INPUT_INVALID" });
  }
  const parsed = RuntimeRevocationWriteInputV04.safeParse(input);
  if (!parsed.success) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_REVOCATION_INPUT_INVALID" });
  }
  const binding = inspectCapturedRevocation(parsed.data.captured_request);
  if (binding === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" });
  }
  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) {
    return opened.error === "RUNTIME_FILE_STORE_POISONED"
      ? Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_REVOCATION_OUTCOME_UNKNOWN" })
      : Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_REVOCATION_PREFIX_INVALID" });
  }
  try {
    const inspected = inspectStore(opened.session);
    if (inspected === null || !matchesBinding(binding, inspected)) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_REVOCATION_PREFIX_INVALID" });
    }
    if (consumeCapturedRevocation(parsed.data.captured_request) === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID" });
    }
    const revocationNext = nextState(inspected, [binding.revocation_event], {
      path: binding.record_path,
      bytes: binding.record_bytes,
    });
    if (revocationNext === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_REVOCATION_NOT_COMMITTED" });
    }
    const committed = await commitRuntimeRecordFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
      expected_manifest_hash: inspected.manifest.manifest_hash,
      record: { relative_path: binding.record_path, bytes: binding.record_bytes },
      next_ledger_bytes: revocationNext.ledger_bytes,
      next_manifest_bytes: revocationNext.manifest_bytes,
    });
    if (!committed.ok) {
      if (committed.classification === "OUTCOME_UNKNOWN") {
        return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_REVOCATION_OUTCOME_UNKNOWN" });
      }
      return committed.error === "RUN_LOCK_IDENTITY_INVALID"
        || committed.error === "RUN_DIRECTORY_IDENTITY_CHANGED"
        || committed.error === "RUN_DIRECTORY_MODE_CHANGED"
        || committed.error === "RUNTIME_STORE_DRIFT"
        || committed.error === "RUNTIME_EXPECTATION_MISMATCH"
        ? Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_REVOCATION_PREFIX_INVALID" })
        : Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_REVOCATION_NOT_COMMITTED" });
    }
    const afterRevocation = inspectStore(opened.session);
    if (afterRevocation === null
      || afterRevocation.ledger.events.at(-1)?.event_type !== "authority.grant-revoked"
      || afterRevocation.ledger.state.current_fence_epoch !== binding.current_fence_epoch) {
      return Object.freeze({
        ok: false,
        classification: "OUTCOME_UNKNOWN",
        error: "RUNTIME_REVOCATION_OUTCOME_UNKNOWN",
        revocation_event_ref: refOf(binding.revocation_event),
      });
    }
    const fenceNext = nextState(afterRevocation, [binding.fence_event], null);
    if (fenceNext === null) {
      return Object.freeze({
        ok: false,
        classification: "REVOCATION_COMMITTED_FENCE_NOT_COMMITTED",
        error: "RUNTIME_REVOCATION_FENCE_NOT_COMMITTED",
        revocation_event_ref: refOf(binding.revocation_event),
      });
    }
    const fenced = await commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: afterRevocation.ledger.ledger_bytes_hash,
      expected_manifest_hash: afterRevocation.manifest.manifest_hash,
      next_ledger_bytes: fenceNext.ledger_bytes,
      next_manifest_bytes: fenceNext.manifest_bytes,
    });
    if (!fenced.ok) {
      if (fenced.classification === "OUTCOME_UNKNOWN") {
        return Object.freeze({
          ok: false,
          classification: "OUTCOME_UNKNOWN",
          error: "RUNTIME_REVOCATION_OUTCOME_UNKNOWN",
          revocation_event_ref: refOf(binding.revocation_event),
        });
      }
      return Object.freeze({
        ok: false,
        classification: "REVOCATION_COMMITTED_FENCE_NOT_COMMITTED",
        error: "RUNTIME_REVOCATION_FENCE_NOT_COMMITTED",
        revocation_event_ref: refOf(binding.revocation_event),
      });
    }
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      revocation_event_ref: refOf(binding.revocation_event),
      fence_event_ref: refOf(binding.fence_event),
      ledger_bytes_hash: fenced.ledger_bytes_hash,
      manifest_hash: fenced.manifest_hash,
    });
  } finally {
    await closeRuntimeFileStoreSessionV04(opened.session);
  }
}

export async function continuePendingRuntimeAuthorityRevocationV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<RuntimeAuthorityRevocationWriteResultV04> {
  if (!exactPlainObject(input, ["pending_revocation_event_ref"])) {
    return continuationFailure("NOT_COMMITTED", "RUNTIME_REVOCATION_INPUT_INVALID");
  }
  const parsed = ContinueRuntimeRevocationWriteInputV04.safeParse(input);
  if (!parsed.success) {
    return continuationFailure("NOT_COMMITTED", "RUNTIME_REVOCATION_INPUT_INVALID");
  }
  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) {
    return opened.error === "RUNTIME_FILE_STORE_POISONED"
      ? continuationFailure("OUTCOME_UNKNOWN", "RUNTIME_REVOCATION_OUTCOME_UNKNOWN")
      : continuationFailure("NOT_COMMITTED", "RUNTIME_REVOCATION_PREFIX_INVALID");
  }
  try {
    const inspected = inspectStore(opened.session);
    if (inspected === null
      || inspected.ledger.sequence !== parsed.data.pending_revocation_event_ref.ledger_sequence
      || inspected.ledger.head_hash !== parsed.data.pending_revocation_event_ref.event_hash) {
      return continuationFailure("NOT_COMMITTED", "RUNTIME_REVOCATION_PREFIX_INVALID");
    }
    const revocationEvent = inspected.ledger.events.at(-1);
    if (revocationEvent?.event_type !== "authority.grant-revoked" || revocationEvent.authority_ref === null) {
      return continuationFailure("NOT_COMMITTED", "RUNTIME_REVOCATION_PREFIX_INVALID");
    }
    if (validatedRevocationEventRecord(inspected, revocationEvent) === null) {
      return continuationFailure("NOT_COMMITTED", "RUNTIME_REVOCATION_PREFIX_INVALID");
    }
    const fence = continuationFenceEvent(inspected, revocationEvent);
    if (fence === null) {
      return continuationFailure(
        "REVOCATION_COMMITTED_FENCE_NOT_COMMITTED",
        "RUNTIME_REVOCATION_FENCE_NOT_COMMITTED",
        parsed.data.pending_revocation_event_ref,
      );
    }
    const next = nextState(inspected, [fence], null);
    if (next === null) {
      return continuationFailure(
        "REVOCATION_COMMITTED_FENCE_NOT_COMMITTED",
        "RUNTIME_REVOCATION_FENCE_NOT_COMMITTED",
        parsed.data.pending_revocation_event_ref,
      );
    }
    const committed = await commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
      expected_manifest_hash: inspected.manifest.manifest_hash,
      next_ledger_bytes: next.ledger_bytes,
      next_manifest_bytes: next.manifest_bytes,
    });
    if (!committed.ok) {
      return committed.classification === "OUTCOME_UNKNOWN"
        ? continuationFailure("OUTCOME_UNKNOWN", "RUNTIME_REVOCATION_OUTCOME_UNKNOWN", parsed.data.pending_revocation_event_ref)
        : continuationFailure(
          "REVOCATION_COMMITTED_FENCE_NOT_COMMITTED",
          "RUNTIME_REVOCATION_FENCE_NOT_COMMITTED",
          parsed.data.pending_revocation_event_ref,
        );
    }
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      revocation_event_ref: parsed.data.pending_revocation_event_ref,
      fence_event_ref: refOf(fence),
      ledger_bytes_hash: committed.ledger_bytes_hash,
      manifest_hash: committed.manifest_hash,
    });
  } finally {
    await closeRuntimeFileStoreSessionV04(opened.session);
  }
}
