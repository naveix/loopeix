import { canonicalize, hashCanonical, hashRawBytes } from "../hash.js";
import { RuntimeEventV03, type RuntimeEventV03Value } from "../schema/runtime-v03.js";
import { compareRuntimeUtf8BytesV02 } from "../schema/runtime.js";
import { inspectRuntimeLedgerV03 } from "./runtime-ledger-v03.js";
import {
  classifyRuntimeDurabilityPairV03,
  classifyRuntimeDurabilityV03,
} from "./runtime-durability-policy-v03.js";
import {
  buildRunManifestV03,
  inspectRunManifestV03,
} from "./runtime-manifest-v03.js";

declare const capturedStoreBrandV03: unique symbol;
declare const runtimeWriteSessionBrandV03: unique symbol;
declare const runtimeEventDraftBrandV03: unique symbol;

export type CapturedRuntimeRunStoreV03 = Readonly<{ [capturedStoreBrandV03]: never }>;
export type RuntimeWriteSessionV03 = Readonly<{ [runtimeWriteSessionBrandV03]: never }>;
export type RuntimeEventDraftV03 = Readonly<{ [runtimeEventDraftBrandV03]: never }>;

export type RuntimeWriteExpectationV03 = Readonly<{
  run_id: string;
  ledger_bytes_hash: string;
  ledger_sequence: number;
  ledger_head_hash: string;
  current_fence_epoch: number;
  manifest_hash: string;
}>;

export type OpenRuntimeWriteSessionV03Error =
  | "CAPTURED_STORE_INVALID"
  | "RUN_LOCK_UNAVAILABLE"
  | "RUN_LOCK_IDENTITY_INVALID"
  | "RUNTIME_PREFIX_INVALID"
  | "RUNTIME_EXPECTATION_MISMATCH"
  | "RUN_MANIFEST_INVALID"
  | "RUN_QUARANTINED"
  | "RUN_TERMINAL"
  | "RUNTIME_IO_OUTCOME_UNKNOWN";

export type AppendRuntimeEventV03Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
      manifest_hash: string;
      ledger_bytes_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_EVENT_INVALID"
        | "RUNTIME_WRITE_NOT_COMMITTED"
        | "RUNTIME_WRITE_SESSION_CLOSED"
        | "RUNTIME_WRITE_SESSION_INVALID"
        | "RUNTIME_WRITE_SESSION_POISONED"
        | "RUNTIME_IO_OUTCOME_UNKNOWN";
    }>;

export type AppendRuntimeIntegrityQuarantinePairV03Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      event_refs: readonly [
        Readonly<{ ledger_sequence: number; event_hash: string }>,
        Readonly<{ ledger_sequence: number; event_hash: string }>,
      ];
      manifest_hash: string;
      ledger_bytes_hash: string;
    }>
  | Extract<AppendRuntimeEventV03Result, { ok: false }>;

type EventDraftState = Readonly<{
  event_type: string;
  source: string;
  authority_ref: string | null;
  risk_tier: string;
  related_ids: readonly string[];
  payload: unknown;
}>;

type SyntheticFaultV03 =
  | "before-write"
  | "append-write"
  | "append-write-partial"
  | "ledger-sync"
  | "ledger-close"
  | "ledger-readback"
  | "manifest-temp-write"
  | "manifest-temp-sync"
  | "manifest-temp-close"
  | "manifest-rename"
  | "directory-sync"
  | "final-readback";

type EventEnvelopeV03 = Readonly<{ event_id: string; recorded_at: string }>;
type CapturedRunFileV03 = Readonly<{
  path: string;
  family: "primary" | "record" | "projection";
  required: boolean;
  mode: 384 | null;
  bytes: Uint8Array | null;
}>;
type StoreState = {
  runId: string;
  ledgerBytes: Uint8Array;
  manifestBytes: Uint8Array;
  manifestTempBytes: Uint8Array | null;
  capturedFiles: readonly CapturedRunFileV03[];
  admissionContext: object;
  lockIdentity: string;
  lockHeld: boolean;
  poisoned: boolean;
  faultAt: SyntheticFaultV03 | null;
  faultConsumed: boolean;
  eventEnvelopes: EventEnvelopeV03[];
  operations: string[];
};
type SessionState = {
  store: CapturedRuntimeRunStoreV03;
  lockIdentity: string;
  closed: boolean;
  poisoned: boolean;
  tail: Promise<void>;
};

const stores = new WeakMap<CapturedRuntimeRunStoreV03, StoreState>();
const sessions = new WeakMap<RuntimeWriteSessionV03, SessionState>();
const drafts = new WeakMap<RuntimeEventDraftV03, EventDraftState>();
const heldRunLocks = new Map<string, Readonly<{ store: CapturedRuntimeRunStoreV03; lockIdentity: string }>>();
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type RuntimeAdmissionRecordCaptureV03 = Readonly<{
  path: string;
  bytes: Uint8Array;
  raw_hash: string;
}>;

export type RuntimeAdmissionEnvelopeV03 = Readonly<{ event_id: string; recorded_at: string }>;

export type RuntimeWriteAdmissionSnapshotV03 = Readonly<{
  run_id: string;
  plan_hash: string;
  current_fence_epoch: number;
  ledger_bytes_hash: string;
  ledger_sequence: number;
  ledger_head_hash: string;
  manifest_hash: string;
  events: readonly RuntimeEventV03Value[];
  plan_capture: RuntimeAdmissionRecordCaptureV03;
  record_captures: readonly RuntimeAdmissionRecordCaptureV03[];
  envelopes: readonly [RuntimeAdmissionEnvelopeV03, RuntimeAdmissionEnvelopeV03, RuntimeAdmissionEnvelopeV03];
  admission_context: object;
}>;

export type RuntimeAdmissionCommitExpectationV03 = Readonly<{
  lease_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  admission_clock_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  manifest_hash: string;
}>;

export type RuntimeAdmissionCommitReadbackV03 = Readonly<{
  run_id: string;
  plan_hash: string;
  current_fence_epoch: number;
  ledger_bytes_hash: string;
  ledger_sequence: number;
  ledger_head_hash: string;
  manifest_hash: string;
  runtime_state: Readonly<{
    state: string;
    started: boolean;
    abort_requested: boolean;
    in_flight_action_ids: readonly string[];
  }>;
  events: readonly RuntimeEventV03Value[];
}>;

export type VerifyRuntimeWriteSessionAdmissionReadbackV03Result =
  | Readonly<{ ok: true; readback: RuntimeAdmissionCommitReadbackV03 }>
  | Readonly<{ ok: false; error: VerifyRuntimeWriteSessionAdmissionReadbackV03Error }>;

export type RuntimeWriteSessionTailExpectationV03 = Readonly<{
  events: readonly Readonly<{
    event_type: string;
    event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  }>[];
  manifest_hash: string;
}>;

export type RuntimeWriteSessionTailReadbackV03 = Readonly<{
  run_id: string;
  plan_hash: string;
  current_fence_epoch: number;
  ledger_sequence: number;
  ledger_head_hash: string;
  manifest_hash: string;
  events: readonly RuntimeWriteSessionValidatedEventV03[];
}>;

export type VerifyRuntimeWriteSessionTailReadbackV03Error =
  | "RUNTIME_WRITE_SESSION_INVALID"
  | "RUNTIME_WRITE_SESSION_CLOSED"
  | "RUNTIME_WRITE_SESSION_POISONED"
  | "RUN_LOCK_IDENTITY_INVALID"
  | "RUNTIME_PREFIX_INVALID"
  | "RUN_MANIFEST_INVALID"
  | "TAIL_READBACK_MISMATCH";

export type VerifyRuntimeWriteSessionTailReadbackV03Result =
  | Readonly<{ ok: true; readback: RuntimeWriteSessionTailReadbackV03 }>
  | Readonly<{ ok: false; error: VerifyRuntimeWriteSessionTailReadbackV03Error }>;

export type InspectRuntimeWriteSessionV03ForAdmissionError =
  | "RUNTIME_WRITE_SESSION_INVALID"
  | "RUNTIME_WRITE_SESSION_CLOSED"
  | "RUNTIME_WRITE_SESSION_POISONED"
  | "RUN_LOCK_IDENTITY_INVALID"
  | "RUNTIME_PREFIX_INVALID"
  | "RUN_MANIFEST_INVALID"
  | "RUN_QUARANTINED"
  | "RUN_TERMINAL"
  | "ADMISSION_CAPTURE_INVALID";

export type VerifyRuntimeWriteSessionAdmissionReadbackV03Error =
  | InspectRuntimeWriteSessionV03ForAdmissionError
  | "ADMISSION_READBACK_MISMATCH";

export type RuntimeWriteSessionValidatedEventV03 = RuntimeEventV03Value & Readonly<{
  risk_tier: RuntimeEventV03Value["risk_tier"];
}>;

export type RuntimeWriteDispatchSnapshotV03 = Readonly<{
  run_id: string;
  plan_hash: string;
  current_fence_epoch: number;
  ledger_sequence: number;
  ledger_head_hash: string;
  manifest_hash: string;
  events: readonly RuntimeWriteSessionValidatedEventV03[];
}>;

export type InspectRuntimeWriteSessionV03ForDispatchError =
  | "RUNTIME_WRITE_SESSION_INVALID"
  | "RUNTIME_WRITE_SESSION_CLOSED"
  | "RUNTIME_WRITE_SESSION_POISONED"
  | "RUN_LOCK_IDENTITY_INVALID"
  | "RUNTIME_PREFIX_INVALID"
  | "RUN_MANIFEST_INVALID"
  | "RUN_QUARANTINED"
  | "RUN_TERMINAL";

export type InspectRuntimeWriteSessionV03ForDispatchResult =
  | Readonly<{ ok: true; snapshot: RuntimeWriteDispatchSnapshotV03 }>
  | Readonly<{ ok: false; error: InspectRuntimeWriteSessionV03ForDispatchError }>;

export type InspectRuntimeWriteSessionV03ForTerminationError =
  | "RUNTIME_WRITE_SESSION_INVALID"
  | "RUNTIME_WRITE_SESSION_CLOSED"
  | "RUNTIME_WRITE_SESSION_POISONED"
  | "RUN_LOCK_IDENTITY_INVALID"
  | "RUNTIME_PREFIX_INVALID"
  | "RUN_MANIFEST_INVALID"
  | "RUN_QUARANTINE_REQUIRED"
  | "RUN_TERMINAL";

export type InspectRuntimeWriteSessionV03ForTerminationResult =
  | Readonly<{ ok: true; snapshot: RuntimeWriteDispatchSnapshotV03 }>
  | Readonly<{ ok: false; error: InspectRuntimeWriteSessionV03ForTerminationError }>;

export type InspectRuntimeWriteSessionV03ForAdmissionResult =
  | Readonly<{ ok: true; snapshot: RuntimeWriteAdmissionSnapshotV03 }>
  | Readonly<{ ok: false; error: InspectRuntimeWriteSessionV03ForAdmissionError }>;

function bytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}

function plainRecord(value: unknown, keys: readonly string[]): Record<string, PropertyDescriptor> | null {
  try {
    if (typeof value !== "object" || value === null || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string")
      || Object.keys(descriptors).sort().join("\0") !== [...keys].sort().join("\0")) return null;
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true) return null;
    }
    return descriptors;
  } catch {
    return null;
  }
}

function snapshotJson(value: unknown, depth = 0, budget: { nodes: number } = { nodes: 0 }): unknown | null {
  budget.nodes += 1;
  if (depth > 16 || budget.nodes > 2_000) return null;
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "object") return null;
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) return null;
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (Reflect.ownKeys(value).some((key) => typeof key !== "string")
        || Object.keys(descriptors).some((key) => key !== "length" && !/^\d+$/u.test(key))) return null;
      const result: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) return null;
        const child = snapshotJson(descriptor.value, depth + 1, budget);
        if (child === null && descriptor.value !== null) return null;
        result.push(child);
      }
      return result;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string")) return null;
    const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true) return null;
      const child = snapshotJson(descriptor.value, depth + 1, budget);
      if (child === null && descriptor.value !== null) return null;
      result[key] = child;
    }
    return result;
  } catch {
    return null;
  }
}

function isOwnedBytes(value: unknown): value is Uint8Array {
  try {
    return value instanceof Uint8Array
      && Object.getPrototypeOf(value) === Uint8Array.prototype
      && !(value.buffer instanceof SharedArrayBuffer);
  } catch {
    return false;
  }
}

const ADMISSION_CONTEXT_KEYS = [
  "authority_trust_context", "repository_pre_state_hash", "normalized_dispatch_hash", "observed_at",
  "elapsed_ms", "reviewer_view_hash", "enforcement", "condition_results", "lease_id", "clock_id", "action_id",
] as const;
const MAX_ADMISSION_CONTEXT_BYTES = 1_048_576;

function freezeJson(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeJson(child);
  return Object.freeze(value);
}

function captureAdmissionContext(value: unknown): object | null {
  const descriptors = plainRecord(value, ADMISSION_CONTEXT_KEYS);
  if (descriptors === null) return null;
  const authority = descriptors.authority_trust_context!.value;
  if (typeof authority !== "object" || authority === null) return null;
  const owned: Record<string, unknown> = {};
  for (const key of ADMISSION_CONTEXT_KEYS) {
    if (key === "authority_trust_context") continue;
    const original = descriptors[key]!.value;
    const captured = snapshotJson(original);
    if (captured === null && original !== null) return null;
    owned[key] = freezeJson(captured);
  }
  try {
    if (Buffer.byteLength(JSON.stringify(owned), "utf8") > MAX_ADMISSION_CONTEXT_BYTES) return null;
  } catch {
    return null;
  }
  return Object.freeze({ ...owned, authority_trust_context: authority });
}

function copyAdmissionContext(value: object): object | null {
  return captureAdmissionContext(value);
}

function copyCapturedFiles(value: unknown): readonly CapturedRunFileV03[] | null {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length === 0) return null;
  const output: CapturedRunFileV03[] = [];
  for (const row of value) {
    const descriptors = plainRecord(row, ["path", "family", "required", "mode", "bytes"]);
    if (descriptors === null) return null;
    const path = descriptors.path!.value;
    const family = descriptors.family!.value;
    const required = descriptors.required!.value;
    const mode = descriptors.mode!.value;
    const content = descriptors.bytes!.value;
    if (typeof path !== "string" || !["primary", "record", "projection"].includes(family as string)
      || typeof required !== "boolean" || (mode !== 384 && mode !== null)
      || (content !== null && !isOwnedBytes(content))) return null;
    output.push(Object.freeze({ path, family, required, mode, bytes: content === null ? null : bytes(content) }) as CapturedRunFileV03);
  }
  return Object.freeze(output);
}

/** Synthetic, dependency-injected capture fixture. It performs no filesystem, process, network, or host operation. */
export function createSyntheticCapturedRuntimeRunStoreV03ForTest(input: unknown): CapturedRuntimeRunStoreV03 | null {
  const descriptors = plainRecord(input, [
    "run_id", "ledger_bytes", "manifest_bytes", "captured_files", "lock_identity",
    "lock_identity_valid", "event_envelopes", "fault_at", "admission_context",
  ]);
  if (descriptors === null) return null;
  const runId = descriptors.run_id!.value;
  const ledger = descriptors.ledger_bytes!.value;
  const manifest = descriptors.manifest_bytes!.value;
  const capturedFiles = copyCapturedFiles(descriptors.captured_files!.value);
  const lockIdentity = descriptors.lock_identity!.value;
  const lockIdentityValid = descriptors.lock_identity_valid!.value;
  const faultAt = descriptors.fault_at!.value;
  const envelopesValue = descriptors.event_envelopes!.value;
  const admissionContext = captureAdmissionContext(descriptors.admission_context!.value);
  const faults: readonly (SyntheticFaultV03 | null)[] = [null, "before-write", "append-write", "append-write-partial", "ledger-sync", "ledger-close", "ledger-readback", "manifest-temp-write", "manifest-temp-sync", "manifest-temp-close", "manifest-rename", "directory-sync", "final-readback"];
  if (typeof runId !== "string" || !isOwnedBytes(ledger) || !isOwnedBytes(manifest) || admissionContext === null
    || capturedFiles === null || typeof lockIdentity !== "string" || lockIdentity.length === 0
    || typeof lockIdentityValid !== "boolean" || !faults.includes(faultAt as SyntheticFaultV03 | null)
    || !Array.isArray(envelopesValue) || Object.getPrototypeOf(envelopesValue) !== Array.prototype) return null;
  const envelopes: EventEnvelopeV03[] = [];
  for (const envelope of envelopesValue) {
    const fields = plainRecord(envelope, ["event_id", "recorded_at"]);
    if (fields === null || typeof fields.event_id!.value !== "string" || typeof fields.recorded_at!.value !== "string") return null;
    envelopes.push(Object.freeze({ event_id: fields.event_id!.value as string, recorded_at: fields.recorded_at!.value as string }));
  }
  const token = Object.freeze({}) as CapturedRuntimeRunStoreV03;
  stores.set(token, {
    runId,
    ledgerBytes: bytes(ledger),
    manifestBytes: bytes(manifest),
    manifestTempBytes: null,
    capturedFiles,
    admissionContext,
    lockIdentity: lockIdentityValid ? lockIdentity : "",
    lockHeld: false,
    poisoned: false,
    faultAt: faultAt as SyntheticFaultV03 | null,
    faultConsumed: false,
    eventEnvelopes: envelopes,
    operations: [],
  });
  return token;
}

/** Package-private draft mint. The resulting object carries no visible or serializable event fields. */
export function createRuntimeEventDraftV03(input: unknown): RuntimeEventDraftV03 | null {
  const descriptors = plainRecord(input, ["event_type", "source", "authority_ref", "risk_tier", "related_ids", "payload"]);
  if (descriptors === null) return null;
  const snapshot = snapshotJson({
    event_type: descriptors.event_type!.value,
    source: descriptors.source!.value,
    authority_ref: descriptors.authority_ref!.value,
    risk_tier: descriptors.risk_tier!.value,
    related_ids: descriptors.related_ids!.value,
    payload: descriptors.payload!.value,
  });
  if (snapshot === null || typeof snapshot !== "object" || Array.isArray(snapshot)) return null;
  const value = snapshot as Record<string, unknown>;
  if (typeof value.event_type !== "string" || typeof value.source !== "string"
    || (value.authority_ref !== null && typeof value.authority_ref !== "string")
    || typeof value.risk_tier !== "string" || !Array.isArray(value.related_ids)) return null;
  const token = Object.freeze({}) as RuntimeEventDraftV03;
  drafts.set(token, Object.freeze({
    event_type: value.event_type,
    source: value.source,
    authority_ref: value.authority_ref as string | null,
    risk_tier: value.risk_tier,
    related_ids: Object.freeze([...value.related_ids] as string[]),
    payload: value.payload,
  }));
  return token;
}

function expectation(input: unknown): RuntimeWriteExpectationV03 | null {
  const descriptors = plainRecord(input, ["run_id", "ledger_bytes_hash", "ledger_sequence", "ledger_head_hash", "current_fence_epoch", "manifest_hash"]);
  if (descriptors === null) return null;
  const value = Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value])) as Record<string, unknown>;
  if (typeof value.run_id !== "string" || typeof value.ledger_bytes_hash !== "string" || typeof value.ledger_head_hash !== "string"
    || typeof value.manifest_hash !== "string" || !Number.isSafeInteger(value.ledger_sequence) || (value.ledger_sequence as number) <= 0
    || !Number.isSafeInteger(value.current_fence_epoch) || (value.current_fence_epoch as number) < 0) return null;
  return Object.freeze(value) as RuntimeWriteExpectationV03;
}

function replaceLedgerCapture(files: readonly CapturedRunFileV03[], ledger: Uint8Array): readonly CapturedRunFileV03[] {
  return Object.freeze(files.map((row) => row.path === "ledger.jsonl"
    ? Object.freeze({ ...row, bytes: bytes(ledger) })
    : Object.freeze({ ...row, bytes: row.bytes === null ? null : bytes(row.bytes) })));
}

export async function openRuntimeWriteSessionV03(
  store: CapturedRuntimeRunStoreV03,
  expectedInput: unknown,
): Promise<Readonly<{ ok: true; session: RuntimeWriteSessionV03 }> | Readonly<{ ok: false; error: OpenRuntimeWriteSessionV03Error }>> {
  const storeState = stores.get(store);
  if (storeState === undefined) return Object.freeze({ ok: false, error: "CAPTURED_STORE_INVALID" });
  const expected = expectation(expectedInput);
  if (expected === null) return Object.freeze({ ok: false, error: "RUNTIME_EXPECTATION_MISMATCH" });
  if (storeState.poisoned) return Object.freeze({ ok: false, error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
  if (storeState.lockIdentity.length === 0) return Object.freeze({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" });
  if (storeState.lockHeld || heldRunLocks.has(storeState.runId)) return Object.freeze({ ok: false, error: "RUN_LOCK_UNAVAILABLE" });
  storeState.lockHeld = true;
  heldRunLocks.set(storeState.runId, Object.freeze({ store, lockIdentity: storeState.lockIdentity }));
  storeState.operations.push("lock-acquired");
  const release = (): void => {
    const held = heldRunLocks.get(storeState.runId);
    if (held?.store === store && held.lockIdentity === storeState.lockIdentity) heldRunLocks.delete(storeState.runId);
    storeState.lockHeld = false;
  };
  const ledgerBytes = bytes(storeState.ledgerBytes);
  const manifestBytes = bytes(storeState.manifestBytes);
  const ledger = inspectRuntimeLedgerV03(ledgerBytes);
  if (!ledger.ok) {
    release();
    return Object.freeze({ ok: false, error: "RUNTIME_PREFIX_INVALID" });
  }
  const files = replaceLedgerCapture(storeState.capturedFiles, ledgerBytes);
  const manifest = inspectRunManifestV03({ manifest_bytes: manifestBytes, ledger_bytes: ledgerBytes, captured_files: files });
  if (!manifest.ok) {
    release();
    return Object.freeze({ ok: false, error: "RUN_MANIFEST_INVALID" });
  }
  if (storeState.runId !== ledger.ledger.run_id || expected.run_id !== ledger.ledger.run_id
    || expected.ledger_bytes_hash !== ledger.ledger.ledger_bytes_hash
    || expected.ledger_sequence !== ledger.ledger.sequence || expected.ledger_head_hash !== ledger.ledger.head_hash
    || expected.current_fence_epoch !== manifest.manifest.current_fence_epoch
    || expected.manifest_hash !== manifest.manifest.manifest_hash) {
    release();
    return Object.freeze({ ok: false, error: "RUNTIME_EXPECTATION_MISMATCH" });
  }
  if (ledger.state.state === "quarantined" || ledger.state.state === "quarantine-required") {
    release();
    return Object.freeze({ ok: false, error: "RUN_QUARANTINED" });
  }
  if (ledger.ledger.sealed) {
    release();
    return Object.freeze({ ok: false, error: "RUN_TERMINAL" });
  }
  const session = Object.freeze({}) as RuntimeWriteSessionV03;
  sessions.set(session, { store, lockIdentity: storeState.lockIdentity, closed: false, poisoned: false, tail: Promise.resolve() });
  return Object.freeze({ ok: true, session });
}

function unknown(
  sessionState: SessionState,
  storeState: StoreState,
): Extract<AppendRuntimeEventV03Result, { ok: false }> {
  sessionState.poisoned = true;
  storeState.poisoned = true;
  return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
}

function fault(store: StoreState, step: SyntheticFaultV03): boolean {
  if (store.faultConsumed || store.faultAt !== step) return false;
  store.faultConsumed = true;
  store.operations.push(`${step}:failed`);
  return true;
}

async function appendSerialized(
  sessionState: SessionState,
  storeState: StoreState,
  draft: RuntimeEventDraftV03,
): Promise<AppendRuntimeEventV03Result> {
  if (sessionState.closed) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_SESSION_CLOSED" });
  }
  if (sessionState.poisoned || storeState.poisoned) {
    return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_WRITE_SESSION_POISONED" });
  }
  if (!storeState.lockHeld || sessionState.lockIdentity !== storeState.lockIdentity) return unknown(sessionState, storeState);
  const draftState = drafts.get(draft);
  if (draftState === undefined) return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
  const prior = inspectRuntimeLedgerV03(bytes(storeState.ledgerBytes));
  const envelope = storeState.eventEnvelopes[0];
  if (!prior.ok || envelope === undefined) return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
  const preimage = {
    schema_version: "0.3" as const,
    event_id: envelope.event_id,
    run_id: prior.ledger.run_id,
    sequence: prior.ledger.sequence + 1,
    recorded_at: envelope.recorded_at,
    event_type: draftState.event_type,
    source: draftState.source,
    authority_ref: draftState.authority_ref,
    risk_tier: draftState.risk_tier,
    related_ids: draftState.related_ids,
    previous_event_hash: prior.ledger.head_hash,
    payload: draftState.payload,
  };
  const candidate = { ...preimage, event_hash: hashCanonical(preimage) };
  const parsed = RuntimeEventV03.safeParse(candidate);
  if (!parsed.success) return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
  const eventLine = encoder.encode(`${canonicalize(parsed.data)}\n`);
  const priorLedgerBytes = bytes(storeState.ledgerBytes);
  const priorLedgerText = decoder.decode(priorLedgerBytes);
  const eventLineText = decoder.decode(eventLine);
  const nextLedger = new Uint8Array(storeState.ledgerBytes.byteLength + eventLine.byteLength);
  nextLedger.set(storeState.ledgerBytes);
  nextLedger.set(eventLine, storeState.ledgerBytes.byteLength);
  const nextInspection = inspectRuntimeLedgerV03(nextLedger);
  if (!nextInspection.ok) return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
  storeState.operations.push("prefix-validation:accepted");
  if (fault(storeState, "before-write")) {
    sessionState.closed = true;
    const held = heldRunLocks.get(storeState.runId);
    if (held?.store === sessionState.store && held.lockIdentity === sessionState.lockIdentity) heldRunLocks.delete(storeState.runId);
    storeState.lockHeld = false;
    const classified = classifyRuntimeDurabilityV03({
      policy_version: "0.1",
      prior_head: {
        sequence: prior.ledger.sequence,
        event_hash: prior.ledger.head_hash,
        ledger_bytes_hash: prior.ledger.ledger_bytes_hash,
      },
      target_head: {
        sequence: nextInspection.ledger.sequence,
        event_hash: nextInspection.ledger.head_hash,
        ledger_bytes_hash: nextInspection.ledger.ledger_bytes_hash,
      },
      prior_ledger_text: priorLedgerText,
      event_line: {
        bytes: eventLineText,
        bytes_hash: hashRawBytes(eventLine),
        byte_length: eventLine.byteLength,
      },
      steps: [{ step: "prefix-validation", outcome: "rejected-before-write" }],
    });
    return classified.classification === "NOT_COMMITTED"
      ? Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_NOT_COMMITTED" })
      : unknown(sessionState, storeState);
  }
  storeState.operations.push("append-write:began");
  if (fault(storeState, "append-write")) {
    storeState.ledgerBytes = nextLedger.slice(0, storeState.ledgerBytes.byteLength + Math.max(1, Math.floor(eventLine.byteLength / 2)));
    return unknown(sessionState, storeState);
  }
  if (fault(storeState, "append-write-partial")) {
    storeState.ledgerBytes = nextLedger.slice(0, storeState.ledgerBytes.byteLength + Math.max(1, Math.floor(eventLine.byteLength / 2)));
    return unknown(sessionState, storeState);
  }
  storeState.ledgerBytes = nextLedger;
  storeState.operations.push("append-write:complete");
  if (fault(storeState, "ledger-sync")) return unknown(sessionState, storeState);
  storeState.operations.push("ledger-sync:confirmed");
  if (fault(storeState, "ledger-close")) return unknown(sessionState, storeState);
  storeState.operations.push("ledger-close:confirmed");
  if (fault(storeState, "ledger-readback")) return unknown(sessionState, storeState);
  if (!inspectRuntimeLedgerV03(bytes(storeState.ledgerBytes)).ok) return unknown(sessionState, storeState);
  storeState.operations.push("ledger-readback:exact");

  const nextFiles = replaceLedgerCapture(storeState.capturedFiles, nextLedger);
  const previousManifest = inspectRunManifestV03({
    manifest_bytes: bytes(storeState.manifestBytes),
    ledger_bytes: bytes(storeState.ledgerBytes.slice(0, storeState.ledgerBytes.byteLength - eventLine.byteLength)),
    captured_files: replaceLedgerCapture(storeState.capturedFiles, storeState.ledgerBytes.slice(0, storeState.ledgerBytes.byteLength - eventLine.byteLength)),
  });
  if (!previousManifest.ok) return unknown(sessionState, storeState);
  const nextManifest = buildRunManifestV03({
    ledger_bytes: nextLedger,
    created_at: previousManifest.manifest.created_at,
    captured_files: nextFiles,
  });
  if (!nextManifest.ok) return unknown(sessionState, storeState);
  if (fault(storeState, "manifest-temp-write")) return unknown(sessionState, storeState);
  storeState.manifestTempBytes = bytes(nextManifest.bytes);
  storeState.operations.push("manifest-temp-write:complete");
  if (fault(storeState, "manifest-temp-sync")) return unknown(sessionState, storeState);
  storeState.operations.push("manifest-temp-sync:confirmed");
  if (fault(storeState, "manifest-temp-close")) return unknown(sessionState, storeState);
  storeState.operations.push("manifest-temp-close:confirmed");
  if (fault(storeState, "manifest-rename")) return unknown(sessionState, storeState);
  storeState.manifestBytes = bytes(storeState.manifestTempBytes);
  storeState.manifestTempBytes = null;
  storeState.operations.push("manifest-rename:complete");
  if (fault(storeState, "directory-sync")) return unknown(sessionState, storeState);
  storeState.operations.push("directory-sync:confirmed");
  if (fault(storeState, "final-readback")) return unknown(sessionState, storeState);
  const finalLedgerBytes = bytes(storeState.ledgerBytes);
  const finalManifestBytes = bytes(storeState.manifestBytes);
  const finalManifest = inspectRunManifestV03({ manifest_bytes: finalManifestBytes, ledger_bytes: finalLedgerBytes, captured_files: nextFiles });
  if (!finalManifest.ok || hashRawBytes(finalLedgerBytes) !== nextInspection.ledger.ledger_bytes_hash) return unknown(sessionState, storeState);
  const classified = classifyRuntimeDurabilityV03({
    policy_version: "0.1",
    prior_head: {
      sequence: prior.ledger.sequence,
      event_hash: prior.ledger.head_hash,
      ledger_bytes_hash: prior.ledger.ledger_bytes_hash,
    },
    target_head: {
      sequence: nextInspection.ledger.sequence,
      event_hash: nextInspection.ledger.head_hash,
      ledger_bytes_hash: nextInspection.ledger.ledger_bytes_hash,
    },
    prior_ledger_text: priorLedgerText,
    event_line: {
      bytes: eventLineText,
      bytes_hash: hashRawBytes(eventLine),
      byte_length: eventLine.byteLength,
    },
    steps: [
      { step: "prefix-validation", outcome: "accepted" },
      { step: "append-write", outcome: "complete" },
      { step: "ledger-sync", outcome: "confirmed" },
      { step: "ledger-readback", outcome: "exact" },
      { step: "head-publish", outcome: "complete" },
      { step: "directory-sync", outcome: "confirmed" },
      { step: "final-readback", outcome: "exact" },
    ],
  });
  if (classified.classification !== "COMMITTED") return unknown(sessionState, storeState);
  storeState.operations.push("final-readback:exact");
  storeState.capturedFiles = nextFiles;
  storeState.eventEnvelopes.shift();
  return Object.freeze({
    ok: true,
    classification: "COMMITTED",
    event_ref: Object.freeze({ ledger_sequence: nextInspection.ledger.sequence, event_hash: nextInspection.ledger.head_hash }),
    manifest_hash: finalManifest.manifest.manifest_hash,
    ledger_bytes_hash: nextInspection.ledger.ledger_bytes_hash,
  });
}

async function appendIntegrityQuarantinePairSerialized(
  sessionState: SessionState,
  storeState: StoreState,
  rejectionDraft: RuntimeEventDraftV03,
): Promise<AppendRuntimeIntegrityQuarantinePairV03Result> {
  if (sessionState.closed) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_SESSION_CLOSED" });
  }
  if (sessionState.poisoned || storeState.poisoned) {
    return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_WRITE_SESSION_POISONED" });
  }
  if (!storeState.lockHeld || sessionState.lockIdentity !== storeState.lockIdentity) return unknown(sessionState, storeState);
  const rejectionState = drafts.get(rejectionDraft);
  if (rejectionState?.event_type !== "integrity.observation-rejected") {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
  }
  const priorLedgerBytes = bytes(storeState.ledgerBytes);
  const prior = inspectRuntimeLedgerV03(priorLedgerBytes);
  const [rejectionEnvelope, quarantineEnvelope] = storeState.eventEnvelopes;
  if (!prior.ok || rejectionEnvelope === undefined || quarantineEnvelope === undefined) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
  }
  const rejectionPreimage = {
    schema_version: "0.3" as const, event_id: rejectionEnvelope.event_id, run_id: prior.ledger.run_id,
    sequence: prior.ledger.sequence + 1, recorded_at: rejectionEnvelope.recorded_at,
    event_type: rejectionState.event_type, source: rejectionState.source, authority_ref: rejectionState.authority_ref,
    risk_tier: rejectionState.risk_tier, related_ids: rejectionState.related_ids,
    previous_event_hash: prior.ledger.head_hash, payload: rejectionState.payload,
  };
  const rejectionCandidate = { ...rejectionPreimage, event_hash: hashCanonical(rejectionPreimage) };
  const parsedRejection = RuntimeEventV03.safeParse(rejectionCandidate);
  if (!parsedRejection.success || parsedRejection.data.event_type !== "integrity.observation-rejected") {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
  }
  const rejectionLine = encoder.encode(`${canonicalize(parsedRejection.data)}\n`);
  const intermediateLedger = new Uint8Array(priorLedgerBytes.byteLength + rejectionLine.byteLength);
  intermediateLedger.set(priorLedgerBytes);
  intermediateLedger.set(rejectionLine, priorLedgerBytes.byteLength);
  const intermediate = inspectRuntimeLedgerV03(intermediateLedger);
  if (!intermediate.ok || intermediate.state.state !== "quarantine-required") {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
  }
  const quarantinePayload = Object.freeze({
    reason_code: parsedRejection.data.payload.reason_code,
    evidence_refs: Object.freeze([Object.freeze({
      ledger_sequence: intermediate.ledger.sequence,
      event_hash: intermediate.ledger.head_hash,
    })]),
  });
  const quarantinePreimage = {
    schema_version: "0.3" as const, event_id: quarantineEnvelope.event_id, run_id: prior.ledger.run_id,
    sequence: intermediate.ledger.sequence + 1, recorded_at: quarantineEnvelope.recorded_at,
    event_type: "run.quarantined" as const, source: "integrity" as const, authority_ref: null,
    risk_tier: parsedRejection.data.risk_tier, related_ids: [] as const,
    previous_event_hash: intermediate.ledger.head_hash, payload: quarantinePayload,
  };
  const quarantineCandidate = { ...quarantinePreimage, event_hash: hashCanonical(quarantinePreimage) };
  const parsedQuarantine = RuntimeEventV03.safeParse(quarantineCandidate);
  if (!parsedQuarantine.success) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
  }
  const quarantineLine = encoder.encode(`${canonicalize(parsedQuarantine.data)}\n`);
  const pairBytes = new Uint8Array(rejectionLine.byteLength + quarantineLine.byteLength);
  pairBytes.set(rejectionLine);
  pairBytes.set(quarantineLine, rejectionLine.byteLength);
  const nextLedger = new Uint8Array(priorLedgerBytes.byteLength + pairBytes.byteLength);
  nextLedger.set(priorLedgerBytes);
  nextLedger.set(pairBytes, priorLedgerBytes.byteLength);
  const nextInspection = inspectRuntimeLedgerV03(nextLedger);
  if (!nextInspection.ok || nextInspection.state.state !== "quarantined") {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
  }
  storeState.operations.push("prefix-validation:accepted");
  const priorLedgerText = decoder.decode(priorLedgerBytes);
  const rejectionLineText = decoder.decode(rejectionLine);
  const quarantineLineText = decoder.decode(quarantineLine);
  if (fault(storeState, "before-write")) {
    sessionState.closed = true;
    const held = heldRunLocks.get(storeState.runId);
    if (held?.store === sessionState.store && held.lockIdentity === sessionState.lockIdentity) heldRunLocks.delete(storeState.runId);
    storeState.lockHeld = false;
    const classified = classifyRuntimeDurabilityPairV03({
      policy_version: "0.2",
      prior_head: { sequence: prior.ledger.sequence, event_hash: prior.ledger.head_hash, ledger_bytes_hash: prior.ledger.ledger_bytes_hash },
      target_head: { sequence: nextInspection.ledger.sequence, event_hash: nextInspection.ledger.head_hash, ledger_bytes_hash: nextInspection.ledger.ledger_bytes_hash },
      prior_ledger_text: priorLedgerText,
      event_lines: [
        { bytes: rejectionLineText, bytes_hash: hashRawBytes(rejectionLine), byte_length: rejectionLine.byteLength },
        { bytes: quarantineLineText, bytes_hash: hashRawBytes(quarantineLine), byte_length: quarantineLine.byteLength },
      ],
      steps: [{ step: "prefix-validation", outcome: "rejected-before-write" }],
    });
    return classified.classification === "NOT_COMMITTED"
      ? Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_NOT_COMMITTED" })
      : unknown(sessionState, storeState);
  }
  storeState.operations.push("append-write:began");
  if (fault(storeState, "append-write")) {
    storeState.ledgerBytes = nextLedger.slice(0, priorLedgerBytes.byteLength + rejectionLine.byteLength);
    return unknown(sessionState, storeState);
  }
  if (fault(storeState, "append-write-partial")) {
    storeState.ledgerBytes = nextLedger.slice(0, priorLedgerBytes.byteLength + Math.max(1, Math.floor(rejectionLine.byteLength / 2)));
    return unknown(sessionState, storeState);
  }
  storeState.ledgerBytes = nextLedger;
  storeState.operations.push("append-write:complete");
  if (fault(storeState, "ledger-sync")) return unknown(sessionState, storeState);
  storeState.operations.push("ledger-sync:confirmed");
  if (fault(storeState, "ledger-close")) return unknown(sessionState, storeState);
  storeState.operations.push("ledger-close:confirmed");
  if (fault(storeState, "ledger-readback")) return unknown(sessionState, storeState);
  const exactLedgerReadback = inspectRuntimeLedgerV03(bytes(storeState.ledgerBytes));
  if (!exactLedgerReadback.ok || exactLedgerReadback.ledger.ledger_bytes_hash !== nextInspection.ledger.ledger_bytes_hash) {
    return unknown(sessionState, storeState);
  }
  storeState.operations.push("ledger-readback:exact");
  const previousManifest = inspectRunManifestV03({
    manifest_bytes: bytes(storeState.manifestBytes), ledger_bytes: priorLedgerBytes,
    captured_files: replaceLedgerCapture(storeState.capturedFiles, priorLedgerBytes),
  });
  if (!previousManifest.ok) return unknown(sessionState, storeState);
  const nextFiles = replaceLedgerCapture(storeState.capturedFiles, nextLedger);
  const nextManifest = buildRunManifestV03({
    ledger_bytes: nextLedger, created_at: previousManifest.manifest.created_at, captured_files: nextFiles,
  });
  if (!nextManifest.ok) return unknown(sessionState, storeState);
  if (fault(storeState, "manifest-temp-write")) return unknown(sessionState, storeState);
  storeState.manifestTempBytes = bytes(nextManifest.bytes);
  storeState.operations.push("manifest-temp-write:complete");
  if (fault(storeState, "manifest-temp-sync")) return unknown(sessionState, storeState);
  storeState.operations.push("manifest-temp-sync:confirmed");
  if (fault(storeState, "manifest-temp-close")) return unknown(sessionState, storeState);
  storeState.operations.push("manifest-temp-close:confirmed");
  if (fault(storeState, "manifest-rename")) return unknown(sessionState, storeState);
  storeState.manifestBytes = bytes(storeState.manifestTempBytes);
  storeState.manifestTempBytes = null;
  storeState.operations.push("manifest-rename:complete");
  if (fault(storeState, "directory-sync")) return unknown(sessionState, storeState);
  storeState.operations.push("directory-sync:confirmed");
  if (fault(storeState, "final-readback")) return unknown(sessionState, storeState);
  const finalLedgerBytes = bytes(storeState.ledgerBytes);
  const finalManifest = inspectRunManifestV03({
    manifest_bytes: bytes(storeState.manifestBytes), ledger_bytes: finalLedgerBytes, captured_files: nextFiles,
  });
  if (!finalManifest.ok) return unknown(sessionState, storeState);
  const classified = classifyRuntimeDurabilityPairV03({
    policy_version: "0.2",
    prior_head: { sequence: prior.ledger.sequence, event_hash: prior.ledger.head_hash, ledger_bytes_hash: prior.ledger.ledger_bytes_hash },
    target_head: { sequence: nextInspection.ledger.sequence, event_hash: nextInspection.ledger.head_hash, ledger_bytes_hash: nextInspection.ledger.ledger_bytes_hash },
    prior_ledger_text: priorLedgerText,
    event_lines: [
      { bytes: rejectionLineText, bytes_hash: hashRawBytes(rejectionLine), byte_length: rejectionLine.byteLength },
      { bytes: quarantineLineText, bytes_hash: hashRawBytes(quarantineLine), byte_length: quarantineLine.byteLength },
    ],
    steps: [
      { step: "prefix-validation", outcome: "accepted" },
      { step: "append-write", outcome: "complete" },
      { step: "ledger-sync", outcome: "confirmed" },
      { step: "ledger-readback", outcome: "exact" },
      { step: "head-publish", outcome: "complete" },
      { step: "directory-sync", outcome: "confirmed" },
      { step: "final-readback", outcome: "exact" },
    ],
  });
  if (classified.classification !== "COMMITTED") return unknown(sessionState, storeState);
  storeState.operations.push("final-readback:exact");
  storeState.capturedFiles = nextFiles;
  storeState.eventEnvelopes.splice(0, 2);
  const events = nextInspection.ledger.events.slice(-2);
  return Object.freeze({
    ok: true,
    classification: "COMMITTED",
    event_refs: Object.freeze([
      Object.freeze({ ledger_sequence: events[0]!.sequence, event_hash: events[0]!.event_hash }),
      Object.freeze({ ledger_sequence: events[1]!.sequence, event_hash: events[1]!.event_hash }),
    ]) as unknown as readonly [Readonly<{ ledger_sequence: number; event_hash: string }>, Readonly<{ ledger_sequence: number; event_hash: string }>],
    manifest_hash: finalManifest.manifest.manifest_hash,
    ledger_bytes_hash: nextInspection.ledger.ledger_bytes_hash,
  });
}

export async function appendRuntimeIntegrityQuarantinePairV03(
  session: RuntimeWriteSessionV03,
  rejectionDraft: RuntimeEventDraftV03,
): Promise<AppendRuntimeIntegrityQuarantinePairV03Result> {
  const state = sessions.get(session);
  if (state === undefined) return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_SESSION_INVALID" });
  const store = stores.get(state.store);
  if (store === undefined) return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
  let result: AppendRuntimeIntegrityQuarantinePairV03Result | undefined;
  const operation = state.tail.then(async () => {
    result = await appendIntegrityQuarantinePairSerialized(state, store, rejectionDraft);
  });
  state.tail = operation.then(() => undefined, () => undefined);
  await operation;
  return result ?? unknown(state, store);
}

export async function appendRuntimeEventV03(
  session: RuntimeWriteSessionV03,
  draft: RuntimeEventDraftV03,
): Promise<AppendRuntimeEventV03Result> {
  const state = sessions.get(session);
  if (state === undefined) return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_SESSION_INVALID" });
  const store = stores.get(state.store);
  if (store === undefined) return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
  let result: AppendRuntimeEventV03Result | undefined;
  const operation = state.tail.then(async () => { result = await appendSerialized(state, store, draft); });
  state.tail = operation.then(() => undefined, () => undefined);
  await operation;
  return result ?? unknown(state, store);
}

export async function closeRuntimeWriteSessionV03(session: RuntimeWriteSessionV03): Promise<boolean> {
  const state = sessions.get(session);
  if (state === undefined) return false;
  let result = false;
  const operation = state.tail.then(() => {
    if (state.closed) return;
    const store = stores.get(state.store);
    if (store === undefined) return;
    state.closed = true;
    const held = heldRunLocks.get(store.runId);
    if (held?.store !== state.store || held.lockIdentity !== state.lockIdentity) {
      state.poisoned = true;
      store.poisoned = true;
      return;
    }
    heldRunLocks.delete(store.runId);
    store.lockHeld = false;
    store.operations.push("lock-released");
    result = true;
  });
  state.tail = operation.then(() => undefined, () => undefined);
  await operation;
  return result;
}

function hasExactLiveLock(state: SessionState, store: StoreState): boolean {
  const held = heldRunLocks.get(store.runId);
  return store.lockHeld && held?.store === state.store && held.lockIdentity === state.lockIdentity;
}

function captureAdmissionSnapshot(
  state: SessionState,
  store: StoreState,
): InspectRuntimeWriteSessionV03ForAdmissionResult {
  if (state.closed) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_CLOSED" });
  if (state.poisoned || store.poisoned) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
  if (!hasExactLiveLock(state, store)) return Object.freeze({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" });
  const ledgerBytes = bytes(store.ledgerBytes);
  const ledger = inspectRuntimeLedgerV03(ledgerBytes);
  if (!ledger.ok) return Object.freeze({ ok: false, error: "RUNTIME_PREFIX_INVALID" });
  const capturedFiles = replaceLedgerCapture(store.capturedFiles, ledgerBytes);
  const manifest = inspectRunManifestV03({
    manifest_bytes: bytes(store.manifestBytes),
    ledger_bytes: ledgerBytes,
    captured_files: capturedFiles,
  });
  if (!manifest.ok) return Object.freeze({ ok: false, error: "RUN_MANIFEST_INVALID" });
  if (ledger.state.state === "quarantined" || ledger.state.state === "quarantine-required") {
    return Object.freeze({ ok: false, error: "RUN_QUARANTINED" });
  }
  if (ledger.ledger.sealed) return Object.freeze({ ok: false, error: "RUN_TERMINAL" });
  const envelopes = store.eventEnvelopes.slice(0, 3);
  if (envelopes.length !== 3) return Object.freeze({ ok: false, error: "ADMISSION_CAPTURE_INVALID" });
  const records = capturedFiles
    .filter((row): row is CapturedRunFileV03 & { bytes: Uint8Array } => row.family === "record" && row.bytes !== null)
    .map((row) => Object.freeze({ path: row.path, bytes: bytes(row.bytes), raw_hash: hashRawBytes(row.bytes) }))
    .sort((left, right) => compareRuntimeUtf8BytesV02(left.path, right.path));
  const planRows = capturedFiles.filter((row) => (
    row.path === "resolved-run-plan.json" || row.path.endsWith("/resolved-run-plan.json")
  ));
  const planRow = planRows[0];
  if (planRows.length !== 1 || planRow?.path !== "resolved-run-plan.json" || planRow.family !== "primary"
    || planRow.required !== true || planRow.mode !== 384 || planRow.bytes === null) {
    return Object.freeze({ ok: false, error: "ADMISSION_CAPTURE_INVALID" });
  }
  const planCapture = Object.freeze({
    path: planRow.path,
    bytes: bytes(planRow.bytes),
    raw_hash: hashRawBytes(planRow.bytes),
  });
  const admissionContext = copyAdmissionContext(store.admissionContext);
  if (admissionContext === null) return Object.freeze({ ok: false, error: "ADMISSION_CAPTURE_INVALID" });
  const snapshot: RuntimeWriteAdmissionSnapshotV03 = Object.freeze({
    run_id: ledger.ledger.run_id,
    plan_hash: ledger.ledger.plan_hash,
    current_fence_epoch: manifest.manifest.current_fence_epoch,
    ledger_bytes_hash: ledger.ledger.ledger_bytes_hash,
    ledger_sequence: ledger.ledger.sequence,
    ledger_head_hash: ledger.ledger.head_hash,
    manifest_hash: manifest.manifest.manifest_hash,
    events: Object.freeze([...ledger.ledger.events]),
    plan_capture: planCapture,
    record_captures: Object.freeze(records),
    envelopes: Object.freeze(envelopes.map((entry) => Object.freeze({ ...entry }))) as unknown as readonly [RuntimeAdmissionEnvelopeV03, RuntimeAdmissionEnvelopeV03, RuntimeAdmissionEnvelopeV03],
    admission_context: admissionContext,
  });
  return Object.freeze({ ok: true, snapshot });
}

export async function inspectRuntimeWriteSessionV03ForAdmission(
  session: RuntimeWriteSessionV03,
): Promise<InspectRuntimeWriteSessionV03ForAdmissionResult> {
  const state = sessions.get(session);
  if (state === undefined) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  const store = stores.get(state.store);
  if (store === undefined) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  let result: InspectRuntimeWriteSessionV03ForAdmissionResult | undefined;
  const operation = state.tail.then(() => { result = captureAdmissionSnapshot(state, store); });
  state.tail = operation.then(() => undefined, () => undefined);
  await operation;
  return result ?? Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
}

export async function inspectRuntimeWriteSessionV03ForDispatch(
  session: RuntimeWriteSessionV03,
): Promise<InspectRuntimeWriteSessionV03ForDispatchResult> {
  const state = sessions.get(session);
  if (state === undefined) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  const store = stores.get(state.store);
  if (store === undefined) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  let result: InspectRuntimeWriteSessionV03ForDispatchResult | undefined;
  const operation = state.tail.then(() => {
    if (state.closed) { result = Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_CLOSED" }); return; }
    if (state.poisoned || store.poisoned) { result = Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" }); return; }
    if (!hasExactLiveLock(state, store)) { result = Object.freeze({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" }); return; }
    const ledgerBytes = bytes(store.ledgerBytes);
    const ledger = inspectRuntimeLedgerV03(ledgerBytes);
    if (!ledger.ok) { result = Object.freeze({ ok: false, error: "RUNTIME_PREFIX_INVALID" }); return; }
    const manifest = inspectRunManifestV03({
      manifest_bytes: bytes(store.manifestBytes),
      ledger_bytes: ledgerBytes,
      captured_files: replaceLedgerCapture(store.capturedFiles, ledgerBytes),
    });
    if (!manifest.ok) { result = Object.freeze({ ok: false, error: "RUN_MANIFEST_INVALID" }); return; }
    if (ledger.state.state === "quarantined" || ledger.state.state === "quarantine-required") {
      result = Object.freeze({ ok: false, error: "RUN_QUARANTINED" }); return;
    }
    if (ledger.ledger.sealed) { result = Object.freeze({ ok: false, error: "RUN_TERMINAL" }); return; }
    result = Object.freeze({
      ok: true,
      snapshot: Object.freeze({
        run_id: ledger.ledger.run_id,
        plan_hash: ledger.ledger.plan_hash,
        current_fence_epoch: manifest.manifest.current_fence_epoch,
        ledger_sequence: ledger.ledger.sequence,
        ledger_head_hash: ledger.ledger.head_hash,
        manifest_hash: manifest.manifest.manifest_hash,
        events: Object.freeze([...ledger.ledger.events]),
      }),
    });
  });
  state.tail = operation.then(() => undefined, () => undefined);
  await operation;
  return result ?? Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
}

/** Package-private authenticated snapshot for termination and quarantine handling. */
export async function inspectRuntimeWriteSessionV03ForTermination(
  session: RuntimeWriteSessionV03,
): Promise<InspectRuntimeWriteSessionV03ForTerminationResult> {
  const state = sessions.get(session);
  if (state === undefined) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  const store = stores.get(state.store);
  if (store === undefined) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  let result: InspectRuntimeWriteSessionV03ForTerminationResult | undefined;
  const operation = state.tail.then(() => {
    if (state.closed) { result = Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_CLOSED" }); return; }
    if (state.poisoned || store.poisoned) { result = Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" }); return; }
    if (!hasExactLiveLock(state, store)) { result = Object.freeze({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" }); return; }
    const ledgerBytes = bytes(store.ledgerBytes);
    const ledger = inspectRuntimeLedgerV03(ledgerBytes);
    if (!ledger.ok) { result = Object.freeze({ ok: false, error: "RUNTIME_PREFIX_INVALID" }); return; }
    const manifest = inspectRunManifestV03({
      manifest_bytes: bytes(store.manifestBytes), ledger_bytes: ledgerBytes,
      captured_files: replaceLedgerCapture(store.capturedFiles, ledgerBytes),
    });
    if (!manifest.ok) { result = Object.freeze({ ok: false, error: "RUN_MANIFEST_INVALID" }); return; }
    if (ledger.state.state === "quarantine-required") {
      result = Object.freeze({ ok: false, error: "RUN_QUARANTINE_REQUIRED" }); return;
    }
    if (ledger.ledger.sealed) { result = Object.freeze({ ok: false, error: "RUN_TERMINAL" }); return; }
    result = Object.freeze({
      ok: true,
      snapshot: Object.freeze({
        run_id: ledger.ledger.run_id,
        plan_hash: ledger.ledger.plan_hash,
        current_fence_epoch: manifest.manifest.current_fence_epoch,
        ledger_sequence: ledger.ledger.sequence,
        ledger_head_hash: ledger.ledger.head_hash,
        manifest_hash: manifest.manifest.manifest_hash,
        events: Object.freeze([...ledger.ledger.events]),
      }),
    });
  });
  state.tail = operation.then(() => undefined, () => undefined);
  await operation;
  return result ?? Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
}

export async function poisonRuntimeWriteSessionV03ForAdmission(
  session: RuntimeWriteSessionV03,
): Promise<boolean> {
  const state = sessions.get(session);
  if (state === undefined) return false;
  const store = stores.get(state.store);
  if (store === undefined) return false;
  let result = false;
  const operation = state.tail.then(() => {
    if (state.poisoned && store.poisoned) return;
    state.poisoned = true;
    store.poisoned = true;
    result = true;
  });
  state.tail = operation.then(() => undefined, () => undefined);
  await operation;
  return result;
}

function captureAdmissionReadbackExpectation(input: unknown): RuntimeAdmissionCommitExpectationV03 | null {
  const descriptors = plainRecord(input, ["lease_event_ref", "admission_clock_ref", "action_admission_event_ref", "manifest_hash"]);
  if (descriptors === null || typeof descriptors.manifest_hash!.value !== "string") return null;
  const ref = (value: unknown): Readonly<{ ledger_sequence: number; event_hash: string }> | null => {
    const fields = plainRecord(value, ["ledger_sequence", "event_hash"]);
    if (fields === null || !Number.isSafeInteger(fields.ledger_sequence!.value) || (fields.ledger_sequence!.value as number) <= 0
      || typeof fields.event_hash!.value !== "string") return null;
    return Object.freeze({ ledger_sequence: fields.ledger_sequence!.value as number, event_hash: fields.event_hash!.value as string });
  };
  const lease = ref(descriptors.lease_event_ref!.value);
  const clock = ref(descriptors.admission_clock_ref!.value);
  const action = ref(descriptors.action_admission_event_ref!.value);
  return lease === null || clock === null || action === null ? null : Object.freeze({
    lease_event_ref: lease,
    admission_clock_ref: clock,
    action_admission_event_ref: action,
    manifest_hash: descriptors.manifest_hash!.value as string,
  });
}

const RUNTIME_SHA256_HASH_V03 = /^sha256:[0-9a-f]{64}$/u;

function captureTailReadbackExpectation(input: unknown): RuntimeWriteSessionTailExpectationV03 | null {
  const descriptors = plainRecord(input, ["events", "manifest_hash"]);
  if (descriptors === null || typeof descriptors.manifest_hash!.value !== "string"
    || !RUNTIME_SHA256_HASH_V03.test(descriptors.manifest_hash!.value)) return null;
  const eventsValue = descriptors.events!.value;
  if (!Array.isArray(eventsValue) || Object.getPrototypeOf(eventsValue) !== Array.prototype
    || eventsValue.length < 1 || eventsValue.length > 3) return null;
  const arrayDescriptors = Object.getOwnPropertyDescriptors(eventsValue);
  if (Reflect.ownKeys(eventsValue).some((key) => typeof key !== "string")
    || Object.keys(arrayDescriptors).some((key) => key !== "length" && !/^\d+$/u.test(key))) return null;
  const events: Array<RuntimeWriteSessionTailExpectationV03["events"][number]> = [];
  for (let index = 0; index < eventsValue.length; index += 1) {
    const itemDescriptor = arrayDescriptors[String(index)];
    if (itemDescriptor === undefined || !("value" in itemDescriptor) || itemDescriptor.get !== undefined
      || itemDescriptor.set !== undefined || itemDescriptor.enumerable !== true) return null;
    const event = plainRecord(itemDescriptor.value, ["event_type", "event_ref"]);
    if (event === null || typeof event.event_type!.value !== "string" || event.event_type!.value.length === 0) return null;
    const reference = plainRecord(event.event_ref!.value, ["ledger_sequence", "event_hash"]);
    if (reference === null || !Number.isSafeInteger(reference.ledger_sequence!.value)
      || (reference.ledger_sequence!.value as number) <= 0 || typeof reference.event_hash!.value !== "string"
      || !RUNTIME_SHA256_HASH_V03.test(reference.event_hash!.value)) return null;
    events.push(Object.freeze({
      event_type: event.event_type!.value as string,
      event_ref: Object.freeze({
        ledger_sequence: reference.ledger_sequence!.value as number,
        event_hash: reference.event_hash!.value as string,
      }),
    }));
  }
  return Object.freeze({
    events: Object.freeze(events),
    manifest_hash: descriptors.manifest_hash!.value,
  });
}

/** Package-private exact post-commit proof for one bounded ledger tail. */
export async function verifyRuntimeWriteSessionTailReadbackV03(
  session: RuntimeWriteSessionV03,
  expectedInput: unknown,
): Promise<VerifyRuntimeWriteSessionTailReadbackV03Result> {
  const expected = captureTailReadbackExpectation(expectedInput);
  if (expected === null) return Object.freeze({ ok: false, error: "TAIL_READBACK_MISMATCH" });
  const state = sessions.get(session);
  if (state === undefined) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  const store = stores.get(state.store);
  if (store === undefined) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  let result: VerifyRuntimeWriteSessionTailReadbackV03Result | undefined;
  const operation = state.tail.then(() => {
    if (state.closed) { result = Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_CLOSED" }); return; }
    if (state.poisoned || store.poisoned) { result = Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" }); return; }
    if (!hasExactLiveLock(state, store)) { result = Object.freeze({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" }); return; }
    const ledgerBytes = bytes(store.ledgerBytes);
    const ledger = inspectRuntimeLedgerV03(ledgerBytes);
    if (!ledger.ok) { result = Object.freeze({ ok: false, error: "RUNTIME_PREFIX_INVALID" }); return; }
    const manifest = inspectRunManifestV03({
      manifest_bytes: bytes(store.manifestBytes),
      ledger_bytes: ledgerBytes,
      captured_files: replaceLedgerCapture(store.capturedFiles, ledgerBytes),
    });
    if (!manifest.ok) { result = Object.freeze({ ok: false, error: "RUN_MANIFEST_INVALID" }); return; }
    const latestExpected = expected.events.at(-1)!;
    const tail = ledger.ledger.events.slice(-expected.events.length);
    const matched = manifest.manifest.manifest_hash === expected.manifest_hash
      && ledger.ledger.sequence === latestExpected.event_ref.ledger_sequence
      && ledger.ledger.head_hash === latestExpected.event_ref.event_hash
      && tail.length === expected.events.length
      && tail.every((event, index) => {
        const expectedEvent = expected.events[index]!;
        return event.event_type === expectedEvent.event_type
          && event.sequence === expectedEvent.event_ref.ledger_sequence
          && event.event_hash === expectedEvent.event_ref.event_hash;
      });
    if (!matched) { result = Object.freeze({ ok: false, error: "TAIL_READBACK_MISMATCH" }); return; }
    result = Object.freeze({
      ok: true,
      readback: Object.freeze({
        run_id: ledger.ledger.run_id,
        plan_hash: ledger.ledger.plan_hash,
        current_fence_epoch: manifest.manifest.current_fence_epoch,
        ledger_sequence: ledger.ledger.sequence,
        ledger_head_hash: ledger.ledger.head_hash,
        manifest_hash: manifest.manifest.manifest_hash,
        events: Object.freeze([...tail]),
      }),
    });
  });
  state.tail = operation.then(() => undefined, () => undefined);
  await operation;
  return result ?? Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
}

export async function verifyRuntimeWriteSessionAdmissionReadbackV03(
  session: RuntimeWriteSessionV03,
  expectedInput: unknown,
): Promise<VerifyRuntimeWriteSessionAdmissionReadbackV03Result> {
  const expected = captureAdmissionReadbackExpectation(expectedInput);
  if (expected === null) return Object.freeze({ ok: false, error: "ADMISSION_READBACK_MISMATCH" });
  const state = sessions.get(session);
  if (state === undefined) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  const store = stores.get(state.store);
  if (store === undefined) return Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  let result: VerifyRuntimeWriteSessionAdmissionReadbackV03Result | undefined;
  const operation = state.tail.then(() => {
    if (state.closed) { result = Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_CLOSED" }); return; }
    if (state.poisoned || store.poisoned) { result = Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" }); return; }
    if (!hasExactLiveLock(state, store)) { result = Object.freeze({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" }); return; }
    const ledgerBytes = bytes(store.ledgerBytes);
    const ledger = inspectRuntimeLedgerV03(ledgerBytes);
    if (!ledger.ok) { result = Object.freeze({ ok: false, error: "RUNTIME_PREFIX_INVALID" }); return; }
    const capturedFiles = replaceLedgerCapture(store.capturedFiles, ledgerBytes);
    const manifest = inspectRunManifestV03({
      manifest_bytes: bytes(store.manifestBytes), ledger_bytes: ledgerBytes, captured_files: capturedFiles,
    });
    if (!manifest.ok) { result = Object.freeze({ ok: false, error: "RUN_MANIFEST_INVALID" }); return; }
    if (ledger.state.state === "quarantined" || ledger.state.state === "quarantine-required") {
      result = Object.freeze({ ok: false, error: "RUN_QUARANTINED" }); return;
    }
    if (ledger.ledger.sealed) { result = Object.freeze({ ok: false, error: "RUN_TERMINAL" }); return; }
    const latest = ledger.ledger.events.slice(-3) as Array<Record<string, unknown>>;
    const matches = (
      event: Record<string, unknown> | undefined,
      eventType: string,
      reference: Readonly<{ ledger_sequence: number; event_hash: string }>,
    ): boolean => event?.event_type === eventType
      && event.sequence === reference.ledger_sequence
      && event.event_hash === reference.event_hash;
    const matched = manifest.manifest.manifest_hash === expected.manifest_hash
      && ledger.ledger.sequence === expected.action_admission_event_ref.ledger_sequence
      && ledger.ledger.head_hash === expected.action_admission_event_ref.event_hash
      && matches(latest[0], "lease.issued", expected.lease_event_ref)
      && matches(latest[1], "run.clock-observed", expected.admission_clock_ref)
      && matches(latest[2], "task.action-admitted", expected.action_admission_event_ref);
    if (!matched) { result = Object.freeze({ ok: false, error: "ADMISSION_READBACK_MISMATCH" }); return; }
    result = Object.freeze({
      ok: true,
      readback: Object.freeze({
        run_id: ledger.ledger.run_id,
        plan_hash: ledger.ledger.plan_hash,
        current_fence_epoch: manifest.manifest.current_fence_epoch,
        ledger_bytes_hash: ledger.ledger.ledger_bytes_hash,
        ledger_sequence: ledger.ledger.sequence,
        ledger_head_hash: ledger.ledger.head_hash,
        manifest_hash: manifest.manifest.manifest_hash,
        runtime_state: Object.freeze({
          state: ledger.state.state,
          started: ledger.state.started,
          abort_requested: ledger.state.abort_requested,
          in_flight_action_ids: Object.freeze([...ledger.state.in_flight_action_ids]),
        }),
        events: Object.freeze([...ledger.ledger.events]),
      }),
    });
  });
  state.tail = operation.then(() => undefined, () => undefined);
  await operation;
  return result ?? Object.freeze({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
}

export function inspectSyntheticRuntimeRunStoreV03ForTest(store: CapturedRuntimeRunStoreV03): Readonly<{
  ledger_bytes: Uint8Array;
  manifest_bytes: Uint8Array;
  operations: readonly string[];
  lock_held: boolean;
  poisoned: boolean;
}> | null {
  const state = stores.get(store);
  return state === undefined ? null : Object.freeze({
    ledger_bytes: bytes(state.ledgerBytes),
    manifest_bytes: bytes(state.manifestBytes),
    operations: Object.freeze([...state.operations]),
    lock_held: state.lockHeld,
    poisoned: state.poisoned,
  });
}

/** Synthetic lock-loss fixture. It performs no filesystem, process, network, or host operation. */
export function invalidateSyntheticRuntimeRunStoreLockV03ForTest(store: CapturedRuntimeRunStoreV03): boolean {
  const state = stores.get(store);
  if (state === undefined || !state.lockHeld) return false;
  state.lockHeld = false;
  return true;
}
