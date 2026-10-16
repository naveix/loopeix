import { isProxy } from "node:util/types";

import { z } from "zod";

import { hashCanonical } from "../hash.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../schema/runtime-v04.js";
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
  inspectRunManifestV04,
  isValidatedRunManifestPairV04,
  type ValidatedRunManifestV04,
} from "./runtime-manifest-v04.js";
import {
  HumanAuthorizationProofV02,
  isCapturedAuthorityTrustContextV02,
  verifyHumanAuthorizationProofV02,
  type CapturedAuthorityTrustContextForS36V02,
} from "./runtime-record-admission-v02.js";
import { reduceRuntimeEventPrefixV04, type RuntimeStateV04 } from "./runtime-state-reducer-v04.js";

type LedgerRef = Readonly<{ ledger_sequence: number; event_hash: string }>;

const RuntimeAbortRequestV04 = z.object({ request_id: MachineIdV02 }).strict();
const AbortCaptureInputV04 = z.object({
  trust_context: z.custom<CapturedAuthorityTrustContextForS36V02>(),
  authorization_proof: HumanAuthorizationProofV02,
  validated_plan: z.custom<ValidatedRuntimePlanV03>(),
  ledger: z.custom<ValidatedRuntimeLedgerV04>(),
  manifest: z.custom<ValidatedRunManifestV04>(),
  request: RuntimeAbortRequestV04,
}).strict();
const AbortWriteInputV04 = z.object({
  captured_request: z.custom<CapturedRuntimeAbortRequestV04>(),
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  request_event_id: MachineIdV02,
  fence_event_id: MachineIdV02,
}).strict();
const ContinueAbortInputV04 = z.object({
  pending_request_event_ref: z.object({ ledger_sequence: z.number().int().positive(), event_hash: z.string() }).strict(),
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  fence_event_id: MachineIdV02,
}).strict();

const RISK_TIER_RANK = Object.freeze({ T0: 0, T1: 1, T2: 2, T3a: 3, T3b: 4, T3c: 5, T3d: 6, T4: 7 } as const);

export type RuntimeAbortAuthorizationSubjectV04 = Readonly<{
  purpose: "runtime-abort-request-v04";
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
  reason_code: "operator-requested";
  current_attempt_event_ref: LedgerRef;
  run_owner_lease_event_ref: LedgerRef;
  current_fence_epoch: number;
  authority_envelope_hash: string;
}>;

export type RuntimeAbortActionScopeV04 = Readonly<{
  purpose: "runtime-abort-scope-v04";
  schema_version: "0.4";
  operation: "abort";
  run_id: string;
  plan_hash: string;
  runtime_input_hash: string;
  runtime_recovery_policy_hash: string;
  request_id: string;
  requested_by: "operator";
  reason_code: "operator-requested";
  current_attempt_event_ref: LedgerRef;
  run_owner_lease_event_ref: LedgerRef;
  current_fence_epoch: number;
  authority_envelope_hash: string;
}>;

type AbortBinding = Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  subject: RuntimeAbortAuthorizationSubjectV04;
  request_id: string;
  authority_ref: string;
  approved_risk_tier: keyof typeof RISK_TIER_RANK;
  expires_at: string;
}>;

class CapturedRuntimeAbortRequestTokenV04 {
  readonly #brand = true;
  private constructor() { void this.#brand; Object.freeze(this); }
  static create(): CapturedRuntimeAbortRequestTokenV04 { return new CapturedRuntimeAbortRequestTokenV04(); }
}

export type CapturedRuntimeAbortRequestV04 = CapturedRuntimeAbortRequestTokenV04;
const capturedAbortRequests = new WeakMap<object, AbortBinding>();

export type CaptureRuntimeAbortRequestResultV04 =
  | Readonly<{ ok: true; value: CapturedRuntimeAbortRequestV04 }>
  | Readonly<{ ok: false; error: "RUNTIME_ABORT_REQUEST_AUTHORIZATION_INVALID" }>;

export type RuntimeAbortWriteResultV04 =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      request_event_ref: LedgerRef;
      fence_event_ref: LedgerRef;
      ledger_bytes_hash: string;
      manifest_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "REQUEST_COMMITTED_ABORT_NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_ABORT_INPUT_INVALID"
        | "RUNTIME_ABORT_AUTHORIZATION_INVALID"
        | "RUNTIME_ABORT_PREFIX_INVALID"
        | "RUNTIME_ABORT_REFUSED"
        | "RUNTIME_ABORT_NOT_COMMITTED"
        | "RUNTIME_ABORT_OUTCOME_UNKNOWN";
      request_event_ref?: LedgerRef;
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

function sameRef(left: LedgerRef | null, right: LedgerRef | null): boolean {
  return left === null || right === null
    ? left === right
    : left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function currentAttempt(plan: ValidatedRuntimePlanV03, ledger: ValidatedRuntimeLedgerV04) {
  const reference = ledger.state.current_attempt_event_ref;
  if (reference === null) return null;
  const row = ledger.events[reference.ledger_sequence - 1];
  if (row?.event_type !== "execution.attempt-started"
    || row.event_hash !== reference.event_hash
    || row.payload.plan_hash !== plan.plan_hash
    || row.payload.input_hash !== plan.plan.runtime_input_hash
    || row.payload.recovery_policy_hash !== plan.plan.runtime_recovery_policy_hash) return null;
  return Object.freeze({ reference, authority_envelope_hash: row.payload.authority_envelope_hash });
}

function authorizationSubject(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  request: Readonly<{ request_id: string }>;
}>): RuntimeAbortAuthorizationSubjectV04 | null {
  if (!isValidatedRuntimePlanV03(input.validated_plan)
    || !isValidatedRunManifestPairV04(input.manifest, input.ledger)) return null;
  const attempt = currentAttempt(input.validated_plan, input.ledger);
  const owner = input.ledger.state.active_run_owner;
  if (attempt === null || owner?.active !== true || !sameRef(attempt.reference, owner.lease_event_ref)) return null;
  return Object.freeze({
    purpose: "runtime-abort-request-v04",
    schema_version: "0.4",
    run_id: input.validated_plan.run_id,
    plan_hash: input.validated_plan.plan_hash,
    runtime_input_hash: input.validated_plan.plan.runtime_input_hash,
    runtime_recovery_policy_hash: input.validated_plan.plan.runtime_recovery_policy_hash,
    source_boundary_sequence: input.ledger.sequence,
    source_boundary_head_hash: input.ledger.head_hash,
    source_manifest_hash: input.manifest.manifest_hash,
    request_id: input.request.request_id,
    requested_by: "operator",
    reason_code: "operator-requested",
    current_attempt_event_ref: attempt.reference,
    run_owner_lease_event_ref: owner.lease_event_ref,
    current_fence_epoch: input.ledger.state.current_fence_epoch,
    authority_envelope_hash: attempt.authority_envelope_hash,
  });
}

function authorizationScope(subject: RuntimeAbortAuthorizationSubjectV04): RuntimeAbortActionScopeV04 {
  return Object.freeze({
    purpose: "runtime-abort-scope-v04",
    schema_version: "0.4",
    operation: "abort",
    run_id: subject.run_id,
    plan_hash: subject.plan_hash,
    runtime_input_hash: subject.runtime_input_hash,
    runtime_recovery_policy_hash: subject.runtime_recovery_policy_hash,
    request_id: subject.request_id,
    requested_by: subject.requested_by,
    reason_code: subject.reason_code,
    current_attempt_event_ref: subject.current_attempt_event_ref,
    run_owner_lease_event_ref: subject.run_owner_lease_event_ref,
    current_fence_epoch: subject.current_fence_epoch,
    authority_envelope_hash: subject.authority_envelope_hash,
  });
}

export function hashRuntimeAbortAuthorizationSubjectV04(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  request: Readonly<{ request_id: string }>;
}>): string | null {
  const subject = authorizationSubject(input);
  return subject === null ? null : hashCanonical(subject);
}

export function hashRuntimeAbortActionScopeV04(input: Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  request: Readonly<{ request_id: string }>;
}>): string | null {
  const subject = authorizationSubject(input);
  return subject === null ? null : hashCanonical(authorizationScope(subject));
}

export function captureRuntimeAbortRequestV04(input: unknown): CaptureRuntimeAbortRequestResultV04 {
  try {
    const parsed = AbortCaptureInputV04.safeParse(input);
    if (!parsed.success
      || !isCapturedAuthorityTrustContextV02(parsed.data.trust_context)
      || !isValidatedRuntimePlanV03(parsed.data.validated_plan)
      || !isValidatedRunManifestPairV04(parsed.data.manifest, parsed.data.ledger)) {
      return Object.freeze({ ok: false, error: "RUNTIME_ABORT_REQUEST_AUTHORIZATION_INVALID" });
    }
    const subject = authorizationSubject(parsed.data);
    const proof = parsed.data.authorization_proof;
    if (subject === null
      || parsed.data.ledger.state.state !== "running"
      || parsed.data.ledger.state.in_flight_action_ids.length !== 0
      || parsed.data.ledger.events.some((row) => row.event_type === "control.abort-requested")
      || !verifyHumanAuthorizationProofV02(parsed.data.trust_context, proof).ok
      || proof.run_id !== subject.run_id
      || proof.plan_hash !== subject.plan_hash
      || proof.authorization_subject_hash !== hashCanonical(subject)
      || proof.action_scope_hash !== hashCanonical(authorizationScope(subject))
      || RISK_TIER_RANK[proof.approved_risk_tier] < RISK_TIER_RANK.T4) {
      return Object.freeze({ ok: false, error: "RUNTIME_ABORT_REQUEST_AUTHORIZATION_INVALID" });
    }
    const token = CapturedRuntimeAbortRequestTokenV04.create();
    capturedAbortRequests.set(token, Object.freeze({
      validated_plan: parsed.data.validated_plan,
      ledger: parsed.data.ledger,
      manifest: parsed.data.manifest,
      subject,
      request_id: parsed.data.request.request_id,
      authority_ref: proof.authenticated_principal_ref,
      approved_risk_tier: proof.approved_risk_tier,
      expires_at: proof.expires_at,
    }));
    return Object.freeze({ ok: true, value: token });
  } catch {
    return Object.freeze({ ok: false, error: "RUNTIME_ABORT_REQUEST_AUTHORIZATION_INVALID" });
  }
}

function inspectCapturedAbort(value: unknown): AbortBinding | null {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return null;
  return capturedAbortRequests.get(value) ?? null;
}

function consumeCapturedAbort(value: unknown): AbortBinding | null {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return null;
  const binding = capturedAbortRequests.get(value);
  if (binding === undefined) return null;
  capturedAbortRequests.delete(value);
  return binding;
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
  if (!manifest.ok || plan.validated_plan.run_id !== manifest.ledger.run_id
    || plan.validated_plan.plan_hash !== manifest.ledger.plan_hash) return null;
  return Object.freeze({ snapshot: read.snapshot, plan: plan.validated_plan, ledger: manifest.ledger, manifest: manifest.validated_manifest });
}

function matchesBinding(binding: AbortBinding, inspected: InspectedStore): boolean {
  return binding.validated_plan.run_id === inspected.plan.run_id
    && binding.validated_plan.plan_hash === inspected.plan.plan_hash
    && binding.subject.source_boundary_sequence === inspected.ledger.sequence
    && binding.subject.source_boundary_head_hash === inspected.ledger.head_hash
    && binding.subject.source_manifest_hash === inspected.manifest.manifest_hash
    && binding.subject.current_fence_epoch === inspected.ledger.state.current_fence_epoch
    && sameRef(binding.subject.current_attempt_event_ref, inspected.ledger.state.current_attempt_event_ref)
    && sameRef(binding.subject.run_owner_lease_event_ref, inspected.ledger.state.active_run_owner?.lease_event_ref ?? null);
}

function ownerRefs(state: RuntimeStateV04): readonly LedgerRef[] | null {
  if (state.active_run_owner?.active !== true) return null;
  const refs = [state.active_run_owner.lease_event_ref,
    ...state.subordinate_owner_leases.filter((row) => row.active).map((row) => row.lease_event_ref)];
  return Object.freeze(refs.map((row) => Object.freeze({ ...row })));
}

function maximumElapsed(ledger: ValidatedRuntimeLedgerV04): number {
  return ledger.events.reduce((maximum, row) => row.event_type === "run.clock-observed"
    ? Math.max(maximum, row.payload.elapsed_ms) : maximum, 0);
}

function event(
  prior: readonly RuntimeEventV04Value[], eventId: string, recordedAt: string,
  eventType: RuntimeEventV04Value["event_type"], source: RuntimeEventV04Value["source"],
  authorityRef: string | null, riskTier: RuntimeEventV04Value["risk_tier"], payload: unknown,
): RuntimeEventV04Value | null {
  const preimage = {
    schema_version: "0.4" as const, event_id: eventId, run_id: prior[0]!.run_id,
    sequence: prior.length + 1, recorded_at: recordedAt, event_type: eventType,
    source, authority_ref: authorityRef, risk_tier: riskTier, related_ids: [],
    previous_event_hash: prior.at(-1)!.event_hash, payload,
  };
  const parsed = RuntimeEventV04.safeParse({ ...preimage, event_hash: hashCanonical(preimage) });
  return parsed.success ? parsed.data : null;
}

function appendLedgerBytes(source: Uint8Array, events: readonly RuntimeEventV04Value[]): Uint8Array {
  const tail = new TextEncoder().encode(events.map((row) => `${JSON.stringify(row)}\n`).join(""));
  const joined = new Uint8Array(source.byteLength + tail.byteLength);
  joined.set(source); joined.set(tail, source.byteLength);
  return joined;
}

function nextState(inspected: InspectedStore, events: readonly RuntimeEventV04Value[]) {
  const ledgerBytes = appendLedgerBytes(inspected.snapshot.ledger_bytes, events);
  const checked = inspectRuntimeLedgerV04(ledgerBytes);
  if (!checked.ok) return null;
  const manifest = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: inspected.manifest.created_at,
    captured_files: capturedFilesWithLedger(inspected.snapshot, ledgerBytes),
  });
  return manifest.ok ? Object.freeze({ ledger_bytes: ledgerBytes, manifest_bytes: manifest.bytes }) : null;
}

function failure(classification: "NOT_COMMITTED" | "REQUEST_COMMITTED_ABORT_NOT_COMMITTED" | "OUTCOME_UNKNOWN", error: Extract<RuntimeAbortWriteResultV04, { ok: false }>["error"], request?: LedgerRef): RuntimeAbortWriteResultV04 {
  return Object.freeze({ ok: false, classification, error, ...(request === undefined ? {} : { request_event_ref: request }) });
}

async function commitFence(
  session: RuntimeFileStoreSessionV04,
  inspected: InspectedStore,
  requestRef: LedgerRef,
  authorityRef: string,
  riskTier: RuntimeEventV04Value["risk_tier"],
  recordedAt: string,
  fenceEventId: string,
): Promise<RuntimeAbortWriteResultV04> {
  const reduced = reduceRuntimeEventPrefixV04(inspected.ledger.events);
  const request = inspected.ledger.events.at(-1);
  if (!reduced.ok || request?.event_type !== "control.abort-requested"
    || !sameRef(refOf(request), requestRef) || request.authority_ref !== authorityRef
    || reduced.state.current_attempt_event_ref === null
    || reduced.state.current_fence_epoch >= Number.MAX_SAFE_INTEGER) {
    return failure("REQUEST_COMMITTED_ABORT_NOT_COMMITTED", "RUNTIME_ABORT_NOT_COMMITTED", requestRef);
  }
  const owners = ownerRefs(reduced.state);
  if (owners === null) return failure("REQUEST_COMMITTED_ABORT_NOT_COMMITTED", "RUNTIME_ABORT_NOT_COMMITTED", requestRef);
  const fence = event(inspected.ledger.events, fenceEventId, recordedAt, "run.fence-advanced",
    "policy-enforcement-point", authorityRef, riskTier, {
      previous_fence_epoch: reduced.state.current_fence_epoch,
      fence_epoch: reduced.state.current_fence_epoch + 1,
      reason: "abort-request",
      evidence_refs: [requestRef],
      attempt_ref: reduced.state.current_attempt_event_ref,
      owner_lease_refs: owners,
    });
  const next = fence === null ? null : nextState(inspected, [fence]);
  if (fence === null || next === null) return failure("REQUEST_COMMITTED_ABORT_NOT_COMMITTED", "RUNTIME_ABORT_NOT_COMMITTED", requestRef);
  const committed = await commitRuntimeFileStoreSessionV04(session, {
    expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
    expected_manifest_hash: inspected.manifest.manifest_hash,
    next_ledger_bytes: next.ledger_bytes,
    next_manifest_bytes: next.manifest_bytes,
  });
  if (!committed.ok) return committed.classification === "OUTCOME_UNKNOWN"
    ? failure("OUTCOME_UNKNOWN", "RUNTIME_ABORT_OUTCOME_UNKNOWN")
    : failure("REQUEST_COMMITTED_ABORT_NOT_COMMITTED", "RUNTIME_ABORT_NOT_COMMITTED", requestRef);
  return Object.freeze({ ok: true, classification: "COMMITTED", request_event_ref: requestRef,
    fence_event_ref: refOf(fence), ledger_bytes_hash: committed.ledger_bytes_hash, manifest_hash: committed.manifest_hash });
}

export async function abortRuntimeControlV04(store: CapturedRuntimeFileStoreV04, input: unknown): Promise<RuntimeAbortWriteResultV04> {
  if (!exactPlainObject(input, ["captured_request", "observation", "request_event_id", "fence_event_id"]))
    return failure("NOT_COMMITTED", "RUNTIME_ABORT_INPUT_INVALID");
  const parsed = AbortWriteInputV04.safeParse(input);
  if (!parsed.success) return failure("NOT_COMMITTED", "RUNTIME_ABORT_INPUT_INVALID");
  const binding = inspectCapturedAbort(parsed.data.captured_request);
  if (binding === null) return failure("NOT_COMMITTED", "RUNTIME_ABORT_AUTHORIZATION_INVALID");
  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) return opened.error === "RUNTIME_FILE_STORE_POISONED"
    ? failure("OUTCOME_UNKNOWN", "RUNTIME_ABORT_OUTCOME_UNKNOWN")
    : failure("NOT_COMMITTED", "RUNTIME_ABORT_PREFIX_INVALID");
  try {
    const inspected = inspectStore(opened.session);
    if (inspected === null || !matchesBinding(binding, inspected)) {
      return failure("NOT_COMMITTED", "RUNTIME_ABORT_AUTHORIZATION_INVALID");
    }
    const facts = consumeRuntimeClockObservationV04(parsed.data.observation);
    if (facts === null
      || Date.parse(facts.observed_at) > Date.parse(binding.expires_at)
      || Date.parse(facts.observed_at) < Date.parse(inspected.ledger.events.at(-1)!.recorded_at)
      || facts.elapsed_ms < maximumElapsed(inspected.ledger)) {
      return failure("NOT_COMMITTED", "RUNTIME_ABORT_AUTHORIZATION_INVALID");
    }
    const reduced = reduceRuntimeEventPrefixV04(inspected.ledger.events);
    const owners = reduced.ok ? ownerRefs(reduced.state) : null;
    if (!reduced.ok || reduced.state.state !== "running" || reduced.state.in_flight_action_ids.length !== 0 || owners === null)
      return failure("NOT_COMMITTED", "RUNTIME_ABORT_REFUSED");
    const request = event(inspected.ledger.events, parsed.data.request_event_id, facts.observed_at,
      "control.abort-requested", "operator", binding.authority_ref, binding.approved_risk_tier, {
        request_id: binding.request_id,
        requested_by: "operator",
        reason_code: "operator-requested",
        policy_decision_ref: null,
        evidence_refs: owners.slice(1),
      });
    const next = request === null ? null : nextState(inspected, [request]);
    if (request === null || next === null || consumeCapturedAbort(parsed.data.captured_request) === null)
      return failure("NOT_COMMITTED", "RUNTIME_ABORT_AUTHORIZATION_INVALID");
    const committed = await commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
      expected_manifest_hash: inspected.manifest.manifest_hash,
      next_ledger_bytes: next.ledger_bytes,
      next_manifest_bytes: next.manifest_bytes,
    });
    if (!committed.ok) return committed.classification === "OUTCOME_UNKNOWN"
      ? failure("OUTCOME_UNKNOWN", "RUNTIME_ABORT_OUTCOME_UNKNOWN")
      : failure("NOT_COMMITTED", "RUNTIME_ABORT_NOT_COMMITTED");
    const after = inspectStore(opened.session);
    if (after === null) return failure("REQUEST_COMMITTED_ABORT_NOT_COMMITTED", "RUNTIME_ABORT_NOT_COMMITTED", refOf(request));
    return commitFence(opened.session, after, refOf(request), binding.authority_ref,
      binding.approved_risk_tier, facts.observed_at, parsed.data.fence_event_id);
  } finally { await closeRuntimeFileStoreSessionV04(opened.session); }
}

export async function continuePendingAbortRuntimeControlV04(store: CapturedRuntimeFileStoreV04, input: unknown): Promise<RuntimeAbortWriteResultV04> {
  if (!exactPlainObject(input, ["pending_request_event_ref", "observation", "fence_event_id"]))
    return failure("NOT_COMMITTED", "RUNTIME_ABORT_INPUT_INVALID");
  const parsed = ContinueAbortInputV04.safeParse(input);
  if (!parsed.success) return failure("NOT_COMMITTED", "RUNTIME_ABORT_INPUT_INVALID");
  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) return opened.error === "RUNTIME_FILE_STORE_POISONED"
    ? failure("OUTCOME_UNKNOWN", "RUNTIME_ABORT_OUTCOME_UNKNOWN")
    : failure("NOT_COMMITTED", "RUNTIME_ABORT_PREFIX_INVALID");
  try {
    const inspected = inspectStore(opened.session);
    if (inspected === null || inspected.ledger.sequence !== parsed.data.pending_request_event_ref.ledger_sequence
      || inspected.ledger.head_hash !== parsed.data.pending_request_event_ref.event_hash)
      return failure("NOT_COMMITTED", "RUNTIME_ABORT_PREFIX_INVALID");
    const request = inspected.ledger.events.at(-1);
    const facts = consumeRuntimeClockObservationV04(parsed.data.observation);
    if (request?.event_type !== "control.abort-requested" || request.authority_ref === null || facts === null
      || Date.parse(facts.observed_at) < Date.parse(request.recorded_at)
      || facts.elapsed_ms < maximumElapsed(inspected.ledger))
      return failure("REQUEST_COMMITTED_ABORT_NOT_COMMITTED", "RUNTIME_ABORT_NOT_COMMITTED", parsed.data.pending_request_event_ref);
    return commitFence(opened.session, inspected, parsed.data.pending_request_event_ref,
      request.authority_ref, request.risk_tier, facts.observed_at, parsed.data.fence_event_id);
  } finally { await closeRuntimeFileStoreSessionV04(opened.session); }
}
