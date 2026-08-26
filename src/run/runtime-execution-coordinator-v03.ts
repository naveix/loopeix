import { z } from "zod";

import { Hash } from "../schema/scalars.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import {
  admitRuntimeActionV03,
  type AdmitRuntimeActionV03Error,
  type RuntimeActionAdmissionRequestV03,
} from "./runtime-action-admission-v03.js";
import {
  captureEffectDispatchBrokerV01,
  dispatchAdmittedActionV01,
  type DispatchAdmittedActionV01Error,
  type EffectDispatchInvocationV01,
} from "./runtime-effect-dispatch-broker-v01.js";
import {
  reconcileRuntimeObservationIntegrityV03,
  type ReconcileRuntimeObservationIntegrityV03Error,
} from "./runtime-observation-integrity-v03.js";
import {
  claimRuntimeTerminationCapabilityV03,
  terminateRuntimeActionV03,
  type CapturedRuntimeTerminationCapabilityV03,
  type TerminateRuntimeActionV03Result,
} from "./runtime-termination-v03.js";
import {
  appendRuntimeEventV03,
  closeRuntimeWriteSessionV03,
  createRuntimeEventDraftV03,
  inspectRuntimeWriteSessionV03ForDispatch,
  poisonRuntimeWriteSessionV03ForAdmission,
  verifyRuntimeWriteSessionTailReadbackV03,
  type RuntimeWriteSessionV03,
} from "./runtime-write-session-v03.js";

declare const runtimeExecutionCoordinatorBrandV03: unique symbol;
declare const capturedRuntimeEffectAdapterBrandV03: unique symbol;
declare const runtimeInvocationResultCustodyBrandV01: unique symbol;

export type RuntimeExecutionCoordinatorV03 = Readonly<{ [runtimeExecutionCoordinatorBrandV03]: never }>;
export type CapturedRuntimeEffectAdapterV03 = Readonly<{ [capturedRuntimeEffectAdapterBrandV03]: never }>;
export type RuntimeInvocationResultCustodyV01 = Readonly<{ [runtimeInvocationResultCustodyBrandV01]: never }>;

export type RuntimeEffectDispatchOutcomeV03 = Readonly<{ disposition: "NOT_STARTED" }>
  | Readonly<{ disposition: "DISPATCHED"; observation: unknown | null; result: unknown }>;

export type RuntimeEffectDispatchImplementationV03 = (
  invocation: EffectDispatchInvocationV01,
) => Promise<RuntimeEffectDispatchOutcomeV03>;

export type RuntimeExecutionCleanupStatusV03 = "OPEN" | "CLOSED" | "CLOSE_FAILED";
type LedgerRef = Readonly<{ ledger_sequence: number; event_hash: string }>;
type QuarantineTerminationResultV03 = TerminateRuntimeActionV03Result
  | Readonly<{ ok: false; error: "TERMINATION_COORDINATION_FAILED" }>;

export type CoordinateRuntimeActionV03Error = AdmitRuntimeActionV03Error
  | DispatchAdmittedActionV01Error
  | ReconcileRuntimeObservationIntegrityV03Error
  | "COORDINATOR_INVALID"
  | "COORDINATOR_CLOSED"
  | "RUNTIME_EFFECT_ADAPTER_INVALID"
  | "RUNTIME_EFFECT_ADAPTER_ALREADY_USED"
  | "RUNTIME_EFFECT_ADAPTER_BINDING_MISMATCH"
  | "RUNTIME_EFFECT_RESULT_INVALID"
  | "RUNTIME_EXECUTION_COORDINATION_FAILED"
  | "DISPATCH_NOT_STARTED_PENDING_RECONCILIATION"
  | "DISPATCH_OUTCOME_UNKNOWN_PENDING_RECONCILIATION"
  | "EXECUTION_START_INVALID_PENDING_RECONCILIATION"
  | "EXECUTION_START_NOT_COMMITTED_PENDING_RECONCILIATION"
  | "EXECUTION_START_OUTCOME_UNKNOWN_PENDING_RECONCILIATION"
  | "EXECUTION_START_READBACK_INVALID_PENDING_RECONCILIATION";

export type CoordinateRuntimeActionV03Result =
  | Readonly<{
      ok: true;
      disposition: "MATCHED";
      custody: RuntimeInvocationResultCustodyV01;
      adapter_invocation_id: string;
      action_admission_event_ref: LedgerRef;
      execution_started_event_ref: LedgerRef;
      observation_hash: string;
      cleanup_status: "OPEN";
    }>
  | Readonly<{
      ok: true;
      disposition: "QUARANTINED";
      reason_code: "unmatched-observation" | "authority-breach" | "capture-gap";
      observation_hash: string;
      rejection_event_ref: LedgerRef;
      quarantine_event_ref: LedgerRef;
      committed_manifest_hash: string;
      termination_result: QuarantineTerminationResultV03;
      cleanup_status: "CLOSED" | "CLOSE_FAILED";
    }>
  | Readonly<{
      ok: false;
      error: CoordinateRuntimeActionV03Error;
      cleanup_status: RuntimeExecutionCleanupStatusV03;
    }>;

export type TakeRuntimeInvocationResultV01Result = Readonly<{ ok: true; value: unknown }>
  | Readonly<{
      ok: false;
      error: "RESULT_CUSTODY_INVALID" | "RESULT_CUSTODY_BINDING_MISMATCH" | "RESULT_CUSTODY_ALREADY_TAKEN";
    }>;

type OwnedResult = Readonly<{ value: unknown }>;
type CoordinatorState = {
  session: RuntimeWriteSessionV03;
  tail: Promise<void>;
  closed: boolean;
  closeAttempted: boolean;
  closeStatus: "CLOSED" | "CLOSE_FAILED" | null;
  custodies: Set<RuntimeInvocationResultCustodyV01>;
  terminationCapability: CapturedRuntimeTerminationCapabilityV03;
};
type AdapterState = {
  normalized_dispatch_hash: string;
  adapter_ref: string;
  adapter_version_hash: string;
  adapter_profile_hash: string;
  adapter_invocation_id: string;
  dispatch: RuntimeEffectDispatchImplementationV03;
  used: boolean;
  callbackEntered: boolean;
  boundCoordinator: RuntimeExecutionCoordinatorV03 | null;
  pendingResult: OwnedResult | null;
};
type CustodyState = {
  coordinator: RuntimeExecutionCoordinatorV03;
  session: RuntimeWriteSessionV03;
  adapterInvocationId: string;
  actionAdmissionEventRef: LedgerRef;
  result: OwnedResult | null;
  used: boolean;
};

const coordinators = new WeakMap<RuntimeExecutionCoordinatorV03, CoordinatorState>();
const sessionCoordinators = new WeakMap<RuntimeWriteSessionV03, RuntimeExecutionCoordinatorV03>();
const adapters = new WeakMap<CapturedRuntimeEffectAdapterV03, AdapterState>();
const custodies = new WeakMap<RuntimeInvocationResultCustodyV01, CustodyState>();

const AdapterMetadata = z.object({
  normalized_dispatch_hash: Hash,
  adapter_ref: MachineIdV02,
  adapter_version_hash: Hash,
  adapter_profile_hash: Hash,
  adapter_invocation_id: MachineIdV02,
}).strict();
const RESULT_MAX_DEPTH = 32;
const RESULT_MAX_NODES = 10_000;
const RESULT_MAX_BYTES = 1_048_576;
const resultEncoder = new TextEncoder();

function exactDataRecord(input: unknown, expected: readonly string[]): Record<string, PropertyDescriptor> | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype || Object.getOwnPropertySymbols(input).length > 0) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (Object.keys(descriptors).sort().join("\u0000") !== [...expected].sort().join("\u0000")) return null;
    return expected.every((key) => {
      const descriptor = descriptors[key];
      return descriptor !== undefined && "value" in descriptor && descriptor.get === undefined
        && descriptor.set === undefined && descriptor.enumerable === true;
    }) ? descriptors : null;
  } catch {
    return null;
  }
}

function captureOwnedResult(input: unknown): OwnedResult | null {
  let nodes = 0;
  const visit = (value: unknown, depth: number): unknown | undefined => {
    nodes += 1;
    if (nodes > RESULT_MAX_NODES || depth > RESULT_MAX_DEPTH) return undefined;
    if (value === null || typeof value === "string" || typeof value === "boolean") return value;
    if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
    if (typeof value !== "object") return undefined;
    try {
      if (Object.getOwnPropertySymbols(value).length > 0) return undefined;
      if (Array.isArray(value)) {
        if (Object.getPrototypeOf(value) !== Array.prototype) return undefined;
        const descriptors = Object.getOwnPropertyDescriptors(value);
        const keys = Object.keys(descriptors).filter((key) => key !== "length");
        if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) return undefined;
        const captured: unknown[] = [];
        for (let index = 0; index < value.length; index += 1) {
          const descriptor = descriptors[String(index)];
          if (descriptor === undefined || !("value" in descriptor) || descriptor.get !== undefined
            || descriptor.set !== undefined || descriptor.enumerable !== true) return undefined;
          const child = visit(descriptor.value, depth + 1);
          if (child === undefined) return undefined;
          captured.push(child);
        }
        return Object.freeze(captured);
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) return undefined;
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const captured: Record<string, unknown> = {};
      for (const key of Object.keys(descriptors)) {
        const descriptor = descriptors[key]!;
        if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined
          || descriptor.enumerable !== true) return undefined;
        const child = visit(descriptor.value, depth + 1);
        if (child === undefined) return undefined;
        Object.defineProperty(captured, key, {
          value: child, enumerable: true, configurable: false, writable: false,
        });
      }
      return Object.freeze(captured);
    } catch {
      return undefined;
    }
  };
  const value = visit(input, 0);
  if (value === undefined) return null;
  try {
    if (resultEncoder.encode(JSON.stringify(value)).byteLength > RESULT_MAX_BYTES) return null;
  } catch {
    return null;
  }
  return Object.freeze({ value });
}

function destroyCustodies(state: CoordinatorState): void {
  for (const custody of state.custodies) {
    const custodyState = custodies.get(custody);
    if (custodyState !== undefined) {
      custodyState.result = null;
      custodyState.used = true;
    }
  }
  state.custodies.clear();
}

async function closeState(state: CoordinatorState): Promise<"CLOSED" | "CLOSE_FAILED"> {
  if (state.closeAttempted) return state.closeStatus ?? "CLOSE_FAILED";
  state.closeAttempted = true;
  state.closed = true;
  destroyCustodies(state);
  let closed = false;
  try {
    closed = await closeRuntimeWriteSessionV03(state.session);
  } catch {
    closed = false;
  }
  state.closeStatus = closed ? "CLOSED" : "CLOSE_FAILED";
  if (closed) sessionCoordinators.delete(state.session);
  return state.closeStatus;
}

async function invokeAdapter(
  state: AdapterState,
  invocation: EffectDispatchInvocationV01,
): Promise<Readonly<{ disposition: "NOT_STARTED" }>
  | Readonly<{ disposition: "DISPATCHED"; observation: unknown | null }>> {
  if (state.callbackEntered) throw new Error("runtime effect adapter replay");
  state.callbackEntered = true;
  state.pendingResult = null;
  const outcome = await state.dispatch(invocation);
  const notStarted = exactDataRecord(outcome, ["disposition"]);
  if (notStarted !== null && notStarted.disposition!.value === "NOT_STARTED") {
    return Object.freeze({ disposition: "NOT_STARTED" });
  }
  const dispatched = exactDataRecord(outcome, ["disposition", "observation", "result"]);
  if (dispatched === null || dispatched.disposition!.value !== "DISPATCHED") {
    throw new Error("runtime effect outcome invalid");
  }
  const result = captureOwnedResult(dispatched.result!.value);
  if (result === null) throw new Error("runtime effect result invalid");
  state.pendingResult = result;
  return Object.freeze({ disposition: "DISPATCHED", observation: dispatched.observation!.value as unknown | null });
}

async function appendExecutionStarted(
  state: CoordinatorState,
  admissionRef: LedgerRef,
  adapterInvocationId: string,
): Promise<Readonly<{ ok: true; event_ref: LedgerRef }> | Readonly<{ ok: false; error: CoordinateRuntimeActionV03Error }>> {
  const inspected = await inspectRuntimeWriteSessionV03ForDispatch(state.session);
  if (!inspected.ok) return Object.freeze({ ok: false, error: "EXECUTION_START_INVALID_PENDING_RECONCILIATION" });
  const admission = inspected.snapshot.events.find((event) => (
    event.sequence === admissionRef.ledger_sequence && event.event_hash === admissionRef.event_hash
  ));
  const payload = typeof admission?.payload === "object" && admission.payload !== null
    ? admission.payload as Record<string, unknown> : null;
  const copied = [
    "action_proposal_id", "action_proposal_hash", "action_actor_ref", "action_actor_stable_identity_hash",
    "on_behalf_of_chain_hash", "repository_root_ref", "repository_base_ref_identity_hash",
    "repository_pre_state_hash", "authorized_change_set_hash", "normalized_dispatch_hash",
    "policy_action_kind", "action_approval_class",
  ] as const;
  const draft = admission?.event_type === "task.action-admitted" && payload !== null
    ? createRuntimeEventDraftV03({
        event_type: "task.execution-started",
        source: "adapter",
        authority_ref: null,
        risk_tier: admission.risk_tier,
        related_ids: [],
        payload: {
          action_id: payload.action_id,
          task_ref: payload.task_ref,
          admission_ref: admissionRef,
          adapter_invocation_id: adapterInvocationId,
          ...Object.fromEntries(copied.map((key) => [key, payload[key]])),
        },
      })
    : null;
  if (draft === null) return Object.freeze({ ok: false, error: "EXECUTION_START_INVALID_PENDING_RECONCILIATION" });
  const appended = await appendRuntimeEventV03(state.session, draft);
  if (!appended.ok) return Object.freeze({
    ok: false,
    error: appended.classification === "OUTCOME_UNKNOWN"
      ? "EXECUTION_START_OUTCOME_UNKNOWN_PENDING_RECONCILIATION"
      : "EXECUTION_START_NOT_COMMITTED_PENDING_RECONCILIATION",
  });
  const readback = await verifyRuntimeWriteSessionTailReadbackV03(state.session, {
    events: [{ event_type: "task.execution-started", event_ref: appended.event_ref }],
    manifest_hash: appended.manifest_hash,
  });
  return readback.ok
    ? Object.freeze({ ok: true, event_ref: appended.event_ref })
    : Object.freeze({ ok: false, error: "EXECUTION_START_READBACK_INVALID_PENDING_RECONCILIATION" });
}

async function terminateAfterQuarantine(
  state: CoordinatorState,
  quarantineRef: LedgerRef,
  actionAdmissionEventRef: LedgerRef,
  adapterInvocationId: string,
): Promise<QuarantineTerminationResultV03> {
  try {
    return await terminateRuntimeActionV03(state.session, state.terminationCapability, {
      trigger: "quarantine",
      trigger_event_ref: quarantineRef,
      action_admission_event_ref: actionAdmissionEventRef,
      adapter_invocation_id: adapterInvocationId,
    });
  } catch {
    await poisonRuntimeWriteSessionV03ForAdmission(state.session);
    return Object.freeze({ ok: false, error: "TERMINATION_COORDINATION_FAILED" });
  }
}

async function coordinateSerialized(
  coordinator: RuntimeExecutionCoordinatorV03,
  state: CoordinatorState,
  adapterState: AdapterState,
  request: RuntimeActionAdmissionRequestV03,
): Promise<CoordinateRuntimeActionV03Result> {
  if (state.closed) return Object.freeze({
    ok: false, error: "COORDINATOR_CLOSED", cleanup_status: state.closeStatus ?? "CLOSE_FAILED",
  });
  const admitted = await admitRuntimeActionV03(state.session, request);
  if (!admitted.ok) return Object.freeze({
    ok: false, error: admitted.error, cleanup_status: await closeState(state),
  });
  const broker = captureEffectDispatchBrokerV01({
    normalized_dispatch_hash: adapterState.normalized_dispatch_hash,
    adapter_ref: adapterState.adapter_ref,
    adapter_version_hash: adapterState.adapter_version_hash,
    adapter_profile_hash: adapterState.adapter_profile_hash,
    adapter_invocation_id: adapterState.adapter_invocation_id,
    dispatch: (invocation: EffectDispatchInvocationV01) => invokeAdapter(adapterState, invocation),
  });
  if (broker === null) {
    await poisonRuntimeWriteSessionV03ForAdmission(state.session);
    return Object.freeze({ ok: false, error: "RUNTIME_EFFECT_ADAPTER_INVALID", cleanup_status: await closeState(state) });
  }
  const dispatched = await dispatchAdmittedActionV01(state.session, broker, admitted.permit);
  if (!dispatched.ok) {
    adapterState.pendingResult = null;
    const error = dispatched.error === "DISPATCH_NOT_STARTED"
      ? "DISPATCH_NOT_STARTED_PENDING_RECONCILIATION" as const
      : dispatched.error === "DISPATCH_OUTCOME_UNKNOWN"
        ? "DISPATCH_OUTCOME_UNKNOWN_PENDING_RECONCILIATION" as const
        : dispatched.error;
    return Object.freeze({ ok: false, error, cleanup_status: await closeState(state) });
  }
  const started = await appendExecutionStarted(state, admitted.action_admission_event_ref, dispatched.adapter_invocation_id);
  if (!started.ok) {
    adapterState.pendingResult = null;
    await poisonRuntimeWriteSessionV03ForAdmission(state.session);
    return Object.freeze({ ok: false, error: started.error, cleanup_status: await closeState(state) });
  }
  const reconciled = await reconcileRuntimeObservationIntegrityV03(
    state.session, broker, { adapter_invocation_id: dispatched.adapter_invocation_id },
  );
  if (!reconciled.ok) {
    adapterState.pendingResult = null;
    await poisonRuntimeWriteSessionV03ForAdmission(state.session);
    return Object.freeze({ ok: false, error: reconciled.error, cleanup_status: await closeState(state) });
  }
  if (reconciled.disposition === "QUARANTINED") {
    adapterState.pendingResult = null;
    const terminationResult = await terminateAfterQuarantine(
      state,
      reconciled.quarantine_event_ref,
      admitted.action_admission_event_ref,
      dispatched.adapter_invocation_id,
    );
    return Object.freeze({
      ...reconciled,
      termination_result: terminationResult,
      cleanup_status: await closeState(state),
    });
  }
  const owned = adapterState.pendingResult;
  adapterState.pendingResult = null;
  if (owned === null) {
    await poisonRuntimeWriteSessionV03ForAdmission(state.session);
    return Object.freeze({ ok: false, error: "RUNTIME_EFFECT_RESULT_INVALID", cleanup_status: await closeState(state) });
  }
  const custody = Object.freeze({}) as RuntimeInvocationResultCustodyV01;
  custodies.set(custody, {
    coordinator, session: state.session, adapterInvocationId: dispatched.adapter_invocation_id,
    actionAdmissionEventRef: admitted.action_admission_event_ref, result: owned, used: false,
  });
  state.custodies.add(custody);
  return Object.freeze({
    ok: true,
    disposition: "MATCHED",
    custody,
    adapter_invocation_id: dispatched.adapter_invocation_id,
    action_admission_event_ref: admitted.action_admission_event_ref,
    execution_started_event_ref: started.event_ref,
    observation_hash: reconciled.observation_hash,
    cleanup_status: "OPEN",
  });
}

export async function captureRuntimeExecutionCoordinatorV03(
  session: RuntimeWriteSessionV03,
  terminationCapability: CapturedRuntimeTerminationCapabilityV03,
): Promise<RuntimeExecutionCoordinatorV03 | null> {
  if (sessionCoordinators.has(session)) return null;
  const inspected = await inspectRuntimeWriteSessionV03ForDispatch(session);
  if (!inspected.ok || sessionCoordinators.has(session)) return null;
  const claimedTerminationCapability = claimRuntimeTerminationCapabilityV03(terminationCapability);
  if (claimedTerminationCapability === null) return null;
  const coordinator = Object.freeze({}) as RuntimeExecutionCoordinatorV03;
  coordinators.set(coordinator, {
    session,
    tail: Promise.resolve(),
    closed: false,
    closeAttempted: false,
    closeStatus: null,
    custodies: new Set(),
    terminationCapability: claimedTerminationCapability,
  });
  sessionCoordinators.set(session, coordinator);
  return coordinator;
}

export function captureRuntimeEffectAdapterV03(input: unknown): CapturedRuntimeEffectAdapterV03 | null {
  const keys = [
    "normalized_dispatch_hash", "adapter_ref", "adapter_version_hash", "adapter_profile_hash",
    "adapter_invocation_id", "dispatch",
  ] as const;
  const descriptors = exactDataRecord(input, keys);
  if (descriptors === null) return null;
  const parsed = AdapterMetadata.safeParse(Object.fromEntries(
    keys.filter((key) => key !== "dispatch").map((key) => [key, descriptors[key]!.value]),
  ));
  const dispatch = descriptors.dispatch!.value;
  if (!parsed.success || typeof dispatch !== "function") return null;
  const adapter = Object.freeze({}) as CapturedRuntimeEffectAdapterV03;
  adapters.set(adapter, {
    ...parsed.data,
    dispatch: dispatch as RuntimeEffectDispatchImplementationV03,
    used: false, callbackEntered: false, boundCoordinator: null, pendingResult: null,
  });
  return adapter;
}

export async function coordinateRuntimeActionV03(
  coordinator: RuntimeExecutionCoordinatorV03,
  adapter: CapturedRuntimeEffectAdapterV03,
  admissionRequest: RuntimeActionAdmissionRequestV03,
): Promise<CoordinateRuntimeActionV03Result> {
  const state = coordinators.get(coordinator);
  if (state === undefined) return Object.freeze({
    ok: false, error: "COORDINATOR_INVALID", cleanup_status: "CLOSE_FAILED",
  });
  if (state.closed) return Object.freeze({
    ok: false, error: "COORDINATOR_CLOSED", cleanup_status: state.closeStatus ?? "CLOSE_FAILED",
  });
  const adapterState = adapters.get(adapter);
  if (adapterState === undefined) return Object.freeze({
    ok: false, error: "RUNTIME_EFFECT_ADAPTER_INVALID", cleanup_status: "OPEN",
  });
  if (adapterState.used) return Object.freeze({
    ok: false, error: "RUNTIME_EFFECT_ADAPTER_ALREADY_USED", cleanup_status: "OPEN",
  });
  if (adapterState.boundCoordinator !== null && adapterState.boundCoordinator !== coordinator) return Object.freeze({
    ok: false, error: "RUNTIME_EFFECT_ADAPTER_BINDING_MISMATCH", cleanup_status: "OPEN",
  });
  adapterState.used = true;
  adapterState.boundCoordinator = coordinator;
  let result: CoordinateRuntimeActionV03Result | undefined;
  const operation = state.tail.then(async () => {
    result = await coordinateSerialized(coordinator, state, adapterState, admissionRequest);
  });
  state.tail = operation.then(() => undefined, () => undefined);
  try {
    await operation;
  } catch {
    adapterState.pendingResult = null;
    await poisonRuntimeWriteSessionV03ForAdmission(state.session);
    return Object.freeze({
      ok: false, error: "RUNTIME_EXECUTION_COORDINATION_FAILED", cleanup_status: await closeState(state),
    });
  }
  return result ?? Object.freeze({
    ok: false, error: "RUNTIME_EXECUTION_COORDINATION_FAILED", cleanup_status: await closeState(state),
  });
}

function captureCustodyBinding(input: unknown): Readonly<{
  adapter_invocation_id: string;
  action_admission_event_ref: LedgerRef;
}> | null {
  const top = exactDataRecord(input, ["adapter_invocation_id", "action_admission_event_ref"]);
  if (top === null) return null;
  const nested = exactDataRecord(top.action_admission_event_ref!.value, ["ledger_sequence", "event_hash"]);
  if (nested === null) return null;
  const invocation = MachineIdV02.safeParse(top.adapter_invocation_id!.value);
  const sequence = nested.ledger_sequence!.value;
  const hash = Hash.safeParse(nested.event_hash!.value);
  if (!invocation.success || !Number.isSafeInteger(sequence) || (sequence as number) <= 0 || !hash.success) return null;
  return Object.freeze({
    adapter_invocation_id: invocation.data,
    action_admission_event_ref: Object.freeze({ ledger_sequence: sequence as number, event_hash: hash.data }),
  });
}

export function takeRuntimeInvocationResultV01(
  custody: RuntimeInvocationResultCustodyV01,
  coordinator: RuntimeExecutionCoordinatorV03,
  bindingInput: unknown,
): TakeRuntimeInvocationResultV01Result {
  const state = custodies.get(custody);
  if (state === undefined) return Object.freeze({ ok: false, error: "RESULT_CUSTODY_INVALID" });
  if (state.used || state.result === null) return Object.freeze({ ok: false, error: "RESULT_CUSTODY_ALREADY_TAKEN" });
  const owned = state.result;
  state.result = null;
  state.used = true;
  coordinators.get(state.coordinator)?.custodies.delete(custody);
  const binding = captureCustodyBinding(bindingInput);
  const coordinatorState = coordinators.get(coordinator);
  if (binding === null || state.coordinator !== coordinator || coordinatorState === undefined
    || coordinatorState.session !== state.session
    || binding.adapter_invocation_id !== state.adapterInvocationId
    || binding.action_admission_event_ref.ledger_sequence !== state.actionAdmissionEventRef.ledger_sequence
    || binding.action_admission_event_ref.event_hash !== state.actionAdmissionEventRef.event_hash) {
    return Object.freeze({ ok: false, error: "RESULT_CUSTODY_BINDING_MISMATCH" });
  }
  return Object.freeze({ ok: true, value: owned.value });
}

export async function closeRuntimeExecutionCoordinatorV03(
  coordinator: RuntimeExecutionCoordinatorV03,
): Promise<Readonly<{ ok: true; cleanup_status: "CLOSED" | "CLOSE_FAILED" }>
  | Readonly<{ ok: false; error: "COORDINATOR_INVALID" }>> {
  const state = coordinators.get(coordinator);
  if (state === undefined) return Object.freeze({ ok: false, error: "COORDINATOR_INVALID" });
  let status: "CLOSED" | "CLOSE_FAILED" = "CLOSE_FAILED";
  const operation = state.tail.then(async () => { status = await closeState(state); });
  state.tail = operation.then(() => undefined, () => undefined);
  try {
    await operation;
  } catch {
    status = "CLOSE_FAILED";
  }
  return Object.freeze({ ok: true, cleanup_status: status });
}
