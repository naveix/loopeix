import { z } from "zod";

import { hashCanonical } from "../hash.js";
import { Hash } from "../schema/scalars.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import {
  consumeDispatchPermitV01,
  type DispatchPermitV01,
} from "./runtime-action-admission-v03.js";
import {
  inspectRuntimeWriteSessionV03ForDispatch,
  poisonRuntimeWriteSessionV03ForAdmission,
  type InspectRuntimeWriteSessionV03ForDispatchError,
  type RuntimeWriteSessionV03,
} from "./runtime-write-session-v03.js";

declare const capturedEffectDispatchBrokerBrandV01: unique symbol;

export type CapturedEffectDispatchBrokerV01 = Readonly<{
  [capturedEffectDispatchBrokerBrandV01]: never;
}>;

export type EffectDispatchInvocationV01 = Readonly<{
  adapter_invocation_id: string;
  action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  normalized_dispatch_hash: string;
  adapter_ref: string;
  adapter_version_hash: string;
  adapter_profile_hash: string;
}>;

export type EffectDispatchImplementationV01 = (
  invocation: EffectDispatchInvocationV01,
) => Promise<Readonly<{ disposition: "DISPATCHED"; observation: unknown | null }>
  | Readonly<{ disposition: "NOT_STARTED" }>>;

export type DispatchAdmittedActionV01Error = InspectRuntimeWriteSessionV03ForDispatchError
  | "CAPTURED_BROKER_INVALID"
  | "DISPATCH_PERMIT_INVALID"
  | "DISPATCH_PERMIT_SESSION_MISMATCH"
  | "DISPATCH_BINDING_MISMATCH"
  | "DISPATCH_PERMIT_ALREADY_USED"
  | "DISPATCH_NOT_STARTED"
  | "DISPATCH_OUTCOME_UNKNOWN";

export type DispatchAdmittedActionV01Result = Readonly<{
  ok: true;
  disposition: "DISPATCHED";
  adapter_invocation_id: string;
}> | Readonly<{
  ok: false;
  error: DispatchAdmittedActionV01Error;
}>;

type CapturedObservationState = Readonly<{
  session: RuntimeWriteSessionV03;
  adapter_invocation_id: string;
  action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  normalized_dispatch_hash: string;
  adapter_identity_hash: string;
  adapter_profile_hash: string;
  observation: unknown | null;
}>;

type BrokerState = {
  normalized_dispatch_hash: string;
  adapter_ref: string;
  adapter_version_hash: string;
  adapter_profile_hash: string;
  adapter_invocation_id: string;
  dispatch: EffectDispatchImplementationV01;
  entered: boolean;
  captured_observation: CapturedObservationState | null;
  observation_taken: boolean;
};

const brokerStates = new WeakMap<CapturedEffectDispatchBrokerV01, BrokerState>();

const BrokerDescriptor = z.object({
  normalized_dispatch_hash: Hash,
  adapter_ref: MachineIdV02,
  adapter_version_hash: Hash,
  adapter_profile_hash: Hash,
  adapter_invocation_id: MachineIdV02,
}).strict();

const observationEncoder = new TextEncoder();

function captureObservation(value: unknown): unknown | null | undefined {
  let nodes = 0;
  const visit = (candidate: unknown, depth: number): unknown | undefined => {
    nodes += 1;
    if (nodes > 2_048 || depth > 16) return undefined;
    if (candidate === null || typeof candidate === "string" || typeof candidate === "boolean") return candidate;
    if (typeof candidate === "number") return Number.isFinite(candidate) ? candidate : undefined;
    if (typeof candidate !== "object" || Object.getOwnPropertySymbols(candidate).length > 0) return undefined;
    if (Array.isArray(candidate)) {
      if (Object.getPrototypeOf(candidate) !== Array.prototype) return undefined;
      const descriptors = Object.getOwnPropertyDescriptors(candidate);
      const keys = Object.keys(descriptors).filter((key) => key !== "length");
      if (keys.length !== candidate.length || keys.some((key, index) => key !== String(index)
        || !descriptors[key]?.enumerable || descriptors[key]?.get !== undefined || descriptors[key]?.set !== undefined)) return undefined;
      const copy: unknown[] = [];
      for (let index = 0; index < candidate.length; index += 1) {
        const captured = visit(descriptors[String(index)]!.value, depth + 1);
        if (captured === undefined) return undefined;
        copy.push(captured);
      }
      return Object.freeze(copy);
    }
    const prototype = Object.getPrototypeOf(candidate);
    if (prototype !== Object.prototype && prototype !== null) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    const copy: Record<string, unknown> = {};
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key]!;
      if (!descriptor.enumerable || descriptor.get !== undefined || descriptor.set !== undefined) return undefined;
      const captured = visit(descriptor.value, depth + 1);
      if (captured === undefined) return undefined;
      Object.defineProperty(copy, key, {
        value: captured,
        enumerable: true,
        configurable: false,
        writable: false,
      });
    }
    return Object.freeze(copy);
  };
  const captured = visit(value, 0);
  if (captured === undefined) return undefined;
  try {
    return observationEncoder.encode(JSON.stringify(captured)).byteLength <= 65_536 ? captured : undefined;
  } catch {
    return undefined;
  }
}

export function captureEffectDispatchBrokerV01(input: unknown): CapturedEffectDispatchBrokerV01 | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype) return null;
    const ownKeys = Reflect.ownKeys(input);
    if (ownKeys.some((key) => typeof key === "symbol")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const expected = ["adapter_invocation_id", "adapter_profile_hash", "adapter_ref", "adapter_version_hash", "dispatch", "normalized_dispatch_hash"];
    if ((ownKeys as string[]).sort().join("\u0000") !== expected.join("\u0000")
      || expected.some((key) => descriptors[key]?.get !== undefined || descriptors[key]?.set !== undefined
        || descriptors[key]?.enumerable !== true || !("value" in descriptors[key]!))) return null;
    const parsed = BrokerDescriptor.safeParse({
      normalized_dispatch_hash: descriptors.normalized_dispatch_hash!.value,
      adapter_ref: descriptors.adapter_ref!.value,
      adapter_version_hash: descriptors.adapter_version_hash!.value,
      adapter_profile_hash: descriptors.adapter_profile_hash!.value,
      adapter_invocation_id: descriptors.adapter_invocation_id!.value,
    });
    const dispatch = descriptors.dispatch!.value;
    if (!parsed.success || typeof dispatch !== "function") return null;
    const broker = Object.freeze({}) as CapturedEffectDispatchBrokerV01;
    brokerStates.set(broker, {
      ...parsed.data, dispatch: dispatch as EffectDispatchImplementationV01,
      entered: false, captured_observation: null, observation_taken: false,
    });
    return broker;
  } catch {
    return null;
  }
}

export type TakeCapturedEffectObservationV01Result = Readonly<{
  ok: true;
  binding: Readonly<{
    action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
    normalized_dispatch_hash: string;
    adapter_identity_hash: string;
    adapter_profile_hash: string;
  }>;
  observation: unknown | null;
}> | Readonly<{
  ok: false;
  error: "EFFECT_OBSERVATION_INVALID" | "EFFECT_OBSERVATION_BINDING_MISMATCH" | "EFFECT_OBSERVATION_ALREADY_TAKEN";
}>;

export function takeCapturedEffectObservationV01(
  broker: CapturedEffectDispatchBrokerV01,
  session: RuntimeWriteSessionV03,
  adapterInvocationId: string,
): TakeCapturedEffectObservationV01Result {
  const state = brokerStates.get(broker);
  if (state === undefined) return Object.freeze({ ok: false, error: "EFFECT_OBSERVATION_INVALID" });
  const captured = state.captured_observation;
  if (captured === null || captured.session !== session || captured.adapter_invocation_id !== adapterInvocationId) {
    return Object.freeze({ ok: false, error: "EFFECT_OBSERVATION_BINDING_MISMATCH" });
  }
  if (state.observation_taken) return Object.freeze({ ok: false, error: "EFFECT_OBSERVATION_ALREADY_TAKEN" });
  state.observation_taken = true;
  return Object.freeze({
    ok: true,
    binding: Object.freeze({
      action_admission_event_ref: captured.action_admission_event_ref,
      normalized_dispatch_hash: captured.normalized_dispatch_hash,
      adapter_identity_hash: captured.adapter_identity_hash,
      adapter_profile_hash: captured.adapter_profile_hash,
    }),
    observation: captured.observation,
  });
}

function dispatchEventAt(
  events: readonly Readonly<{ sequence: number; event_hash: string; event_type: string; payload: unknown }>[],
  ref: Readonly<{ ledger_sequence: number; event_hash: string }>,
) {
  return events.find((event) => event.sequence === ref.ledger_sequence && event.event_hash === ref.event_hash);
}

export async function dispatchAdmittedActionV01(
  session: RuntimeWriteSessionV03,
  broker: CapturedEffectDispatchBrokerV01,
  permit: DispatchPermitV01,
): Promise<DispatchAdmittedActionV01Result> {
  const inspected = await inspectRuntimeWriteSessionV03ForDispatch(session);
  if (!inspected.ok) return Object.freeze({ ok: false, error: inspected.error });
  const state = brokerStates.get(broker);
  if (state === undefined) return Object.freeze({ ok: false, error: "CAPTURED_BROKER_INVALID" });
  const consumed = consumeDispatchPermitV01(permit, session, broker, state.normalized_dispatch_hash);
  if (!consumed.ok) {
    if (consumed.error === "DISPATCH_BINDING_MISMATCH" || consumed.error === "DISPATCH_PERMIT_ALREADY_USED") {
      await poisonRuntimeWriteSessionV03ForAdmission(session);
    }
    return Object.freeze({ ok: false, error: consumed.error });
  }
  const admission = dispatchEventAt(inspected.snapshot.events, consumed.action_admission_event_ref);
  const payload = typeof admission?.payload === "object" && admission.payload !== null
    ? admission.payload as Record<string, unknown> : null;
  if (admission?.event_type !== "task.action-admitted"
    || payload?.normalized_dispatch_hash !== state.normalized_dispatch_hash) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: "DISPATCH_BINDING_MISMATCH" });
  }
  if (state.entered) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: "DISPATCH_BINDING_MISMATCH" });
  }
  state.entered = true;
  const invocation = Object.freeze({
    adapter_invocation_id: state.adapter_invocation_id,
    action_admission_event_ref: consumed.action_admission_event_ref,
    normalized_dispatch_hash: state.normalized_dispatch_hash,
    adapter_ref: state.adapter_ref,
    adapter_version_hash: state.adapter_version_hash,
    adapter_profile_hash: state.adapter_profile_hash,
  });
  try {
    const outcome = await state.dispatch(invocation);
    const descriptors = typeof outcome === "object" && outcome !== null && !Array.isArray(outcome)
      ? Object.getOwnPropertyDescriptors(outcome) : null;
    const keys = descriptors === null ? [] : Object.keys(descriptors).sort();
    if (descriptors !== null && Object.getPrototypeOf(outcome) === Object.prototype
      && Object.getOwnPropertySymbols(outcome).length === 0
      && keys.join("\u0000") === "disposition"
      && descriptors.disposition?.get === undefined && descriptors.disposition?.set === undefined
      && descriptors.disposition?.enumerable === true && "value" in descriptors.disposition
      && descriptors.disposition.value === "NOT_STARTED") {
      return Object.freeze({ ok: false, error: "DISPATCH_NOT_STARTED" });
    }
    if (descriptors !== null && Object.getPrototypeOf(outcome) === Object.prototype
      && Object.getOwnPropertySymbols(outcome).length === 0
      && keys.join("\u0000") === "disposition\u0000observation"
      && descriptors.disposition?.get === undefined && descriptors.disposition?.set === undefined
      && descriptors.disposition?.enumerable === true && "value" in descriptors.disposition
      && descriptors.disposition.value === "DISPATCHED"
      && descriptors.observation?.get === undefined && descriptors.observation?.set === undefined
      && descriptors.observation?.enumerable === true && "value" in descriptors.observation) {
      const captured = captureObservation(descriptors.observation.value);
      const observation = captured === undefined ? null : captured;
      state.captured_observation = Object.freeze({
        session,
        adapter_invocation_id: state.adapter_invocation_id,
        action_admission_event_ref: consumed.action_admission_event_ref,
        normalized_dispatch_hash: state.normalized_dispatch_hash,
        adapter_identity_hash: hashCanonical({
          purpose: "effect-dispatch-adapter-identity-v01",
          adapter_ref: state.adapter_ref,
          adapter_version_hash: state.adapter_version_hash,
        }),
        adapter_profile_hash: state.adapter_profile_hash,
        observation,
      });
      return Object.freeze({ ok: true, disposition: "DISPATCHED", adapter_invocation_id: state.adapter_invocation_id });
    }
  } catch {
    // Crossing the broker entry boundary makes the external outcome unknowable.
  }
  await poisonRuntimeWriteSessionV03ForAdmission(session);
  return Object.freeze({ ok: false, error: "DISPATCH_OUTCOME_UNKNOWN" });
}
