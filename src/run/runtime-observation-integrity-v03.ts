import { z } from "zod";

import { canonicalize, hashRawBytes } from "../hash.js";
import { Hash } from "../schema/scalars.js";
import { HumanIdV02, MachineIdV02 } from "../schema/scalars-v02.js";
import { LedgerRefV02 } from "../schema/runtime.js";
import {
  takeCapturedEffectObservationV01,
  type CapturedEffectDispatchBrokerV01,
} from "./runtime-effect-dispatch-broker-v01.js";
import {
  appendRuntimeIntegrityQuarantinePairV03,
  createRuntimeEventDraftV03,
  inspectRuntimeWriteSessionV03ForDispatch,
  poisonRuntimeWriteSessionV03ForAdmission,
  verifyRuntimeWriteSessionTailReadbackV03,
  type InspectRuntimeWriteSessionV03ForDispatchError,
  type RuntimeWriteSessionV03,
} from "./runtime-write-session-v03.js";

const RuntimeObservationIntegrityRequestV03 = z.object({
  adapter_invocation_id: MachineIdV02,
}).strict();

const NormalizedEffectObservationV01 = z.object({
  observation_version: z.literal("0.1"),
  adapter_invocation_id: MachineIdV02,
  claimed_action_id: MachineIdV02,
  action_admission_event_ref: LedgerRefV02,
  normalized_dispatch_hash: Hash,
  effect_refs: z.array(HumanIdV02).min(1).superRefine((values, ctx) => {
    for (let index = 1; index < values.length; index += 1) {
      if (Buffer.from(values[index - 1]!, "utf8").compare(Buffer.from(values[index]!, "utf8")) >= 0) {
        ctx.addIssue({ code: "custom", path: [index], message: "effect refs must be unique and UTF-8 sorted" });
      }
    }
  }),
  adapter_identity_hash: Hash,
  adapter_profile_hash: Hash,
}).strict();

export type ReconcileRuntimeObservationIntegrityV03Error = InspectRuntimeWriteSessionV03ForDispatchError
  | "OBSERVATION_REQUEST_INVALID"
  | "EFFECT_OBSERVATION_INVALID"
  | "EFFECT_OBSERVATION_BINDING_MISMATCH"
  | "EFFECT_OBSERVATION_ALREADY_TAKEN"
  | "INTEGRITY_QUARANTINE_NOT_COMMITTED"
  | "COMMITTED_READBACK_INVALID"
  | "RUNTIME_IO_OUTCOME_UNKNOWN";

export type ReconcileRuntimeObservationIntegrityV03Result = Readonly<{
  ok: true; disposition: "MATCHED"; observation_hash: string;
}> | Readonly<{
  ok: true; disposition: "QUARANTINED";
  reason_code: "unmatched-observation" | "authority-breach" | "capture-gap";
  observation_hash: string;
  rejection_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  quarantine_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  committed_manifest_hash: string;
}> | Readonly<{
  ok: false;
  error: ReconcileRuntimeObservationIntegrityV03Error;
}>;

function eventAt(
  events: readonly Readonly<{ sequence: number; event_hash: string; event_type: string; payload: unknown }>[],
  ref: Readonly<{ ledger_sequence: number; event_hash: string }>,
) {
  return events.find((event) => event.sequence === ref.ledger_sequence && event.event_hash === ref.event_hash);
}

function captureRequest(input: unknown): z.infer<typeof RuntimeObservationIntegrityRequestV03> | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype || Object.getOwnPropertySymbols(input).length > 0) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (Object.keys(descriptors).join("\0") !== "adapter_invocation_id") return null;
    const descriptor = descriptors.adapter_invocation_id;
    if (descriptor === undefined || !("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined
      || descriptor.enumerable !== true) return null;
    const parsed = RuntimeObservationIntegrityRequestV03.safeParse({ adapter_invocation_id: descriptor.value });
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

function plainDataObject(input: unknown, expectedKeys: readonly string[]): Record<string, PropertyDescriptor> | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype || Object.getOwnPropertySymbols(input).length > 0) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (Object.keys(descriptors).sort().join("\0") !== [...expectedKeys].sort().join("\0")) return null;
    return expectedKeys.every((key) => {
      const descriptor = descriptors[key];
      return descriptor !== undefined && "value" in descriptor && descriptor.get === undefined
        && descriptor.set === undefined && descriptor.enumerable === true;
    }) ? descriptors : null;
  } catch {
    return null;
  }
}

function captureNormalizedObservation(input: unknown): z.infer<typeof NormalizedEffectObservationV01> | null {
  const keys = [
    "observation_version", "adapter_invocation_id", "claimed_action_id", "action_admission_event_ref",
    "normalized_dispatch_hash", "effect_refs", "adapter_identity_hash", "adapter_profile_hash",
  ] as const;
  const descriptors = plainDataObject(input, keys);
  if (descriptors === null) return null;
  const ref = descriptors.action_admission_event_ref!.value;
  if (plainDataObject(ref, ["ledger_sequence", "event_hash"]) === null) return null;
  const effects = descriptors.effect_refs!.value;
  try {
    if (!Array.isArray(effects) || Object.getPrototypeOf(effects) !== Array.prototype
      || Object.getOwnPropertySymbols(effects).length > 0) return null;
    const effectDescriptors = Object.getOwnPropertyDescriptors(effects);
    if (Object.keys(effectDescriptors).some((key) => key !== "length" && !/^\d+$/u.test(key))) return null;
    for (let index = 0; index < effects.length; index += 1) {
      const descriptor = effectDescriptors[String(index)];
      if (descriptor === undefined || !("value" in descriptor) || descriptor.get !== undefined
        || descriptor.set !== undefined || descriptor.enumerable !== true) return null;
    }
    const candidate = Object.fromEntries(keys.map((key) => [key, descriptors[key]!.value]));
    const parsed = NormalizedEffectObservationV01.safeParse(candidate);
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

function hashNormalizedObservation(observation: unknown): string | null {
  try {
    return hashRawBytes(new TextEncoder().encode(canonicalize(observation)));
  } catch {
    return null;
  }
}

async function quarantineObservation(
  session: RuntimeWriteSessionV03,
  reasonCode: "unmatched-observation" | "authority-breach" | "capture-gap",
  observationHash: string,
  adapterInvocationId: string | null,
  claimedActionId: string | null,
): Promise<ReconcileRuntimeObservationIntegrityV03Result> {
  const rejectionDraft = createRuntimeEventDraftV03({
    event_type: "integrity.observation-rejected", source: "integrity", authority_ref: null,
    risk_tier: "T5", related_ids: [], payload: {
      reason_code: reasonCode, observation_hash: observationHash,
      adapter_invocation_id: adapterInvocationId, claimed_action_id: claimedActionId,
    },
  });
  if (rejectionDraft === null) {
    return Object.freeze({ ok: false, error: "EFFECT_OBSERVATION_INVALID" });
  }
  const appended = await appendRuntimeIntegrityQuarantinePairV03(session, rejectionDraft);
  if (!appended.ok) return Object.freeze({
    ok: false,
    error: appended.classification === "OUTCOME_UNKNOWN"
      ? "RUNTIME_IO_OUTCOME_UNKNOWN" : "INTEGRITY_QUARANTINE_NOT_COMMITTED",
  });
  const readback = await verifyRuntimeWriteSessionTailReadbackV03(session, {
    events: [
      { event_type: "integrity.observation-rejected", event_ref: appended.event_refs[0] },
      { event_type: "run.quarantined", event_ref: appended.event_refs[1] },
    ],
    manifest_hash: appended.manifest_hash,
  });
  if (!readback.ok) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: "COMMITTED_READBACK_INVALID" });
  }
  return Object.freeze({
    ok: true, disposition: "QUARANTINED", reason_code: reasonCode, observation_hash: observationHash,
    rejection_event_ref: appended.event_refs[0], quarantine_event_ref: appended.event_refs[1],
    committed_manifest_hash: readback.readback.manifest_hash,
  });
}

/** Package-private S40-B5 boundary. Raw observations never leave this module or enter the ledger. */
export async function reconcileRuntimeObservationIntegrityV03(
  session: RuntimeWriteSessionV03,
  broker: CapturedEffectDispatchBrokerV01,
  requestInput: unknown,
): Promise<ReconcileRuntimeObservationIntegrityV03Result> {
  const request = captureRequest(requestInput);
  if (request === null) return Object.freeze({ ok: false, error: "OBSERVATION_REQUEST_INVALID" });
  const inspected = await inspectRuntimeWriteSessionV03ForDispatch(session);
  if (!inspected.ok) return Object.freeze({ ok: false, error: inspected.error });
  const captured = takeCapturedEffectObservationV01(broker, session, request.adapter_invocation_id);
  if (!captured.ok) return Object.freeze({ ok: false, error: captured.error });
  const observation = captureNormalizedObservation(captured.observation);
  const admission = eventAt(inspected.snapshot.events, captured.binding.action_admission_event_ref);
  const payload = typeof admission?.payload === "object" && admission.payload !== null
    ? admission.payload as Record<string, unknown> : null;
  const admissionRef = LedgerRefV02.safeParse(captured.binding.action_admission_event_ref);
  if (admission?.event_type !== "task.action-admitted" || payload === null || !admissionRef.success) {
    return Object.freeze({ ok: false, error: "EFFECT_OBSERVATION_BINDING_MISMATCH" });
  }
  const observationHash = hashNormalizedObservation(captured.observation);
  if (observationHash === null) return Object.freeze({ ok: false, error: "EFFECT_OBSERVATION_INVALID" });
  if (observation === null) {
    return quarantineObservation(
      session, "capture-gap", observationHash, request.adapter_invocation_id, null,
    );
  }
  const admittedEffects = Array.isArray(payload.side_effect_refs) ? payload.side_effect_refs : [];
  const exact = observation.adapter_invocation_id === request.adapter_invocation_id
    && observation.claimed_action_id === payload.action_id
    && observation.action_admission_event_ref.ledger_sequence === captured.binding.action_admission_event_ref.ledger_sequence
    && observation.action_admission_event_ref.event_hash === captured.binding.action_admission_event_ref.event_hash
    && observation.normalized_dispatch_hash === payload.normalized_dispatch_hash
    && observation.normalized_dispatch_hash === captured.binding.normalized_dispatch_hash
    && canonicalize(observation.effect_refs) === canonicalize(admittedEffects)
    && observation.adapter_identity_hash === captured.binding.adapter_identity_hash
    && observation.adapter_profile_hash === captured.binding.adapter_profile_hash;
  if (exact) {
    return Object.freeze({
      ok: true, disposition: "MATCHED", observation_hash: observationHash,
    });
  }
  const knownAction = inspected.snapshot.events.some((event) => {
    const candidate = typeof event.payload === "object" && event.payload !== null
      ? event.payload as Record<string, unknown> : null;
    return event.event_type === "task.action-admitted" && candidate?.action_id === observation.claimed_action_id;
  });
  const reason = observation.adapter_invocation_id !== request.adapter_invocation_id || !knownAction
    ? "unmatched-observation" as const : "authority-breach" as const;
  return quarantineObservation(
    session, reason, observationHash, observation.adapter_invocation_id, observation.claimed_action_id,
  );
}
