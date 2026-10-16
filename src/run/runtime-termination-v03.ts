import { z } from "zod";

import { hashCanonical } from "../hash.js";
import { Hash } from "../schema/scalars.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import {
  appendRuntimeEventV03,
  createRuntimeEventDraftV03,
  inspectRuntimeWriteSessionV03ForTermination,
  poisonRuntimeWriteSessionV03ForAdmission,
  verifyRuntimeWriteSessionTailReadbackV03,
  type InspectRuntimeWriteSessionV03ForTerminationError,
  type RuntimeWriteSessionV03,
} from "./runtime-write-session-v03.js";

declare const terminationCapabilityBrandV03: unique symbol;
export type CapturedRuntimeTerminationCapabilityV03 = Readonly<{ [terminationCapabilityBrandV03]: never }>;

const LedgerRef = z.object({ ledger_sequence: z.number().int().positive().refine(Number.isSafeInteger), event_hash: Hash }).strict();
const Request = z.object({
  trigger: z.enum(["abort", "quarantine"]),
  trigger_event_ref: LedgerRef,
  action_admission_event_ref: LedgerRef,
  adapter_invocation_id: MachineIdV02,
}).strict();
const Identity = z.string().min(1).refine((value) => new TextEncoder().encode(value).byteLength <= 4_096);
const CaptureDescriptor = z.object({ host_identity: Identity, boot_id: Identity, unit_name: Identity, cgroup_path: Identity }).strict();
const Observation = CaptureDescriptor.extend({
  cgroup_populated: z.union([z.literal(0), z.literal(1)]),
  unit_state: z.enum(["active", "inactive", "unknown"]),
}).strict();

type State = z.infer<typeof CaptureDescriptor> & {
  terminate: (request: Readonly<z.infer<typeof CaptureDescriptor>>) => Promise<unknown>;
  claimed: boolean;
  used: boolean;
};
const capabilities = new WeakMap<CapturedRuntimeTerminationCapabilityV03, State>();

export function captureRuntimeTerminationCapabilityV03(input: unknown): CapturedRuntimeTerminationCapabilityV03 | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype
      || Reflect.ownKeys(input).some((key) => typeof key === "symbol")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const keys = Object.keys(descriptors).sort();
    if (keys.join("\u0000") !== "boot_id\u0000cgroup_path\u0000host_identity\u0000terminate\u0000unit_name"
      || keys.some((key) => descriptors[key]?.get !== undefined || descriptors[key]?.set !== undefined
        || descriptors[key]?.enumerable !== true)) return null;
    const candidate = input as Record<string, unknown>;
    const parsed = CaptureDescriptor.safeParse({
      host_identity: candidate.host_identity, boot_id: candidate.boot_id,
      unit_name: candidate.unit_name, cgroup_path: candidate.cgroup_path,
    });
    if (!parsed.success || typeof candidate.terminate !== "function") return null;
    const capability = Object.freeze({}) as CapturedRuntimeTerminationCapabilityV03;
    capabilities.set(capability, {
      ...parsed.data,
      terminate: candidate.terminate as State["terminate"],
      claimed: false,
      used: false,
    });
    return capability;
  } catch { return null; }
}

/** Package-private one-way transfer into a coordinator-owned termination path. */
export function claimRuntimeTerminationCapabilityV03(
  capability: CapturedRuntimeTerminationCapabilityV03,
): CapturedRuntimeTerminationCapabilityV03 | null {
  const state = capabilities.get(capability);
  if (state === undefined || state.claimed || state.used) return null;
  state.claimed = true;
  capabilities.delete(capability);
  const claimed = Object.freeze({}) as CapturedRuntimeTerminationCapabilityV03;
  capabilities.set(claimed, state);
  return claimed;
}

export type TerminateRuntimeActionV03Result = Readonly<{
  ok: true;
  observed_outcome: "terminated" | "not-terminated" | "unknown";
  event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  committed_manifest_hash: string;
}> | Readonly<{ ok: false; error: TerminateRuntimeActionV03Error }>;

export type TerminateRuntimeActionV03Error = InspectRuntimeWriteSessionV03ForTerminationError
  | "TERMINATION_REQUEST_INVALID" | "TERMINATION_CAPABILITY_INVALID" | "TERMINATION_ALREADY_ATTEMPTED"
  | "TERMINATION_BINDING_INVALID" | "TERMINATION_EVENT_INVALID" | "TERMINATION_APPEND_OUTCOME_UNKNOWN"
  | "TERMINATION_NOT_COMMITTED" | "TERMINATION_READBACK_INVALID";

function parseExactPlain<T extends z.ZodTypeAny>(input: unknown, keys: readonly string[], schema: T): z.infer<T> | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype || Reflect.ownKeys(input).some((key) => typeof key === "symbol")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (Object.keys(descriptors).sort().join("\u0000") !== [...keys].sort().join("\u0000")
      || keys.some((key) => descriptors[key]?.get !== undefined || descriptors[key]?.set !== undefined
        || descriptors[key]?.enumerable !== true || !("value" in descriptors[key]!))) return null;
    const owned = Object.fromEntries(keys.map((key) => [key, descriptors[key]!.value]));
    const parsed = schema.safeParse(owned);
    return parsed.success ? parsed.data : null;
  } catch { return null; }
}

function captureRequest(input: unknown): z.infer<typeof Request> | null {
  const top = parseExactPlain(input,
    ["trigger", "trigger_event_ref", "action_admission_event_ref", "adapter_invocation_id"],
    z.object({ trigger: z.enum(["abort", "quarantine"]), trigger_event_ref: z.unknown(),
      action_admission_event_ref: z.unknown(), adapter_invocation_id: MachineIdV02 }).strict());
  if (top === null) return null;
  const triggerRef = parseExactPlain(top.trigger_event_ref, ["ledger_sequence", "event_hash"], LedgerRef);
  const actionRef = parseExactPlain(top.action_admission_event_ref, ["ledger_sequence", "event_hash"], LedgerRef);
  return triggerRef === null || actionRef === null ? null : Object.freeze({
    trigger: top.trigger, trigger_event_ref: Object.freeze(triggerRef),
    action_admission_event_ref: Object.freeze(actionRef), adapter_invocation_id: top.adapter_invocation_id,
  });
}

function atRef(events: readonly Readonly<{ sequence: number; event_hash: string; event_type: string; payload: unknown }>[], ref: z.infer<typeof LedgerRef>) {
  return events.find((event) => event.sequence === ref.ledger_sequence && event.event_hash === ref.event_hash);
}

export async function terminateRuntimeActionV03(
  session: RuntimeWriteSessionV03,
  capability: CapturedRuntimeTerminationCapabilityV03,
  requestInput: unknown,
): Promise<TerminateRuntimeActionV03Result> {
  const request = captureRequest(requestInput);
  if (request === null) return Object.freeze({ ok: false, error: "TERMINATION_REQUEST_INVALID" });
  const inspected = await inspectRuntimeWriteSessionV03ForTermination(session);
  if (!inspected.ok) return Object.freeze({ ok: false, error: inspected.error });
  const state = capabilities.get(capability);
  if (state === undefined) return Object.freeze({ ok: false, error: "TERMINATION_CAPABILITY_INVALID" });
  if (state.used) return Object.freeze({ ok: false, error: "TERMINATION_ALREADY_ATTEMPTED" });
  const action = atRef(inspected.snapshot.events, request.action_admission_event_ref);
  const trigger = atRef(inspected.snapshot.events, request.trigger_event_ref);
  const actionPayload = typeof action?.payload === "object" && action.payload !== null ? action.payload as Record<string, unknown> : {};
  const starts = inspected.snapshot.events.filter((event) => {
    const payload = typeof event.payload === "object" && event.payload !== null ? event.payload as Record<string, unknown> : {};
    const ref = payload.admission_ref as z.infer<typeof LedgerRef> | undefined;
    const copied = ["action_id", "task_ref", "action_proposal_id", "action_proposal_hash", "action_actor_ref",
      "action_actor_stable_identity_hash", "on_behalf_of_chain_hash", "repository_root_ref",
      "repository_base_ref_identity_hash", "repository_pre_state_hash", "authorized_change_set_hash",
      "normalized_dispatch_hash", "policy_action_kind", "action_approval_class"];
    return event.event_type === "task.execution-started" && payload.adapter_invocation_id === request.adapter_invocation_id
      && ref?.ledger_sequence === request.action_admission_event_ref.ledger_sequence
      && ref.event_hash === request.action_admission_event_ref.event_hash
      && copied.every((key) => payload[key] === actionPayload[key]);
  });
  const expectedTrigger = request.trigger === "abort" ? "control.abort-requested" : "run.quarantined";
  if (action?.event_type !== "task.action-admitted" || trigger?.event_type !== expectedTrigger || starts.length !== 1
    || action.sequence >= starts[0]!.sequence || starts[0]!.sequence >= trigger.sequence) {
    return Object.freeze({ ok: false, error: "TERMINATION_BINDING_INVALID" });
  }
  state.used = true;
  const expected = Object.freeze({
    host_identity: state.host_identity, boot_id: state.boot_id, unit_name: state.unit_name, cgroup_path: state.cgroup_path,
  });
  let observation: z.infer<typeof Observation> | null = null;
  try {
    observation = parseExactPlain(await state.terminate(expected),
      ["host_identity", "boot_id", "unit_name", "cgroup_path", "cgroup_populated", "unit_state"], Observation);
  } catch { /* ambiguous host boundary */ }
  const observedOutcome = observation === null ? "unknown"
    : observation.host_identity === state.host_identity && observation.boot_id === state.boot_id
      && observation.unit_name === state.unit_name && observation.cgroup_path === state.cgroup_path
      && observation.cgroup_populated === 0 && observation.unit_state === "inactive" ? "terminated" : "not-terminated";
  const requestHash = hashCanonical({ purpose: "runtime-termination-request-v03", ...expected, ...request });
  const observationHash = hashCanonical({ purpose: "runtime-termination-observation-v03", observation });
  const draft = createRuntimeEventDraftV03({
    event_type: "process.termination-attempted", source: "adapter", authority_ref: null, risk_tier: "T5", related_ids: [],
    payload: {
      ...request,
      host_identity_hash: hashCanonical({ purpose: "runtime-host-identity-v03", value: state.host_identity }),
      boot_id_hash: hashCanonical({ purpose: "runtime-boot-id-v03", value: state.boot_id }),
      unit_name_hash: hashCanonical({ purpose: "runtime-unit-name-v03", value: state.unit_name }),
      cgroup_path_hash: hashCanonical({ purpose: "runtime-cgroup-path-v03", value: state.cgroup_path }),
      termination_request_hash: requestHash, termination_observation_hash: observationHash, observed_outcome: observedOutcome,
    },
  });
  if (draft === null) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: "TERMINATION_EVENT_INVALID" });
  }
  const appended = await appendRuntimeEventV03(session, draft);
  if (!appended.ok) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: appended.classification === "OUTCOME_UNKNOWN" ? "TERMINATION_APPEND_OUTCOME_UNKNOWN" : "TERMINATION_NOT_COMMITTED" });
  }
  const readback = await verifyRuntimeWriteSessionTailReadbackV03(session, {
    events: [{ event_type: "process.termination-attempted", event_ref: appended.event_ref }], manifest_hash: appended.manifest_hash,
  });
  if (!readback.ok) {
    await poisonRuntimeWriteSessionV03ForAdmission(session);
    return Object.freeze({ ok: false, error: "TERMINATION_READBACK_INVALID" });
  }
  return Object.freeze({ ok: true, observed_outcome: observedOutcome, event_ref: appended.event_ref, committed_manifest_hash: appended.manifest_hash });
}
