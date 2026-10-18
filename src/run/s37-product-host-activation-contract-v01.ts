import { parseDocument } from "yaml";
import { z } from "zod";

import { hashCanonical, hashRawBytes } from "../hash.js";
import { Hash } from "../schema/scalars.js";

const EVENT_SCHEMA = "s37-product-host-activation-event-v01";
const LEDGER_SCHEMA = "s37-product-host-activation-ledger-v01";
const MANIFEST_SCHEMA = "s37-product-host-activation-manifest-v01";
const MAX_LEDGER_BYTES = 16_777_216;
const MAX_MANIFEST_BYTES = 65_536;
const MAX_EVENT_BYTES = 65_536;
const MAX_EVENTS = 100_000;

const safePositiveInteger = z.number().int().positive().refine(Number.isSafeInteger);
const safeNonnegativeInteger = z.number().int().nonnegative().refine(Number.isSafeInteger);
const ActivationId = z.string().regex(/^activation_[a-f0-9]{64}$/u);
const Operation = z.enum(["install-and-launch", "transition-and-launch", "launch-stable"]);
const Outcome = z.enum(["OUTCOME_UNKNOWN", "RECOVERY_REQUIRED", "NOT_COMMITTED", "NOT_STARTED", "COMPLETED"]);

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  if (ArrayBuffer.isView(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

const RequestedPayload = z.object({
  request_hash: Hash,
  bundle_hash: Hash.nullable(),
  proof_request_hash: Hash,
  qualification_intent_hash: Hash,
  action_scope_hash: Hash,
  initial_absence_observation_hash: Hash,
}).strict();

const NoncesReservedPayload = z.object({
  proof_record_hash: Hash,
  authorization_nonce_record_hash: Hash,
  launch_nonce_record_hash: Hash,
}).strict();

const AnchorStablePayload = z.object({
  mutation_plan_hash: Hash.nullable(),
  proposed_anchor_hash: Hash.nullable(),
  anchor_observation_hash: Hash,
}).strict();

const QualificationIssuedPayload = z.object({
  qualification_intent_hash: Hash,
  activation_decision_facts_hash: Hash,
  decision_input_hash: Hash,
  decision_simulation_hash: Hash,
  lease_simulation_hash: Hash,
  qualification_absence_observation_hash: Hash,
  qualification_request_hash: Hash,
  qualification_hash: Hash,
  qualification_nonce_record_hash: Hash,
  boot_observation_hash: Hash,
}).strict();

const LaunchAdmittedPayload = z.object({
  launch_admission_hash: Hash,
  qualification_hash: Hash,
  prelaunch_authorization_revalidation_hash: Hash,
  final_observation_hash: Hash,
  broker_request_hash: Hash,
}).strict();

const DispatchEnteredPayload = z.object({
  launch_admission_hash: Hash,
  broker_request_hash: Hash,
  conformance_receipt_hash: Hash,
  systemd_run_hash: Hash,
  runtime_profile_hash: Hash,
  artifact_set_hash: Hash,
  controller_uid: safePositiveInteger,
  primary_gid: safePositiveInteger,
  controller_identity_hash: Hash,
  unit_name_hash: Hash,
  cgroup_path_hash: Hash,
  broker_entry_evidence_hash: Hash,
}).strict();

const CompletedPayload = z.object({
  outcome: z.literal("COMPLETED"),
  broker_entry_evidence_hash: Hash,
  completion_evidence_hash: Hash,
}).strict();

const EventPayload = z.discriminatedUnion("event_type", [
  z.object({ event_type: z.literal("activation.requested"), payload: RequestedPayload }),
  z.object({ event_type: z.literal("activation.nonces-reserved"), payload: NoncesReservedPayload }),
  z.object({ event_type: z.literal("activation.anchor-stable"), payload: AnchorStablePayload }),
  z.object({ event_type: z.literal("activation.qualification-issued"), payload: QualificationIssuedPayload }),
  z.object({ event_type: z.literal("activation.launch-admitted"), payload: LaunchAdmittedPayload }),
  z.object({ event_type: z.literal("activation.dispatch-entered"), payload: DispatchEnteredPayload }),
  z.object({ event_type: z.literal("activation.completed"), payload: CompletedPayload }),
]);

const EventRaw = z.object({
  schema_version: z.literal(EVENT_SCHEMA),
  activation_id: ActivationId,
  operation: Operation,
  sequence: safePositiveInteger,
  event_type: z.enum([
    "activation.requested", "activation.nonces-reserved", "activation.anchor-stable",
    "activation.qualification-issued", "activation.launch-admitted", "activation.dispatch-entered",
    "activation.completed",
  ]),
  previous_event_hash: Hash.nullable(),
  anchor_generation: safePositiveInteger,
  anchor_hash: Hash,
  boot_id_hash: Hash,
  controller_uid: safePositiveInteger,
  fence_epoch: safeNonnegativeInteger,
  payload: z.unknown(),
  event_hash: Hash,
}).strict().superRefine((event, context) => {
  const payload = EventPayload.safeParse({ event_type: event.event_type, payload: event.payload });
  if (!payload.success) {
    context.addIssue({ code: "custom", path: ["payload"], message: "payload must match the exact event variant" });
    return;
  }
  if ((event.sequence === 1) !== (event.previous_event_hash === null)) {
    context.addIssue({ code: "custom", path: ["previous_event_hash"], message: "only global sequence one has a null predecessor" });
  }
  if (event.operation === "launch-stable") {
    if (payload.data.event_type === "activation.requested" && payload.data.payload.bundle_hash !== null) {
      context.addIssue({ code: "custom", path: ["payload", "bundle_hash"], message: "stable launch has no bundle" });
    }
    if (payload.data.event_type === "activation.anchor-stable"
      && (payload.data.payload.mutation_plan_hash !== null || payload.data.payload.proposed_anchor_hash !== null)) {
      context.addIssue({ code: "custom", path: ["payload"], message: "stable launch has no anchor mutation" });
    }
  } else {
    if (payload.data.event_type === "activation.requested" && payload.data.payload.bundle_hash === null) {
      context.addIssue({ code: "custom", path: ["payload", "bundle_hash"], message: "mutating launch requires a bundle" });
    }
    if (payload.data.event_type === "activation.anchor-stable"
      && (payload.data.payload.mutation_plan_hash === null || payload.data.payload.proposed_anchor_hash === null)) {
      context.addIssue({ code: "custom", path: ["payload"], message: "mutating launch requires the mutation and proposed anchor" });
    }
  }
  const { event_hash: _eventHash, ...preimage } = event;
  if (event.event_hash !== hashS37ProductHostActivationEventV01(preimage)) {
    context.addIssue({ code: "custom", path: ["event_hash"], message: "event hash must bind the exact preimage" });
  }
});

export type S37ProductHostActivationEventV01Value = z.infer<typeof EventRaw>;
export const S37ProductHostActivationEventV01 = EventRaw.transform((event) => {
  const variant = EventPayload.parse({ event_type: event.event_type, payload: event.payload });
  return freezeDeep({ ...event, payload: variant.payload });
});

const ManifestRaw = z.object({
  schema_version: z.literal(MANIFEST_SCHEMA),
  active_activation_id: ActivationId,
  operation: Operation,
  status: z.enum(["REQUESTED", "NONCES_RESERVED", "ANCHOR_STABLE", "QUALIFICATION_ISSUED", "LAUNCH_ADMITTED", "DISPATCH_ENTERED", "COMPLETED"]),
  ledger_bytes_hash: Hash,
  ledger_sequence: safePositiveInteger,
  ledger_head_hash: Hash,
  activation_request_hash: Hash,
  anchor_generation: safePositiveInteger,
  anchor_hash: Hash,
  launch_admission_hash: Hash.nullable(),
  broker_request_hash: Hash.nullable(),
  fence_epoch: safeNonnegativeInteger,
  manifest_hash: Hash,
}).strict().superRefine((manifest, context) => {
  const { manifest_hash: _manifestHash, ...preimage } = manifest;
  if (manifest.manifest_hash !== hashS37ProductHostActivationManifestV01(preimage)) {
    context.addIssue({ code: "custom", path: ["manifest_hash"], message: "manifest hash must bind the exact preimage" });
  }
  const admitted = ["LAUNCH_ADMITTED", "DISPATCH_ENTERED", "COMPLETED"].includes(manifest.status);
  if (admitted !== (manifest.launch_admission_hash !== null && manifest.broker_request_hash !== null)) {
    context.addIssue({ code: "custom", path: ["launch_admission_hash"], message: "admission fields must exist exactly from stage five" });
  }
});

export type S37ProductHostActivationManifestV01Value = z.infer<typeof ManifestRaw>;
export const S37ProductHostActivationManifestV01 = ManifestRaw.transform((manifest) => freezeDeep(manifest));

const EVENT_TYPES = [
  "activation.requested", "activation.nonces-reserved", "activation.anchor-stable",
  "activation.qualification-issued", "activation.launch-admitted", "activation.dispatch-entered",
  "activation.completed",
] as const;
const STATUSES = [
  "REQUESTED", "NONCES_RESERVED", "ANCHOR_STABLE", "QUALIFICATION_ISSUED",
  "LAUNCH_ADMITTED", "DISPATCH_ENTERED", "COMPLETED",
] as const;

export type S37ProductHostActivationOutcomeV01 = z.infer<typeof Outcome>;
export type S37ProductHostActivationStateV01 = Readonly<{
  activation_id: string | null;
  status: "EMPTY" | (typeof STATUSES)[number];
  outcome: S37ProductHostActivationOutcomeV01;
  sequence: number;
  fence_epoch: number | null;
}>;

type FailureReason = "ACTIVATION_INPUT_INVALID" | "LEDGER_SYNTAX_INVALID" | "LEDGER_EVENT_SCHEMA_INVALID"
  | "LEDGER_HASH_CHAIN_INVALID" | "LEDGER_HISTORY_INVALID" | "MANIFEST_SYNTAX_INVALID"
  | "MANIFEST_SCHEMA_INVALID" | "MANIFEST_CROSS_CHECK_INVALID";
type HistoryFailureReason = "LEDGER_HASH_CHAIN_INVALID" | "LEDGER_HISTORY_INVALID";

function captureBytes(value: unknown, maximum: number): Uint8Array | null {
  try {
    if (!(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype
      || value.buffer instanceof SharedArrayBuffer || value.byteLength === 0 || value.byteLength > maximum) return null;
    return new Uint8Array(value);
  } catch {
    return null;
  }
}

function exactInput(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  try {
    if (typeof value !== "object" || value === null || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string")
      || Object.keys(descriptors).sort().join("\0") !== [...keys].sort().join("\0")) return null;
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined || !descriptor.enumerable) return null;
    }
    return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
  } catch {
    return null;
  }
}

function parseJson(text: string): unknown | null {
  try {
    const document = parseDocument(text, { uniqueKeys: true });
    if (document.errors.length > 0) return null;
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function parseLedger(bytes: Uint8Array): Readonly<{ ok: true; events: readonly S37ProductHostActivationEventV01Value[] }>
  | Readonly<{ ok: false; reason: FailureReason }> {
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { return { ok: false, reason: "LEDGER_SYNTAX_INVALID" }; }
  if (!text.endsWith("\n")) return { ok: false, reason: "LEDGER_SYNTAX_INVALID" };
  const lines = text.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.length > MAX_EVENTS
    || lines.some((line) => line.length === 0 || Buffer.byteLength(line, "utf8") > MAX_EVENT_BYTES)) {
    return { ok: false, reason: "LEDGER_SYNTAX_INVALID" };
  }
  const events: S37ProductHostActivationEventV01Value[] = [];
  for (const line of lines) {
    const value = parseJson(line);
    if (value === null) return { ok: false, reason: "LEDGER_SYNTAX_INVALID" };
    const parsed = S37ProductHostActivationEventV01.safeParse(value);
    if (!parsed.success) return { ok: false, reason: "LEDGER_EVENT_SCHEMA_INVALID" };
    events.push(parsed.data);
  }
  const history = validateHistory(events);
  return history === null ? { ok: true, events: freezeDeep(events) } : { ok: false, reason: history };
}

function validateHistory(events: readonly S37ProductHostActivationEventV01Value[]): HistoryFailureReason | null {
  let previous: S37ProductHostActivationEventV01Value | undefined;
  for (const [index, event] of events.entries()) {
    if (event.sequence !== index + 1 || event.previous_event_hash !== (previous?.event_hash ?? null)) {
      return "LEDGER_HASH_CHAIN_INVALID";
    }
    const stage = index % EVENT_TYPES.length;
    const blockStart = index - stage;
    const first = events[blockStart]!;
    if (event.event_type !== EVENT_TYPES[stage]) return "LEDGER_HISTORY_INVALID";
    if (stage === 0) {
      if (previous !== undefined && (previous.event_type !== "activation.completed"
        || event.fence_epoch !== previous.fence_epoch + 1 || event.activation_id === previous.activation_id)) {
        return "LEDGER_HISTORY_INVALID";
      }
    } else if (event.activation_id !== first.activation_id || event.operation !== first.operation
      || event.anchor_generation !== first.anchor_generation || event.anchor_hash !== first.anchor_hash
      || event.boot_id_hash !== first.boot_id_hash || event.controller_uid !== first.controller_uid
      || event.fence_epoch !== first.fence_epoch) {
      return "LEDGER_HISTORY_INVALID";
    }
    previous = event;
  }
  for (let start = 0; start < events.length; start += EVENT_TYPES.length) {
    const block = events.slice(start, Math.min(start + EVENT_TYPES.length, events.length));
    const requested = block[0];
    const anchor = block[2];
    const qualification = block[3];
    const admission = block[4];
    const dispatch = block[5];
    const completed = block[6];
    if (requested?.event_type !== "activation.requested") return "LEDGER_HISTORY_INVALID";
    const requestedPayload = requested.payload as z.infer<typeof RequestedPayload>;
    const anchorPayload = anchor?.payload as z.infer<typeof AnchorStablePayload> | undefined;
    const qualificationPayload = qualification?.payload as z.infer<typeof QualificationIssuedPayload> | undefined;
    const admissionPayload = admission?.payload as z.infer<typeof LaunchAdmittedPayload> | undefined;
    const dispatchPayload = dispatch?.payload as z.infer<typeof DispatchEnteredPayload> | undefined;
    const completedPayload = completed?.payload as z.infer<typeof CompletedPayload> | undefined;
    if (anchor?.event_type === "activation.anchor-stable" && requested.operation !== "launch-stable"
      && anchorPayload?.proposed_anchor_hash !== anchor.anchor_hash) return "LEDGER_HISTORY_INVALID";
    if (qualification?.event_type === "activation.qualification-issued"
      && qualificationPayload?.qualification_intent_hash !== requestedPayload.qualification_intent_hash) {
      return "LEDGER_HISTORY_INVALID";
    }
    if (admission?.event_type === "activation.launch-admitted" && qualification?.event_type === "activation.qualification-issued"
      && admissionPayload?.qualification_hash !== qualificationPayload?.qualification_hash) return "LEDGER_HISTORY_INVALID";
    if (dispatch?.event_type === "activation.dispatch-entered" && admission?.event_type === "activation.launch-admitted"
      && (dispatchPayload?.launch_admission_hash !== admissionPayload?.launch_admission_hash
        || dispatchPayload?.broker_request_hash !== admissionPayload?.broker_request_hash
        || dispatchPayload?.controller_uid !== dispatch.controller_uid)) return "LEDGER_HISTORY_INVALID";
    if (completed?.event_type === "activation.completed" && dispatch?.event_type === "activation.dispatch-entered"
      && completedPayload?.broker_entry_evidence_hash !== dispatchPayload?.broker_entry_evidence_hash) {
      return "LEDGER_HISTORY_INVALID";
    }
  }
  return null;
}

function stateFor(events: readonly S37ProductHostActivationEventV01Value[]): S37ProductHostActivationStateV01 {
  const last = events.at(-1);
  if (last === undefined) return freezeDeep({ activation_id: null, status: "EMPTY", outcome: "NOT_STARTED", sequence: 0, fence_epoch: null });
  const stage = EVENT_TYPES.indexOf(last.event_type);
  const outcome = stage >= 4 ? (stage === 6 ? "COMPLETED" : "OUTCOME_UNKNOWN") : "RECOVERY_REQUIRED";
  return freezeDeep({ activation_id: last.activation_id, status: STATUSES[stage]!, outcome, sequence: last.sequence, fence_epoch: last.fence_epoch });
}

export function hashS37ProductHostActivationEventV01(event: unknown): string {
  return hashCanonical({ purpose: EVENT_SCHEMA, event });
}

export function hashS37ProductHostActivationLedgerV01(bytes: Uint8Array): string {
  return hashCanonical({ purpose: LEDGER_SCHEMA, ledger_bytes_sha256: hashRawBytes(bytes) });
}

export function hashS37ProductHostActivationManifestV01(manifest: unknown): string {
  return hashCanonical({ purpose: MANIFEST_SCHEMA, manifest });
}

function projectManifest(events: readonly S37ProductHostActivationEventV01Value[], ledgerBytes: Uint8Array): S37ProductHostActivationManifestV01Value {
  const last = events.at(-1)!;
  const stage = EVENT_TYPES.indexOf(last.event_type);
  const blockStart = events.length - 1 - stage;
  const requested = events[blockStart]!;
  const admitted = stage >= 4 ? events[blockStart + 4] : undefined;
  if (requested.event_type !== "activation.requested"
    || (admitted !== undefined && admitted.event_type !== "activation.launch-admitted")) {
    throw new TypeError("validated activation block was not projectable");
  }
  const requestedPayload = requested.payload as z.infer<typeof RequestedPayload>;
  const admittedPayload = admitted?.payload as z.infer<typeof LaunchAdmittedPayload> | undefined;
  const preimage = {
    schema_version: MANIFEST_SCHEMA,
    active_activation_id: last.activation_id,
    operation: last.operation,
    status: STATUSES[stage]!,
    ledger_bytes_hash: hashS37ProductHostActivationLedgerV01(ledgerBytes),
    ledger_sequence: last.sequence,
    ledger_head_hash: last.event_hash,
    activation_request_hash: requestedPayload.request_hash,
    anchor_generation: last.anchor_generation,
    anchor_hash: last.anchor_hash,
    launch_admission_hash: admittedPayload?.launch_admission_hash ?? null,
    broker_request_hash: admittedPayload?.broker_request_hash ?? null,
    fence_epoch: last.fence_epoch,
  };
  return S37ProductHostActivationManifestV01.parse({
    ...preimage,
    manifest_hash: hashS37ProductHostActivationManifestV01(preimage),
  });
}

export function buildS37ProductHostActivationManifestV01(input: unknown):
  | Readonly<{ ok: true; manifest: S37ProductHostActivationManifestV01Value; bytes: Uint8Array }>
  | Readonly<{ ok: false; reason: FailureReason }> {
  const captured = exactInput(input, ["ledger_bytes"]);
  if (captured === null) return { ok: false, reason: "ACTIVATION_INPUT_INVALID" };
  const ledgerBytes = captureBytes(captured.ledger_bytes, MAX_LEDGER_BYTES);
  if (ledgerBytes === null) return { ok: false, reason: "ACTIVATION_INPUT_INVALID" };
  const ledger = parseLedger(ledgerBytes);
  if (!ledger.ok) return ledger;
  const manifest = projectManifest(ledger.events, ledgerBytes);
  return freezeDeep({ ok: true, manifest, bytes: new TextEncoder().encode(JSON.stringify(manifest)) });
}

const validatedActivations = new WeakSet<object>();
export type ValidatedS37ProductHostActivationV01 = Readonly<{
  readonly __validated_s37_product_host_activation_v01: unique symbol;
  events: readonly S37ProductHostActivationEventV01Value[];
  manifest: S37ProductHostActivationManifestV01Value;
  state: S37ProductHostActivationStateV01;
}>;

export function isValidatedS37ProductHostActivationV01(value: unknown): value is ValidatedS37ProductHostActivationV01 {
  return typeof value === "object" && value !== null && validatedActivations.has(value);
}

export function inspectS37ProductHostActivationV01(input: unknown):
  | Readonly<{ ok: true; validated_activation: ValidatedS37ProductHostActivationV01; state: S37ProductHostActivationStateV01 }>
  | Readonly<{ ok: false; reason: FailureReason }> {
  const captured = exactInput(input, ["ledger_bytes", "manifest_bytes"]);
  if (captured === null) return { ok: false, reason: "ACTIVATION_INPUT_INVALID" };
  const ledgerBytes = captureBytes(captured.ledger_bytes, MAX_LEDGER_BYTES);
  const manifestBytes = captureBytes(captured.manifest_bytes, MAX_MANIFEST_BYTES);
  if (ledgerBytes === null || manifestBytes === null) return { ok: false, reason: "ACTIVATION_INPUT_INVALID" };
  const ledger = parseLedger(ledgerBytes);
  if (!ledger.ok) return ledger;
  let manifestText: string;
  try { manifestText = new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes); }
  catch { return { ok: false, reason: "MANIFEST_SYNTAX_INVALID" }; }
  const rawManifest = parseJson(manifestText);
  if (rawManifest === null) return { ok: false, reason: "MANIFEST_SYNTAX_INVALID" };
  const parsedManifest = S37ProductHostActivationManifestV01.safeParse(rawManifest);
  if (!parsedManifest.success) return { ok: false, reason: "MANIFEST_SCHEMA_INVALID" };
  const expected = projectManifest(ledger.events, ledgerBytes);
  if (parsedManifest.data.ledger_bytes_hash !== expected.ledger_bytes_hash
    && parsedManifest.data.ledger_head_hash !== expected.ledger_head_hash) {
    return { ok: false, reason: "LEDGER_HISTORY_INVALID" };
  }
  if (JSON.stringify(parsedManifest.data) !== JSON.stringify(expected)) {
    return { ok: false, reason: "MANIFEST_CROSS_CHECK_INVALID" };
  }
  const state = stateFor(ledger.events);
  const validated = freezeDeep({ events: ledger.events, manifest: parsedManifest.data, state }) as unknown as ValidatedS37ProductHostActivationV01;
  validatedActivations.add(validated);
  return freezeDeep({ ok: true, validated_activation: validated, state });
}

export function reduceS37ProductHostActivationPrefixV01(input: unknown):
  | Readonly<{ ok: true; state: S37ProductHostActivationStateV01 }>
  | Readonly<{ ok: false; reason: "LEDGER_EVENT_SCHEMA_INVALID" | "LEDGER_HASH_CHAIN_INVALID" | "LEDGER_HISTORY_INVALID" }> {
  if (!Array.isArray(input)) return { ok: false, reason: "LEDGER_EVENT_SCHEMA_INVALID" };
  const events: S37ProductHostActivationEventV01Value[] = [];
  for (const candidate of input) {
    const parsed = S37ProductHostActivationEventV01.safeParse(candidate);
    if (!parsed.success) return { ok: false, reason: "LEDGER_EVENT_SCHEMA_INVALID" };
    events.push(parsed.data);
  }
  if (events.length === 0) return { ok: true, state: stateFor(events) };
  const history = validateHistory(events);
  return history === null ? { ok: true, state: stateFor(events) } : { ok: false, reason: history };
}

export function resolveS37ProductHostActivationOutcomeV01(values: readonly S37ProductHostActivationOutcomeV01[]): S37ProductHostActivationOutcomeV01 {
  const parsed = z.array(Outcome).safeParse(values);
  if (!parsed.success) throw new TypeError("activation outcomes must use the closed outcome set");
  const precedence: readonly S37ProductHostActivationOutcomeV01[] = [
    "OUTCOME_UNKNOWN", "RECOVERY_REQUIRED", "NOT_COMMITTED", "NOT_STARTED", "COMPLETED",
  ];
  return precedence.find((value) => parsed.data.includes(value)) ?? "NOT_STARTED";
}
