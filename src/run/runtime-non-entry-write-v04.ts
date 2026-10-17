import { isProxy } from "node:util/types";

import { z } from "zod";

import { hashCanonical } from "../hash.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../schema/runtime-v04.js";
import { LedgerRefV02 } from "../schema/runtime.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import {
  buildRunManifestV04,
  inspectRunManifestV04,
  type ValidatedRunManifestV04,
} from "./runtime-manifest-v04.js";
import {
  closeRuntimeFileStoreSessionV04,
  commitRuntimeFileStoreSessionV04,
  openRuntimeFileStoreSessionV04,
  readRuntimeFileStoreSessionSnapshotV04,
  type CapturedRuntimeFileStoreV04,
  type RuntimeFileStoreSessionV04,
  type RuntimeFileStoreSessionSnapshotV04,
} from "./runtime-file-store-v04.js";
import {
  inspectRuntimeLedgerV04,
  type ValidatedRuntimeLedgerV04,
} from "./runtime-ledger-v04.js";
import {
  inspectRuntimePlanV03,
  type ValidatedRuntimePlanV03,
} from "./project-plan-v03.js";
import { reduceRuntimeEventPrefixV04 } from "./runtime-state-reducer-v04.js";
import {
  consumeRuntimeClockObservationV04,
  type CapturedRuntimeClockObservationV04,
} from "./runtime-clock-observation-v04.js";

declare const runtimeNonEntryAcknowledgementBrandV04: unique symbol;
declare const runtimeTerminationEvidenceBrandV04: unique symbol;

type LedgerRef = Readonly<z.infer<typeof LedgerRefV02>>;
type ActionAdmissionPayloadV04 = Extract<
  RuntimeEventV04Value,
  Readonly<{ event_type: "task.action-admitted" }>
>["payload"];

type AdmissionPayload = Readonly<{
  action_id: string;
  task_ref: string;
  attempt_event_ref: LedgerRef;
  fence_epoch: number;
  side_effect_refs: readonly string[];
  action_proposal_id: string;
  action_proposal_hash: string;
  action_actor_ref: string;
  action_actor_stable_identity_hash: string;
  on_behalf_of_chain_hash: string;
  repository_root_ref: string;
  repository_base_ref_identity_hash: string;
  repository_pre_state_hash: string;
  authorized_change_set_hash: string;
  normalized_dispatch_hash: string;
  policy_action_kind: ActionAdmissionPayloadV04["policy_action_kind"];
  action_approval_class: "automatic" | "agency";
}>;

type RepositoryState = Readonly<{
  repository_root_ref: string;
  base_ref_identity_hash: string;
  head: Readonly<{ algorithm: "sha1" | "sha256"; value: string }>;
  merge_base: Readonly<{ algorithm: "sha1" | "sha256"; value: string }>;
  head_state_hash: string;
  tracked_diff_hash: string;
  staged_diff_hash: string;
  untracked_content_hash: string;
  submodule_state_hash: string;
  repository_state_hash: string;
}>;

export type CapturedRuntimeNonEntryAcknowledgementV04 = Readonly<{
  [runtimeNonEntryAcknowledgementBrandV04]: never;
}>;

export type CapturedRuntimeTerminationEvidenceV04 = Readonly<{
  [runtimeTerminationEvidenceBrandV04]: never;
}>;

const WriteRuntimeNonEntryInputV04 = z.object({
  action_admission_event_ref: LedgerRefV02,
  acknowledgement: z.custom<CapturedRuntimeNonEntryAcknowledgementV04>(),
  termination: z.custom<CapturedRuntimeTerminationEvidenceV04>(),
  acknowledged_event_id: MachineIdV02,
  termination_event_id: MachineIdV02,
  reconciliation_event_id: MachineIdV02,
  effect_outcome_event_ids: z.array(MachineIdV02).min(1),
  settled_event_id: MachineIdV02,
}).strict();

type NonEntryAcknowledgementEvidenceV04Value = Readonly<{
  recorded_at: string;
  action_admission_event_ref: LedgerRef;
  action_id: string;
  task_ref: string;
  attempt_event_ref: LedgerRef;
  adapter_invocation_id: string;
  adapter_ref: string;
  adapter_version_hash: string;
  fence_epoch: number;
  host_identity_hash: string;
  boot_id_hash: string;
  unit_name_hash: string;
  cgroup_path_hash: string;
  acknowledgement_observation_hash: string;
}>;
type TerminationEvidenceV04Value = Readonly<{
  recorded_at: string;
  action_admission_event_ref: LedgerRef;
  adapter_invocation_id: string;
  host_identity_hash: string;
  boot_id_hash: string;
  unit_name_hash: string;
  cgroup_path_hash: string;
  termination_request_hash: string;
  termination_observation_hash: string;
  observed_outcome: "terminated" | "not-terminated" | "unknown";
}>;

export type CaptureRuntimeNonEntryAcknowledgementV04Result =
  | Readonly<{ ok: true; value: CapturedRuntimeNonEntryAcknowledgementV04 }>
  | Readonly<{ ok: false; error: "RUNTIME_NON_ENTRY_ACKNOWLEDGEMENT_INVALID" }>;

export type CaptureRuntimeTerminationEvidenceV04Result =
  | Readonly<{ ok: true; value: CapturedRuntimeTerminationEvidenceV04 }>
  | Readonly<{ ok: false; error: "RUNTIME_NON_ENTRY_TERMINATION_INVALID" }>;

export type WriteRuntimeNonEntryReconciliationV04Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      acknowledgement_event_ref: LedgerRef;
      termination_event_ref: LedgerRef;
      reconciliation_event_ref: LedgerRef;
      settled_event_ref: LedgerRef;
      ledger_bytes_hash: string;
      manifest_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_NON_ENTRY_INPUT_INVALID"
        | "RUNTIME_NON_ENTRY_ACKNOWLEDGEMENT_INVALID"
        | "RUNTIME_NON_ENTRY_TERMINATION_INVALID"
        | "RUNTIME_NON_ENTRY_PREFIX_INVALID"
        | "RUNTIME_NON_ENTRY_REFUSED"
        | "RUNTIME_NON_ENTRY_NOT_COMMITTED"
        | "RUNTIME_NON_ENTRY_OUTCOME_UNKNOWN";
      refusal_reason?: string;
    }>;

const nonEntryAcknowledgements = new WeakMap<object, NonEntryAcknowledgementEvidenceV04Value>();
const terminationEvidence = new WeakMap<object, TerminationEvidenceV04Value>();

const INVALID_ACKNOWLEDGEMENT = Object.freeze({
  ok: false,
  error: "RUNTIME_NON_ENTRY_ACKNOWLEDGEMENT_INVALID",
} as const);
const INVALID_TERMINATION = Object.freeze({
  ok: false,
  error: "RUNTIME_NON_ENTRY_TERMINATION_INVALID",
} as const);

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

function exactDataDescriptors(
  input: unknown,
  expectedKeys: readonly string[],
): Readonly<Record<string, PropertyDescriptor>> | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)
      || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
      || Object.getOwnPropertySymbols(input).length !== 0) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (Object.keys(descriptors).sort().join("\u0000") !== [...expectedKeys].sort().join("\u0000")) return null;
    if (expectedKeys.some((key) => {
      const descriptor = descriptors[key];
      return descriptor === undefined || descriptor.enumerable !== true
        || descriptor.get !== undefined || descriptor.set !== undefined
        || !("value" in descriptor);
    })) return null;
    return descriptors;
  } catch {
    return null;
  }
}

function exactStringArray(input: unknown): readonly string[] | null {
  try {
    if (!Array.isArray(input) || isProxy(input)
      || Object.getPrototypeOf(input) !== Array.prototype
      || Reflect.ownKeys(input).some((key) => typeof key === "symbol")) return null;
    return input.every((entry) => typeof entry === "string")
      ? Object.freeze([...input])
      : null;
  } catch {
    return null;
  }
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function refOf(event: Readonly<{ sequence: number; event_hash: string }>): LedgerRef {
  return Object.freeze({ ledger_sequence: event.sequence, event_hash: event.event_hash });
}

function sameRef(left: LedgerRef, right: LedgerRef): boolean {
  return left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

export function captureRuntimeNonEntryAcknowledgementV04(
  input: unknown,
): CaptureRuntimeNonEntryAcknowledgementV04Result {
  const keys = [
    "observation",
    "action_admission_event_ref",
    "action_id",
    "task_ref",
    "attempt_event_ref",
    "adapter_invocation_id",
    "adapter_ref",
    "adapter_version_hash",
    "fence_epoch",
    "host_identity_hash",
    "boot_id_hash",
    "unit_name_hash",
    "cgroup_path_hash",
    "acknowledgement_observation_hash",
  ] as const;
  const descriptors = exactDataDescriptors(input, keys);
  if (descriptors === null) {
    return INVALID_ACKNOWLEDGEMENT;
  }
  const admissionRef = descriptors.action_admission_event_ref!.value;
  const attemptRef = descriptors.attempt_event_ref!.value;
  const observed = consumeRuntimeClockObservationV04(
    descriptors.observation!.value as CapturedRuntimeClockObservationV04,
  );
  const stringFields = [
    descriptors.action_id!.value,
    descriptors.task_ref!.value,
    descriptors.adapter_invocation_id!.value,
    descriptors.adapter_ref!.value,
    descriptors.adapter_version_hash!.value,
    descriptors.host_identity_hash!.value,
    descriptors.boot_id_hash!.value,
    descriptors.unit_name_hash!.value,
    descriptors.cgroup_path_hash!.value,
    descriptors.acknowledgement_observation_hash!.value,
  ];
  if (observed === null
    || !stringFields.every((value) => typeof value === "string" && value.length > 0)
    || typeof admissionRef !== "object" || admissionRef === null
    || typeof attemptRef !== "object" || attemptRef === null
    || !isSafeNonNegativeInteger(descriptors.fence_epoch!.value)) {
    return INVALID_ACKNOWLEDGEMENT;
  }
  const capability = Object.freeze({}) as CapturedRuntimeNonEntryAcknowledgementV04;
  nonEntryAcknowledgements.set(capability, freezeDeep({
    recorded_at: observed.observed_at,
    action_admission_event_ref: freezeDeep(structuredClone(admissionRef as LedgerRef)),
    action_id: descriptors.action_id!.value as string,
    task_ref: descriptors.task_ref!.value as string,
    attempt_event_ref: freezeDeep(structuredClone(attemptRef as LedgerRef)),
    adapter_invocation_id: descriptors.adapter_invocation_id!.value as string,
    adapter_ref: descriptors.adapter_ref!.value as string,
    adapter_version_hash: descriptors.adapter_version_hash!.value as string,
    fence_epoch: descriptors.fence_epoch!.value as number,
    host_identity_hash: descriptors.host_identity_hash!.value as string,
    boot_id_hash: descriptors.boot_id_hash!.value as string,
    unit_name_hash: descriptors.unit_name_hash!.value as string,
    cgroup_path_hash: descriptors.cgroup_path_hash!.value as string,
    acknowledgement_observation_hash: descriptors.acknowledgement_observation_hash!.value as string,
  } satisfies NonEntryAcknowledgementEvidenceV04Value));
  return Object.freeze({ ok: true, value: capability });
}

export function inspectCapturedRuntimeNonEntryAcknowledgementV04(
  capability: unknown,
): NonEntryAcknowledgementEvidenceV04Value | null {
  if ((typeof capability !== "object" && typeof capability !== "function") || capability === null) return null;
  const binding = nonEntryAcknowledgements.get(capability);
  return binding === undefined ? null : freezeDeep(structuredClone(binding));
}

export function consumeCapturedRuntimeNonEntryAcknowledgementV04(
  capability: unknown,
): NonEntryAcknowledgementEvidenceV04Value | null {
  if ((typeof capability !== "object" && typeof capability !== "function") || capability === null) return null;
  const binding = nonEntryAcknowledgements.get(capability);
  if (binding === undefined) return null;
  nonEntryAcknowledgements.delete(capability);
  return freezeDeep(structuredClone(binding));
}

export function captureRuntimeTerminationEvidenceV04(
  input: unknown,
): CaptureRuntimeTerminationEvidenceV04Result {
  const keys = [
    "observation",
    "action_admission_event_ref",
    "adapter_invocation_id",
    "host_identity_hash",
    "boot_id_hash",
    "unit_name_hash",
    "cgroup_path_hash",
    "termination_request_hash",
    "termination_observation_hash",
    "observed_outcome",
  ] as const;
  const descriptors = exactDataDescriptors(input, keys);
  if (descriptors === null) {
    return INVALID_TERMINATION;
  }
  const observed = consumeRuntimeClockObservationV04(
    descriptors.observation!.value as CapturedRuntimeClockObservationV04,
  );
  const stringFields = [
    descriptors.adapter_invocation_id!.value,
    descriptors.host_identity_hash!.value,
    descriptors.boot_id_hash!.value,
    descriptors.unit_name_hash!.value,
    descriptors.cgroup_path_hash!.value,
    descriptors.termination_request_hash!.value,
    descriptors.termination_observation_hash!.value,
  ];
  if (observed === null
    || !stringFields.every((value) => typeof value === "string" && value.length > 0)
    || typeof descriptors.action_admission_event_ref!.value !== "object"
    || descriptors.action_admission_event_ref!.value === null
    || !["terminated", "not-terminated", "unknown"].includes(
      descriptors.observed_outcome!.value as string,
    )) {
    return INVALID_TERMINATION;
  }
  const capability = Object.freeze({}) as CapturedRuntimeTerminationEvidenceV04;
  terminationEvidence.set(capability, freezeDeep({
    recorded_at: observed.observed_at,
    action_admission_event_ref: freezeDeep(structuredClone(descriptors.action_admission_event_ref!.value as LedgerRef)),
    adapter_invocation_id: descriptors.adapter_invocation_id!.value as string,
    host_identity_hash: descriptors.host_identity_hash!.value as string,
    boot_id_hash: descriptors.boot_id_hash!.value as string,
    unit_name_hash: descriptors.unit_name_hash!.value as string,
    cgroup_path_hash: descriptors.cgroup_path_hash!.value as string,
    termination_request_hash: descriptors.termination_request_hash!.value as string,
    termination_observation_hash: descriptors.termination_observation_hash!.value as string,
    observed_outcome: descriptors.observed_outcome!.value as "terminated" | "not-terminated" | "unknown",
  } satisfies TerminationEvidenceV04Value));
  return Object.freeze({ ok: true, value: capability });
}

export function inspectCapturedRuntimeTerminationEvidenceV04(
  capability: unknown,
): TerminationEvidenceV04Value | null {
  if ((typeof capability !== "object" && typeof capability !== "function") || capability === null) return null;
  const binding = terminationEvidence.get(capability);
  return binding === undefined ? null : freezeDeep(structuredClone(binding));
}

export function consumeCapturedRuntimeTerminationEvidenceV04(
  capability: unknown,
): TerminationEvidenceV04Value | null {
  if ((typeof capability !== "object" && typeof capability !== "function") || capability === null) return null;
  const binding = terminationEvidence.get(capability);
  if (binding === undefined) return null;
  terminationEvidence.delete(capability);
  return freezeDeep(structuredClone(binding));
}

type InspectedStore = Readonly<{
  snapshot: RuntimeFileStoreSessionSnapshotV04;
  plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
}>;

type OpenedInspectedStore = Readonly<{
  ok: true;
  session: RuntimeFileStoreSessionV04;
  inspected: InspectedStore;
}>;

type OpenedInspectedStoreFailure = Readonly<{
  ok: false;
  classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN";
  error: "RUNTIME_NON_ENTRY_PREFIX_INVALID" | "RUNTIME_NON_ENTRY_OUTCOME_UNKNOWN";
}>;

function capturedFilesWithLedger(
  snapshot: RuntimeFileStoreSessionSnapshotV04,
  ledgerBytes: Uint8Array,
) {
  return snapshot.captured_files.map((file) => Object.freeze({
    path: file.path,
    family: file.family,
    required: file.required,
    mode: file.path === "ledger.jsonl" ? 384 as const : file.mode,
    bytes: file.path === "ledger.jsonl"
      ? new Uint8Array(ledgerBytes)
      : file.bytes === null ? null : new Uint8Array(file.bytes),
  }));
}

function inspectStoreSnapshot(
  store: CapturedRuntimeFileStoreV04,
): Promise<OpenedInspectedStore | OpenedInspectedStoreFailure> {
  return (async () => {
    const opened = await openRuntimeFileStoreSessionV04(store);
    if (!opened.ok) {
      return opened.error === "RUNTIME_FILE_STORE_POISONED"
        ? Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_NON_ENTRY_OUTCOME_UNKNOWN" as const })
        : Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_PREFIX_INVALID" as const });
    }
    const read = readRuntimeFileStoreSessionSnapshotV04(opened.session);
    if (!read.ok) {
      await closeRuntimeFileStoreSessionV04(opened.session);
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_PREFIX_INVALID" as const });
    }
    const plan = inspectRuntimePlanV03(read.snapshot.resolved_run_plan_bytes);
    const ledger = inspectRuntimeLedgerV04(read.snapshot.ledger_bytes);
    if (!plan.ok || !ledger.ok) {
      await closeRuntimeFileStoreSessionV04(opened.session);
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_PREFIX_INVALID" as const });
    }
    const manifest = inspectRunManifestV04({
      manifest_bytes: read.snapshot.manifest_bytes,
      ledger_bytes: read.snapshot.ledger_bytes,
      captured_files: capturedFilesWithLedger(read.snapshot, read.snapshot.ledger_bytes),
    });
    if (!manifest.ok
      || plan.validated_plan.run_id !== ledger.ledger.run_id
      || plan.validated_plan.plan_hash !== ledger.ledger.plan_hash
      || manifest.manifest.run_id !== ledger.ledger.run_id
      || manifest.manifest.plan_hash !== ledger.ledger.plan_hash) {
      await closeRuntimeFileStoreSessionV04(opened.session);
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_PREFIX_INVALID" as const });
    }
    return Object.freeze({
      ok: true,
      session: opened.session,
      inspected: Object.freeze({
        snapshot: read.snapshot,
        plan: plan.validated_plan,
        ledger: manifest.ledger,
        manifest: manifest.validated_manifest,
      }),
    });
  })();
}

function event(
  prior: readonly RuntimeEventV04Value[],
  envelope: Readonly<{ event_id: string; recorded_at: string }>,
  eventType: RuntimeEventV04Value["event_type"],
  source: RuntimeEventV04Value["source"],
  authorityRef: string | null,
  riskTier: RuntimeEventV04Value["risk_tier"],
  payload: unknown,
): RuntimeEventV04Value | null {
  const sequence = prior.length + 1;
  const preimage = {
    schema_version: "0.4" as const,
    event_id: envelope.event_id,
    run_id: prior[0]!.run_id,
    sequence,
    recorded_at: envelope.recorded_at,
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

function appendLedgerBytes(source: Uint8Array, events: readonly RuntimeEventV04Value[]): Uint8Array {
  const encoder = new TextEncoder();
  const tail = encoder.encode(events.map((row) => `${JSON.stringify(row)}\n`).join(""));
  const joined = new Uint8Array(source.byteLength + tail.byteLength);
  joined.set(source, 0);
  joined.set(tail, source.byteLength);
  return joined;
}

function nextState(
  inspected: InspectedStore,
  events: readonly RuntimeEventV04Value[],
): Readonly<{ ledger_bytes: Uint8Array; manifest_bytes: Uint8Array }> | null {
  const ledgerBytes = appendLedgerBytes(inspected.snapshot.ledger_bytes, events);
  const built = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: inspected.manifest.created_at,
    captured_files: capturedFilesWithLedger(inspected.snapshot, ledgerBytes),
  });
  return built.ok
    ? Object.freeze({ ledger_bytes: ledgerBytes, manifest_bytes: built.bytes })
    : null;
}

function actionFactMatches(event: RuntimeEventV04Value, actionId: string): boolean {
  const payload = event.payload as Record<string, unknown>;
  return payload.action_id === actionId && [
    "task.execution-started",
    "task.execution-completed",
    "task.execution-failed",
    "task.progress-fact-recorded",
    "task.action-outcome-unknown",
    "task.execution-non-entry-acknowledged",
    "task.action-outcome-reconciled",
    "effect.outcome",
    "task.action-settled",
  ].includes(event.event_type);
}

function eventAt(
  ledger: ValidatedRuntimeLedgerV04,
  reference: LedgerRef,
): RuntimeEventV04Value | null {
  const candidate = ledger.events[reference.ledger_sequence - 1];
  return candidate?.event_hash === reference.event_hash ? candidate : null;
}

function currentRepositoryState(
  plan: ValidatedRuntimePlanV03,
  ledger: ValidatedRuntimeLedgerV04,
): RepositoryState {
  const settlement = [...ledger.events].reverse().find((event) => event.event_type === "task.action-settled");
  const source = settlement?.event_type === "task.action-settled"
    ? settlement.payload.repository_post_state
    : plan.plan.authority_subject.repository.initial_state;
  return freezeDeep(structuredClone(source)) as RepositoryState;
}

function effectOutcomeIds(value: unknown): readonly string[] | null {
  const captured = exactStringArray(value);
  if (captured === null || captured.length === 0) return null;
  return new Set(captured).size === captured.length ? captured : null;
}

function parseWriteInput(input: unknown): z.infer<typeof WriteRuntimeNonEntryInputV04> | null {
  const record = exactDataDescriptors(input, [
    "action_admission_event_ref",
    "acknowledgement",
    "termination",
    "acknowledged_event_id",
    "termination_event_id",
    "reconciliation_event_id",
    "effect_outcome_event_ids",
    "settled_event_id",
  ]);
  if (record === null) return null;
  const ids = effectOutcomeIds(record.effect_outcome_event_ids?.value);
  if (ids === null
    || exactDataDescriptors(record.action_admission_event_ref?.value, ["ledger_sequence", "event_hash"]) === null) return null;
  const candidate = {
    action_admission_event_ref: record.action_admission_event_ref!.value,
    acknowledgement: record.acknowledgement!.value,
    termination: record.termination!.value,
    acknowledged_event_id: record.acknowledged_event_id!.value,
    termination_event_id: record.termination_event_id!.value,
    reconciliation_event_id: record.reconciliation_event_id!.value,
    effect_outcome_event_ids: ids,
    settled_event_id: record.settled_event_id!.value,
  };
  const parsed = WriteRuntimeNonEntryInputV04.safeParse(candidate);
  return parsed.success ? parsed.data : null;
}

function commitFailure(
  committed: Awaited<ReturnType<typeof commitRuntimeFileStoreSessionV04>>,
): Extract<WriteRuntimeNonEntryReconciliationV04Result, { ok: false }> {
  return committed.classification === "OUTCOME_UNKNOWN"
    ? Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_NON_ENTRY_OUTCOME_UNKNOWN" })
    : Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_NOT_COMMITTED" });
}

function asAdmissionPayload(event: RuntimeEventV04Value): AdmissionPayload | null {
  if (event.event_type !== "task.action-admitted") return null;
  return event.payload as AdmissionPayload;
}

export async function writeRuntimeNonEntryReconciliationV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<WriteRuntimeNonEntryReconciliationV04Result> {
  const parsed = parseWriteInput(input);
  if (parsed === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_INPUT_INVALID" });
  }
  const opened = await inspectStoreSnapshot(store);
  if (!opened.ok) return opened;

  try {
    const acknowledgementPreview = inspectCapturedRuntimeNonEntryAcknowledgementV04(parsed.acknowledgement);
    if (acknowledgementPreview === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_ACKNOWLEDGEMENT_INVALID" });
    }
    const terminationPreview = inspectCapturedRuntimeTerminationEvidenceV04(parsed.termination);
    if (terminationPreview === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_TERMINATION_INVALID" });
    }
    const reduced = reduceRuntimeEventPrefixV04(opened.inspected.ledger.events);
    if (!reduced.ok) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_PREFIX_INVALID" });
    }
    const admission = eventAt(opened.inspected.ledger, parsed.action_admission_event_ref);
    const admissionPayload = admission === null ? null : asAdmissionPayload(admission);
    if (admission === null
      || admissionPayload === null
      || !sameRef(acknowledgementPreview.action_admission_event_ref, parsed.action_admission_event_ref)
      || !sameRef(terminationPreview.action_admission_event_ref, parsed.action_admission_event_ref)
      || !sameRef(acknowledgementPreview.action_admission_event_ref, terminationPreview.action_admission_event_ref)
      || acknowledgementPreview.action_id !== admissionPayload.action_id
      || acknowledgementPreview.task_ref !== admissionPayload.task_ref
      || !sameRef(acknowledgementPreview.attempt_event_ref, admissionPayload.attempt_event_ref)
      || acknowledgementPreview.fence_epoch !== admissionPayload.fence_epoch
      || terminationPreview.adapter_invocation_id !== acknowledgementPreview.adapter_invocation_id
      || terminationPreview.host_identity_hash !== acknowledgementPreview.host_identity_hash
      || terminationPreview.boot_id_hash !== acknowledgementPreview.boot_id_hash
      || terminationPreview.unit_name_hash !== acknowledgementPreview.unit_name_hash
      || terminationPreview.cgroup_path_hash !== acknowledgementPreview.cgroup_path_hash) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_REFUSED", refusal_reason: "admission-or-evidence-mismatch" });
    }
    const matchedAdmission = admission;
    if (!reduced.state.in_flight_action_ids.includes(admissionPayload.action_id)) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_REFUSED", refusal_reason: "action-not-in-flight" });
    }
    const contradictory = opened.inspected.ledger.events
      .slice(matchedAdmission.sequence)
      .find((candidate) => actionFactMatches(candidate, admissionPayload.action_id));
    if (contradictory !== undefined) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_REFUSED", refusal_reason: "contradictory-action-fact" });
    }
    const terminationAlready = opened.inspected.ledger.events.find((candidate) => candidate.event_type === "process.termination-attempted"
      && sameRef((candidate.payload as Readonly<{ action_admission_event_ref: LedgerRef }>).action_admission_event_ref, parsed.action_admission_event_ref));
    if (terminationAlready !== undefined) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_REFUSED", refusal_reason: "termination-already-recorded" });
    }
    if (terminationPreview.observed_outcome !== "terminated") {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_REFUSED", refusal_reason: "termination-unproven" });
    }
    if (Date.parse(terminationPreview.recorded_at) < Date.parse(acknowledgementPreview.recorded_at)) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_REFUSED", refusal_reason: "termination-precedes-acknowledgement" });
    }
    if (admissionPayload.side_effect_refs.length !== parsed.effect_outcome_event_ids.length) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_INPUT_INVALID" });
    }
    const repositoryState = currentRepositoryState(opened.inspected.plan, opened.inspected.ledger);
    if (repositoryState.repository_state_hash !== admissionPayload.repository_pre_state_hash
      || repositoryState.repository_root_ref !== admissionPayload.repository_root_ref
      || repositoryState.base_ref_identity_hash !== admissionPayload.repository_base_ref_identity_hash) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_REFUSED", refusal_reason: "repository-state-drift" });
    }
    const acknowledgement = consumeCapturedRuntimeNonEntryAcknowledgementV04(parsed.acknowledgement);
    const termination = consumeCapturedRuntimeTerminationEvidenceV04(parsed.termination);
    if (acknowledgement === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_ACKNOWLEDGEMENT_INVALID" });
    }
    if (termination === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_TERMINATION_INVALID" });
    }

    const riskTier = matchedAdmission.risk_tier;
    const acknowledgementEvent = event(opened.inspected.ledger.events, {
      event_id: parsed.acknowledged_event_id,
      recorded_at: acknowledgement.recorded_at,
    }, "task.execution-non-entry-acknowledged", "adapter", null, riskTier, {
      action_id: acknowledgement.action_id,
      task_ref: acknowledgement.task_ref,
      admission_ref: parsed.action_admission_event_ref,
      attempt_event_ref: acknowledgement.attempt_event_ref,
      adapter_invocation_id: acknowledgement.adapter_invocation_id,
      adapter_ref: acknowledgement.adapter_ref,
      adapter_version_hash: acknowledgement.adapter_version_hash,
      fence_epoch: acknowledgement.fence_epoch,
      host_identity_hash: acknowledgement.host_identity_hash,
      boot_id_hash: acknowledgement.boot_id_hash,
      unit_name_hash: acknowledgement.unit_name_hash,
      cgroup_path_hash: acknowledgement.cgroup_path_hash,
      acknowledgement_observation_hash: acknowledgement.acknowledgement_observation_hash,
    });
    const terminationEvent = acknowledgementEvent === null ? null : event(
      [...opened.inspected.ledger.events, acknowledgementEvent],
      {
        event_id: parsed.termination_event_id,
        recorded_at: termination.recorded_at,
      },
      "process.termination-attempted",
      "adapter",
      null,
      riskTier,
      {
        trigger: "reconciliation",
        trigger_event_ref: refOf(acknowledgementEvent),
        action_admission_event_ref: parsed.action_admission_event_ref,
        adapter_invocation_id: termination.adapter_invocation_id,
        host_identity_hash: termination.host_identity_hash,
        boot_id_hash: termination.boot_id_hash,
        unit_name_hash: termination.unit_name_hash,
        cgroup_path_hash: termination.cgroup_path_hash,
        termination_request_hash: termination.termination_request_hash,
        termination_observation_hash: termination.termination_observation_hash,
        observed_outcome: termination.observed_outcome,
      },
    );
    const reconciliationEvent = terminationEvent === null ? null : event(
      [...opened.inspected.ledger.events, acknowledgementEvent!, terminationEvent],
      {
        event_id: parsed.reconciliation_event_id,
        recorded_at: termination.recorded_at,
      },
      "task.action-outcome-reconciled",
      "integrity",
      null,
      riskTier,
      {
        action_id: acknowledgement.action_id,
        task_ref: acknowledgement.task_ref,
        admission_ref: parsed.action_admission_event_ref,
        reconciliation_status: "proven-non-start",
        attempt_event_ref: acknowledgement.attempt_event_ref,
        adapter_invocation_id: acknowledgement.adapter_invocation_id,
        adapter_ref: acknowledgement.adapter_ref,
        adapter_version_hash: acknowledgement.adapter_version_hash,
        non_entry_ack_event_ref: refOf(acknowledgementEvent!),
        process_cannot_continue_ref: refOf(terminationEvent),
        fence_epoch: acknowledgement.fence_epoch,
      },
    );
    if (acknowledgementEvent === null || terminationEvent === null || reconciliationEvent === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_INPUT_INVALID" });
    }

    const emitted: RuntimeEventV04Value[] = [
      acknowledgementEvent,
      terminationEvent,
      reconciliationEvent,
    ];
    const effectOutcomes: Array<{
      effect_ref: string;
      outcome: "not-committed";
      outcome_event_ref: LedgerRef;
    }> = [];
    for (const [index, effectRef] of admissionPayload.side_effect_refs.entries()) {
      const effectEvent = event(
        [...opened.inspected.ledger.events, ...emitted],
        {
          event_id: parsed.effect_outcome_event_ids[index]!,
          recorded_at: termination.recorded_at,
        },
        "effect.outcome",
        "integrity",
        null,
        riskTier,
        {
          task_ref: acknowledgement.task_ref,
          effect_ref: effectRef,
          action_id: acknowledgement.action_id,
          outcome: "not-committed",
          evidence_refs: [refOf(reconciliationEvent)],
          reconciliation_event_ref: refOf(reconciliationEvent),
        },
      );
      if (effectEvent === null) {
        return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_INPUT_INVALID" });
      }
      emitted.push(effectEvent);
      effectOutcomes.push({
        effect_ref: effectRef,
        outcome: "not-committed",
        outcome_event_ref: refOf(effectEvent),
      });
    }
    const observedChangeSet = {
      repository_root_ref: repositoryState.repository_root_ref,
      base_ref_identity_hash: repositoryState.base_ref_identity_hash,
      repository_pre_state_hash: repositoryState.repository_state_hash,
      repository_post_state_hash: repositoryState.repository_state_hash,
      head_before: repositoryState.head,
      head_after: repositoryState.head,
      changes: [],
    };
    const settlementEvent = event(
      [...opened.inspected.ledger.events, ...emitted],
      {
        event_id: parsed.settled_event_id,
        recorded_at: termination.recorded_at,
      },
      "task.action-settled",
      "kernel",
      null,
      riskTier,
      {
        action_id: admissionPayload.action_id,
        task_ref: admissionPayload.task_ref,
        terminal_event_ref: refOf(reconciliationEvent),
        action_proposal_id: admissionPayload.action_proposal_id,
        action_proposal_hash: admissionPayload.action_proposal_hash,
        action_actor_ref: admissionPayload.action_actor_ref,
        action_actor_stable_identity_hash: admissionPayload.action_actor_stable_identity_hash,
        on_behalf_of_chain_hash: admissionPayload.on_behalf_of_chain_hash,
        repository_root_ref: admissionPayload.repository_root_ref,
        repository_base_ref_identity_hash: admissionPayload.repository_base_ref_identity_hash,
        repository_pre_state_hash: admissionPayload.repository_pre_state_hash,
        authorized_change_set_hash: admissionPayload.authorized_change_set_hash,
        normalized_dispatch_hash: admissionPayload.normalized_dispatch_hash,
        policy_action_kind: admissionPayload.policy_action_kind,
        action_approval_class: admissionPayload.action_approval_class,
        repository_post_state: repositoryState,
        repository_post_state_hash: repositoryState.repository_state_hash,
        observed_change_set: {
          ...observedChangeSet,
          observed_change_set_hash: hashCanonical({
            purpose: "observed-repository-change-set-v02",
            ...observedChangeSet,
          }),
        },
        observed_change_set_hash: hashCanonical({
          purpose: "observed-repository-change-set-v02",
          ...observedChangeSet,
        }),
        repository_transition_status: "unchanged",
        effect_outcomes: effectOutcomes,
      },
    );
    if (settlementEvent === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_INPUT_INVALID" });
    }
    const next = nextState(opened.inspected, [...emitted, settlementEvent]);
    if (next === null) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NON_ENTRY_INPUT_INVALID" });
    }
    const committed = await commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: opened.inspected.ledger.ledger_bytes_hash,
      expected_manifest_hash: opened.inspected.manifest.manifest_hash,
      next_ledger_bytes: next.ledger_bytes,
      next_manifest_bytes: next.manifest_bytes,
    });
    if (!committed.ok) return commitFailure(committed);
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      acknowledgement_event_ref: refOf(acknowledgementEvent),
      termination_event_ref: refOf(terminationEvent),
      reconciliation_event_ref: refOf(reconciliationEvent),
      settled_event_ref: refOf(settlementEvent),
      ledger_bytes_hash: committed.ledger_bytes_hash,
      manifest_hash: committed.manifest_hash,
    });
  } finally {
    await closeRuntimeFileStoreSessionV04(opened.session);
  }
}
