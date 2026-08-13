import { z, type ZodType } from "zod";

import { canonicalize, hashCanonical, hashRawBytes } from "../hash.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";
import {
  ArtifactRecordV02,
  RedactionDerivativeRecordV02,
  TaskResultV02,
  compareRuntimeUtf8BytesV02,
  type RuntimeEventV02Value,
} from "../schema/runtime.js";

export type RuntimeRecordAdmissionReasonV02 =
  | "RUNTIME_RECORD_MISSING"
  | "RUNTIME_RECORD_HASH_INVALID"
  | "RUNTIME_RECORD_SCHEMA_INVALID"
  | "RUNTIME_SCHEMA_INVENTORY_INVALID";

export type RuntimeRecordAdmissionInputV02 = Readonly<{
  events: readonly RuntimeEventV02Value[];
  run_id: string;
  plan_hash: string;
  record_bytes_by_path: ReadonlyMap<string, Uint8Array>;
  raw_hash_by_path: ReadonlyMap<string, string>;
}>;

export type RuntimeRecordAdmissionValueV02 = Readonly<{
  records_by_path: ReadonlyMap<string, unknown>;
  content_bytes_by_path: ReadonlyMap<string, Uint8Array>;
  ordered_paths: readonly string[];
}>;

export type RuntimeRecordAdmissionResultV02 =
  | Readonly<{ ok: true; value: RuntimeRecordAdmissionValueV02 }>
  | Readonly<{ ok: false; reason: RuntimeRecordAdmissionReasonV02 }>;

type RecordBinding = Readonly<{
  path: string;
  hash: string;
  id: string;
  event: RuntimeEventV02Value;
  schema: ZodType | null;
  content: Readonly<{ path: string; hash: string; size: number }> | null;
}>;

type BindingDerivationResult =
  | Readonly<{ ok: true; bindings: readonly RecordBinding[] }>
  | Readonly<{ ok: false; reason: "RUNTIME_SCHEMA_INVENTORY_INVALID" }>;

type RegistryRow = Readonly<{
  event_type: RuntimeEventV02Value["event_type"];
  id_field: string;
  event_path_field: string;
  event_hash_field: string;
  path_for_id: (id: string) => string;
  schema: ZodType | null;
  content_fields?: Readonly<{
    path: string;
    hash: string;
    size: string;
    path_for_id?: (id: string) => string;
  }>;
}>;

const row = (
  event_type: RegistryRow["event_type"],
  id_field: string,
  event_path_field: string,
  event_hash_field: string,
  prefix: string,
  schema: ZodType | null = null,
  content_fields?: RegistryRow["content_fields"],
): RegistryRow => ({
  event_type,
  id_field,
  event_path_field,
  event_hash_field,
  path_for_id: (id) => `${prefix}/${id}.json`,
  schema,
  ...(content_fields === undefined ? {} : { content_fields }),
});

/** Closed primary-runtime record/content registry; absent from the package root. */
export const RUNTIME_RECORD_FAMILY_REGISTRY_V02: readonly RegistryRow[] = Object.freeze([
  row("artifact.recorded", "artifact_ref", "artifact_record_path", "artifact_record_hash", "artifacts/records", ArtifactRecordV02,
    { path: "artifact_path", hash: "content_hash", size: "size_bytes" }),
  row("record.redaction-derivative-recorded", "derivative_ref", "derivative_record_path", "derivative_record_hash", "custody/derivatives/pre-seal", RedactionDerivativeRecordV02,
    { path: "derivative_content_path", hash: "derivative_content_hash", size: "derivative_size_bytes",
      path_for_id: (id) => `custody/derivatives/pre-seal/${id}.bin` }),
  row("task.execution-completed", "result_id", "result_path", "result_hash", "task-results", TaskResultV02),
  row("task.execution-failed", "result_id", "result_path", "result_hash", "task-results", TaskResultV02),
  row("evidence.recorded", "evidence_id", "record_path", "record_hash", "evidence/records", null,
    { path: "content_path", hash: "content_hash", size: "size_bytes",
      path_for_id: (id) => `evidence/content/${id}.bin` }),
  row("authority.human-authorization-recorded", "authorization_id", "record_path", "record_hash", "authorities/human"),
  row("authority.envelope-recorded", "authority_envelope_id", "record_path", "record_hash", "authorities/envelopes"),
  row("authority.waiver-recorded", "authority_record_id", "record_path", "record_hash", "authorities/gate-waivers"),
  row("approval.recommendation-recorded", "recommendation_id", "record_path", "record_hash", "authorities/recommendations"),
  row("authority.grant-revoked", "revocation_id", "record_path", "record_hash", "authorities/revocations"),
  row("observation.manual-recorded", "observation_id", "record_path", "record_hash", "observations"),
  row("record.export-decision-recorded", "decision_id", "record_path", "record_hash", "export-decisions"),
  row("claim.recorded", "claim_id", "record_path", "record_hash", "claims"),
  row("finding.recorded", "finding_id", "record_path", "record_hash", "findings"),
  row("waiver.recorded", "waiver_id", "record_path", "record_hash", "waivers"),
  row("gate.result-recorded", "result_id", "record_path", "record_hash", "gates"),
  row("evaluation.result-recorded", "result_id", "record_path", "record_hash", "evaluations"),
]);

const REGISTRY_BY_EVENT = new Map(RUNTIME_RECORD_FAMILY_REGISTRY_V02.map((entry) => [entry.event_type, entry]));

function fail(reason: RuntimeRecordAdmissionReasonV02): RuntimeRecordAdmissionResultV02 {
  return { ok: false, reason };
}

function payloadOf(event: RuntimeEventV02Value): Record<string, unknown> {
  return event.payload as unknown as Record<string, unknown>;
}

function strictPayloadRecordSchema(payload: Record<string, unknown>): ZodType {
  const shape = Object.fromEntries(["schema_version", ...Object.keys(payload)].map((key) => [key, z.unknown()]));
  return z.object(shape).strict();
}

function deriveBindings(events: readonly RuntimeEventV02Value[]): BindingDerivationResult {
  const bindings: RecordBinding[] = [];
  const ownedPaths = new Set<string>();
  for (const event of events) {
    const registry = REGISTRY_BY_EVENT.get(event.event_type);
    if (registry === undefined) continue;
    const payload = payloadOf(event);
    const id = payload[registry.id_field];
    const path = payload[registry.event_path_field];
    const hash = payload[registry.event_hash_field];
    if (typeof id !== "string" || typeof path !== "string" || typeof hash !== "string"
      || path !== registry.path_for_id(id) || ownedPaths.has(path)) {
      return { ok: false, reason: "RUNTIME_SCHEMA_INVENTORY_INVALID" };
    }
    ownedPaths.add(path);

    let content: RecordBinding["content"] = null;
    if (registry.content_fields !== undefined) {
      const contentPath = payload[registry.content_fields.path];
      const contentHash = payload[registry.content_fields.hash];
      const contentSize = payload[registry.content_fields.size];
      const allNull = contentPath === null && contentHash === null && contentSize === null;
      if (!allNull) {
        if (typeof contentPath !== "string" || typeof contentHash !== "string"
          || !Number.isSafeInteger(contentSize) || (contentSize as number) < 0 || ownedPaths.has(contentPath)
          || (registry.content_fields.path_for_id !== undefined
            && contentPath !== registry.content_fields.path_for_id(id))) {
          return { ok: false, reason: "RUNTIME_SCHEMA_INVENTORY_INVALID" };
        }
        ownedPaths.add(contentPath);
        content = { path: contentPath, hash: contentHash, size: contentSize as number };
      }
    }
    bindings.push({ path, hash, id, event, schema: registry.schema, content });
  }
  return { ok: true, bindings };
}

function selectedEventBindingsMatch(record: Record<string, unknown>, binding: RecordBinding): boolean {
  const payload = payloadOf(binding.event);
  for (const [key, eventValue] of Object.entries(payload)) {
    if (Object.hasOwn(record, key) && canonicalize(record[key]) !== canonicalize(eventValue)) return false;
  }
  if (Object.hasOwn(record, "run_id") && record.run_id !== binding.event.run_id) return false;
  return true;
}

export function admitRuntimeRecordsV02(
  input: RuntimeRecordAdmissionInputV02,
): RuntimeRecordAdmissionResultV02 {
  try {
    if (input.events.some((event) => event.run_id !== input.run_id)) {
      return fail("RUNTIME_RECORD_SCHEMA_INVALID");
    }
    const derived = deriveBindings(input.events);
    if (!derived.ok) return derived;
    const bindings = derived.bindings;
    const expectedPaths = new Set(bindings.flatMap((binding) => [binding.path, ...(binding.content === null ? [] : [binding.content.path])]));
    for (const path of expectedPaths) {
      if (!input.record_bytes_by_path.has(path)) return fail("RUNTIME_RECORD_MISSING");
    }
    if (input.record_bytes_by_path.size !== expectedPaths.size
      || [...input.record_bytes_by_path.keys()].some((path) => !expectedPaths.has(path))
      || input.raw_hash_by_path.size !== expectedPaths.size
      || [...input.raw_hash_by_path.keys()].some((path) => !expectedPaths.has(path))) {
      return fail("RUNTIME_SCHEMA_INVENTORY_INVALID");
    }

    const records = new Map<string, unknown>();
    const contents = new Map<string, Uint8Array>();
    for (const binding of [...bindings].sort((left, right) => compareRuntimeUtf8BytesV02(left.path, right.path))) {
      const bytes = input.record_bytes_by_path.get(binding.path)!;
      if (input.raw_hash_by_path.get(binding.path) !== hashRawBytes(bytes)) return fail("RUNTIME_RECORD_HASH_INVALID");
      const decoded = decodeStructuredDocumentV02(bytes, "json");
      if (!decoded.ok || typeof decoded.value !== "object" || decoded.value === null || Array.isArray(decoded.value)) {
        return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      }
      const record = decoded.value as Record<string, unknown>;
      const schema = binding.schema ?? strictPayloadRecordSchema(payloadOf(binding.event));
      if (!schema.safeParse(record).success) return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      if (record.schema_version !== "0.2" || typeof record.record_hash !== "string") return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      const { record_hash: recordHash, ...preimage } = record;
      if (recordHash !== hashCanonical(preimage) || recordHash !== binding.hash) return fail("RUNTIME_RECORD_HASH_INVALID");
      if (Object.hasOwn(record, "run_id") && record.run_id !== input.run_id) return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      if (Object.hasOwn(record, "plan_hash") && record.plan_hash !== input.plan_hash) return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      if (!selectedEventBindingsMatch(record, binding)) return fail("RUNTIME_RECORD_SCHEMA_INVALID");
      records.set(binding.path, Object.freeze(record));

      if (binding.content !== null) {
        const contentBytes = input.record_bytes_by_path.get(binding.content.path)!;
        const rawHash = hashRawBytes(contentBytes);
        if (input.raw_hash_by_path.get(binding.content.path) !== rawHash
          || rawHash !== binding.content.hash || contentBytes.byteLength !== binding.content.size) {
          return fail("RUNTIME_RECORD_HASH_INVALID");
        }
        contents.set(binding.content.path, new Uint8Array(contentBytes));
      }
    }

    const orderedPaths = Object.freeze([...expectedPaths].sort(compareRuntimeUtf8BytesV02));
    return {
      ok: true,
      value: Object.freeze({ records_by_path: records, content_bytes_by_path: contents, ordered_paths: orderedPaths }),
    };
  } catch {
    return fail("RUNTIME_RECORD_SCHEMA_INVALID");
  }
}
