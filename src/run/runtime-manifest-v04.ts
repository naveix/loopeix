import { parseDocument } from "yaml";
import { z } from "zod";

import { hashCanonical, hashRawBytes } from "../hash.js";
import { RunManifestFileEntryV02 } from "../schema/runtime-manifests-v02.js";
import { RuntimeSchemaInventoryV04 } from "../schema/runtime-v04.js";
import { LedgerRefV02, compareRuntimeUtf8BytesV02 } from "../schema/runtime.js";
import { IsoTimestampV02, MachineIdV02 } from "../schema/scalars-v02.js";
import { Hash } from "../schema/scalars.js";
import {
  inspectRuntimeLedgerV04,
  isValidatedRuntimeLedgerV04,
  type ValidatedRuntimeLedgerV04,
} from "./runtime-ledger-v04.js";

const MAX_MANIFEST_BYTES = 16_777_216;
const MAX_CAPTURED_FILES = 10_000;
const validatedRunManifestsV04 = new WeakSet<object>();
const validatedManifestLedgerPairsV04 = new WeakMap<object, ValidatedRuntimeLedgerV04>();
const validatedManifestFilesV04 = new WeakMap<object, ReadonlyMap<string, Uint8Array | null>>();
const safeInteger = z.number().int().refine(Number.isSafeInteger, { message: "must be a safe integer" });

function isExactPlainData(value: unknown, seen = new Set<object>()): boolean {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object") return false;
  try {
    if (seen.has(value)) return false;
    seen.add(value);
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype
        || Reflect.ownKeys(value).some((key) => typeof key === "symbol")) return false;
      const descriptors = Object.getOwnPropertyDescriptors(value);
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor)
          || descriptor.get !== undefined || descriptor.set !== undefined
          || !isExactPlainData(descriptor.value, seen)) return false;
      }
      return Object.keys(descriptors).every((key) => key === "length" || /^(0|[1-9][0-9]*)$/u.test(key));
    }
    if (Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).some((key) => typeof key === "symbol")) return false;
    for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined
        || !isExactPlainData(descriptor.value, seen)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

const RunManifestTerminalV04 = z.object({
  outcome: z.enum(["completed", "held", "blocked", "failed", "stalled", "exhausted", "aborted"]),
  snapshot_hash: Hash,
  seal_event_ref: LedgerRefV02,
}).strict();

const SortedFileInventoryV04 = z.array(RunManifestFileEntryV02).max(MAX_CAPTURED_FILES).superRefine((rows, ctx) => {
  for (const [index, row] of rows.entries()) {
    if (row.path === "run-manifest.json") {
      ctx.addIssue({ code: "custom", path: [index, "path"], message: "manifest may not inventory itself" });
    }
    if (index > 0 && compareRuntimeUtf8BytesV02(rows[index - 1]!.path, row.path) >= 0) {
      ctx.addIssue({ code: "custom", path: [index, "path"], message: "file inventory must be unique and sorted by UTF-8 bytes" });
    }
  }
});

const RunManifestV04Base = z.object({
  schema_version: z.literal("0.4"),
  run_id: MachineIdV02,
  plan_hash: Hash,
  execution_profile: z.literal("bounded-v04"),
  schema_versions: RuntimeSchemaInventoryV04,
  run_state: z.enum(["initialized", "running", "paused", "quarantined", "held", "aborting", "sealed"]),
  created_at: IsoTimestampV02,
  projection_event_ref: LedgerRefV02,
  ledger_bytes_hash: Hash,
  ledger_sequence: safeInteger.positive(),
  ledger_head_hash: Hash,
  current_fence_epoch: safeInteger.nonnegative(),
  terminal: RunManifestTerminalV04.nullable(),
  file_inventory: SortedFileInventoryV04,
  manifest_hash: Hash,
}).strict().superRefine((manifest, ctx) => {
  if (manifest.projection_event_ref.ledger_sequence !== manifest.ledger_sequence
    || manifest.projection_event_ref.event_hash !== manifest.ledger_head_hash) {
    ctx.addIssue({ code: "custom", path: ["projection_event_ref"], message: "projection event must equal the ledger head" });
  }
  if ((manifest.run_state === "sealed") !== (manifest.terminal !== null)) {
    ctx.addIssue({ code: "custom", path: ["terminal"], message: "terminal must exist exactly for sealed state" });
  }
  if (manifest.terminal !== null
    && (manifest.terminal.seal_event_ref.ledger_sequence !== manifest.ledger_sequence
      || manifest.terminal.seal_event_ref.event_hash !== manifest.ledger_head_hash)) {
    ctx.addIssue({ code: "custom", path: ["terminal", "seal_event_ref"], message: "terminal must name the exact seal head" });
  }
  const { manifest_hash: _manifestHash, ...preimage } = manifest;
  if (manifest.manifest_hash !== hashCanonical(preimage)) {
    ctx.addIssue({ code: "custom", path: ["manifest_hash"], message: "manifest hash must match the exact preimage" });
  }
});

export const RunManifestV04 = z.preprocess(
  (value) => isExactPlainData(value) ? value : undefined,
  RunManifestV04Base,
);

export type RunManifestV04Value = z.infer<typeof RunManifestV04>;
export type ValidatedRunManifestV04 = RunManifestV04Value & Readonly<{
  readonly __validated_run_manifest_v04: unique symbol;
}>;

export type RuntimeManifestV04FailureReason =
  | "MANIFEST_INPUT_INVALID"
  | "MANIFEST_SYNTAX_INVALID"
  | "MANIFEST_SCHEMA_INVALID"
  | "LEDGER_INVALID"
  | "LEDGER_STATE_UNPROJECTABLE"
  | "FILE_CAPTURE_INVALID"
  | "MANIFEST_CROSS_CHECK_INVALID";

export type RuntimeManifestV04BuildResult =
  | Readonly<{ ok: true; manifest: RunManifestV04Value; bytes: Uint8Array }>
  | Readonly<{ ok: false; reason: RuntimeManifestV04FailureReason }>;

export type RuntimeManifestV04InspectionResult =
  | Readonly<{
      ok: true;
      manifest: RunManifestV04Value;
      validated_manifest: ValidatedRunManifestV04;
      ledger: ValidatedRuntimeLedgerV04;
      bytes: Uint8Array;
    }>
  | Readonly<{ ok: false; reason: RuntimeManifestV04FailureReason }>;

export function isValidatedRunManifestV04(input: unknown): input is ValidatedRunManifestV04 {
  return typeof input === "object" && input !== null && validatedRunManifestsV04.has(input);
}

export function isValidatedRunManifestPairV04(
  manifest: unknown,
  ledger: unknown,
): manifest is ValidatedRunManifestV04 {
  return isValidatedRunManifestV04(manifest)
    && isValidatedRuntimeLedgerV04(ledger)
    && validatedManifestLedgerPairsV04.get(manifest) === ledger;
}

export type RuntimeManifestCapturedFileV04Result =
  | Readonly<{ ok: true; bytes: Uint8Array | null }>
  | Readonly<{ ok: false; reason: "MANIFEST_BRAND_INVALID" | "MANIFEST_FILE_NOT_CAPTURED" }>;

export function captureValidatedRunManifestFileV04(
  manifest: unknown,
  path: unknown,
): RuntimeManifestCapturedFileV04Result {
  if (!isValidatedRunManifestV04(manifest)) {
    return { ok: false, reason: "MANIFEST_BRAND_INVALID" };
  }
  const files = validatedManifestFilesV04.get(manifest);
  if (typeof path !== "string" || files === undefined || !files.has(path)) {
    return { ok: false, reason: "MANIFEST_FILE_NOT_CAPTURED" };
  }
  const bytes = files.get(path) ?? null;
  return { ok: true, bytes: bytes === null ? null : new Uint8Array(bytes) };
}

type CapturedFile = Readonly<{
  path: string;
  family: "primary" | "record" | "projection";
  required: boolean;
  mode: 384 | null;
  bytes: Uint8Array | null;
}>;

function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  try {
    if (typeof value !== "object" || value === null || Object.getPrototypeOf(value) !== Object.prototype) return null;
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.keys(descriptors).sort().join("|") !== [...keys].sort().join("|")) return null;
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined
        || descriptor.enumerable !== true) return null;
    }
    return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
  } catch {
    return null;
  }
}

function captureBytes(value: unknown, allowEmpty = false): Uint8Array | null {
  try {
    if (!(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype
      || value.buffer instanceof SharedArrayBuffer || (!allowEmpty && value.byteLength === 0)) return null;
    return new Uint8Array(value);
  } catch {
    return null;
  }
}

function captureFiles(value: unknown): readonly CapturedFile[] | null {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
    || value.length === 0 || value.length > MAX_CAPTURED_FILES) return null;
  const captured: CapturedFile[] = [];
  for (const candidate of value) {
    const row = exactObject(candidate, ["path", "family", "required", "mode", "bytes"]);
    if (row === null || typeof row.path !== "string"
      || (row.family !== "primary" && row.family !== "record" && row.family !== "projection")
      || typeof row.required !== "boolean" || (row.mode !== 384 && row.mode !== null)) return null;
    const bytes = row.bytes === null ? null : captureBytes(row.bytes, true);
    if (row.bytes !== null && bytes === null) return null;
    if ((bytes === null) !== (row.mode === null) || (bytes === null && row.required)) return null;
    captured.push({ path: row.path, family: row.family, required: row.required, mode: row.mode, bytes });
  }
  return captured;
}

function projectFiles(
  files: readonly CapturedFile[],
  ledgerBytes: Uint8Array,
): z.infer<typeof RunManifestFileEntryV02>[] | null {
  const rows: z.infer<typeof RunManifestFileEntryV02>[] = [];
  const paths = new Set<string>();
  let ledgerSeen = false;
  for (const file of files) {
    if (file.path === "run-manifest.json" || paths.has(file.path)) return null;
    paths.add(file.path);
    if (file.path === "ledger.jsonl") {
      if (file.family !== "primary" || !file.required || file.mode !== 384 || file.bytes === null
        || !Buffer.from(file.bytes).equals(Buffer.from(ledgerBytes))) return null;
      ledgerSeen = true;
    }
    const row = file.bytes === null
      ? { path: file.path, family: file.family, required: false as const, exists: false as const, mode: null, size_bytes: null, hash: null }
      : { path: file.path, family: file.family, required: file.required, exists: true as const, mode: 384 as const, size_bytes: file.bytes.byteLength, hash: hashRawBytes(file.bytes) };
    const parsed = RunManifestFileEntryV02.safeParse(row);
    if (!parsed.success) return null;
    rows.push(parsed.data);
  }
  if (!ledgerSeen) return null;
  rows.sort((left, right) => compareRuntimeUtf8BytesV02(left.path, right.path));
  return rows;
}

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

type BuiltCaptured = Readonly<{
  ok: true;
  manifest: RunManifestV04Value;
  bytes: Uint8Array;
  ledger: ValidatedRuntimeLedgerV04;
  captured_files: readonly CapturedFile[];
}>;

function buildCaptured(input: unknown): BuiltCaptured | Extract<RuntimeManifestV04BuildResult, { ok: false }> {
  const captured = exactObject(input, ["ledger_bytes", "created_at", "captured_files"]);
  if (captured === null || typeof captured.created_at !== "string") return { ok: false, reason: "MANIFEST_INPUT_INVALID" };
  const ledgerBytes = captureBytes(captured.ledger_bytes);
  const files = captureFiles(captured.captured_files);
  if (ledgerBytes === null || files === null) return { ok: false, reason: "MANIFEST_INPUT_INVALID" };
  const ledgerResult = inspectRuntimeLedgerV04(ledgerBytes);
  if (!ledgerResult.ok) return { ok: false, reason: "LEDGER_INVALID" };
  const createdAt = IsoTimestampV02.safeParse(captured.created_at);
  if (!createdAt.success) return { ok: false, reason: "MANIFEST_INPUT_INVALID" };
  if (ledgerResult.state.state === "quarantine-required") return { ok: false, reason: "LEDGER_STATE_UNPROJECTABLE" };
  const fileInventory = projectFiles(files, ledgerBytes);
  if (fileInventory === null) return { ok: false, reason: "FILE_CAPTURE_INVALID" };
  const first = ledgerResult.ledger.events[0];
  if (first?.event_type !== "run.initialized") return { ok: false, reason: "LEDGER_INVALID" };
  const last = ledgerResult.ledger.events.at(-1)!;
  const terminal = last.event_type === "run.terminal-sealed"
    ? {
        outcome: last.payload.outcome,
        snapshot_hash: last.payload.pre_seal_snapshot_hash,
        seal_event_ref: { ledger_sequence: last.sequence, event_hash: last.event_hash },
      }
    : null;
  const preimage = {
    schema_version: "0.4" as const,
    run_id: ledgerResult.ledger.run_id,
    plan_hash: ledgerResult.ledger.plan_hash,
    execution_profile: "bounded-v04" as const,
    schema_versions: first.payload.runtime_schema_versions,
    run_state: ledgerResult.state.state,
    created_at: createdAt.data,
    projection_event_ref: { ledger_sequence: ledgerResult.ledger.sequence, event_hash: ledgerResult.ledger.head_hash },
    ledger_bytes_hash: ledgerResult.ledger.ledger_bytes_hash,
    ledger_sequence: ledgerResult.ledger.sequence,
    ledger_head_hash: ledgerResult.ledger.head_hash,
    current_fence_epoch: ledgerResult.state.current_fence_epoch,
    terminal,
    file_inventory: fileInventory,
  };
  const parsed = RunManifestV04.safeParse({ ...preimage, manifest_hash: hashCanonical(preimage) });
  if (!parsed.success) return { ok: false, reason: "MANIFEST_SCHEMA_INVALID" };
  const manifest = freezeDeep(parsed.data);
  return {
    ok: true,
    manifest,
    bytes: new TextEncoder().encode(JSON.stringify(manifest)),
    ledger: ledgerResult.ledger,
    captured_files: files,
  };
}

export function buildRunManifestV04(input: unknown): RuntimeManifestV04BuildResult {
  try {
    const built = buildCaptured(input);
    return built.ok
      ? { ok: true, manifest: built.manifest, bytes: built.bytes }
      : built;
  } catch {
    return { ok: false, reason: "MANIFEST_INPUT_INVALID" };
  }
}

export function inspectRunManifestV04(input: unknown): RuntimeManifestV04InspectionResult {
  try {
    const captured = exactObject(input, ["manifest_bytes", "ledger_bytes", "captured_files"]);
    if (captured === null) return { ok: false, reason: "MANIFEST_INPUT_INVALID" };
    const manifestBytes = captureBytes(captured.manifest_bytes);
    if (manifestBytes === null || manifestBytes.byteLength > MAX_MANIFEST_BYTES) {
      return { ok: false, reason: "MANIFEST_INPUT_INVALID" };
    }
    let value: unknown;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes);
      const document = parseDocument(text, { uniqueKeys: true });
      if (document.errors.length > 0) return { ok: false, reason: "MANIFEST_SYNTAX_INVALID" };
      value = JSON.parse(text) as unknown;
    } catch {
      return { ok: false, reason: "MANIFEST_SYNTAX_INVALID" };
    }
    const parsed = RunManifestV04.safeParse(value);
    if (!parsed.success) return { ok: false, reason: "MANIFEST_SCHEMA_INVALID" };
    const projected = buildCaptured({
      ledger_bytes: captured.ledger_bytes,
      created_at: parsed.data.created_at,
      captured_files: captured.captured_files,
    });
    if (!projected.ok) return projected;
    if (hashCanonical(projected.manifest) !== hashCanonical(parsed.data)) {
      return { ok: false, reason: "MANIFEST_CROSS_CHECK_INVALID" };
    }
    const manifest = freezeDeep(parsed.data);
    const validatedManifest = manifest as unknown as ValidatedRunManifestV04;
    validatedRunManifestsV04.add(validatedManifest);
    validatedManifestLedgerPairsV04.set(validatedManifest, projected.ledger);
    validatedManifestFilesV04.set(
      validatedManifest,
      new Map(projected.captured_files.map((file) => [
        file.path,
        file.bytes === null ? null : new Uint8Array(file.bytes),
      ])),
    );
    return {
      ok: true,
      manifest,
      validated_manifest: validatedManifest,
      ledger: projected.ledger,
      bytes: manifestBytes,
    };
  } catch {
    return { ok: false, reason: "MANIFEST_INPUT_INVALID" };
  }
}
