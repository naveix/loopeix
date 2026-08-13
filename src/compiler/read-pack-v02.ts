import { basename } from "node:path";
import { compareUtf8BytesV02 } from "../catalog/item-v02.js";
import { lookupRegisteredCatalogV02 } from "../catalog/registry.js";
import { hashCanonical, hashRawBytes } from "../hash.js";
import {
  openCompilePackCaptureSessionV02,
  type CapturedCompilePackV02,
  type CompilePackCaptureSessionV02,
} from "../io/compile-pack-capture-v02.js";
import { parseDirectChildName, type DirectChildName } from "../io/captured-file.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";
import {
  LoopeixV02Shape,
  checkLoopeixV02Invariants,
  type LoopeixV02,
} from "../schema/loopeix-v02.js";
import {
  BindingInputRecordV02,
  type BindingInputRecordV02 as BindingInputRecordV02Value,
} from "./binding-input-v02.js";
import {
  CompilePackManifestV02,
  type CompilePackManifestV02 as CompilePackManifestV02Value,
} from "./pack.js";
import {
  CatalogResolutionV02,
  CompilationRecordV02,
  IntakeRecordV02,
  WorkItemRecordV02,
  type CatalogResolutionV02 as CatalogResolutionV02Value,
  type CompilationRecordV02 as CompilationRecordV02Value,
  type IntakeRecordV02 as IntakeRecordV02Value,
  type WorkItemRecordV02 as WorkItemRecordV02Value,
} from "./records.js";

const BASELINE_MEMBERS = [
  "pack-manifest.json",
  "work-item.json",
  "intake-record.json",
  "catalog-resolution.json",
  "compile-report.md",
] as const;

const COMPILED_MEMBERS = [
  "work-item.json",
  "binding-input.json",
  "intake-record.json",
  "catalog-resolution.json",
  "compilation-record.json",
  "compile-report.md",
  "generated.loop.yaml",
  "pack-manifest.json",
] as const;

const HOLD_MEMBERS = [
  "work-item.json",
  "binding-input.json",
  "intake-record.json",
  "catalog-resolution.json",
  "compile-report.md",
  "pack-manifest.json",
] as const;

const NON_MANIFEST_CAPTURE_ORDER = [
  "work-item.json",
  "binding-input.json",
  "intake-record.json",
  "catalog-resolution.json",
  "compilation-record.json",
  "generated.loop.yaml",
  "compile-report.md",
] as const;

const STRUCTURED_MEMBER_ORDER = [
  ["work-item.json", "json"],
  ["binding-input.json", "json"],
  ["intake-record.json", "json"],
  ["catalog-resolution.json", "json"],
  ["compilation-record.json", "json"],
  ["generated.loop.yaml", "yaml"],
] as const;

const TOKEN_PATTERN = /^[0-9a-z]+_[0-9a-f]{16}$/;

export type V02ReplaySelector = Readonly<{
  schema_version: "0.2";
  compiler_bundle_id: string;
  catalog_version_hash: string;
}>;

export type ReadCompilePackV02Success = Readonly<{
  ok: true;
  pack: CapturedCompilePackV02;
  selector: V02ReplaySelector;
  manifest: CompilePackManifestV02Value;
  work_item: WorkItemRecordV02Value;
  binding_input: BindingInputRecordV02Value;
  intake: IntakeRecordV02Value;
  catalog_resolution: CatalogResolutionV02Value;
  compilation: CompilationRecordV02Value | null;
  generated_loop: LoopeixV02 | null;
}>;

export type ReadCompilePackV02Reason =
  | "INVALID_COMPILE_PACK"
  | "INPUT_TOO_LARGE"
  | "INVALID_DOCUMENT_ENVELOPE"
  | "MISSING_SCHEMA_VERSION"
  | "MALFORMED_SCHEMA_VERSION"
  | "UNSUPPORTED_SCHEMA_VERSION"
  | "MIXED_SCHEMA_VERSION"
  | "UNAVAILABLE_REPLAY_BUNDLE"
  | "IO_HELPER_UNAVAILABLE"
  | "IO_IDENTITY_MISMATCH";

export type ReadCompilePackV02Result =
  | ReadCompilePackV02Success
  | Readonly<{ ok: false; reason: ReadCompilePackV02Reason; message: string }>;

export type CompilePackDirectoryEntryV02 = Readonly<{
  name: string;
  kind: "regular-file" | "directory" | "symlink" | "other";
}>;

type RegisteredReadSuccessV02 = Readonly<{
  pack: CapturedCompilePackV02;
  consumed: boolean;
}>;

const registeredReadSuccessesV02 = new WeakMap<ReadCompilePackV02Success, RegisteredReadSuccessV02>();

export function consumeRegisteredReadCompilePackV02(
  read: ReadCompilePackV02Success,
): CapturedCompilePackV02 | null {
  const registered = registeredReadSuccessesV02.get(read);
  if (registered === undefined || registered.consumed || registered.pack !== read.pack) return null;
  registeredReadSuccessesV02.set(read, { pack: registered.pack, consumed: true });
  return registered.pack;
}

type StructuredMemberName = (typeof STRUCTURED_MEMBER_ORDER)[number][0];
type DecodedMember = Readonly<{ bytes: Uint8Array; value: unknown }>;

function failure(reason: ReadCompilePackV02Reason, message: string): ReadCompilePackV02Result {
  return { ok: false, reason, message };
}

function invalidPack(): ReadCompilePackV02Result {
  return failure("INVALID_COMPILE_PACK", "The compile pack is invalid.");
}

function directName(value: string): DirectChildName {
  const parsed = parseDirectChildName(value);
  if (parsed === null) throw new Error(`invalid fixed compile-pack member: ${value}`);
  return parsed;
}

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

function dispatchLiteralVersion(value: unknown):
  | { ok: true; schema_version: "0.1" | "0.2" }
  | {
      ok: false;
      reason: "MISSING_SCHEMA_VERSION" | "MALFORMED_SCHEMA_VERSION" | "UNSUPPORTED_SCHEMA_VERSION";
      message: string;
    } {
  if (typeof value !== "object" || value === null || Array.isArray(value) || !("schema_version" in value)) {
    return { ok: false, reason: "MISSING_SCHEMA_VERSION", message: "schema_version is required." };
  }
  const version = (value as { schema_version?: unknown }).schema_version;
  if (typeof version !== "string" || !/^\d+\.\d+$/.test(version)) {
    return {
      ok: false,
      reason: "MALFORMED_SCHEMA_VERSION",
      message: "schema_version must be a canonical major.minor string.",
    };
  }
  if (version !== "0.1" && version !== "0.2") {
    return {
      ok: false,
      reason: "UNSUPPORTED_SCHEMA_VERSION",
      message: "schema_version is not supported; supported versions are '0.1' and '0.2'.",
    };
  }
  return { ok: true, schema_version: version };
}

function exactMemberSet(actual: readonly string[], expected: readonly string[]): boolean {
  if (actual.length !== expected.length || new Set(actual).size !== actual.length) return false;
  const left = [...actual].sort(compareUtf8BytesV02);
  const right = [...expected].sort(compareUtf8BytesV02);
  return left.every((value, index) => value === right[index]);
}

function exactUtcSecond(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && !Number.isNaN(Date.parse(value));
}

function invocationToken(packRoot: string, manifest: CompilePackManifestV02Value): string | null {
  if (!manifest.pack_manifest_id.startsWith("pack_")) return null;
  const token = manifest.pack_manifest_id.slice("pack_".length);
  return TOKEN_PATTERN.test(token) && basename(packRoot) === `compile_${token}` ? token : null;
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function validateLineage(input: {
  packRoot: string;
  manifest: CompilePackManifestV02Value;
  workItem: WorkItemRecordV02Value;
  bindingInput: BindingInputRecordV02Value;
  intake: IntakeRecordV02Value;
  resolution: CatalogResolutionV02Value;
  compilation: CompilationRecordV02Value | null;
  generatedLoop: LoopeixV02 | null;
  members: ReadonlyMap<string, Uint8Array>;
}): boolean {
  const { packRoot, manifest, workItem, bindingInput, intake, resolution, compilation, generatedLoop, members } = input;
  const token = invocationToken(packRoot, manifest);
  if (token === null || !exactUtcSecond(workItem.submitted_at)) return false;
  if (workItem.work_item_id !== `wi_${token}`
    || bindingInput.binding_input_id !== `binding_${token}`
    || intake.intake_id !== `intake_${token}`
    || resolution.resolution_id !== `resolution_${token}`
    || (compilation !== null && compilation.compilation_id !== `compilation_${token}`)) return false;

  const workspaceSourceRefs = bindingInput.bindings
    .filter(({ source }) => source === "workspace-observation")
    .map(({ source_ref: sourceRef }) => sourceRef)
    .filter((sourceRef): sourceRef is string => sourceRef !== null)
    .sort(compareUtf8BytesV02);
  if (new Set(workspaceSourceRefs).size !== workspaceSourceRefs.length
    || !sameStrings(workItem.source_context, workspaceSourceRefs)) return false;

  if (manifest.work_item_id !== workItem.work_item_id
    || manifest.binding_input_id !== bindingInput.binding_input_id
    || manifest.intake_id !== intake.intake_id
    || manifest.resolution_id !== resolution.resolution_id
    || bindingInput.work_item_id !== workItem.work_item_id
    || bindingInput.submitted_at !== workItem.submitted_at
    || intake.work_item_id !== workItem.work_item_id
    || manifest.selected_item_id !== resolution.selected_item_id
    || manifest.terminal_state !== resolution.terminal_state
    || manifest.reason_code !== resolution.reason_code
    || manifest.compiler_bundle_id !== resolution.compiler_bundle_id
    || manifest.catalog_version_hash !== resolution.catalog_version_hash) return false;

  const hashMatches = (name: string, expected: string | undefined): boolean => {
    const bytes = members.get(name);
    return bytes !== undefined && expected !== undefined && hashRawBytes(bytes) === expected;
  };
  if (!hashMatches("work-item.json", manifest.file_hashes.work_item)
    || !hashMatches("binding-input.json", manifest.file_hashes.binding_input)
    || !hashMatches("intake-record.json", manifest.file_hashes.intake)
    || !hashMatches("catalog-resolution.json", manifest.file_hashes.catalog_resolution)
    || !hashMatches("compile-report.md", manifest.file_hashes.report)) return false;

  if (manifest.terminal_state !== "compiled") return compilation === null && generatedLoop === null;
  return compilation !== null
    && generatedLoop !== null
    && manifest.compilation_id === compilation.compilation_id
    && compilation.compiler_bundle_id === manifest.compiler_bundle_id
    && compilation.catalog_version_hash === manifest.catalog_version_hash
    && compilation.binding_input_id === bindingInput.binding_input_id
    && compilation.binding_input_hash === manifest.file_hashes.binding_input
    && compilation.selected_loop_family === generatedLoop.loop_family
    && compilation.selected_loop_version === generatedLoop.version
    && hashCanonical(compilation.effective_risk_controls) === hashCanonical(generatedLoop.risk_controls)
    && hashMatches("compilation-record.json", manifest.file_hashes.compilation)
    && hashMatches("generated.loop.yaml", manifest.file_hashes.generated_loop)
    && manifest.generated_loop_hash === manifest.file_hashes.generated_loop;
}

function mapCaptureFailure(reason: "INVALID_COMPILE_PACK" | "INPUT_TOO_LARGE" | "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH", message: string): ReadCompilePackV02Result {
  return failure(reason, message);
}

async function abortWith(
  session: CompilePackCaptureSessionV02,
  result: ReadCompilePackV02Result,
): Promise<ReadCompilePackV02Result> {
  await session.abort();
  return result;
}

export async function readCompilePackV02(packRoot: string): Promise<ReadCompilePackV02Result> {
  const opened = await openCompilePackCaptureSessionV02(packRoot);
  if (!opened.ok) return mapCaptureFailure(opened.reason, opened.message);
  const session = opened.value;

  const listed = await session.listDirectEntries();
  if (!listed.ok) return abortWith(session, mapCaptureFailure(listed.reason, listed.message));
  return readCompilePackV02FromCapture(packRoot, session, listed.value);
}

export async function readCompilePackV02FromCapture(
  packRoot: string,
  session: CompilePackCaptureSessionV02,
  entries: readonly CompilePackDirectoryEntryV02[],
): Promise<ReadCompilePackV02Result> {
  const listed = { ok: true as const, value: entries };
  const entryByName = new Map(listed.value.map((entry) => [entry.name, entry.kind]));
  if (BASELINE_MEMBERS.some((name) => entryByName.get(name) !== "regular-file")) {
    return abortWith(session, invalidPack());
  }

  const manifestName = directName("pack-manifest.json");
  const existingManifest = session.snapshotCapturedManifest();
  if (!existingManifest.ok) {
    const manifestCapture = await session.captureMember(manifestName);
    if (!manifestCapture.ok) return abortWith(session, mapCaptureFailure(manifestCapture.reason, manifestCapture.message));
  }
  const manifestSnapshot = session.snapshotCapturedManifest();
  if (!manifestSnapshot.ok) return abortWith(session, mapCaptureFailure(manifestSnapshot.reason, manifestSnapshot.message));
  const decodedManifest = decodeStructuredDocumentV02(manifestSnapshot.value, "json");
  if (!decodedManifest.ok) return abortWith(session, failure(decodedManifest.reason, decodedManifest.message));
  const manifestDispatch = dispatchLiteralVersion(decodedManifest.value);
  if (!manifestDispatch.ok) return abortWith(session, failure(manifestDispatch.reason, manifestDispatch.message));
  if (manifestDispatch.schema_version !== "0.2") return abortWith(session, invalidPack());

  const capturedOrder: DirectChildName[] = [manifestName];
  for (const name of NON_MANIFEST_CAPTURE_ORDER) {
    if (entryByName.get(name) !== "regular-file") continue;
    const memberName = directName(name);
    const captured = await session.captureMember(memberName);
    if (!captured.ok) return mapCaptureFailure(captured.reason, captured.message);
    capturedOrder.push(memberName);
  }
  const sealed = await session.seal(capturedOrder, capturedOrder);
  if (!sealed.ok) return mapCaptureFailure(sealed.reason, sealed.message);
  const pack = sealed.value;

  const members = new Map<string, Uint8Array>();
  for (const name of capturedOrder) {
    const snapshot = pack.snapshotMemberBytes(name);
    if (!snapshot.ok) return mapCaptureFailure(snapshot.reason, snapshot.message);
    members.set(name, snapshot.value);
  }

  const decodedMembers = new Map<StructuredMemberName, DecodedMember>();
  for (const [name, format] of STRUCTURED_MEMBER_ORDER) {
    const bytes = members.get(name);
    if (bytes === undefined) continue;
    const decoded = decodeStructuredDocumentV02(bytes, format);
    if (!decoded.ok) return failure(decoded.reason, decoded.message);
    decodedMembers.set(name, { bytes, value: decoded.value });
  }
  for (const [name] of STRUCTURED_MEMBER_ORDER) {
    const decoded = decodedMembers.get(name);
    if (decoded === undefined) continue;
    const dispatch = dispatchLiteralVersion(decoded.value);
    if (!dispatch.ok) return failure(dispatch.reason, dispatch.message);
    if (dispatch.schema_version !== "0.2") {
      return failure("MIXED_SCHEMA_VERSION", "Compile pack members do not share one literal schema_version.");
    }
  }

  const manifestResult = CompilePackManifestV02.safeParse(decodedManifest.value);
  if (!manifestResult.success) return invalidPack();
  const manifest = manifestResult.data;
  const expectedMembers = manifest.terminal_state === "compiled" ? COMPILED_MEMBERS : HOLD_MEMBERS;
  if (!exactMemberSet(listed.value.map(({ name }) => name), expectedMembers)
    || listed.value.some(({ kind }) => kind !== "regular-file")) return invalidPack();

  const workItemResult = WorkItemRecordV02.safeParse(decodedMembers.get("work-item.json")?.value);
  const bindingInputResult = BindingInputRecordV02.safeParse(decodedMembers.get("binding-input.json")?.value);
  const intakeResult = IntakeRecordV02.safeParse(decodedMembers.get("intake-record.json")?.value);
  const resolutionResult = CatalogResolutionV02.safeParse(decodedMembers.get("catalog-resolution.json")?.value);
  if (!workItemResult.success || !bindingInputResult.success || !intakeResult.success || !resolutionResult.success) {
    return invalidPack();
  }
  const compilationResult = decodedMembers.has("compilation-record.json")
    ? CompilationRecordV02.safeParse(decodedMembers.get("compilation-record.json")?.value)
    : null;
  const generatedLoopResult = decodedMembers.has("generated.loop.yaml")
    ? LoopeixV02Shape.safeParse(decodedMembers.get("generated.loop.yaml")?.value)
    : null;
  if ((compilationResult !== null && !compilationResult.success)
    || (generatedLoopResult !== null
      && (!generatedLoopResult.success || checkLoopeixV02Invariants(generatedLoopResult.data).length > 0))) {
    return invalidPack();
  }
  const compilation = compilationResult?.success === true ? compilationResult.data : null;
  const generatedLoop = generatedLoopResult?.success === true ? generatedLoopResult.data : null;
  if ((manifest.terminal_state === "compiled") !== (compilation !== null && generatedLoop !== null)) return invalidPack();

  if (!validateLineage({
    packRoot,
    manifest,
    workItem: workItemResult.data,
    bindingInput: bindingInputResult.data,
    intake: intakeResult.data,
    resolution: resolutionResult.data,
    compilation,
    generatedLoop,
    members,
  })) return invalidPack();

  const selector = Object.freeze({
    schema_version: "0.2" as const,
    compiler_bundle_id: manifest.compiler_bundle_id,
    catalog_version_hash: manifest.catalog_version_hash,
  });
  const bundle = lookupRegisteredCatalogV02(selector);
  if (!bundle.ok) return failure("UNAVAILABLE_REPLAY_BUNDLE", "The exact replay bundle is unavailable.");

  const success = freezeDeep({
    ok: true as const,
    pack,
    selector,
    manifest: structuredClone(manifest),
    work_item: structuredClone(workItemResult.data),
    binding_input: structuredClone(bindingInputResult.data),
    intake: structuredClone(intakeResult.data),
    catalog_resolution: structuredClone(resolutionResult.data),
    compilation: compilation === null ? null : structuredClone(compilation),
    generated_loop: generatedLoop === null ? null : structuredClone(generatedLoop),
  }) as ReadCompilePackV02Success;
  registeredReadSuccessesV02.set(success, { pack, consumed: false });
  return success;
}
