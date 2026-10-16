import { parseAllDocuments, parseDocument } from "yaml";
import { hashRawBytes } from "../hash.js";
import {
  openCompilePackCaptureSessionV02,
  type CompilePackCaptureSessionV02,
} from "../io/compile-pack-capture-v02.js";
import {
  parseDirectChildName,
  type DirectChildName,
  type LegacyCompatibilityPolicy,
  type LegacyV01DocumentKind,
  type LegacyV01ParseResult,
} from "../io/captured-file.js";
import {
  createRegisteredSourceCompilePackV01,
  issueV01SourcePackAccess,
  issueCapturedV01SourcePackRegistrationAdapter,
  registerCapturedPackIdentityV01,
  type CapturedCompilePack,
  type CapturedPackIdentityV01,
  type V01ReplaySelector,
} from "../io/output-capabilities.js";
import { parseLoopeixDocument } from "../schema/version-dispatch.js";
import { CompilePackManifestV01, type CompilePackManifestV01 as CompilePackManifestV01Value } from "./pack.js";
import {
  CatalogResolution,
  CompilationRecord,
  IntakeRecord,
  WorkItemRecord,
} from "./records.js";
import type { CompilePackDirectoryEntryV02 } from "./read-pack-v02.js";
import { V01_CATALOG_VERSION_HASH } from "./strategy-v01.js";

const COMPILED_MEMBERS = [
  "catalog-resolution.json",
  "compilation-record.json",
  "compile-report.md",
  "generated.loop.yaml",
  "intake-record.json",
  "pack-manifest.json",
  "work-item.json",
] as const;
const HOLD_MEMBERS = [
  "catalog-resolution.json",
  "compile-report.md",
  "intake-record.json",
  "pack-manifest.json",
  "work-item.json",
] as const;
const V01_CAPTURE_ORDER = [
  "work-item.json",
  "intake-record.json",
  "catalog-resolution.json",
  "compilation-record.json",
  "generated.loop.yaml",
  "compile-report.md",
] as const;
const AUTOMATIC_V01_POLICY: LegacyCompatibilityPolicy = Object.freeze({
  mode: "operator-approved-finite",
  max_member_bytes: 67_108_864,
  max_total_bytes: 268_435_456,
  max_heap_bytes: 536_870_912,
  max_elapsed_ms: 30_000,
  approved_by: "operator",
});
const V01_PARSE_KIND: Readonly<Partial<Record<string, LegacyV01DocumentKind>>> = Object.freeze({
  "work-item.json": "work-item",
  "intake-record.json": "intake-record",
  "catalog-resolution.json": "catalog-resolution",
  "compilation-record.json": "compilation-record",
  "generated.loop.yaml": "generated-loop",
});

type ReadPackReason =
  | "INVALID_COMPILE_PACK"
  | "INPUT_TOO_LARGE"
  | "UNAVAILABLE_REPLAY_BUNDLE"
  | "LEGACY_REPLAY_RESOURCE_LIMIT"
  | "IO_HELPER_UNAVAILABLE"
  | "IO_IDENTITY_MISMATCH";

export type ReadCompilePackV01Result =
  | {
      readonly ok: true;
      readonly pack: CapturedCompilePack;
      readonly identity: CapturedPackIdentityV01;
      readonly selector: V01ReplaySelector;
      readonly manifest: CompilePackManifestV01Value;
      readonly work_item: Readonly<Record<string, unknown>>;
    }
  | { readonly ok: false; readonly reason: ReadPackReason; readonly message: string };

function failure(reason: ReadPackReason, message: string): ReadCompilePackV01Result {
  return { ok: false, reason, message };
}

function invalidPack(): ReadCompilePackV01Result {
  return failure("INVALID_COMPILE_PACK", "The compile pack is invalid.");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function decodeManifestFromBytes(bytes: Uint8Array): Promise<CompilePackManifestV01Value | null> {
  try {
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    const parsed = CompilePackManifestV01.safeParse(value);
    return parsed.success && parsed.data.schema_version === "0.1" ? parsed.data : null;
  } catch {
    return null;
  }
}

function exactRegularMembers(entries: readonly CompilePackDirectoryEntryV02[], expected: readonly string[]): boolean {
  const actual = entries.map(({ name }) => name).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  const wanted = [...expected].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  return entries.every(({ kind }) => kind === "regular-file")
    && actual.length === wanted.length
    && actual.every((name, index) => name === wanted[index]);
}

function resolveLegacyPolicy(policy: LegacyCompatibilityPolicy | null): LegacyCompatibilityPolicy | null {
  if (policy === null) return AUTOMATIC_V01_POLICY;
  const positive = (value: number): boolean => Number.isSafeInteger(value) && value > 0;
  return policy.mode === "operator-approved-finite" && policy.approved_by === "operator"
    && positive(policy.max_member_bytes) && positive(policy.max_total_bytes)
    && positive(policy.max_heap_bytes) && positive(policy.max_elapsed_ms)
    && policy.max_total_bytes >= policy.max_member_bytes && policy.max_heap_bytes >= policy.max_member_bytes
    ? Object.freeze({ ...policy })
    : null;
}

function parseV01Bytes(name: DirectChildName, bytes: Uint8Array): LegacyV01ParseResult | null {
  const kind = V01_PARSE_KIND[name];
  if (kind === undefined) return null;
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { return { ok: false, reason: "INVALID_DOCUMENT_ENVELOPE", message: "Input is not valid UTF-8." }; }
  if (text.startsWith("\ufeff")) text = text.slice(1);
  let value: unknown;
  try {
    if (name.endsWith(".json")) {
      const duplicateCheck = parseDocument(text, { uniqueKeys: true });
      if (duplicateCheck.errors.length > 0) throw new Error("invalid JSON envelope");
      value = JSON.parse(text) as unknown;
    } else {
      if (/^[ \t]*%/m.test(text) || /(^|[\s[{,])(?:&|\*)[A-Za-z0-9_-]+/.test(text)
        || /(^|\n)[ \t]*<<[ \t]*:/.test(text) || /(^|[\s[{,])![^\s]+/.test(text)) {
        throw new Error("unsafe YAML envelope");
      }
      const documents = parseAllDocuments(text, { uniqueKeys: true });
      const document = documents[0];
      if (documents.length !== 1 || document === undefined || document.errors.length > 0) throw new Error("invalid YAML envelope");
      value = document.toJS({ maxAliasCount: 0 }) as unknown;
    }
  } catch {
    return { ok: false, reason: "INVALID_DOCUMENT_ENVELOPE", message: "Document syntax is invalid." };
  }
  let parsedValue: unknown;
  if (kind === "generated-loop") {
    const parsed = parseLoopeixDocument(value);
    if (!parsed.ok || parsed.schema_version !== "0.1") {
      return { ok: false, reason: "INVALID_V01_DOCUMENT", message: `The captured input is not a valid V01 ${kind} document.` };
    }
    parsedValue = parsed.value;
  } else {
    const parsed = kind === "work-item" ? WorkItemRecord.safeParse(value)
      : kind === "intake-record" ? IntakeRecord.safeParse(value)
        : kind === "catalog-resolution" ? CatalogResolution.safeParse(value)
          : CompilationRecord.safeParse(value);
    if (!parsed.success || parsed.data.schema_version !== "0.1") {
      return { ok: false, reason: "INVALID_V01_DOCUMENT", message: `The captured input is not a valid V01 ${kind} document.` };
    }
    parsedValue = parsed.data;
  }
  return {
    ok: true,
    schema_version: "0.1",
    kind,
    byte_length: bytes.byteLength,
    raw_hash: hashRawBytes(bytes),
    value: parsedValue,
  };
}

async function parseV01Record(pack: CapturedCompilePack, name: string, kind: Parameters<CapturedCompilePack["parseV01Member"]>[1]): Promise<Record<string, unknown> | null> {
  const directName = parseDirectChildName(name);
  if (directName === null) return null;
  const parsed = await pack.parseV01Member(directName, kind);
  return parsed.ok && isRecord(parsed.value) && parsed.value.schema_version === "0.1" ? parsed.value : null;
}

async function validatePackLineage(
  pack: CapturedCompilePack,
  manifest: CompilePackManifestV01Value,
): Promise<{ workItem: Record<string, unknown>; catalogHash: string } | null> {
  const workItem = await parseV01Record(pack, "work-item.json", "work-item");
  const intake = await parseV01Record(pack, "intake-record.json", "intake-record");
  const catalog = await parseV01Record(pack, "catalog-resolution.json", "catalog-resolution");
  const compilation = manifest.terminal_state === "compiled"
    ? await parseV01Record(pack, "compilation-record.json", "compilation-record")
    : null;
  const generatedLoop = manifest.terminal_state === "compiled"
    ? await parseV01Record(pack, "generated.loop.yaml", "generated-loop")
    : null;
  if (workItem === null || intake === null || catalog === null) return null;
  const catalogHash = catalog.catalog_version_hash;
  const baseLineageValid = manifest.work_item_id === workItem.work_item_id
    && manifest.intake_id === intake.intake_id
    && intake.work_item_id === workItem.work_item_id
    && manifest.resolution_id === catalog.resolution_id
    && manifest.terminal_state === catalog.terminal_state
    && manifest.selected_item_id === catalog.selected_item_id
    && typeof catalogHash === "string";
  if (!baseLineageValid) return null;
  if (manifest.terminal_state === "compiled") {
    if (compilation === null || generatedLoop === null
      || manifest.compilation_id !== compilation.compilation_id
      || compilation.selected_loop_family !== generatedLoop.loop_family
      || compilation.selected_loop_version !== generatedLoop.version) return null;
  } else if (compilation !== null || generatedLoop !== null) {
    return null;
  }
  return typeof catalogHash === "string" ? { workItem, catalogHash } : null;
}

export async function readCompilePackV01(
  packRoot: string,
  legacyPolicy: LegacyCompatibilityPolicy | null = null,
): Promise<ReadCompilePackV01Result> {
  const opened = await openCompilePackCaptureSessionV02(packRoot);
  if (!opened.ok) return failure(opened.reason, opened.message);
  const listed = await opened.value.listDirectEntries();
  if (!listed.ok) {
    await opened.value.abort();
    return failure(listed.reason, listed.message);
  }
  return readCompilePackV01FromCapture(packRoot, opened.value, listed.value, legacyPolicy);
}

export async function readCompilePackV01FromCapture(
  _packRoot: string,
  session: CompilePackCaptureSessionV02,
  entries: readonly CompilePackDirectoryEntryV02[],
  legacyPolicy: LegacyCompatibilityPolicy | null = null,
): Promise<ReadCompilePackV01Result> {
  const policy = resolveLegacyPolicy(legacyPolicy);
  if (policy === null) {
    await session.abort();
    return failure("LEGACY_REPLAY_RESOURCE_LIMIT", "The finite V01 replay policy is invalid.");
  }
  const manifestName = parseDirectChildName("pack-manifest.json")!;
  let initialSnapshot = session.snapshotCapturedManifest();
  if (!initialSnapshot.ok) {
    const captured = await session.captureMember(manifestName);
    if (!captured.ok) {
      await session.abort();
      return failure(captured.reason, captured.message);
    }
    initialSnapshot = session.snapshotCapturedManifest();
  }
  if (!initialSnapshot.ok) {
    await session.abort();
    return failure(initialSnapshot.reason, initialSnapshot.message);
  }
  const initialManifest = await decodeManifestFromBytes(initialSnapshot.value);
  if (initialManifest === null) {
    await session.abort();
    return invalidPack();
  }
  const expectedNames = initialManifest.terminal_state === "compiled" ? COMPILED_MEMBERS : HOLD_MEMBERS;
  if (!exactRegularMembers(entries, expectedNames)) {
    await session.abort();
    return invalidPack();
  }
  const capturedOrder: DirectChildName[] = [manifestName];
  for (const fixed of V01_CAPTURE_ORDER) {
    if (!expectedNames.some((expected) => expected === fixed)) continue;
    const name = parseDirectChildName(fixed)!;
    const captured = await session.captureLegacyMember(name, {
      max_member_bytes: policy.max_member_bytes,
      max_total_bytes: policy.max_total_bytes,
    });
    if (!captured.ok) {
      await session.abort();
      return captured.reason === "INPUT_TOO_LARGE"
        ? failure("LEGACY_REPLAY_RESOURCE_LIMIT", captured.message)
        : failure(captured.reason, captured.message);
    }
    capturedOrder.push(name);
  }
  const sealed = await session.seal(capturedOrder, capturedOrder);
  if (!sealed.ok) return failure(sealed.reason, sealed.message);
  const rows = capturedOrder.map((name) => {
    const snapshot = sealed.value.snapshotMemberBytes(name);
    if (!snapshot.ok) return null;
    return {
      name,
      bytes: snapshot.value,
      parse_kind: V01_PARSE_KIND[name] ?? null,
      parse_result: parseV01Bytes(name, snapshot.value),
    };
  });
  if (rows.some((row) => row === null)) return failure("IO_HELPER_UNAVAILABLE", "A captured V01 member became unavailable.");
  const adapter = issueCapturedV01SourcePackRegistrationAdapter(
    rows as Exclude<(typeof rows)[number], null>[],
    policy,
  );
  if (!adapter.ok) {
    return adapter.reason === "LEGACY_REPLAY_RESOURCE_LIMIT"
      ? failure(adapter.reason, adapter.message)
      : adapter.reason === "IO_HELPER_UNAVAILABLE"
        ? failure(adapter.reason, adapter.message)
        : invalidPack();
  }
  const registered = await createRegisteredSourceCompilePackV01(adapter.adapter);
  if (!registered.ok) {
    return registered.reason === "LEGACY_REPLAY_RESOURCE_LIMIT"
      ? failure(registered.reason, registered.message)
      : registered.reason === "IO_HELPER_UNAVAILABLE"
        ? failure(registered.reason, registered.message)
        : invalidPack();
  }
  const registeredManifestSnapshot = await registered.pack.snapshotMemberBytes(manifestName);
  if (!registeredManifestSnapshot.ok) return failure(registeredManifestSnapshot.reason, registeredManifestSnapshot.message);
  const manifest = await decodeManifestFromBytes(registeredManifestSnapshot.bytes);
  if (manifest === null || manifest.terminal_state !== initialManifest.terminal_state) return invalidPack();
  const lineage = await validatePackLineage(registered.pack, manifest);
  if (lineage === null) return invalidPack();
  if (lineage.catalogHash !== V01_CATALOG_VERSION_HASH) {
    return failure("UNAVAILABLE_REPLAY_BUNDLE", "The exact replay bundle is unavailable.");
  }
  const selector = Object.freeze({ schema_version: "0.1", catalog_version_hash: lineage.catalogHash }) as V01ReplaySelector;
  const access = issueV01SourcePackAccess(registered.pack);
  if (!access.ok) return invalidPack();
  const identity = await registerCapturedPackIdentityV01(access.access, selector, legacyPolicy);
  if (!identity.ok) {
    return identity.reason === "LEGACY_REPLAY_RESOURCE_LIMIT"
      ? failure(identity.reason, identity.message)
      : identity.reason === "IO_HELPER_UNAVAILABLE"
        ? failure(identity.reason, identity.message)
        : invalidPack();
  }
  return Object.freeze({
    ok: true,
    pack: registered.pack,
    identity: identity.identity,
    selector: identity.identity.selector,
    manifest,
    work_item: Object.freeze({ ...lineage.workItem }),
  });
}
