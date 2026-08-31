import { randomUUID } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  lstat,
  open,
  realpath,
  rename,
  stat,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

import { parseDocument } from "yaml";

import { hashRawBytes } from "../hash.js";
import {
  captureRunFileForRuntimeV02,
  issueAnchoredRunDirectoryReadCapabilityV02,
  type AnchoredRunDirectoryReadCapabilityV02,
  type HelperOwnedRunFileCaptureV02,
  type RuntimeRunFileCaptureErrorV02,
  type RuntimeRunFileCaptureResultV02,
} from "../io/runtime-file-capture-v02.js";
import { RelativeRunPathV02 } from "../schema/scalars-v02.js";
import { inspectRuntimeLedgerV04 } from "./runtime-ledger-v04.js";
import {
  inspectRunManifestV04,
  RunManifestV04,
  type RunManifestV04Value,
} from "./runtime-manifest-v04.js";
import {
  AuthorityRevocationRecordV02,
  type AuthorityRevocationRecordV02Value,
} from "./runtime-record-admission-v02.js";

declare const capturedRuntimeFileStoreBrandV04: unique symbol;
declare const runtimeFileStoreSessionBrandV04: unique symbol;

export type CapturedRuntimeFileStoreV04 = Readonly<{
  readonly [capturedRuntimeFileStoreBrandV04]: true;
}>;

export type RuntimeFileStoreSessionV04 = Readonly<{
  readonly [runtimeFileStoreSessionBrandV04]: true;
}>;

export type RuntimeFileStoreCaptureV04Error =
  | "STORE_INPUT_INVALID"
  | "RUN_DIRECTORY_INVALID"
  | "RUN_DIRECTORY_IDENTITY_CHANGED"
  | "RUN_DIRECTORY_MODE_CHANGED"
  | "RUN_FILE_PATH_INVALID"
  | "RUN_FILE_NOT_REGULAR"
  | "RUN_FILE_MODE_INVALID"
  | "RUN_FILE_IDENTITY_CHANGED"
  | "RUN_FILE_TOO_LARGE"
  | "RUN_FILE_CAPTURE_FAILED"
  | "RUN_MANIFEST_SYNTAX_INVALID"
  | "RUN_MANIFEST_SCHEMA_INVALID"
  | "RUN_MANIFEST_INVALID"
  | "RUN_MANIFEST_FILESET_INVALID";

export type RuntimeFileStoreCaptureV04Result =
  | Readonly<{ ok: true; store: CapturedRuntimeFileStoreV04 }>
  | Readonly<{ ok: false; error: RuntimeFileStoreCaptureV04Error }>;

export type OpenRuntimeFileStoreSessionV04Error =
  | "CAPTURED_STORE_INVALID"
  | "RUNTIME_FILE_STORE_POISONED"
  | "RUN_DIRECTORY_IDENTITY_CHANGED"
  | "RUN_DIRECTORY_MODE_CHANGED"
  | "RUN_LOCK_UNAVAILABLE"
  | "RUN_LOCK_INVALID"
  | "RUN_LOCK_IDENTITY_INVALID"
  | "RUN_FILE_IDENTITY_CHANGED";

export type OpenRuntimeFileStoreSessionV04Result =
  | Readonly<{ ok: true; session: RuntimeFileStoreSessionV04 }>
  | Readonly<{ ok: false; error: OpenRuntimeFileStoreSessionV04Error }>;

export type RuntimeFileStoreSessionSnapshotV04 = Readonly<{
  run_directory: string;
  lock_path: string;
  resolved_run_plan_bytes: Uint8Array;
  ledger_bytes: Uint8Array;
  manifest_bytes: Uint8Array;
  captured_files: readonly RuntimeFileStoreCapturedFileSnapshotV04[];
  summary_content_directory: RuntimeFileStoreDirectorySnapshotV04 | null;
  summary_record_directory: RuntimeFileStoreDirectorySnapshotV04 | null;
  revocation_record_directory: RuntimeFileStoreDirectorySnapshotV04 | null;
}>;

export type RuntimeFileStoreDirectorySnapshotV04 = Readonly<{
  path: string;
  mode: number;
  device: string;
  inode: string;
}>;

export type RuntimeFileStoreCapturedFileSnapshotV04 = Readonly<{
  path: string;
  family: "primary" | "record" | "projection";
  required: boolean;
  exists: boolean;
  mode: 384 | null;
  size_bytes: number | null;
  hash: string | null;
  bytes: Uint8Array | null;
}>;

export type ReadRuntimeFileStoreSessionSnapshotV04Result =
  | Readonly<{ ok: true; snapshot: RuntimeFileStoreSessionSnapshotV04 }>
  | Readonly<{
      ok: false;
      error:
        | "RUNTIME_FILE_STORE_SESSION_INVALID"
        | "RUNTIME_FILE_STORE_SESSION_CLOSED"
        | "RUNTIME_FILE_STORE_SESSION_POISONED";
    }>;

export type RuntimeFileStoreCommitInputV04 = Readonly<{
  expected_ledger_bytes_hash: string;
  expected_manifest_hash: string;
  next_ledger_bytes: Uint8Array;
  next_manifest_bytes: Uint8Array;
}>;

export type CommitRuntimeFileStoreSessionV04Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      ledger_bytes_hash: string;
      manifest_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_FILE_STORE_SESSION_INVALID"
        | "RUNTIME_FILE_STORE_SESSION_CLOSED"
        | "RUNTIME_FILE_STORE_SESSION_POISONED"
        | "RUN_LOCK_IDENTITY_INVALID"
        | "RUN_DIRECTORY_IDENTITY_CHANGED"
        | "RUN_DIRECTORY_MODE_CHANGED"
        | "RUNTIME_STORE_DRIFT"
        | "RUNTIME_EXPECTATION_MISMATCH"
        | "RUNTIME_NEXT_STATE_INVALID"
        | "RUNTIME_IO_NOT_COMMITTED"
        | "RUNTIME_IO_OUTCOME_UNKNOWN";
    }>;

export type RuntimeFileStoreCompactionCommitInputV04 = Readonly<{
  expected_ledger_bytes_hash: string;
  expected_manifest_hash: string;
  summary_content: Readonly<{ relative_path: string; bytes: Uint8Array }>;
  summary_record: Readonly<{ relative_path: string; bytes: Uint8Array }>;
  next_ledger_bytes: Uint8Array;
  next_manifest_bytes: Uint8Array;
}>;

export type RuntimeFileStoreRecordCommitInputV04 = Readonly<{
  expected_ledger_bytes_hash: string;
  expected_manifest_hash: string;
  record: Readonly<{ relative_path: string; bytes: Uint8Array }>;
  next_ledger_bytes: Uint8Array;
  next_manifest_bytes: Uint8Array;
}>;

export type CommitRuntimeCompactionFileStoreSessionV04Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      ledger_bytes_hash: string;
      manifest_hash: string;
      summary_content_hash: string;
      summary_record_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_FILE_STORE_SESSION_INVALID"
        | "RUNTIME_FILE_STORE_SESSION_CLOSED"
        | "RUNTIME_FILE_STORE_SESSION_POISONED"
        | "RUN_LOCK_IDENTITY_INVALID"
        | "RUN_DIRECTORY_IDENTITY_CHANGED"
        | "RUN_DIRECTORY_MODE_CHANGED"
        | "RUNTIME_STORE_DRIFT"
        | "RUNTIME_EXPECTATION_MISMATCH"
        | "RUNTIME_COMPACTION_INVALID"
        | "RUNTIME_COMPACTION_DIRECTORIES_UNAVAILABLE"
        | "RUNTIME_COMPACTION_PATH_EXISTS"
        | "RUNTIME_IO_NOT_COMMITTED"
        | "RUNTIME_IO_OUTCOME_UNKNOWN";
    }>;

export type CommitRuntimeRecordFileStoreSessionV04Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      ledger_bytes_hash: string;
      manifest_hash: string;
      record_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_FILE_STORE_SESSION_INVALID"
        | "RUNTIME_FILE_STORE_SESSION_CLOSED"
        | "RUNTIME_FILE_STORE_SESSION_POISONED"
        | "RUN_LOCK_IDENTITY_INVALID"
        | "RUN_DIRECTORY_IDENTITY_CHANGED"
        | "RUN_DIRECTORY_MODE_CHANGED"
        | "RUNTIME_STORE_DRIFT"
        | "RUNTIME_EXPECTATION_MISMATCH"
        | "RUNTIME_RECORD_INVALID"
        | "RUNTIME_RECORD_PATH_EXISTS"
        | "RUNTIME_IO_NOT_COMMITTED"
        | "RUNTIME_IO_OUTCOME_UNKNOWN";
    }>;

export type RuntimeFileStoreIoOverridesV04 = Readonly<Partial<{
  lstat: (path: string) => Promise<BigIntStats>;
  stat: (path: string) => Promise<BigIntStats>;
  realpath: (path: string) => Promise<string>;
  open: (path: string, flags: number, mode?: number) => Promise<FileHandle>;
  rename: (source: string, target: string) => Promise<void>;
  unlink: (path: string) => Promise<void>;
  capture_file: (
    input: Readonly<{
      anchored_run_directory: AnchoredRunDirectoryReadCapabilityV02;
      relative_path: string;
      max_bytes: number;
    }>,
  ) => Promise<RuntimeRunFileCaptureResultV02<HelperOwnedRunFileCaptureV02>>;
  write: (
    handle: FileHandle,
    bytes: Uint8Array,
    offset: number,
    length: number,
    position: number | null,
  ) => Promise<number>;
  sync: (handle: FileHandle) => Promise<void>;
  close: (handle: FileHandle) => Promise<void>;
}>>;

type RuntimeFileStoreIoV04 = Required<RuntimeFileStoreIoOverridesV04>;

type Identity = Readonly<{
  device: string;
  inode: string;
}>;

type DirectoryState = Identity & Readonly<{
  path: string;
  mode: bigint;
  anchored: AnchoredRunDirectoryReadCapabilityV02;
}>;

type ExistingFileState = Identity & Readonly<{
  path: string;
  family: "primary" | "record" | "projection";
  required: boolean;
  exists: true;
  mode: 384;
  size_bytes: number;
  hash: string;
  bytes: Uint8Array;
  nlink: bigint;
}>;

type MissingFileState = Readonly<{
  path: string;
  family: "primary" | "record" | "projection";
  required: false;
  exists: false;
  mode: null;
  size_bytes: null;
  hash: null;
  bytes: null;
}>;

type CapturedFileState = ExistingFileState | MissingFileState;

type StoreState = {
  root: DirectoryState;
  plan: ExistingFileState;
  ledger: ExistingFileState;
  manifest: ExistingFileState;
  inventory: readonly CapturedFileState[];
  summary_content_directory: DirectoryState | null;
  summary_record_directory: DirectoryState | null;
  revocation_record_directory: DirectoryState | null;
  lock_path: string;
  poisoned: boolean;
  io: RuntimeFileStoreIoV04;
};

type SessionState = {
  store: CapturedRuntimeFileStoreV04;
  lock_handle: FileHandle;
  lock_identity: Identity & Readonly<{ mode: bigint; size: bigint; nlink: bigint }>;
  closed: boolean;
  poisoned: boolean;
};

const MAX_LEDGER_BYTES = 67_108_864;
const MAX_PLAN_BYTES = 16_777_216;
const MAX_MANIFEST_BYTES = 16_777_216;
const MAX_CAPTURED_FILE_BYTES = 67_108_864;
const LOCK_FILE_NAME = ".runtime-v04.lock";
const TEMP_MANIFEST_PREFIX = ".run-manifest.json.tmp.";
const SUMMARY_CONTENT_DIRECTORY = "summaries/content";
const SUMMARY_RECORD_DIRECTORY = "summaries/records";
const REVOCATION_RECORD_DIRECTORY = "authorities/revocations";
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const stores = new WeakMap<CapturedRuntimeFileStoreV04, StoreState>();
const sessions = new WeakMap<RuntimeFileStoreSessionV04, SessionState>();

const defaultIo: RuntimeFileStoreIoV04 = {
  lstat: (path) => lstat(path, { bigint: true }),
  stat: (path) => stat(path, { bigint: true }),
  realpath,
  open,
  rename,
  unlink,
  capture_file: (input) => captureRunFileForRuntimeV02(input),
  write: async (handle, bytes, offset, length, position) =>
    (await handle.write(bytes, offset, length, position)).bytesWritten,
  sync: (handle) => handle.sync(),
  close: (handle) => handle.close(),
};

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

function captureBytes(value: unknown): Uint8Array | null {
  try {
    if (!(value instanceof Uint8Array)
      || Object.getPrototypeOf(value) !== Uint8Array.prototype
      || value.buffer instanceof SharedArrayBuffer) {
      return null;
    }
    return new Uint8Array(value);
  } catch {
    return null;
  }
}

function freezeSnapshotFile(file: CapturedFileState): RuntimeFileStoreCapturedFileSnapshotV04 {
  return Object.freeze({
    path: file.path,
    family: file.family,
    required: file.required,
    exists: file.exists,
    mode: file.mode,
    size_bytes: file.size_bytes,
    hash: file.hash,
    bytes: file.bytes === null ? null : new Uint8Array(file.bytes),
  });
}

function identityOf(statsValue: Pick<BigIntStats, "dev" | "ino">): Identity {
  return Object.freeze({
    device: statsValue.dev.toString(),
    inode: statsValue.ino.toString(),
  });
}

function sameIdentity(statsValue: Pick<BigIntStats, "dev" | "ino">, identity: Identity): boolean {
  return statsValue.dev.toString() === identity.device && statsValue.ino.toString() === identity.inode;
}

function permissionMode(mode: bigint): bigint {
  return mode & 0o7777n;
}

function isCanonicalAbsolutePath(path: string): boolean {
  return isAbsolute(path) && resolve(path) === path;
}

function isInsideRoot(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child.length > 0 && child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child);
}

function mapRuntimeCaptureError(
  error: RuntimeRunFileCaptureErrorV02,
): RuntimeFileStoreCaptureV04Error {
  switch (error) {
    case "RUNTIME_FILE_NOT_FOUND":
      return "RUN_FILE_CAPTURE_FAILED";
    case "RUNTIME_FILE_PATH_INVALID":
      return "RUN_FILE_PATH_INVALID";
    case "RUNTIME_FILE_NOT_REGULAR":
      return "RUN_FILE_NOT_REGULAR";
    case "RUNTIME_FILE_MODE_INVALID":
      return "RUN_FILE_MODE_INVALID";
    case "RUNTIME_FILE_IDENTITY_CHANGED":
      return "RUN_FILE_IDENTITY_CHANGED";
    case "RUNTIME_INPUT_RESOURCE_LIMIT":
      return "RUN_FILE_TOO_LARGE";
    case "RUNTIME_FILE_CAPTURE_FAILED":
      return "RUN_FILE_CAPTURE_FAILED";
  }
}

async function verifyRootState(root: DirectoryState, io: RuntimeFileStoreIoV04): Promise<RuntimeFileStoreCaptureV04Error | null> {
  try {
    const direct = await io.lstat(root.path);
    if (!direct.isDirectory() || direct.isSymbolicLink()) return "RUN_DIRECTORY_INVALID";
    if (direct.mode !== root.mode) return "RUN_DIRECTORY_MODE_CHANGED";
    if (!sameIdentity(direct, root)) return "RUN_DIRECTORY_IDENTITY_CHANGED";
    if (await io.realpath(root.path) !== root.path) return "RUN_DIRECTORY_INVALID";
    const followed = await io.stat(root.path);
    if (!followed.isDirectory() || !sameIdentity(followed, root)) return "RUN_DIRECTORY_IDENTITY_CHANGED";
    return null;
  } catch {
    return "RUN_DIRECTORY_IDENTITY_CHANGED";
  }
}

async function captureRootState(
  runDirectory: string,
  io: RuntimeFileStoreIoV04,
): Promise<Readonly<{ ok: true; root: DirectoryState }> | Readonly<{ ok: false; error: RuntimeFileStoreCaptureV04Error }>> {
  if (!isCanonicalAbsolutePath(runDirectory)) return { ok: false, error: "RUN_DIRECTORY_INVALID" };
  try {
    const direct = await io.lstat(runDirectory);
    if (!direct.isDirectory() || direct.isSymbolicLink()) return { ok: false, error: "RUN_DIRECTORY_INVALID" };
    if (await io.realpath(runDirectory) !== runDirectory) return { ok: false, error: "RUN_DIRECTORY_INVALID" };
    const followed = await io.stat(runDirectory);
    if (!followed.isDirectory() || !sameIdentity(followed, identityOf(direct))) {
      return { ok: false, error: "RUN_DIRECTORY_IDENTITY_CHANGED" };
    }
    const issued = await issueAnchoredRunDirectoryReadCapabilityV02(runDirectory);
    if (!issued.ok) {
      return {
        ok: false,
        error: issued.error === "RUNTIME_FILE_IDENTITY_CHANGED"
          ? "RUN_DIRECTORY_IDENTITY_CHANGED"
          : "RUN_DIRECTORY_INVALID",
      };
    }
    return {
      ok: true,
      root: Object.freeze({
        path: runDirectory,
        mode: direct.mode,
        anchored: issued.value,
        ...identityOf(direct),
      }),
    };
  } catch {
    return { ok: false, error: "RUN_DIRECTORY_INVALID" };
  }
}

async function captureOptionalStrictDirectory(
  root: DirectoryState,
  relativePath: string,
  io: RuntimeFileStoreIoV04,
): Promise<DirectoryState | null> {
  const path = absoluteRunPath(root, relativePath);
  if (path === null) return null;
  try {
    const direct = await io.lstat(path);
    if (!direct.isDirectory() || direct.isSymbolicLink() || permissionMode(direct.mode) !== 0o700n) return null;
    if (await io.realpath(path) !== path) return null;
    const followed = await io.stat(path);
    if (!followed.isDirectory() || !sameIdentity(followed, identityOf(direct))) return null;
    const issued = await issueAnchoredRunDirectoryReadCapabilityV02(path);
    if (!issued.ok) return null;
    return Object.freeze({ path, mode: direct.mode, anchored: issued.value, ...identityOf(direct) });
  } catch {
    return null;
  }
}

function absoluteRunPath(root: DirectoryState, relativePath: string): string | null {
  const parsed = RelativeRunPathV02.safeParse(relativePath);
  if (!parsed.success) return null;
  const path = join(root.path, ...parsed.data.split("/"));
  return isInsideRoot(root.path, path) ? path : null;
}

async function captureExistingFile(
  root: DirectoryState,
  relativePath: string,
  maxBytes: number,
  io: RuntimeFileStoreIoV04,
): Promise<Readonly<{ ok: true; file: ExistingFileState }> | Readonly<{ ok: false; error: RuntimeFileStoreCaptureV04Error }>> {
  const absolutePath = absoluteRunPath(root, relativePath);
  if (absolutePath === null) return { ok: false, error: "RUN_FILE_PATH_INVALID" };
  try {
    const before = await io.lstat(absolutePath);
    if (!before.isFile() || before.isSymbolicLink()) return { ok: false, error: "RUN_FILE_NOT_REGULAR" };
    if (before.nlink !== 1n) return { ok: false, error: "RUN_FILE_IDENTITY_CHANGED" };
    if (permissionMode(before.mode) !== 0o600n) return { ok: false, error: "RUN_FILE_MODE_INVALID" };
    const captured = await io.capture_file({
      anchored_run_directory: root.anchored,
      relative_path: relativePath,
      max_bytes: maxBytes,
    });
    if (!captured.ok) return { ok: false, error: mapRuntimeCaptureError(captured.error) };
    const after = await io.lstat(absolutePath);
    if (!after.isFile() || after.isSymbolicLink() || after.nlink !== 1n
      || before.mode !== after.mode || before.size !== after.size || !sameIdentity(after, identityOf(before))) {
      return { ok: false, error: "RUN_FILE_IDENTITY_CHANGED" };
    }
    return {
      ok: true,
      file: Object.freeze({
        path: relativePath,
        family: "record",
        required: true,
        exists: true,
        mode: 384 as const,
        size_bytes: captured.value.metadata.size_bytes,
        hash: captured.value.metadata.sha256,
        bytes: new Uint8Array(captured.value.bytes),
        nlink: after.nlink,
        ...identityOf(after),
      }),
    };
  } catch {
    return { ok: false, error: "RUN_FILE_CAPTURE_FAILED" };
  }
}

async function verifyMissingOptionalFile(
  root: DirectoryState,
  relativePath: string,
  io: RuntimeFileStoreIoV04,
): Promise<boolean> {
  const absolutePath = absoluteRunPath(root, relativePath);
  if (absolutePath === null) return false;
  try {
    await io.lstat(absolutePath);
    return false;
  } catch (error) {
    return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
  }
}

function parseManifestForCapture(manifestBytes: Uint8Array):
  | Readonly<{ ok: true; manifest: RunManifestV04Value }>
  | Readonly<{ ok: false; error: RuntimeFileStoreCaptureV04Error }> {
  if (manifestBytes.byteLength > MAX_MANIFEST_BYTES) return { ok: false, error: "RUN_FILE_TOO_LARGE" };
  try {
    const text = UTF8.decode(manifestBytes);
    const document = parseDocument(text, { uniqueKeys: true });
    if (document.errors.length > 0) return { ok: false, error: "RUN_MANIFEST_SYNTAX_INVALID" };
    const parsed = RunManifestV04.safeParse(JSON.parse(text) as unknown);
    if (!parsed.success) return { ok: false, error: "RUN_MANIFEST_SCHEMA_INVALID" };
    return { ok: true, manifest: parsed.data };
  } catch {
    return { ok: false, error: "RUN_MANIFEST_SYNTAX_INVALID" };
  }
}

function parseAuthorityRevocationRecordForCommit(
  bytes: Uint8Array,
): AuthorityRevocationRecordV02Value | null {
  try {
    const text = UTF8.decode(bytes);
    const document = parseDocument(text, { uniqueKeys: true });
    if (document.errors.length > 0) return null;
    const parsed = AuthorityRevocationRecordV02.safeParse(JSON.parse(text) as unknown);
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

function withManifestMetadata(
  file: ExistingFileState,
  family: CapturedFileState["family"],
  required: boolean,
): ExistingFileState {
  return Object.freeze({
    ...file,
    family,
    required,
  });
}

function withMissingMetadata(
  path: string,
  family: CapturedFileState["family"],
): MissingFileState {
  return Object.freeze({
    path,
    family,
    required: false,
    exists: false,
    mode: null,
    size_bytes: null,
    hash: null,
    bytes: null,
  });
}

function capturedFilesForManifest(files: readonly CapturedFileState[]): ReadonlyArray<{
  path: string;
  family: "primary" | "record" | "projection";
  required: boolean;
  mode: 384 | null;
  bytes: Uint8Array | null;
}> {
  return Object.freeze(files.map((file) => Object.freeze({
    path: file.path,
    family: file.family,
    required: file.required,
    mode: file.mode,
    bytes: file.bytes === null ? null : new Uint8Array(file.bytes),
  })));
}

function fileMatchesInventory(
  file: ExistingFileState,
  row: RunManifestV04Value["file_inventory"][number],
): boolean {
  return row.exists
    && row.mode === 384
    && row.size_bytes === file.size_bytes
    && row.hash === file.hash;
}

async function captureInventory(
  root: DirectoryState,
  plan: ExistingFileState,
  ledger: ExistingFileState,
  manifest: RunManifestV04Value,
  io: RuntimeFileStoreIoV04,
): Promise<Readonly<{ ok: true; files: readonly CapturedFileState[] }> | Readonly<{ ok: false; error: RuntimeFileStoreCaptureV04Error }>> {
  let sawPlan = false;
  let sawLedger = false;
  const files: CapturedFileState[] = [];
  for (const row of manifest.file_inventory) {
    if (row.path === "ledger.jsonl") {
      sawLedger = true;
      if (!fileMatchesInventory(ledger, row)) return { ok: false, error: "RUN_MANIFEST_FILESET_INVALID" };
      files.push(withManifestMetadata(ledger, row.family, row.required));
      continue;
    }
    if (row.path === "resolved-run-plan.json") {
      sawPlan = true;
      if (!fileMatchesInventory(plan, row)) return { ok: false, error: "RUN_MANIFEST_FILESET_INVALID" };
      files.push(withManifestMetadata(plan, row.family, row.required));
      continue;
    }
    if (!row.exists) {
      if (!await verifyMissingOptionalFile(root, row.path, io)) return { ok: false, error: "RUN_MANIFEST_FILESET_INVALID" };
      files.push(withMissingMetadata(row.path, row.family));
      continue;
    }
    if (row.mode !== 384 || row.size_bytes === null || row.hash === null || row.required !== true) {
      return { ok: false, error: "RUN_MANIFEST_FILESET_INVALID" };
    }
    if (row.size_bytes > MAX_CAPTURED_FILE_BYTES) return { ok: false, error: "RUN_FILE_TOO_LARGE" };
    const captured = await captureExistingFile(root, row.path, Math.max(1, row.size_bytes), io);
    if (!captured.ok) return captured;
    const file = withManifestMetadata(captured.file, row.family, true);
    if (!fileMatchesInventory(file, row)) return { ok: false, error: "RUN_MANIFEST_FILESET_INVALID" };
    files.push(file);
  }
  return sawPlan && sawLedger
    ? { ok: true, files: Object.freeze(files) }
    : { ok: false, error: "RUN_MANIFEST_FILESET_INVALID" };
}

function captureInput(value: unknown): Readonly<{ run_directory: string }> | null {
  const record = exactObject(value, ["run_directory"]);
  return record !== null && typeof record.run_directory === "string"
    ? Object.freeze({ run_directory: record.run_directory })
    : null;
}

function commitInput(value: unknown): RuntimeFileStoreCommitInputV04 | null {
  const record = exactObject(value, [
    "expected_ledger_bytes_hash",
    "expected_manifest_hash",
    "next_ledger_bytes",
    "next_manifest_bytes",
  ]);
  if (record === null
    || typeof record.expected_ledger_bytes_hash !== "string"
    || typeof record.expected_manifest_hash !== "string") return null;
  const nextLedgerBytes = captureBytes(record.next_ledger_bytes);
  const nextManifestBytes = captureBytes(record.next_manifest_bytes);
  if (nextLedgerBytes === null || nextManifestBytes === null) return null;
  return Object.freeze({
    expected_ledger_bytes_hash: record.expected_ledger_bytes_hash,
    expected_manifest_hash: record.expected_manifest_hash,
    next_ledger_bytes: nextLedgerBytes,
    next_manifest_bytes: nextManifestBytes,
  });
}

function compactionArtifactInput(value: unknown): Readonly<{ relative_path: string; bytes: Uint8Array }> | null {
  const record = exactObject(value, ["relative_path", "bytes"]);
  if (record === null || typeof record.relative_path !== "string") return null;
  const bytes = captureBytes(record.bytes);
  return bytes === null || bytes.byteLength === 0
    ? null
    : Object.freeze({ relative_path: record.relative_path, bytes });
}

function compactionCommitInput(value: unknown): RuntimeFileStoreCompactionCommitInputV04 | null {
  const record = exactObject(value, [
    "expected_ledger_bytes_hash",
    "expected_manifest_hash",
    "summary_content",
    "summary_record",
    "next_ledger_bytes",
    "next_manifest_bytes",
  ]);
  if (record === null
    || typeof record.expected_ledger_bytes_hash !== "string"
    || typeof record.expected_manifest_hash !== "string") return null;
  const summaryContent = compactionArtifactInput(record.summary_content);
  const summaryRecord = compactionArtifactInput(record.summary_record);
  const nextLedgerBytes = captureBytes(record.next_ledger_bytes);
  const nextManifestBytes = captureBytes(record.next_manifest_bytes);
  if (summaryContent === null || summaryRecord === null || nextLedgerBytes === null || nextManifestBytes === null) return null;
  return Object.freeze({
    expected_ledger_bytes_hash: record.expected_ledger_bytes_hash,
    expected_manifest_hash: record.expected_manifest_hash,
    summary_content: summaryContent,
    summary_record: summaryRecord,
    next_ledger_bytes: nextLedgerBytes,
    next_manifest_bytes: nextManifestBytes,
  });
}

function recordCommitInput(value: unknown): RuntimeFileStoreRecordCommitInputV04 | null {
  const record = exactObject(value, [
    "expected_ledger_bytes_hash",
    "expected_manifest_hash",
    "record",
    "next_ledger_bytes",
    "next_manifest_bytes",
  ]);
  if (record === null
    || typeof record.expected_ledger_bytes_hash !== "string"
    || typeof record.expected_manifest_hash !== "string") return null;
  const persistedRecord = compactionArtifactInput(record.record);
  const nextLedgerBytes = captureBytes(record.next_ledger_bytes);
  const nextManifestBytes = captureBytes(record.next_manifest_bytes);
  if (persistedRecord === null || nextLedgerBytes === null || nextManifestBytes === null) return null;
  return Object.freeze({
    expected_ledger_bytes_hash: record.expected_ledger_bytes_hash,
    expected_manifest_hash: record.expected_manifest_hash,
    record: persistedRecord,
    next_ledger_bytes: nextLedgerBytes,
    next_manifest_bytes: nextManifestBytes,
  });
}

async function readExactFile(
  root: DirectoryState,
  relativePath: string,
  expectedSize: number,
  io: RuntimeFileStoreIoV04,
): Promise<Readonly<{ ok: true; file: ExistingFileState }> | Readonly<{ ok: false; error: RuntimeFileStoreCaptureV04Error }>> {
  return captureExistingFile(root, relativePath, Math.max(1, expectedSize), io);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}

function sameExistingFile(left: ExistingFileState, right: ExistingFileState): boolean {
  return sameBytes(left.bytes, right.bytes)
    && left.hash === right.hash
    && left.size_bytes === right.size_bytes
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.device === right.device
    && left.inode === right.inode;
}

type CurrentStoreReadback = Readonly<{
  plan: ExistingFileState;
  ledger: ExistingFileState;
  manifest: ExistingFileState;
  manifest_files: readonly CapturedFileState[];
  current_manifest_hash: string;
}>;

async function verifyStoreStillMatchesCaptured(
  store: StoreState,
): Promise<Readonly<{ ok: true; state: CurrentStoreReadback }> | Readonly<{
  ok: false;
  error:
    | "RUN_DIRECTORY_IDENTITY_CHANGED"
    | "RUN_DIRECTORY_MODE_CHANGED"
    | "RUNTIME_STORE_DRIFT"
    | "RUN_LOCK_IDENTITY_INVALID";
}>> {
  const rootCheck = await verifyRootState(store.root, store.io);
  if (rootCheck === "RUN_DIRECTORY_IDENTITY_CHANGED") return { ok: false, error: "RUN_DIRECTORY_IDENTITY_CHANGED" };
  if (rootCheck === "RUN_DIRECTORY_MODE_CHANGED") return { ok: false, error: "RUN_DIRECTORY_MODE_CHANGED" };
  if (rootCheck !== null) return { ok: false, error: "RUNTIME_STORE_DRIFT" };

  const plan = await readExactFile(store.root, store.plan.path, store.plan.size_bytes, store.io);
  if (!plan.ok || !sameExistingFile(withManifestMetadata(plan.file, store.plan.family, store.plan.required), store.plan)) {
    return { ok: false, error: "RUNTIME_STORE_DRIFT" };
  }
  const ledger = await readExactFile(store.root, store.ledger.path, store.ledger.size_bytes, store.io);
  if (!ledger.ok || !sameExistingFile(withManifestMetadata(ledger.file, store.ledger.family, store.ledger.required), store.ledger)) {
    return { ok: false, error: "RUNTIME_STORE_DRIFT" };
  }
  const manifest = await readExactFile(store.root, store.manifest.path, store.manifest.size_bytes, store.io);
  if (!manifest.ok || !sameExistingFile(withManifestMetadata(manifest.file, store.manifest.family, store.manifest.required), store.manifest)) {
    return { ok: false, error: "RUNTIME_STORE_DRIFT" };
  }

  const files: CapturedFileState[] = [];
  for (const file of store.inventory) {
    if (!file.exists) {
      if (!await verifyMissingOptionalFile(store.root, file.path, store.io)) return { ok: false, error: "RUNTIME_STORE_DRIFT" };
      files.push(file);
      continue;
    }
    const captured = file.path === store.plan.path
      ? plan.file
      : file.path === store.ledger.path
        ? ledger.file
        : await readExactFile(store.root, file.path, file.size_bytes, store.io).then((value) => value.ok ? value.file : value);
    if (!("exists" in captured) || captured.exists !== true) return { ok: false, error: "RUNTIME_STORE_DRIFT" };
    const current = withManifestMetadata(captured, file.family, file.required);
    if (!sameExistingFile(current, file)) return { ok: false, error: "RUNTIME_STORE_DRIFT" };
    files.push(current);
  }

  const inspectedManifest = inspectRunManifestV04({
    manifest_bytes: manifest.file.bytes,
    ledger_bytes: ledger.file.bytes,
    captured_files: capturedFilesForManifest(files),
  });
  if (!inspectedManifest.ok) return { ok: false, error: "RUNTIME_STORE_DRIFT" };
  return {
    ok: true,
    state: Object.freeze({
      plan: withManifestMetadata(plan.file, store.plan.family, store.plan.required),
      ledger: withManifestMetadata(ledger.file, store.ledger.family, store.ledger.required),
      manifest: withManifestMetadata(manifest.file, store.manifest.family, store.manifest.required),
      manifest_files: Object.freeze(files),
      current_manifest_hash: inspectedManifest.manifest.manifest_hash,
    }),
  };
}

function startsWithBytes(bytes: Uint8Array, prefix: Uint8Array): boolean {
  return bytes.byteLength >= prefix.byteLength && sameBytes(bytes.subarray(0, prefix.byteLength), prefix);
}

async function openDirectoryHandle(path: string, io: RuntimeFileStoreIoV04): Promise<FileHandle> {
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  const directory = "O_DIRECTORY" in constants ? constants.O_DIRECTORY : 0;
  return io.open(path, constants.O_RDONLY | noFollow | directory);
}

async function verifySessionLock(
  session: SessionState,
): Promise<boolean> {
  const store = stores.get(session.store);
  if (store === undefined) return false;
  try {
    const byHandle = await session.lock_handle.stat({ bigint: true });
    const byPath = await store.io.lstat(store.lock_path);
    return byHandle.isFile()
      && byPath.isFile()
      && !byPath.isSymbolicLink()
      && permissionMode(byPath.mode) === 0o600n
      && byHandle.nlink === 1n
      && byPath.nlink === 1n
      && byHandle.mode === session.lock_identity.mode
      && byPath.mode === session.lock_identity.mode
      && byHandle.size === session.lock_identity.size
      && byPath.size === session.lock_identity.size
      && sameIdentity(byHandle, session.lock_identity)
      && sameIdentity(byPath, session.lock_identity);
  } catch {
    return false;
  }
}

async function writeSingleExact(
  handle: FileHandle,
  bytes: Uint8Array,
  position: number | null,
  io: RuntimeFileStoreIoV04,
): Promise<boolean> {
  const written = await io.write(handle, bytes, 0, bytes.byteLength, position);
  return written === bytes.byteLength;
}

type OutcomeUnknownCommitV04 = Readonly<{
  ok: false;
  classification: "OUTCOME_UNKNOWN";
  error: "RUNTIME_IO_OUTCOME_UNKNOWN";
}>;

type PreWriteCommitFailureV04 = Readonly<{
  ok: false;
  classification: "NOT_COMMITTED";
  error: "RUNTIME_IO_NOT_COMMITTED";
}>;

function unknown(
  session: SessionState,
  store: StoreState,
): OutcomeUnknownCommitV04 {
  session.poisoned = true;
  session.closed = false;
  store.poisoned = true;
  return Object.freeze({
    ok: false,
    classification: "OUTCOME_UNKNOWN",
    error: "RUNTIME_IO_OUTCOME_UNKNOWN",
  });
}

function notCommittedIoFailure(): PreWriteCommitFailureV04 {
  return Object.freeze({
    ok: false,
    classification: "NOT_COMMITTED",
    error: "RUNTIME_IO_NOT_COMMITTED",
  });
}

type InvocationOwnedFileV04 = Readonly<{
  absolute_path: string;
  relative_path: string;
  identity: Identity;
  parent: DirectoryState;
}>;

function hasErrorCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}

async function pathIsAbsent(path: string, io: RuntimeFileStoreIoV04): Promise<boolean> {
  try {
    await io.lstat(path);
    return false;
  } catch (error) {
    return hasErrorCode(error, "ENOENT");
  }
}

async function cleanupInvocationOwnedFiles(
  owned: readonly InvocationOwnedFileV04[],
  io: RuntimeFileStoreIoV04,
): Promise<boolean> {
  let clean = true;
  for (const file of [...owned].reverse()) {
    try {
      const byPath = await io.lstat(file.absolute_path);
      if (!byPath.isFile() || byPath.isSymbolicLink() || byPath.nlink !== 1n || !sameIdentity(byPath, file.identity)) {
        clean = false;
        continue;
      }
      await io.unlink(file.absolute_path);
      const directoryHandle = await openDirectoryHandle(file.parent.path, io);
      try {
        await io.sync(directoryHandle);
      } finally {
        await io.close(directoryHandle);
      }
    } catch {
      clean = false;
    }
  }
  return clean;
}

async function openOwnedCreateNewFile(
  root: DirectoryState,
  parent: DirectoryState,
  relativePath: string,
  io: RuntimeFileStoreIoV04,
): Promise<Readonly<{ handle: FileHandle; owned: InvocationOwnedFileV04 }>> {
  const absolutePath = absoluteRunPath(root, relativePath);
  if (absolutePath === null || !isInsideRoot(parent.path, absolutePath) || resolve(absolutePath) !== absolutePath) {
    throw new Error("invalid-created-path");
  }
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  const handle = await io.open(absolutePath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow, 0o600);
  try {
    const byHandle = await handle.stat({ bigint: true });
    const byPath = await io.lstat(absolutePath);
    if (!byHandle.isFile() || !byPath.isFile() || byPath.isSymbolicLink()
      || byHandle.nlink !== 1n || byPath.nlink !== 1n
      || permissionMode(byHandle.mode) !== 0o600n || permissionMode(byPath.mode) !== 0o600n
      || !sameIdentity(byPath, identityOf(byHandle))) {
      throw new Error("created-file-identity-invalid");
    }
    return Object.freeze({
      handle,
      owned: Object.freeze({
        absolute_path: absolutePath,
        relative_path: relativePath,
        identity: identityOf(byHandle),
        parent,
      }),
    });
  } catch (error) {
    await io.close(handle).catch(() => undefined);
    throw error;
  }
}

async function verifyInvocationOwnedFile(
  root: DirectoryState,
  owned: InvocationOwnedFileV04,
  bytes: Uint8Array,
  io: RuntimeFileStoreIoV04,
): Promise<ExistingFileState | null> {
  const captured = await readExactFile(root, owned.relative_path, bytes.byteLength, io);
  if (!captured.ok
    || captured.file.device !== owned.identity.device
    || captured.file.inode !== owned.identity.inode
    || !sameBytes(captured.file.bytes, bytes)) return null;
  return captured.file;
}

async function cleanupOwnedLockOnOpenFailure(
  lockHandle: FileHandle,
  lockPath: string,
  root: DirectoryState,
  io: RuntimeFileStoreIoV04,
): Promise<void> {
  try {
    const byHandle = await lockHandle.stat({ bigint: true });
    try {
      const byPath = await io.lstat(lockPath);
      if (byPath.isFile() && !byPath.isSymbolicLink() && sameIdentity(byPath, identityOf(byHandle))) {
        await io.unlink(lockPath);
        const directoryHandle = await openDirectoryHandle(root.path, io);
        try {
          await io.sync(directoryHandle);
        } finally {
          await io.close(directoryHandle);
        }
      }
    } catch {
      // Best effort cleanup only.
    }
  } finally {
    await io.close(lockHandle).catch(() => undefined);
  }
}

export async function captureRuntimeFileStoreV04(input: unknown): Promise<RuntimeFileStoreCaptureV04Result> {
  return captureRuntimeFileStoreV04ForTest(input, {});
}

export async function captureRuntimeFileStoreV04ForTest(
  input: unknown,
  overrides: RuntimeFileStoreIoOverridesV04,
): Promise<RuntimeFileStoreCaptureV04Result> {
  try {
    const capturedInput = captureInput(input);
    if (capturedInput === null) return Object.freeze({ ok: false, error: "STORE_INPUT_INVALID" });
    const io: RuntimeFileStoreIoV04 = Object.freeze({ ...defaultIo, ...overrides });
    const rootResult = await captureRootState(capturedInput.run_directory, io);
    if (!rootResult.ok) return Object.freeze(rootResult);

    const plan = await captureExistingFile(rootResult.root, "resolved-run-plan.json", MAX_PLAN_BYTES, io);
    if (!plan.ok) return Object.freeze(plan);
    const ledger = await captureExistingFile(rootResult.root, "ledger.jsonl", MAX_LEDGER_BYTES, io);
    if (!ledger.ok) return Object.freeze(ledger);
    const manifest = await captureExistingFile(rootResult.root, "run-manifest.json", MAX_MANIFEST_BYTES, io);
    if (!manifest.ok) return Object.freeze(manifest);

    const parsedManifest = parseManifestForCapture(manifest.file.bytes);
    if (!parsedManifest.ok) return Object.freeze(parsedManifest);
    const inventory = await captureInventory(
      rootResult.root,
      withManifestMetadata(plan.file, "primary", true),
      withManifestMetadata(ledger.file, "primary", true),
      parsedManifest.manifest,
      io,
    );
    if (!inventory.ok) return Object.freeze(inventory);

    const inspectedManifest = inspectRunManifestV04({
      manifest_bytes: manifest.file.bytes,
      ledger_bytes: ledger.file.bytes,
      captured_files: capturedFilesForManifest(inventory.files),
    });
    if (!inspectedManifest.ok) return Object.freeze({ ok: false, error: "RUN_MANIFEST_INVALID" });

    const summaryContentDirectory = await captureOptionalStrictDirectory(
      rootResult.root,
      SUMMARY_CONTENT_DIRECTORY,
      io,
    );
    const summaryRecordDirectory = await captureOptionalStrictDirectory(
      rootResult.root,
      SUMMARY_RECORD_DIRECTORY,
      io,
    );
    const revocationRecordDirectory = await captureOptionalStrictDirectory(
      rootResult.root,
      REVOCATION_RECORD_DIRECTORY,
      io,
    );

    const store = Object.freeze({}) as CapturedRuntimeFileStoreV04;
    stores.set(store, {
      root: rootResult.root,
      plan: withManifestMetadata(plan.file, "primary", true),
      ledger: withManifestMetadata(ledger.file, "primary", true),
      manifest: withManifestMetadata(manifest.file, "projection", true),
      inventory: inventory.files,
      summary_content_directory: summaryContentDirectory,
      summary_record_directory: summaryRecordDirectory,
      revocation_record_directory: revocationRecordDirectory,
      lock_path: join(rootResult.root.path, LOCK_FILE_NAME),
      poisoned: false,
      io,
    });
    return Object.freeze({ ok: true, store });
  } catch {
    return Object.freeze({ ok: false, error: "STORE_INPUT_INVALID" });
  }
}

export async function openRuntimeFileStoreSessionV04(
  store: CapturedRuntimeFileStoreV04,
): Promise<OpenRuntimeFileStoreSessionV04Result> {
  const state = stores.get(store);
  if (state === undefined) return Object.freeze({ ok: false, error: "CAPTURED_STORE_INVALID" });
  if (state.poisoned) return Object.freeze({ ok: false, error: "RUNTIME_FILE_STORE_POISONED" });
  const rootCheck = await verifyRootState(state.root, state.io);
  if (rootCheck === "RUN_DIRECTORY_MODE_CHANGED") return Object.freeze({ ok: false, error: rootCheck });
  if (rootCheck === "RUN_DIRECTORY_IDENTITY_CHANGED") return Object.freeze({ ok: false, error: rootCheck });
  if (rootCheck !== null) return Object.freeze({ ok: false, error: "RUN_FILE_IDENTITY_CHANGED" });

  try {
    const existing = await state.io.lstat(state.lock_path);
    if (!existing.isFile() || existing.isSymbolicLink() || permissionMode(existing.mode) !== 0o600n || existing.nlink !== 1n) {
      return Object.freeze({ ok: false, error: "RUN_LOCK_INVALID" });
    }
    return Object.freeze({ ok: false, error: "RUN_LOCK_UNAVAILABLE" });
  } catch (error) {
    if (!(typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT")) {
      return Object.freeze({ ok: false, error: "RUN_LOCK_INVALID" });
    }
  }

  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  let lockHandle: FileHandle | undefined;
  let directoryHandle: FileHandle | undefined;
  try {
    lockHandle = await state.io.open(
      state.lock_path,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | noFollow,
      0o600,
    );
    const lockBytes = new TextEncoder().encode(JSON.stringify({
      schema_version: "0.4",
      lock_id: randomUUID(),
      created_at: new Date().toISOString(),
    }));
    if (!await writeSingleExact(lockHandle, lockBytes, 0, state.io)) {
      await cleanupOwnedLockOnOpenFailure(lockHandle, state.lock_path, state.root, state.io);
      return Object.freeze({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" });
    }
    await state.io.sync(lockHandle);
    directoryHandle = await openDirectoryHandle(state.root.path, state.io);
    await state.io.sync(directoryHandle);
    const byHandle = await lockHandle.stat({ bigint: true });
    const byPath = await state.io.lstat(state.lock_path);
    if (!byHandle.isFile() || !byPath.isFile() || byPath.isSymbolicLink()
      || permissionMode(byPath.mode) !== 0o600n || byHandle.nlink !== 1n || byPath.nlink !== 1n
      || !sameIdentity(byHandle, identityOf(byPath))) {
      await cleanupOwnedLockOnOpenFailure(lockHandle, state.lock_path, state.root, state.io);
      return Object.freeze({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" });
    }
    const session = Object.freeze({}) as RuntimeFileStoreSessionV04;
    sessions.set(session, {
      store,
      lock_handle: lockHandle,
      lock_identity: Object.freeze({
        ...identityOf(byHandle),
        mode: byHandle.mode,
        size: byHandle.size,
        nlink: byHandle.nlink,
      }),
      closed: false,
      poisoned: false,
    });
    return Object.freeze({ ok: true, session });
  } catch (error) {
    if (lockHandle !== undefined) await cleanupOwnedLockOnOpenFailure(lockHandle, state.lock_path, state.root, state.io);
    if (typeof error === "object" && error !== null && "code" in error && error.code === "EEXIST") {
      return Object.freeze({ ok: false, error: "RUN_LOCK_UNAVAILABLE" });
    }
    return Object.freeze({ ok: false, error: "RUN_LOCK_INVALID" });
  } finally {
    if (directoryHandle !== undefined) await state.io.close(directoryHandle).catch(() => undefined);
  }
}

export function readRuntimeFileStoreSessionSnapshotV04(
  session: RuntimeFileStoreSessionV04,
): ReadRuntimeFileStoreSessionSnapshotV04Result {
  const state = sessions.get(session);
  if (state === undefined) return Object.freeze({ ok: false, error: "RUNTIME_FILE_STORE_SESSION_INVALID" });
  if (state.closed) return Object.freeze({ ok: false, error: "RUNTIME_FILE_STORE_SESSION_CLOSED" });
  const store = stores.get(state.store);
  if (store === undefined || state.poisoned || store.poisoned) {
    return Object.freeze({ ok: false, error: "RUNTIME_FILE_STORE_SESSION_POISONED" });
  }
  return Object.freeze({
    ok: true,
    snapshot: Object.freeze({
      run_directory: store.root.path,
      lock_path: store.lock_path,
      resolved_run_plan_bytes: new Uint8Array(store.plan.bytes),
      ledger_bytes: new Uint8Array(store.ledger.bytes),
      manifest_bytes: new Uint8Array(store.manifest.bytes),
      captured_files: Object.freeze(store.inventory.map((file) => freezeSnapshotFile(file))),
      summary_content_directory: store.summary_content_directory === null ? null : Object.freeze({
        path: store.summary_content_directory.path,
        mode: Number(permissionMode(store.summary_content_directory.mode)),
        device: store.summary_content_directory.device,
        inode: store.summary_content_directory.inode,
      }),
      summary_record_directory: store.summary_record_directory === null ? null : Object.freeze({
        path: store.summary_record_directory.path,
        mode: Number(permissionMode(store.summary_record_directory.mode)),
        device: store.summary_record_directory.device,
        inode: store.summary_record_directory.inode,
      }),
      revocation_record_directory: store.revocation_record_directory === null ? null : Object.freeze({
        path: store.revocation_record_directory.path,
        mode: Number(permissionMode(store.revocation_record_directory.mode)),
        device: store.revocation_record_directory.device,
        inode: store.revocation_record_directory.inode,
      }),
    }),
  });
}

export async function commitRuntimeFileStoreSessionV04(
  session: RuntimeFileStoreSessionV04,
  input: unknown,
): Promise<CommitRuntimeFileStoreSessionV04Result> {
  const sessionState = sessions.get(session);
  if (sessionState === undefined) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_FILE_STORE_SESSION_INVALID" });
  }
  if (sessionState.closed) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_FILE_STORE_SESSION_CLOSED" });
  }
  const store = stores.get(sessionState.store);
  if (store === undefined || sessionState.poisoned || store.poisoned) {
    return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_FILE_STORE_SESSION_POISONED" });
  }
  const parsedInput = commitInput(input);
  if (parsedInput === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NEXT_STATE_INVALID" });
  }
  if (!await verifySessionLock(sessionState)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUN_LOCK_IDENTITY_INVALID" });
  }

  const current = await verifyStoreStillMatchesCaptured(store);
  if (!current.ok) {
    return Object.freeze({
      ok: false,
      classification: "NOT_COMMITTED",
      error: current.error === "RUN_DIRECTORY_IDENTITY_CHANGED"
        ? "RUN_DIRECTORY_IDENTITY_CHANGED"
        : current.error === "RUN_DIRECTORY_MODE_CHANGED"
          ? "RUN_DIRECTORY_MODE_CHANGED"
          : current.error,
    });
  }

  if (parsedInput.expected_ledger_bytes_hash !== current.state.ledger.hash
    || parsedInput.expected_manifest_hash !== current.state.current_manifest_hash) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EXPECTATION_MISMATCH" });
  }
  if (!startsWithBytes(parsedInput.next_ledger_bytes, current.state.ledger.bytes)
    || parsedInput.next_ledger_bytes.byteLength === current.state.ledger.bytes.byteLength) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NEXT_STATE_INVALID" });
  }

  const nextLedgerInspection = inspectRuntimeLedgerV04(parsedInput.next_ledger_bytes);
  if (!nextLedgerInspection.ok) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NEXT_STATE_INVALID" });
  }

  const nextManifestFiles = current.state.manifest_files.map((file) => file.path === "ledger.jsonl"
    ? withManifestMetadata(
      Object.freeze({
        ...current.state.ledger,
        size_bytes: parsedInput.next_ledger_bytes.byteLength,
        hash: hashRawBytes(parsedInput.next_ledger_bytes),
        bytes: new Uint8Array(parsedInput.next_ledger_bytes),
      }),
      file.family,
      file.required,
    )
    : file);
  const nextManifestInspection = inspectRunManifestV04({
    manifest_bytes: parsedInput.next_manifest_bytes,
    ledger_bytes: parsedInput.next_ledger_bytes,
    captured_files: capturedFilesForManifest(nextManifestFiles),
  });
  if (!nextManifestInspection.ok) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_NEXT_STATE_INVALID" });
  }

  const ledgerTail = parsedInput.next_ledger_bytes.subarray(current.state.ledger.bytes.byteLength);
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  let appendHandle: FileHandle | undefined;
  let tempHandle: FileHandle | undefined;
  let directoryHandle: FileHandle | undefined;
  const tempPath = join(store.root.path, `${TEMP_MANIFEST_PREFIX}${randomUUID()}.json`);
  let phase:
    | "pre-append-open"
    | "pre-append-verify"
    | "append-attempted"
    | "post-append" = "pre-append-open";
  try {
    appendHandle = await store.io.open(store.ledger.path === "ledger.jsonl" ? join(store.root.path, store.ledger.path) : store.ledger.path,
      constants.O_WRONLY | constants.O_APPEND | noFollow);
    phase = "pre-append-verify";
    const appendStat = await appendHandle.stat({ bigint: true });
    if (!appendStat.isFile() || appendStat.nlink !== 1n || !sameIdentity(appendStat, current.state.ledger)) {
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_STORE_DRIFT" });
    }
    phase = "append-attempted";
    if (!await writeSingleExact(appendHandle, ledgerTail, null, store.io)) return unknown(sessionState, store);
    phase = "post-append";
    await store.io.sync(appendHandle);
    await store.io.close(appendHandle);
    appendHandle = undefined;

    const ledgerReadback = await readExactFile(store.root, "ledger.jsonl", parsedInput.next_ledger_bytes.byteLength, store.io);
    if (!ledgerReadback.ok || !sameBytes(ledgerReadback.file.bytes, parsedInput.next_ledger_bytes)) return unknown(sessionState, store);

    tempHandle = await store.io.open(
      tempPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow,
      0o600,
    );
    const tempStat = await tempHandle.stat({ bigint: true });
    if (!tempStat.isFile() || tempStat.nlink !== 1n || permissionMode(tempStat.mode) !== 0o600n) return unknown(sessionState, store);
    if (!await writeSingleExact(tempHandle, parsedInput.next_manifest_bytes, 0, store.io)) return unknown(sessionState, store);
    await store.io.sync(tempHandle);
    await store.io.close(tempHandle);
    tempHandle = undefined;
    await store.io.rename(tempPath, join(store.root.path, "run-manifest.json"));
    directoryHandle = await openDirectoryHandle(store.root.path, store.io);
    await store.io.sync(directoryHandle);
    await store.io.close(directoryHandle);
    directoryHandle = undefined;

    const manifestReadback = await readExactFile(store.root, "run-manifest.json", parsedInput.next_manifest_bytes.byteLength, store.io);
    if (!manifestReadback.ok || !sameBytes(manifestReadback.file.bytes, parsedInput.next_manifest_bytes)) return unknown(sessionState, store);
    const finalLedger = await readExactFile(store.root, "ledger.jsonl", parsedInput.next_ledger_bytes.byteLength, store.io);
    if (!finalLedger.ok || !sameBytes(finalLedger.file.bytes, parsedInput.next_ledger_bytes)) return unknown(sessionState, store);

    const nextInventory: CapturedFileState[] = [];
    for (const row of nextManifestInspection.manifest.file_inventory) {
      if (row.path === "ledger.jsonl") {
        nextInventory.push(withManifestMetadata(
          Object.freeze({
            ...finalLedger.file,
            family: "primary",
            required: true,
          }),
          row.family,
          row.required,
        ));
        continue;
      }
      const existing = current.state.manifest_files.find((file) => file.path === row.path);
      if (existing === undefined) return unknown(sessionState, store);
      nextInventory.push(existing);
    }

    store.plan = current.state.plan;
    store.ledger = withManifestMetadata(finalLedger.file, "primary", true);
    store.manifest = withManifestMetadata(manifestReadback.file, "projection", true);
    store.inventory = Object.freeze(nextInventory);
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      ledger_bytes_hash: finalLedger.file.hash,
      manifest_hash: nextManifestInspection.manifest.manifest_hash,
    });
  } catch {
    return phase === "pre-append-open" || phase === "pre-append-verify"
      ? notCommittedIoFailure()
      : unknown(sessionState, store);
  } finally {
    if (appendHandle !== undefined) await store.io.close(appendHandle).catch(() => undefined);
    if (tempHandle !== undefined) await store.io.close(tempHandle).catch(() => undefined);
    if (directoryHandle !== undefined) await store.io.close(directoryHandle).catch(() => undefined);
  }
}

export async function commitRuntimeCompactionFileStoreSessionV04(
  session: RuntimeFileStoreSessionV04,
  input: unknown,
): Promise<CommitRuntimeCompactionFileStoreSessionV04Result> {
  const sessionState = sessions.get(session);
  if (sessionState === undefined) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_FILE_STORE_SESSION_INVALID" });
  }
  if (sessionState.closed) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_FILE_STORE_SESSION_CLOSED" });
  }
  const store = stores.get(sessionState.store);
  if (store === undefined || sessionState.poisoned || store.poisoned) {
    return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_FILE_STORE_SESSION_POISONED" });
  }
  const parsedInput = compactionCommitInput(input);
  if (parsedInput === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INVALID" });
  }
  if (!await verifySessionLock(sessionState)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUN_LOCK_IDENTITY_INVALID" });
  }
  const contentDirectory = store.summary_content_directory;
  const recordDirectory = store.summary_record_directory;
  if (contentDirectory === null || recordDirectory === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_DIRECTORIES_UNAVAILABLE" });
  }
  const contentDirectoryCheck = await verifyRootState(contentDirectory, store.io);
  const recordDirectoryCheck = await verifyRootState(recordDirectory, store.io);
  if (contentDirectoryCheck !== null || recordDirectoryCheck !== null) {
    return Object.freeze({
      ok: false,
      classification: "NOT_COMMITTED",
      error: contentDirectoryCheck === "RUN_DIRECTORY_MODE_CHANGED" || recordDirectoryCheck === "RUN_DIRECTORY_MODE_CHANGED"
        ? "RUN_DIRECTORY_MODE_CHANGED"
        : "RUN_DIRECTORY_IDENTITY_CHANGED",
    });
  }

  const current = await verifyStoreStillMatchesCaptured(store);
  if (!current.ok) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: current.error });
  }
  if (parsedInput.expected_ledger_bytes_hash !== current.state.ledger.hash
    || parsedInput.expected_manifest_hash !== current.state.current_manifest_hash) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EXPECTATION_MISMATCH" });
  }
  if (!startsWithBytes(parsedInput.next_ledger_bytes, current.state.ledger.bytes)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INVALID" });
  }

  const currentLedgerInspection = inspectRuntimeLedgerV04(current.state.ledger.bytes);
  const nextLedgerInspection = inspectRuntimeLedgerV04(parsedInput.next_ledger_bytes);
  if (!currentLedgerInspection.ok || !nextLedgerInspection.ok
    || nextLedgerInspection.ledger.events.length !== currentLedgerInspection.ledger.events.length + 1) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INVALID" });
  }
  const compaction = nextLedgerInspection.ledger.events.at(-1);
  if (compaction?.event_type !== "run.compaction-recorded"
    || compaction.payload.summary_content_path !== parsedInput.summary_content.relative_path
    || compaction.payload.summary_record_path !== parsedInput.summary_record.relative_path
    || compaction.payload.summary_content_hash !== hashRawBytes(parsedInput.summary_content.bytes)
    || compaction.payload.summary_record_hash !== hashRawBytes(parsedInput.summary_record.bytes)
    || compaction.payload.summary_size_bytes !== parsedInput.summary_content.bytes.byteLength) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INVALID" });
  }

  const expectedContentPath = `summaries/content/${compaction.payload.summary_id}.bin`;
  const expectedRecordPath = `summaries/records/${compaction.payload.summary_id}.json`;
  if (parsedInput.summary_content.relative_path !== expectedContentPath
    || parsedInput.summary_record.relative_path !== expectedRecordPath
    || current.state.manifest_files.some((file) => file.path === expectedContentPath || file.path === expectedRecordPath)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INVALID" });
  }

  const projectedFile = (path: string, bytes: Uint8Array): ExistingFileState => Object.freeze({
    path,
    family: "record",
    required: true,
    exists: true,
    mode: 384,
    size_bytes: bytes.byteLength,
    hash: hashRawBytes(bytes),
    bytes: new Uint8Array(bytes),
    nlink: 1n,
    device: "unpersisted",
    inode: "unpersisted",
  });
  const nextManifestFiles = [
    ...current.state.manifest_files.map((file) => file.path === "ledger.jsonl"
      ? withManifestMetadata(Object.freeze({
          ...current.state.ledger,
          size_bytes: parsedInput.next_ledger_bytes.byteLength,
          hash: hashRawBytes(parsedInput.next_ledger_bytes),
          bytes: new Uint8Array(parsedInput.next_ledger_bytes),
        }), file.family, file.required)
      : file),
    projectedFile(expectedContentPath, parsedInput.summary_content.bytes),
    projectedFile(expectedRecordPath, parsedInput.summary_record.bytes),
  ];
  const nextManifestInspection = inspectRunManifestV04({
    manifest_bytes: parsedInput.next_manifest_bytes,
    ledger_bytes: parsedInput.next_ledger_bytes,
    captured_files: capturedFilesForManifest(nextManifestFiles),
  });
  if (!nextManifestInspection.ok) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INVALID" });
  }

  const contentAbsolutePath = absoluteRunPath(store.root, expectedContentPath);
  const recordAbsolutePath = absoluteRunPath(store.root, expectedRecordPath);
  if (contentAbsolutePath === null || recordAbsolutePath === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INVALID" });
  }
  if (!await pathIsAbsent(contentAbsolutePath, store.io) || !await pathIsAbsent(recordAbsolutePath, store.io)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_PATH_EXISTS" });
  }

  const tempRelativePath = `${TEMP_MANIFEST_PREFIX}${randomUUID()}.json`;
  const owned: InvocationOwnedFileV04[] = [];
  let openHandle: FileHandle | undefined;
  let appendHandle: FileHandle | undefined;
  let phase: "pre-append" | "append-attempted" = "pre-append";

  const persistBeforeCommit = async (
    relativePath: string,
    bytes: Uint8Array,
    parent: DirectoryState,
  ): Promise<ExistingFileState> => {
    const created = await openOwnedCreateNewFile(store.root, parent, relativePath, store.io);
    openHandle = created.handle;
    owned.push(created.owned);
    if (!await writeSingleExact(openHandle, bytes, 0, store.io)) throw new Error("created-file-short-write");
    await store.io.sync(openHandle);
    const byHandle = await openHandle.stat({ bigint: true });
    const byPath = await store.io.lstat(created.owned.absolute_path);
    if (!byHandle.isFile() || byHandle.nlink !== 1n || !sameIdentity(byHandle, created.owned.identity)
      || !byPath.isFile() || byPath.isSymbolicLink() || byPath.nlink !== 1n
      || !sameIdentity(byPath, created.owned.identity)) throw new Error("created-file-drift");
    await store.io.close(openHandle);
    openHandle = undefined;
    const readback = await verifyInvocationOwnedFile(store.root, created.owned, bytes, store.io);
    if (readback === null) throw new Error("created-file-readback-invalid");
    const directoryHandle = await openDirectoryHandle(parent.path, store.io);
    try {
      await store.io.sync(directoryHandle);
    } finally {
      await store.io.close(directoryHandle);
    }
    if (await verifyRootState(parent, store.io) !== null) throw new Error("created-file-directory-drift");
    return readback;
  };

  try {
    const persistedContent = await persistBeforeCommit(
      expectedContentPath,
      parsedInput.summary_content.bytes,
      contentDirectory,
    );
    const persistedRecord = await persistBeforeCommit(
      expectedRecordPath,
      parsedInput.summary_record.bytes,
      recordDirectory,
    );
    const persistedTempManifest = await persistBeforeCommit(
      tempRelativePath,
      parsedInput.next_manifest_bytes,
      store.root,
    );

    if (!await verifySessionLock(sessionState)
      || !(await verifyStoreStillMatchesCaptured(store)).ok
      || await verifyRootState(contentDirectory, store.io) !== null
      || await verifyRootState(recordDirectory, store.io) !== null
      || await verifyInvocationOwnedFile(store.root, owned[0]!, parsedInput.summary_content.bytes, store.io) === null
      || await verifyInvocationOwnedFile(store.root, owned[1]!, parsedInput.summary_record.bytes, store.io) === null
      || await verifyInvocationOwnedFile(store.root, owned[2]!, parsedInput.next_manifest_bytes, store.io) === null) {
      throw new Error("pre-append-revalidation-failed");
    }

    const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
    appendHandle = await store.io.open(join(store.root.path, "ledger.jsonl"), constants.O_WRONLY | constants.O_APPEND | noFollow);
    const appendStat = await appendHandle.stat({ bigint: true });
    if (!appendStat.isFile() || appendStat.nlink !== 1n || !sameIdentity(appendStat, current.state.ledger)) {
      throw new Error("append-handle-drift");
    }
    const ledgerTail = parsedInput.next_ledger_bytes.subarray(current.state.ledger.bytes.byteLength);
    phase = "append-attempted";
    if (!await writeSingleExact(appendHandle, ledgerTail, null, store.io)) return unknown(sessionState, store);
    await store.io.sync(appendHandle);
    await store.io.close(appendHandle);
    appendHandle = undefined;

    const ledgerReadback = await readExactFile(store.root, "ledger.jsonl", parsedInput.next_ledger_bytes.byteLength, store.io);
    if (!ledgerReadback.ok || !sameBytes(ledgerReadback.file.bytes, parsedInput.next_ledger_bytes)) return unknown(sessionState, store);

    await store.io.rename(join(store.root.path, persistedTempManifest.path), join(store.root.path, "run-manifest.json"));
    const runDirectoryHandle = await openDirectoryHandle(store.root.path, store.io);
    try {
      await store.io.sync(runDirectoryHandle);
    } finally {
      await store.io.close(runDirectoryHandle);
    }

    const manifestReadback = await readExactFile(store.root, "run-manifest.json", parsedInput.next_manifest_bytes.byteLength, store.io);
    const finalLedger = await readExactFile(store.root, "ledger.jsonl", parsedInput.next_ledger_bytes.byteLength, store.io);
    const finalContent = await verifyInvocationOwnedFile(store.root, owned[0]!, parsedInput.summary_content.bytes, store.io);
    const finalRecord = await verifyInvocationOwnedFile(store.root, owned[1]!, parsedInput.summary_record.bytes, store.io);
    if (!manifestReadback.ok || !sameBytes(manifestReadback.file.bytes, parsedInput.next_manifest_bytes)
      || !finalLedger.ok || !sameBytes(finalLedger.file.bytes, parsedInput.next_ledger_bytes)
      || finalContent === null || finalRecord === null
      || finalContent.device !== persistedContent.device || finalContent.inode !== persistedContent.inode
      || finalRecord.device !== persistedRecord.device || finalRecord.inode !== persistedRecord.inode
      || !await verifySessionLock(sessionState)
      || await verifyRootState(contentDirectory, store.io) !== null
      || await verifyRootState(recordDirectory, store.io) !== null) return unknown(sessionState, store);

    const persistedByPath = new Map<string, ExistingFileState>([
      [expectedContentPath, withManifestMetadata(finalContent, "record", true)],
      [expectedRecordPath, withManifestMetadata(finalRecord, "record", true)],
    ]);
    const nextInventory: CapturedFileState[] = [];
    for (const row of nextManifestInspection.manifest.file_inventory) {
      if (row.path === "ledger.jsonl") {
        nextInventory.push(withManifestMetadata(finalLedger.file, row.family, row.required));
        continue;
      }
      const newlyPersisted = persistedByPath.get(row.path);
      if (newlyPersisted !== undefined) {
        nextInventory.push(newlyPersisted);
        continue;
      }
      const existing = current.state.manifest_files.find((file) => file.path === row.path);
      if (existing === undefined) return unknown(sessionState, store);
      nextInventory.push(existing);
    }

    store.plan = current.state.plan;
    store.ledger = withManifestMetadata(finalLedger.file, "primary", true);
    store.manifest = withManifestMetadata(manifestReadback.file, "projection", true);
    store.inventory = Object.freeze(nextInventory);
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      ledger_bytes_hash: finalLedger.file.hash,
      manifest_hash: nextManifestInspection.manifest.manifest_hash,
      summary_content_hash: finalContent.hash,
      summary_record_hash: finalRecord.hash,
    });
  } catch (error) {
    if (phase === "append-attempted") return unknown(sessionState, store);
    if (openHandle !== undefined) {
      await store.io.close(openHandle).catch(() => undefined);
      openHandle = undefined;
    }
    const cleaned = await cleanupInvocationOwnedFiles(owned, store.io);
    if (!cleaned) return unknown(sessionState, store);
    return Object.freeze({
      ok: false,
      classification: "NOT_COMMITTED",
      error: hasErrorCode(error, "EEXIST") ? "RUNTIME_COMPACTION_PATH_EXISTS" : "RUNTIME_IO_NOT_COMMITTED",
    });
  } finally {
    if (openHandle !== undefined) await store.io.close(openHandle).catch(() => undefined);
    if (appendHandle !== undefined) await store.io.close(appendHandle).catch(() => undefined);
  }
  // A stale lock or post-commit intent is deliberately not auto-reconciled here:
  // without separately authenticated evidence, recovery must remain fail-closed.
}

export async function commitRuntimeRecordFileStoreSessionV04(
  session: RuntimeFileStoreSessionV04,
  input: unknown,
): Promise<CommitRuntimeRecordFileStoreSessionV04Result> {
  const sessionState = sessions.get(session);
  if (sessionState === undefined) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_FILE_STORE_SESSION_INVALID" });
  }
  if (sessionState.closed) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_FILE_STORE_SESSION_CLOSED" });
  }
  const store = stores.get(sessionState.store);
  if (store === undefined || sessionState.poisoned || store.poisoned) {
    return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_FILE_STORE_SESSION_POISONED" });
  }
  const parsedInput = recordCommitInput(input);
  if (parsedInput === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECORD_INVALID" });
  }
  if (!await verifySessionLock(sessionState)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUN_LOCK_IDENTITY_INVALID" });
  }
  const recordDirectory = store.revocation_record_directory;
  if (recordDirectory === null) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECORD_INVALID" });
  }
  const recordDirectoryCheck = await verifyRootState(recordDirectory, store.io);
  if (recordDirectoryCheck !== null) {
    return Object.freeze({
      ok: false,
      classification: "NOT_COMMITTED",
      error: recordDirectoryCheck === "RUN_DIRECTORY_MODE_CHANGED"
        ? "RUN_DIRECTORY_MODE_CHANGED"
        : "RUN_DIRECTORY_IDENTITY_CHANGED",
    });
  }

  const current = await verifyStoreStillMatchesCaptured(store);
  if (!current.ok) {
    return Object.freeze({
      ok: false,
      classification: "NOT_COMMITTED",
      error: current.error === "RUN_DIRECTORY_IDENTITY_CHANGED"
        ? "RUN_DIRECTORY_IDENTITY_CHANGED"
        : current.error === "RUN_DIRECTORY_MODE_CHANGED"
          ? "RUN_DIRECTORY_MODE_CHANGED"
          : current.error,
    });
  }
  if (parsedInput.expected_ledger_bytes_hash !== current.state.ledger.hash
    || parsedInput.expected_manifest_hash !== current.state.current_manifest_hash) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EXPECTATION_MISMATCH" });
  }
  if (!startsWithBytes(parsedInput.next_ledger_bytes, current.state.ledger.bytes)) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECORD_INVALID" });
  }

  const currentLedgerInspection = inspectRuntimeLedgerV04(current.state.ledger.bytes);
  const nextLedgerInspection = inspectRuntimeLedgerV04(parsedInput.next_ledger_bytes);
  if (!currentLedgerInspection.ok || !nextLedgerInspection.ok
    || nextLedgerInspection.ledger.events.length !== currentLedgerInspection.ledger.events.length + 1) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECORD_INVALID" });
  }
  const appended = nextLedgerInspection.ledger.events.at(-1);
  const revocationRecord = parseAuthorityRevocationRecordForCommit(parsedInput.record.bytes);
  const expectedRecordPath = revocationRecord === null
    ? null
    : `authorities/revocations/${revocationRecord.revocation_id}.json`;
  if (appended === undefined
    || revocationRecord === null
    || expectedRecordPath === null
    || parsedInput.record.relative_path !== expectedRecordPath
    || appended.event_type !== "authority.grant-revoked"
    || appended.payload.record_path !== parsedInput.record.relative_path
    || appended.payload.record_hash !== hashRawBytes(parsedInput.record.bytes)
    || appended.payload.signer_key_ref !== revocationRecord.producer_attestation.signer_key_ref
    || appended.payload.statement_hash !== revocationRecord.producer_attestation.statement_hash
    || appended.payload.revocation_id !== revocationRecord.revocation_id
    || appended.payload.run_id !== revocationRecord.run_id
    || appended.payload.plan_hash !== revocationRecord.plan_hash) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECORD_INVALID" });
  }
  const recordAbsolutePath = absoluteRunPath(store.root, parsedInput.record.relative_path);
  if (recordAbsolutePath === null
    || current.state.manifest_files.some((file) => file.path === parsedInput.record.relative_path)
    || !await pathIsAbsent(recordAbsolutePath, store.io)) {
    return Object.freeze({
      ok: false,
      classification: "NOT_COMMITTED",
      error: current.state.manifest_files.some((file) => file.path === parsedInput.record.relative_path)
        ? "RUNTIME_RECORD_INVALID"
        : "RUNTIME_RECORD_PATH_EXISTS",
    });
  }

  const projectedFile: ExistingFileState = Object.freeze({
    path: parsedInput.record.relative_path,
    family: "record",
    required: true,
    exists: true,
    mode: 384,
    size_bytes: parsedInput.record.bytes.byteLength,
    hash: hashRawBytes(parsedInput.record.bytes),
    bytes: new Uint8Array(parsedInput.record.bytes),
    nlink: 1n,
    device: "unpersisted",
    inode: "unpersisted",
  });
  const nextManifestFiles = [
    ...current.state.manifest_files.map((file) => file.path === "ledger.jsonl"
      ? withManifestMetadata(Object.freeze({
          ...current.state.ledger,
          size_bytes: parsedInput.next_ledger_bytes.byteLength,
          hash: hashRawBytes(parsedInput.next_ledger_bytes),
          bytes: new Uint8Array(parsedInput.next_ledger_bytes),
        }), file.family, file.required)
      : file),
    projectedFile,
  ];
  const nextManifestInspection = inspectRunManifestV04({
    manifest_bytes: parsedInput.next_manifest_bytes,
    ledger_bytes: parsedInput.next_ledger_bytes,
    captured_files: capturedFilesForManifest(nextManifestFiles),
  });
  if (!nextManifestInspection.ok) {
    return Object.freeze({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_RECORD_INVALID" });
  }

  const tempRelativePath = `${TEMP_MANIFEST_PREFIX}${randomUUID()}.json`;
  const owned: InvocationOwnedFileV04[] = [];
  let openHandle: FileHandle | undefined;
  let appendHandle: FileHandle | undefined;
  let phase: "pre-append" | "append-attempted" = "pre-append";

  const persistBeforeCommit = async (
    relativePath: string,
    bytes: Uint8Array,
    parent: DirectoryState,
  ): Promise<ExistingFileState> => {
    const created = await openOwnedCreateNewFile(store.root, parent, relativePath, store.io);
    openHandle = created.handle;
    owned.push(created.owned);
    if (!await writeSingleExact(openHandle, bytes, 0, store.io)) throw new Error("created-file-short-write");
    await store.io.sync(openHandle);
    const byHandle = await openHandle.stat({ bigint: true });
    const byPath = await store.io.lstat(created.owned.absolute_path);
    if (!byHandle.isFile() || byHandle.nlink !== 1n || !sameIdentity(byHandle, created.owned.identity)
      || !byPath.isFile() || byPath.isSymbolicLink() || byPath.nlink !== 1n
      || !sameIdentity(byPath, created.owned.identity)) throw new Error("created-file-drift");
    await store.io.close(openHandle);
    openHandle = undefined;
    const readback = await verifyInvocationOwnedFile(store.root, created.owned, bytes, store.io);
    if (readback === null) throw new Error("created-file-readback-invalid");
    const directoryHandle = await openDirectoryHandle(parent.path, store.io);
    try {
      await store.io.sync(directoryHandle);
    } finally {
      await store.io.close(directoryHandle);
    }
    if (await verifyRootState(parent, store.io) !== null) throw new Error("created-file-directory-drift");
    return readback;
  };

  try {
    const persistedRecord = await persistBeforeCommit(
      parsedInput.record.relative_path,
      parsedInput.record.bytes,
      recordDirectory,
    );
    const persistedTempManifest = await persistBeforeCommit(
      tempRelativePath,
      parsedInput.next_manifest_bytes,
      store.root,
    );

    if (!await verifySessionLock(sessionState)
      || !(await verifyStoreStillMatchesCaptured(store)).ok
      || await verifyRootState(recordDirectory, store.io) !== null
      || await verifyInvocationOwnedFile(store.root, owned[0]!, parsedInput.record.bytes, store.io) === null
      || await verifyInvocationOwnedFile(store.root, owned[1]!, parsedInput.next_manifest_bytes, store.io) === null) {
      throw new Error("pre-append-revalidation-failed");
    }

    const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
    appendHandle = await store.io.open(join(store.root.path, "ledger.jsonl"), constants.O_WRONLY | constants.O_APPEND | noFollow);
    const appendStat = await appendHandle.stat({ bigint: true });
    if (!appendStat.isFile() || appendStat.nlink !== 1n || !sameIdentity(appendStat, current.state.ledger)) {
      throw new Error("append-handle-drift");
    }
    const ledgerTail = parsedInput.next_ledger_bytes.subarray(current.state.ledger.bytes.byteLength);
    phase = "append-attempted";
    if (!await writeSingleExact(appendHandle, ledgerTail, null, store.io)) return unknown(sessionState, store);
    await store.io.sync(appendHandle);
    await store.io.close(appendHandle);
    appendHandle = undefined;

    const ledgerReadback = await readExactFile(store.root, "ledger.jsonl", parsedInput.next_ledger_bytes.byteLength, store.io);
    if (!ledgerReadback.ok || !sameBytes(ledgerReadback.file.bytes, parsedInput.next_ledger_bytes)) return unknown(sessionState, store);

    await store.io.rename(join(store.root.path, persistedTempManifest.path), join(store.root.path, "run-manifest.json"));
    const runDirectoryHandle = await openDirectoryHandle(store.root.path, store.io);
    try {
      await store.io.sync(runDirectoryHandle);
    } finally {
      await store.io.close(runDirectoryHandle);
    }

    const manifestReadback = await readExactFile(store.root, "run-manifest.json", parsedInput.next_manifest_bytes.byteLength, store.io);
    const finalLedger = await readExactFile(store.root, "ledger.jsonl", parsedInput.next_ledger_bytes.byteLength, store.io);
    const finalRecord = await verifyInvocationOwnedFile(store.root, owned[0]!, parsedInput.record.bytes, store.io);
    if (!manifestReadback.ok || !sameBytes(manifestReadback.file.bytes, parsedInput.next_manifest_bytes)
      || !finalLedger.ok || !sameBytes(finalLedger.file.bytes, parsedInput.next_ledger_bytes)
      || finalRecord === null
      || finalRecord.device !== persistedRecord.device || finalRecord.inode !== persistedRecord.inode
      || !await verifySessionLock(sessionState)
      || await verifyRootState(recordDirectory, store.io) !== null) return unknown(sessionState, store);

    const nextInventory: CapturedFileState[] = [];
    for (const row of nextManifestInspection.manifest.file_inventory) {
      if (row.path === "ledger.jsonl") {
        nextInventory.push(withManifestMetadata(finalLedger.file, row.family, row.required));
        continue;
      }
      if (row.path === parsedInput.record.relative_path) {
        nextInventory.push(withManifestMetadata(finalRecord, "record", true));
        continue;
      }
      const existing = current.state.manifest_files.find((file) => file.path === row.path);
      if (existing === undefined) return unknown(sessionState, store);
      nextInventory.push(existing);
    }

    store.plan = current.state.plan;
    store.ledger = withManifestMetadata(finalLedger.file, "primary", true);
    store.manifest = withManifestMetadata(manifestReadback.file, "projection", true);
    store.inventory = Object.freeze(nextInventory);
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      ledger_bytes_hash: finalLedger.file.hash,
      manifest_hash: nextManifestInspection.manifest.manifest_hash,
      record_hash: finalRecord.hash,
    });
  } catch (error) {
    if (phase === "append-attempted") return unknown(sessionState, store);
    if (openHandle !== undefined) {
      await store.io.close(openHandle).catch(() => undefined);
      openHandle = undefined;
    }
    const cleaned = await cleanupInvocationOwnedFiles(owned, store.io);
    if (!cleaned) return unknown(sessionState, store);
    return Object.freeze({
      ok: false,
      classification: "NOT_COMMITTED",
      error: hasErrorCode(error, "EEXIST") ? "RUNTIME_RECORD_PATH_EXISTS" : "RUNTIME_IO_NOT_COMMITTED",
    });
  } finally {
    if (openHandle !== undefined) await store.io.close(openHandle).catch(() => undefined);
    if (appendHandle !== undefined) await store.io.close(appendHandle).catch(() => undefined);
  }
}

export async function closeRuntimeFileStoreSessionV04(session: RuntimeFileStoreSessionV04): Promise<boolean> {
  const state = sessions.get(session);
  if (state === undefined) return false;
  if (state.closed) return true;
  const store = stores.get(state.store);
  state.closed = true;
  if (store === undefined) {
    await state.lock_handle.close().catch(() => undefined);
    return false;
  }
  let released = false;
  try {
    const byHandle = await state.lock_handle.stat({ bigint: true });
    try {
      const byPath = await store.io.lstat(store.lock_path);
      if (byPath.isFile()
        && !byPath.isSymbolicLink()
        && byPath.nlink === 1n
        && sameIdentity(byHandle, identityOf(byPath))
        && sameIdentity(byPath, state.lock_identity)) {
        await store.io.unlink(store.lock_path);
        const directoryHandle = await openDirectoryHandle(store.root.path, store.io);
        try {
          await store.io.sync(directoryHandle);
        } finally {
          await store.io.close(directoryHandle).catch(() => undefined);
        }
        released = true;
      }
    } catch {
      released = false;
    }
  } finally {
    await state.lock_handle.close().catch(() => undefined);
  }
  return released;
}
