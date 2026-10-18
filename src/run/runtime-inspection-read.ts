import { lstat, realpath } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

import { parseDirectChildName } from "../io/captured-file.js";
import {
  captureRunFileForRuntimeInspectionV02,
  captureRunFileForRuntimeInspectionWithHooksV02,
  issueAnchoredRunDirectoryReadCapabilityV02,
  type AnchoredRunDirectoryReadCapabilityV02,
  type HelperOwnedRunFileCaptureV02,
  type RuntimeRunFileCaptureHooksV02,
  type RuntimeRunFileCaptureErrorV02,
  type RuntimeRunFileCaptureResultV02,
} from "../io/runtime-file-capture-v02.js";

export type RunInspectionTarget =
  | Readonly<{ kind: "directory"; path: string }>
  | Readonly<{ kind: "file"; path: string }>;

export type RunInspectionTargetResult =
  | Readonly<{ ok: true; target: RunInspectionTarget }>
  | Readonly<{
      ok: false;
      reason: "INPUT_NOT_FOUND" | "INPUT_PATH_INVALID" | "INPUT_UNSUPPORTED_KIND";
      message: string;
    }>;

export type RuntimeInspectionReadFailureReason =
  | "FILE_NOT_FOUND"
  | "FILE_CAPTURE_INVALID"
  | "FILE_CAPTURE_MODE_INVALID"
  | "FILE_CAPTURE_IDENTITY_CHANGED"
  | "FILE_CAPTURE_TOO_LARGE"
  | "FILE_CAPTURE_UNAVAILABLE"
  | "FILE_CONTENT_INVALID";

export type RuntimeInspectionReadResult =
  | Readonly<{ ok: true; path: string; text: string }>
  | Readonly<{ ok: false; reason: RuntimeInspectionReadFailureReason; message: string }>;

type CaptureReadHooks = RuntimeRunFileCaptureHooksV02;
type RuntimeCaptureFn = (
  input: Readonly<{
    anchored_run_directory: AnchoredRunDirectoryReadCapabilityV02;
    relative_path: string;
    max_bytes: number;
  }>,
  hooks?: CaptureReadHooks,
) => Promise<RuntimeRunFileCaptureResultV02<HelperOwnedRunFileCaptureV02>>;

const UTF8 = new TextDecoder("utf-8", { fatal: true });

function readFailure(reason: RuntimeInspectionReadFailureReason, message: string): RuntimeInspectionReadResult {
  return { ok: false, reason, message };
}

function targetFailure(
  reason: "INPUT_NOT_FOUND" | "INPUT_PATH_INVALID" | "INPUT_UNSUPPORTED_KIND",
  message: string,
): RunInspectionTargetResult {
  return { ok: false, reason, message };
}

function mapCaptureFailure(failure: RuntimeRunFileCaptureErrorV02): RuntimeInspectionReadResult {
  switch (failure) {
    case "RUNTIME_FILE_NOT_FOUND":
      return readFailure("FILE_NOT_FOUND", "The runtime file does not exist.");
    case "RUNTIME_FILE_PATH_INVALID":
    case "RUNTIME_FILE_NOT_REGULAR":
      return readFailure("FILE_CAPTURE_INVALID", "The runtime file path is invalid or not a regular file.");
    case "RUNTIME_FILE_MODE_INVALID":
      return readFailure(
        "FILE_CAPTURE_MODE_INVALID",
        "The runtime file must be a direct regular 0600 file, or a legacy 0644 file for read-only inspection.",
      );
    case "RUNTIME_FILE_IDENTITY_CHANGED":
      return readFailure("FILE_CAPTURE_IDENTITY_CHANGED", "The runtime file identity changed during capture.");
    case "RUNTIME_INPUT_RESOURCE_LIMIT":
      return readFailure("FILE_CAPTURE_TOO_LARGE", "The runtime file exceeds the bounded capture limit.");
    case "RUNTIME_FILE_CAPTURE_FAILED":
      return readFailure("FILE_CAPTURE_UNAVAILABLE", "The runtime file could not be captured safely.");
  }
}

function decodeText(bytes: Uint8Array): RuntimeInspectionReadResult {
  try {
    return { ok: true, path: "", text: UTF8.decode(bytes) };
  } catch {
    return readFailure("FILE_CONTENT_INVALID", "The runtime file is not valid UTF-8.");
  }
}

async function captureFromAnchoredRoot(
  rootPath: string,
  fileName: string,
  maxBytes: number,
  capture: RuntimeCaptureFn,
  hooks?: CaptureReadHooks,
  classifyMissingDirectChild = false,
  outputPath?: string,
): Promise<RuntimeInspectionReadResult> {
  const directName = parseDirectChildName(fileName);
  if (directName === null) {
    return readFailure("FILE_CAPTURE_INVALID", "The runtime file name is not a direct child.");
  }
  let canonicalRoot: string;
  try {
    canonicalRoot = await realpath(rootPath);
  } catch {
    return readFailure("FILE_CAPTURE_UNAVAILABLE", `The runtime root is unavailable: ${rootPath}`);
  }
  void classifyMissingDirectChild;
  const issued = await issueAnchoredRunDirectoryReadCapabilityV02(canonicalRoot);
  if (!issued.ok) return mapCaptureFailure(issued.error);
  const result = await capture({
    anchored_run_directory: issued.value,
    relative_path: directName,
    max_bytes: maxBytes,
  }, hooks);
  if (!result.ok) {
    if (result.error === "RUNTIME_FILE_NOT_FOUND") {
      return readFailure("FILE_NOT_FOUND", `The runtime file does not exist: ${resolve(canonicalRoot, fileName)}`);
    }
    return mapCaptureFailure(result.error);
  }
  const decoded = decodeText(result.value.bytes);
  return decoded.ok
    ? { ok: true, path: outputPath ?? resolve(canonicalRoot, fileName), text: decoded.text }
    : decoded;
}

async function readDirectFile(
  filePath: string,
  maxBytes: number,
  capture: RuntimeCaptureFn,
  hooks?: CaptureReadHooks,
): Promise<RuntimeInspectionReadResult> {
  const absoluteFilePath = resolve(filePath);
  try {
    const metadata = await lstat(absoluteFilePath, { bigint: true });
    if (metadata.isSymbolicLink()) {
      return readFailure("FILE_CAPTURE_INVALID", "The runtime file path must not be a symlink.");
    }
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
      return readFailure("FILE_NOT_FOUND", `The runtime file does not exist: ${absoluteFilePath}`);
    }
    return readFailure("FILE_CAPTURE_UNAVAILABLE", `The runtime file is unavailable: ${absoluteFilePath}`);
  }
  return captureFromAnchoredRoot(
    dirname(absoluteFilePath),
    basename(absoluteFilePath),
    maxBytes,
    capture,
    hooks,
    false,
    absoluteFilePath,
  );
}

const captureRuntimeFile: RuntimeCaptureFn = async (input) => captureRunFileForRuntimeInspectionV02(input);
const captureRuntimeFileForTest: RuntimeCaptureFn = async (input, hooks) =>
  captureRunFileForRuntimeInspectionWithHooksV02(input, hooks ?? {});

export async function resolveRunInspectionTarget(inputPath: string): Promise<RunInspectionTargetResult> {
  const absolutePath = resolve(inputPath);
  try {
    const metadata = await lstat(absolutePath, { bigint: true });
    if (metadata.isSymbolicLink()) {
      return targetFailure("INPUT_PATH_INVALID", `The input path must not be a symlink: ${absolutePath}`);
    }
    if (metadata.isDirectory()) return { ok: true, target: { kind: "directory", path: absolutePath } };
    if (metadata.isFile()) return { ok: true, target: { kind: "file", path: absolutePath } };
    return targetFailure("INPUT_UNSUPPORTED_KIND", `The input path is not a supported file or directory: ${absolutePath}`);
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
      return targetFailure("INPUT_NOT_FOUND", `The input path does not exist: ${absolutePath}`);
    }
    return targetFailure("INPUT_PATH_INVALID", `The input path could not be inspected safely: ${absolutePath}`);
  }
}

export async function readAnchoredRuntimeTextFile(
  filePath: string,
  maxBytes: number,
): Promise<RuntimeInspectionReadResult> {
  return readDirectFile(filePath, maxBytes, captureRuntimeFile);
}

export async function readAnchoredRuntimeDirectoryMemberText(
  directoryPath: string,
  fileName: string,
  maxBytes: number,
): Promise<RuntimeInspectionReadResult> {
  return captureFromAnchoredRoot(resolve(directoryPath), fileName, maxBytes, captureRuntimeFile, undefined, true);
}

export async function readAnchoredRuntimeTextFileForTest(
  filePath: string,
  maxBytes: number,
  hooks: CaptureReadHooks,
): Promise<RuntimeInspectionReadResult> {
  return readDirectFile(filePath, maxBytes, captureRuntimeFileForTest, hooks);
}

export async function readAnchoredRuntimeDirectoryMemberTextForTest(
  directoryPath: string,
  fileName: string,
  maxBytes: number,
  hooks: CaptureReadHooks,
): Promise<RuntimeInspectionReadResult> {
  return captureFromAnchoredRoot(resolve(directoryPath), fileName, maxBytes, captureRuntimeFileForTest, hooks, true);
}
