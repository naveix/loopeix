import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath, stat } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

import {
  RelativeRunPathV02,
  type RelativeRunPathV02Value,
} from "../schema/scalars-v02.js";

export type RuntimeRunFileCaptureErrorV02 =
  | "RUNTIME_FILE_PATH_INVALID"
  | "RUNTIME_FILE_NOT_FOUND"
  | "RUNTIME_FILE_NOT_REGULAR"
  | "RUNTIME_FILE_MODE_INVALID"
  | "RUNTIME_FILE_IDENTITY_CHANGED"
  | "RUNTIME_INPUT_RESOURCE_LIMIT"
  | "RUNTIME_FILE_CAPTURE_FAILED";

export type RuntimeRunFileCaptureResultV02<T> =
  | { ok: true; value: T }
  | { ok: false; error: RuntimeRunFileCaptureErrorV02 };

declare const anchoredRunDirectoryReadCapabilityBrandV02: unique symbol;
export type AnchoredRunDirectoryReadCapabilityV02 = {
  readonly [anchoredRunDirectoryReadCapabilityBrandV02]: true;
};

declare const capturedRunFileMetadataBrandV02: unique symbol;
export type CapturedRunFileMetadataV02 = Readonly<{
  mode: 384 | 420;
  size_bytes: number;
  sha256: `sha256:${string}`;
  [capturedRunFileMetadataBrandV02]: true;
}>;

declare const helperOwnedRunFileCaptureBrandV02: unique symbol;
export type HelperOwnedRunFileCaptureV02 = Readonly<{
  relative_path: RelativeRunPathV02Value;
  bytes: Uint8Array;
  metadata: CapturedRunFileMetadataV02;
  [helperOwnedRunFileCaptureBrandV02]: true;
}>;

type Identity = Readonly<{
  device: string;
  inode: string;
}>;

type RootState = Identity & Readonly<{
  path: string;
}>;

type ParentIdentity = Identity & Readonly<{
  path: string;
  mode: bigint;
}>;

type FileIdentity = Identity & Readonly<{
  mode: bigint;
  size: bigint;
}>;

export type RuntimeRunFileCaptureHooksV02 = Readonly<{
  after_read_before_recheck?: () => void | Promise<void>;
}>;

type CaptureModePolicyV02 = "WRITE_AUTHORITY_0600_ONLY" | "READ_ONLY_INSPECTION_LEGACY_OK";

const anchoredRoots = new WeakMap<object, RootState>();
const capturedMetadata = new WeakSet<object>();
const capturedFiles = new WeakMap<object, Uint8Array>();

function failure<T>(error: RuntimeRunFileCaptureErrorV02): RuntimeRunFileCaptureResultV02<T> {
  return { ok: false, error };
}

function identityOf(metadata: { dev: bigint; ino: bigint }): Identity {
  return {
    device: metadata.dev.toString(),
    inode: metadata.ino.toString(),
  };
}

function sameIdentity(metadata: { dev: bigint; ino: bigint }, identity: Identity): boolean {
  return metadata.dev.toString() === identity.device && metadata.ino.toString() === identity.inode;
}

function permissionMode(mode: bigint): bigint {
  // Include setuid, setgid, and sticky bits: the contract requires exactly
  // 0600, not merely owner read/write after special bits are discarded.
  return mode & 0o7777n;
}

function isPermittedCaptureMode(mode: bigint, policy: CaptureModePolicyV02): mode is 0o600n | 0o644n {
  const permissions = permissionMode(mode);
  if (policy === "WRITE_AUTHORITY_0600_ONLY") return permissions === 0o600n;
  return permissions === 0o600n || permissions === 0o644n;
}

function isCanonicalAbsolutePath(path: string): boolean {
  return isAbsolute(path) && resolve(path) === path;
}

function isInsideRoot(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child.length > 0 && child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child);
}

async function verifyRoot(state: RootState): Promise<boolean> {
  try {
    const direct = await lstat(state.path, { bigint: true });
    if (!direct.isDirectory() || direct.isSymbolicLink() || !sameIdentity(direct, state)) return false;
    if (await realpath(state.path) !== state.path) return false;
    const followed = await stat(state.path, { bigint: true });
    return followed.isDirectory() && sameIdentity(followed, state);
  } catch {
    return false;
  }
}

export async function issueAnchoredRunDirectoryReadCapabilityV02(
  rootPath: unknown,
): Promise<RuntimeRunFileCaptureResultV02<AnchoredRunDirectoryReadCapabilityV02>> {
  if (typeof rootPath !== "string" || !isCanonicalAbsolutePath(rootPath)) {
    return failure("RUNTIME_FILE_PATH_INVALID");
  }

  try {
    const direct = await lstat(rootPath, { bigint: true });
    if (!direct.isDirectory() || direct.isSymbolicLink()) return failure("RUNTIME_FILE_PATH_INVALID");
    if (await realpath(rootPath) !== rootPath) return failure("RUNTIME_FILE_PATH_INVALID");
    const followed = await stat(rootPath, { bigint: true });
    if (!followed.isDirectory() || !sameIdentity(followed, identityOf(direct))) {
      return failure("RUNTIME_FILE_IDENTITY_CHANGED");
    }

    const capability = Object.freeze({}) as AnchoredRunDirectoryReadCapabilityV02;
    const identity = identityOf(direct);
    anchoredRoots.set(capability, { path: rootPath, ...identity });
    return { ok: true, value: capability };
  } catch {
    return failure("RUNTIME_FILE_PATH_INVALID");
  }
}

export function isAnchoredRunDirectoryReadCapabilityV02(
  value: unknown,
): value is AnchoredRunDirectoryReadCapabilityV02 {
  return typeof value === "object" && value !== null && anchoredRoots.has(value);
}

export function isCapturedRunFileMetadataV02(value: unknown): value is CapturedRunFileMetadataV02 {
  return typeof value === "object" && value !== null && capturedMetadata.has(value);
}

export function isHelperOwnedRunFileCaptureV02(value: unknown): value is HelperOwnedRunFileCaptureV02 {
  return typeof value === "object" && value !== null && capturedFiles.has(value);
}

async function captureParentChain(
  root: RootState,
  segments: readonly string[],
): Promise<RuntimeRunFileCaptureResultV02<readonly ParentIdentity[]>> {
  const identities: ParentIdentity[] = [];
  let path = root.path;

  for (const segment of segments) {
    path = join(path, segment);
    if (!isInsideRoot(root.path, path)) return failure("RUNTIME_FILE_PATH_INVALID");
    try {
      const direct = await lstat(path, { bigint: true });
      if (!direct.isDirectory() || direct.isSymbolicLink()) return failure("RUNTIME_FILE_PATH_INVALID");
      if (await realpath(path) !== path) return failure("RUNTIME_FILE_PATH_INVALID");
      const followed = await stat(path, { bigint: true });
      if (!followed.isDirectory() || !sameIdentity(followed, identityOf(direct))) {
        return failure("RUNTIME_FILE_IDENTITY_CHANGED");
      }
      identities.push({ path, ...identityOf(direct), mode: direct.mode });
    } catch {
      return failure("RUNTIME_FILE_PATH_INVALID");
    }
  }

  return { ok: true, value: identities };
}

async function verifyParentChain(root: RootState, identities: readonly ParentIdentity[]): Promise<boolean> {
  if (!await verifyRoot(root)) return false;
  for (const identity of identities) {
    try {
      const current = await lstat(identity.path, { bigint: true });
      if (
        !current.isDirectory() ||
        current.isSymbolicLink() ||
        current.mode !== identity.mode ||
        !sameIdentity(current, identity) ||
        await realpath(identity.path) !== identity.path
      ) {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

function fileIdentity(metadata: { dev: bigint; ino: bigint; mode: bigint; size: bigint }): FileIdentity {
  return { ...identityOf(metadata), mode: metadata.mode, size: metadata.size };
}

function sameFileIdentity(
  metadata: { dev: bigint; ino: bigint; mode: bigint; size: bigint },
  identity: FileIdentity,
): boolean {
  return sameIdentity(metadata, identity) && metadata.mode === identity.mode && metadata.size === identity.size;
}

async function captureRunFile(
  capability: AnchoredRunDirectoryReadCapabilityV02,
  relativePath: unknown,
  maxBytes: unknown,
  policy: CaptureModePolicyV02,
  hooks: RuntimeRunFileCaptureHooksV02,
): Promise<RuntimeRunFileCaptureResultV02<HelperOwnedRunFileCaptureV02>> {
  const root = typeof capability === "object" && capability !== null ? anchoredRoots.get(capability) : undefined;
  if (root === undefined) return failure("RUNTIME_FILE_PATH_INVALID");
  const parsedPath = RelativeRunPathV02.safeParse(relativePath);
  if (!parsedPath.success) return failure("RUNTIME_FILE_PATH_INVALID");
  if (typeof maxBytes !== "number" || !Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    return failure("RUNTIME_INPUT_RESOURCE_LIMIT");
  }
  if (!await verifyRoot(root)) return failure("RUNTIME_FILE_IDENTITY_CHANGED");

  const segments = parsedPath.data.split("/");
  const parents = await captureParentChain(root, segments.slice(0, -1));
  if (!parents.ok) return parents;
  const path = join(root.path, ...segments);
  if (!isInsideRoot(root.path, path)) return failure("RUNTIME_FILE_PATH_INVALID");

  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const before = await lstat(path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink()) return failure("RUNTIME_FILE_NOT_REGULAR");
    if (!isPermittedCaptureMode(before.mode, policy)) return failure("RUNTIME_FILE_MODE_INVALID");
    if (before.size < 0n || before.size > BigInt(maxBytes) || before.size >= BigInt(Number.MAX_SAFE_INTEGER)) {
      return failure("RUNTIME_INPUT_RESOURCE_LIMIT");
    }

    const expected = fileIdentity(before);
    const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
    handle = await open(path, constants.O_RDONLY | noFollow);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameFileIdentity(opened, expected)) {
      return failure("RUNTIME_FILE_IDENTITY_CHANGED");
    }

    const expectedSize = Number(expected.size);
    const readBuffer = Buffer.alloc(expectedSize + 1);
    let total = 0;
    while (total < readBuffer.byteLength) {
      const result = await handle.read(readBuffer, total, readBuffer.byteLength - total, total);
      if (result.bytesRead === 0) break;
      total += result.bytesRead;
    }
    if (total !== expectedSize) return failure("RUNTIME_FILE_IDENTITY_CHANGED");

    await hooks.after_read_before_recheck?.();

    const afterHandle = await handle.stat({ bigint: true });
    const afterPath = await lstat(path, { bigint: true });
    if (
      !afterHandle.isFile() ||
      !afterPath.isFile() ||
      afterPath.isSymbolicLink() ||
      !sameFileIdentity(afterHandle, expected) ||
      !sameFileIdentity(afterPath, expected) ||
      !await verifyParentChain(root, parents.value)
    ) {
      return failure("RUNTIME_FILE_IDENTITY_CHANGED");
    }

    const privateBytes = new Uint8Array(expectedSize);
    privateBytes.set(readBuffer.subarray(0, expectedSize));
    const sha256 = `sha256:${createHash("sha256").update(privateBytes).digest("hex")}` as const;
    const exactMode = Number(permissionMode(expected.mode));
    if (exactMode !== 0o600 && exactMode !== 0o644) return failure("RUNTIME_FILE_MODE_INVALID");
    const metadata = Object.freeze({
      mode: exactMode as 384 | 420,
      size_bytes: privateBytes.byteLength,
      sha256,
    }) as CapturedRunFileMetadataV02;
    capturedMetadata.add(metadata);

    let capture: HelperOwnedRunFileCaptureV02;
    capture = Object.freeze({
      relative_path: parsedPath.data,
      metadata,
      get bytes(): Uint8Array {
        const retained = capturedFiles.get(capture);
        return retained === undefined ? new Uint8Array() : new Uint8Array(retained);
      },
    }) as HelperOwnedRunFileCaptureV02;
    capturedFiles.set(capture, privateBytes);
    return { ok: true, value: capture };
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return failure("RUNTIME_FILE_NOT_FOUND");
    }
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      (error.code === "ELOOP" || error.code === "EMLINK")
    ) {
      return failure("RUNTIME_FILE_NOT_REGULAR");
    }
    return failure("RUNTIME_FILE_CAPTURE_FAILED");
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        // The closed result domain deliberately does not expose cleanup details.
      }
    }
  }
}

export function captureRunFileForRuntimeV02(input: Readonly<{
  anchored_run_directory: AnchoredRunDirectoryReadCapabilityV02;
  relative_path: unknown;
  max_bytes: unknown;
}>): Promise<RuntimeRunFileCaptureResultV02<HelperOwnedRunFileCaptureV02>> {
  try {
    if (typeof input !== "object" || input === null) {
      return Promise.resolve(failure("RUNTIME_FILE_PATH_INVALID"));
    }
    return captureRunFile(
      input.anchored_run_directory,
      input.relative_path,
      input.max_bytes,
      "WRITE_AUTHORITY_0600_ONLY",
      {},
    );
  } catch {
    return Promise.resolve(failure("RUNTIME_FILE_PATH_INVALID"));
  }
}

/** Package-internal race seam. It is intentionally absent from the package root. */
export function captureRunFileForRuntimeV02ForTest(
  input: Readonly<{
    anchored_run_directory: AnchoredRunDirectoryReadCapabilityV02;
    relative_path: unknown;
    max_bytes: unknown;
  }>,
  hooks: RuntimeRunFileCaptureHooksV02,
): Promise<RuntimeRunFileCaptureResultV02<HelperOwnedRunFileCaptureV02>> {
  return captureRunFile(
    input.anchored_run_directory,
    input.relative_path,
    input.max_bytes,
    "WRITE_AUTHORITY_0600_ONLY",
    hooks,
  );
}

export function captureRunFileForRuntimeInspectionV02(input: Readonly<{
  anchored_run_directory: AnchoredRunDirectoryReadCapabilityV02;
  relative_path: unknown;
  max_bytes: unknown;
}>): Promise<RuntimeRunFileCaptureResultV02<HelperOwnedRunFileCaptureV02>> {
  try {
    if (typeof input !== "object" || input === null) {
      return Promise.resolve(failure("RUNTIME_FILE_PATH_INVALID"));
    }
    return captureRunFile(
      input.anchored_run_directory,
      input.relative_path,
      input.max_bytes,
      "READ_ONLY_INSPECTION_LEGACY_OK",
      {},
    );
  } catch {
    return Promise.resolve(failure("RUNTIME_FILE_PATH_INVALID"));
  }
}

/** Package-internal read seam. It is intentionally absent from the package root. */
export function captureRunFileForRuntimeInspectionWithHooksV02(
  input: Readonly<{
    anchored_run_directory: AnchoredRunDirectoryReadCapabilityV02;
    relative_path: unknown;
    max_bytes: unknown;
  }>,
  hooks: RuntimeRunFileCaptureHooksV02,
): Promise<RuntimeRunFileCaptureResultV02<HelperOwnedRunFileCaptureV02>> {
  return captureRunFile(
    input.anchored_run_directory,
    input.relative_path,
    input.max_bytes,
    "READ_ONLY_INSPECTION_LEGACY_OK",
    hooks,
  );
}

/** Package-internal race seam. It is intentionally absent from the package root. */
export function captureRunFileForRuntimeInspectionV02ForTest(
  input: Readonly<{
    anchored_run_directory: AnchoredRunDirectoryReadCapabilityV02;
    relative_path: unknown;
    max_bytes: unknown;
  }>,
  hooks: RuntimeRunFileCaptureHooksV02,
): Promise<RuntimeRunFileCaptureResultV02<HelperOwnedRunFileCaptureV02>> {
  return captureRunFileForRuntimeInspectionWithHooksV02(input, hooks);
}
