import { constants } from "node:fs";
import { lstat, open, realpath, stat, type FileHandle } from "node:fs/promises";
import { resolve } from "node:path";

export const COMPILE_STORE_SENTINEL_TEXT = "*\n!.gitignore\n";
const COMPILE_STORE_SENTINEL_BYTES = Buffer.from(COMPILE_STORE_SENTINEL_TEXT, "ascii");

type CompileStoreStat = Readonly<{
  dev: bigint;
  ino: bigint;
  isDirectory(): boolean;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}>;

type CompileStoreReadHandle = Readonly<{
  stat(options: { bigint: true }): Promise<CompileStoreStat>;
  read(buffer: Uint8Array, offset: number, length: number, position: number): Promise<{ bytesRead: number }>;
  close(): Promise<void>;
}>;

export type CompileStoreIo = Readonly<{
  lstat(path: string, options: { bigint: true }): Promise<CompileStoreStat>;
  stat(path: string, options: { bigint: true }): Promise<CompileStoreStat>;
  realpath(path: string): Promise<string>;
  open(path: string, flags: number): Promise<CompileStoreReadHandle>;
}>;

export type VerifiedCompileStoreV02 = Readonly<{
  boundary_kind: "compile-store";
  root_identity: Readonly<{ device: string; inode: string }>;
  readonly __verified_compile_store_v02: unique symbol;
}>;

export type CompileStoreVerificationResultV02 =
  | { ok: true; store: VerifiedCompileStoreV02 }
  | {
      ok: false;
      reason: "COMPILE_STORE_INVALID";
      message: "The compile store or its sentinel is unavailable or invalid.";
    };

export type CompileStoreVerificationOptions = Readonly<{
  io?: Partial<CompileStoreIo>;
}>;

type VerifiedCompileStoreState = Readonly<{
  path: string;
  device: string;
  inode: string;
}>;

const registry = new WeakMap<VerifiedCompileStoreV02, VerifiedCompileStoreState>();

const defaultIo: CompileStoreIo = {
  lstat: (path, options) => lstat(path, options),
  stat: (path, options) => stat(path, options),
  realpath,
  open: async (path, flags) => open(path, flags) as Promise<FileHandle>,
};

function invalidStore(): CompileStoreVerificationResultV02 {
  return {
    ok: false,
    reason: "COMPILE_STORE_INVALID",
    message: "The compile store or its sentinel is unavailable or invalid.",
  };
}

function sameIdentity(left: CompileStoreStat, right: CompileStoreStat): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function readBoundedSentinel(handle: CompileStoreReadHandle): Promise<Uint8Array> {
  const bytes = new Uint8Array(COMPILE_STORE_SENTINEL_BYTES.byteLength + 1);
  let length = 0;
  while (length < bytes.byteLength) {
    const read = await handle.read(bytes, length, bytes.byteLength - length, length);
    if (!Number.isSafeInteger(read.bytesRead) || read.bytesRead < 0 || read.bytesRead > bytes.byteLength - length) {
      throw new Error("invalid sentinel read length");
    }
    if (read.bytesRead === 0) break;
    length += read.bytesRead;
  }
  return bytes.subarray(0, length);
}

async function inspectCompileStorePath(
  requestedPath: string,
  io: CompileStoreIo,
): Promise<VerifiedCompileStoreState | null> {
  let handle: CompileStoreReadHandle | null = null;

  try {
    const directRoot = await io.lstat(requestedPath, { bigint: true });
    if (directRoot.isSymbolicLink() || !directRoot.isDirectory()) return null;

    const canonicalPath = await io.realpath(requestedPath);
    const rootIdentity = await io.stat(canonicalPath, { bigint: true });
    if (!rootIdentity.isDirectory() || !sameIdentity(directRoot, rootIdentity)) return null;

    const sentinelPath = resolve(canonicalPath, ".gitignore");
    const directSentinel = await io.lstat(sentinelPath, { bigint: true });
    if (directSentinel.isSymbolicLink() || !directSentinel.isFile()) return null;

    handle = await io.open(sentinelPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const descriptorSentinel = await handle.stat({ bigint: true });
    if (!descriptorSentinel.isFile() || !sameIdentity(directSentinel, descriptorSentinel)) return null;

    const bytes = await readBoundedSentinel(handle);
    await handle.close();
    handle = null;

    if (!Buffer.from(bytes).equals(COMPILE_STORE_SENTINEL_BYTES)) return null;

    const finalSentinel = await io.lstat(sentinelPath, { bigint: true });
    const finalRoot = await io.stat(canonicalPath, { bigint: true });
    if (
      finalSentinel.isSymbolicLink() ||
      !finalSentinel.isFile() ||
      !sameIdentity(descriptorSentinel, finalSentinel) ||
      !finalRoot.isDirectory() ||
      !sameIdentity(rootIdentity, finalRoot)
    ) {
      return null;
    }

    return Object.freeze({
      path: canonicalPath,
      device: rootIdentity.dev.toString(),
      inode: rootIdentity.ino.toString(),
    });
  } catch {
    return null;
  } finally {
    if (handle !== null) await handle.close().catch(() => undefined);
  }
}

export async function verifyCompileStoreV02(
  workspaceRoot: string,
  options: CompileStoreVerificationOptions = {},
): Promise<CompileStoreVerificationResultV02> {
  const io: CompileStoreIo = { ...defaultIo, ...options.io };
  const state = await inspectCompileStorePath(resolve(workspaceRoot, ".loopeix", "compiles"), io);
  if (state === null) return invalidStore();

  const store = Object.freeze({
    boundary_kind: "compile-store" as const,
    root_identity: Object.freeze({ device: state.device, inode: state.inode }),
  }) as VerifiedCompileStoreV02;
  registry.set(store, state);
  return { ok: true, store };
}

export function resolveVerifiedCompileStoreV02(store: VerifiedCompileStoreV02): VerifiedCompileStoreState | null {
  return registry.get(store) ?? null;
}

export async function revalidateCompileStoreV02(store: VerifiedCompileStoreV02): Promise<boolean> {
  const expected = registry.get(store);
  if (expected === undefined) return false;
  const current = await inspectCompileStorePath(expected.path, defaultIo);
  return current !== null &&
    current.path === expected.path &&
    current.device === expected.device &&
    current.inode === expected.inode;
}
