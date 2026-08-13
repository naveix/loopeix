import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, rmdir, stat, unlink, type FileHandle } from "node:fs/promises";
import { basename, join } from "node:path";
import { pathToFileURL } from "node:url";
import type {
  CompilerWriterFailureReason,
  CompilerWriterHelperRequest,
  CompilerWriterHelperResponse,
} from "./compiler-writer-protocol.js";

type Identity = Readonly<{ device: string; inode: string }>;
type CreatedFile = { path: string; identity: Identity };

function failure(
  reason: Exclude<CompilerWriterFailureReason, "DESTINATION_EXISTS">,
  message: string,
): CompilerWriterHelperResponse {
  return { ok: false, reason, message };
}

function destinationExists(
  collisionDestination: "compile-pack" | "standalone-loop",
): CompilerWriterHelperResponse {
  return {
    ok: false,
    reason: "DESTINATION_EXISTS",
    message: "Destination already exists.",
    collision_destination: collisionDestination,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDirectChild(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value !== "." && value !== ".." &&
    !value.includes("/") && !value.includes("\\") && !value.includes("\0") &&
    value.normalize("NFC") === value && basename(value) === value;
}

function isIdentity(value: unknown): value is Identity {
  return isRecord(value) && Object.keys(value).sort().join("|") === "device|inode" &&
    typeof value.device === "string" && /^\d+$/.test(value.device) &&
    typeof value.inode === "string" && /^\d+$/.test(value.inode);
}

function canonicalBase64(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0) return false;
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const bodyLength = value.length - padding;
  for (let index = 0; index < bodyLength; index += 1) {
    const code = value.charCodeAt(index);
    const valid = (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a) ||
      (code >= 0x30 && code <= 0x39) || code === 0x2b || code === 0x2f;
    if (!valid) return false;
  }
  for (let index = bodyLength; index < value.length; index += 1) if (value[index] !== "=") return false;
  return true;
}

function parseRequest(value: unknown): CompilerWriterHelperRequest | null {
  if (!isRecord(value) || Object.keys(value).sort().join("|") !== "compile_store_identity|pack_basename|pack_members|standalone|version" ||
      value.version !== "0.1" || !isIdentity(value.compile_store_identity) || !isDirectChild(value.pack_basename) ||
      !Array.isArray(value.pack_members) || value.pack_members.length === 0) return null;
  const names = new Set<string>();
  for (const member of value.pack_members) {
    if (!isRecord(member) || Object.keys(member).sort().join("|") !== "bytes_base64|name" ||
        !isDirectChild(member.name) || !canonicalBase64(member.bytes_base64) || names.has(member.name)) return null;
    names.add(member.name);
  }
  if (value.pack_members.at(-1)?.name !== "pack-manifest.json") return null;
  if (value.standalone !== null) {
    const standalone = value.standalone;
    if (!isRecord(standalone) || Object.keys(standalone).sort().join("|") !== "basename|bytes_base64|parent_identity|parent_path" ||
        typeof standalone.parent_path !== "string" || standalone.parent_path.length === 0 ||
        !isIdentity(standalone.parent_identity) || !isDirectChild(standalone.basename) ||
        !canonicalBase64(standalone.bytes_base64)) return null;
  }
  return value as CompilerWriterHelperRequest;
}

function identityOf(metadata: { dev: bigint; ino: bigint }): Identity {
  return { device: metadata.dev.toString(), inode: metadata.ino.toString() };
}

function sameIdentity(metadata: { dev: bigint; ino: bigint }, identity: Identity): boolean {
  return metadata.dev.toString() === identity.device && metadata.ino.toString() === identity.inode;
}

function errorCode(error: unknown): string | null {
  return isRecord(error) && typeof error.code === "string" ? error.code : null;
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY);
  try { await handle.sync(); } finally { await handle.close(); }
}

async function verifyDirectory(path: string, identity: Identity): Promise<boolean> {
  try {
    const direct = await lstat(path, { bigint: true });
    if (direct.isSymbolicLink() || !direct.isDirectory() || !sameIdentity(direct, identity)) return false;
    const current = await stat(path, { bigint: true });
    return current.isDirectory() && sameIdentity(current, identity);
  } catch { return false; }
}

async function reserveFile(path: string): Promise<{ handle: FileHandle; created: CreatedFile }> {
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollow, 0o600);
  try {
    await handle.chmod(0o600);
    const metadata = await handle.stat({ bigint: true });
    if (!metadata.isFile() || (metadata.mode & 0o777n) !== 0o600n) throw new Error("invalid created file mode");
    return { handle, created: { path, identity: identityOf(metadata) } };
  } catch (error: unknown) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

async function unlinkIfSame(created: CreatedFile): Promise<boolean> {
  try {
    const current = await lstat(created.path, { bigint: true });
    if (current.isSymbolicLink() || !current.isFile() || !sameIdentity(current, created.identity)) return false;
    await unlink(created.path);
    return true;
  } catch { return false; }
}

async function cleanupEmptyPack(packPath: string, packIdentity: Identity): Promise<boolean> {
  try {
    const current = await lstat(packPath, { bigint: true });
    if (current.isSymbolicLink() || !current.isDirectory() || !sameIdentity(current, packIdentity)) return false;
    await rmdir(packPath);
    await syncDirectory(".");
    return true;
  } catch { return false; }
}

async function cleanupBeforeManifest(
  packBasename: string,
  compileStoreIdentity: Identity,
  packIdentity: Identity,
  packFiles: readonly CreatedFile[],
  standalone: CreatedFile | null,
  standaloneParent: string | null,
): Promise<boolean> {
  let clean = true;
  for (const file of [...packFiles].reverse()) clean = (await unlinkIfSame(file)) && clean;
  if (standalone !== null) clean = (await unlinkIfSame(standalone)) && clean;
  try {
    const current = await stat(".", { bigint: true });
    if (current.isSymbolicLink() || !current.isDirectory() || !sameIdentity(current, packIdentity)) clean = false;
  } catch { clean = false; }
  try {
    process.chdir("..");
    const parent = await stat(".", { bigint: true });
    if (!parent.isDirectory() || !sameIdentity(parent, compileStoreIdentity)) clean = false;
    else {
      await rmdir(packBasename);
      await syncDirectory(".");
    }
  } catch { clean = false; }
  if (standaloneParent !== null) {
    try { await syncDirectory(standaloneParent); } catch { clean = false; }
  }
  return clean;
}

export async function executeCompilerWriterRequest(request: CompilerWriterHelperRequest): Promise<CompilerWriterHelperResponse> {
  if (!(await verifyDirectory(".", request.compile_store_identity))) {
    return failure("IO_IDENTITY_MISMATCH", "Filesystem identity validation failed.");
  }

  const packPath = join(".", request.pack_basename);
  let packIdentity: Identity | null = null;
  try {
    await mkdir(packPath, { mode: 0o700 });
    const direct = await lstat(packPath, { bigint: true });
    if (direct.isSymbolicLink() || !direct.isDirectory()) {
      throw failure("IO_IDENTITY_MISMATCH", "Filesystem identity validation failed.");
    }
    packIdentity = identityOf(direct);
    await chmod(packPath, 0o700);
    const modeChecked = await lstat(packPath, { bigint: true });
    if (!sameIdentity(modeChecked, packIdentity) || (modeChecked.mode & 0o777n) !== 0o700n) {
      throw failure("IO_IDENTITY_MISMATCH", "Filesystem identity validation failed.");
    }
    if (!(await verifyDirectory(packPath, packIdentity))) {
      throw failure("IO_IDENTITY_MISMATCH", "Filesystem identity validation failed.");
    }
  } catch (error: unknown) {
    if (errorCode(error) === "EEXIST") return destinationExists("compile-pack");
    const structured = isRecord(error) && error.ok === false && error.reason === "IO_IDENTITY_MISMATCH"
      ? error as Extract<CompilerWriterHelperResponse, { ok: false }>
      : null;
    if (packIdentity !== null) {
      const cleaned = await cleanupEmptyPack(packPath, packIdentity);
      if (!cleaned) return failure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.");
    }
    return structured ?? failure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.");
  }

  if (packIdentity === null) return failure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.");

  try {
    process.chdir(request.pack_basename);
    const entered = await stat(".", { bigint: true });
    if (!entered.isDirectory() || !sameIdentity(entered, packIdentity)) throw new Error("pack entry identity changed");
  } catch {
    let cleaned = false;
    try {
      const current = await stat(".", { bigint: true });
      if (sameIdentity(current, packIdentity)) {
        cleaned = await cleanupBeforeManifest(
          request.pack_basename,
          request.compile_store_identity,
          packIdentity,
          [],
          null,
          null,
        );
      } else {
        cleaned = await cleanupEmptyPack(packPath, packIdentity);
      }
    } catch { cleaned = false; }
    return cleaned
      ? failure("IO_IDENTITY_MISMATCH", "Filesystem identity validation failed.")
      : failure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.");
  }

  let standaloneHandle: FileHandle | null = null;
  let standaloneCreated: CreatedFile | null = null;
  const packFiles: CreatedFile[] = [];
  let manifestStarted = false;
  let contentStarted = false;

  try {
    if (request.standalone !== null) {
      if (!(await verifyDirectory(request.standalone.parent_path, request.standalone.parent_identity))) {
        throw failure("IO_IDENTITY_MISMATCH", "Filesystem identity validation failed.");
      }
      const reserved = await reserveFile(join(request.standalone.parent_path, request.standalone.basename));
      standaloneHandle = reserved.handle;
      standaloneCreated = reserved.created;
    }

    const nonManifest = request.pack_members.slice(0, -1);
    for (const member of nonManifest) {
      const reserved = await reserveFile(member.name);
      packFiles.push(reserved.created);
      contentStarted = true;
      try {
        await reserved.handle.writeFile(Buffer.from(member.bytes_base64, "base64"));
        await reserved.handle.sync();
      } finally {
        await reserved.handle.close();
      }
    }

    if (request.standalone !== null && standaloneHandle !== null) {
      contentStarted = true;
      await standaloneHandle.writeFile(Buffer.from(request.standalone.bytes_base64, "base64"));
      await standaloneHandle.sync();
      await standaloneHandle.close();
      standaloneHandle = null;
      await syncDirectory(request.standalone.parent_path);
    }

    const manifest = request.pack_members.at(-1)!;
    manifestStarted = true;
    const reservedManifest = await reserveFile(manifest.name);
    packFiles.push(reservedManifest.created);
    try {
      await reservedManifest.handle.writeFile(Buffer.from(manifest.bytes_base64, "base64"));
      await reservedManifest.handle.sync();
    } finally {
      await reservedManifest.handle.close();
    }
    await syncDirectory(".");
    process.chdir("..");
    const compileStore = await stat(".", { bigint: true });
    if (!compileStore.isDirectory() || !sameIdentity(compileStore, request.compile_store_identity)) {
      throw failure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.");
    }
    await syncDirectory(".");
    return { ok: true };
  } catch (error: unknown) {
    if (standaloneHandle !== null) await standaloneHandle.close().catch(() => undefined);
    const structured = isRecord(error) && error.ok === false && typeof error.reason === "string"
      ? error as Extract<CompilerWriterHelperResponse, { ok: false }>
      : null;
    if (manifestStarted || contentStarted) {
      if (!manifestStarted) {
        const cleaned = await cleanupBeforeManifest(
          request.pack_basename,
          request.compile_store_identity,
          packIdentity,
          packFiles,
          standaloneCreated,
          standaloneCreated === null ? null : request.standalone?.parent_path ?? null,
        );
        if (!cleaned) return failure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.");
      }
      return failure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.");
    }
    const cleaned = await cleanupBeforeManifest(
      request.pack_basename,
      request.compile_store_identity,
      packIdentity,
      packFiles,
      standaloneCreated,
      standaloneCreated === null ? null : request.standalone?.parent_path ?? null,
    );
    if (!cleaned) return failure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.");
    if (structured !== null && structured.reason === "IO_IDENTITY_MISMATCH") return structured;
    return errorCode(error) === "EEXIST"
      ? destinationExists("standalone-loop")
      : failure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.");
  }
}

async function main(): Promise<void> {
  let input = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) input += chunk;
  let parsed: unknown;
  try { parsed = JSON.parse(input); } catch {
    process.stdout.write(`${JSON.stringify(failure("IO_HELPER_UNAVAILABLE", "Required filesystem helper is unavailable."))}\n`);
    return;
  }
  const request = parseRequest(parsed);
  const response = request === null
    ? failure("IO_HELPER_UNAVAILABLE", "Required filesystem helper is unavailable.")
    : await executeCompilerWriterRequest(request);
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch(() => {
    process.stdout.write(`${JSON.stringify(failure("IO_HELPER_UNAVAILABLE", "Required filesystem helper is unavailable."))}\n`);
  });
}
