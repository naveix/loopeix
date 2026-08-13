import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  type BigIntStats,
} from "node:fs";
import { join } from "node:path";
import { Command, Flags } from "@oclif/core";

const WORKSPACE_YAML = `schema_version: "0.1"
workspace_version: "0.1"
loops_dir: "loops"
defaults:
  retention_class: "run"
  redaction_policy_version: "0.1"
engine_disclosure: >-
  Loopeix adds no telemetry and makes no hidden network calls. Codex CLI and
  Claude Code CLI may transmit data under their own settings; disclosed before each run.
`;

const KEY_SENTINEL_BYTES = "*\n";
const COMPILE_SENTINEL_BYTES = "*\n!.gitignore\n";
const BASE_PATHS = [
  ".loopeix/",
  ".loopeix/loops/",
  ".loopeix/workspace.yaml",
  ".loopeix/keys/",
  ".loopeix/keys/.gitignore",
] as const;
const COMPILE_PATHS = [
  ".loopeix/compiles/",
  ".loopeix/compiles/.gitignore",
] as const;
const FRESH_PATHS = [...BASE_PATHS, ...COMPILE_PATHS] as const;
const SENTINEL_PATH = ".loopeix/compiles/.gitignore";

type InitFailureReason = "COMPILE_STORE_INVALID" | "IO_IDENTITY_MISMATCH" | "IO_DURABILITY_UNCONFIRMED";

export type InitCommandResult =
  | Readonly<{
      created: string[];
      dryRun?: true;
      repaired?: string[];
      wouldRepair?: string[];
    }>
  | Readonly<{
      ok: false;
      disposition: "hold";
      reason: InitFailureReason;
      findings: [string];
    }>;

type Identity = Readonly<{ dev: bigint; ino: bigint; uid: bigint }>;
type StableFile = Readonly<{ identity: Identity; bytes: Buffer }>;

class IdentityFailure extends Error {}
class DurabilityFailure extends Error {}

function errorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : "";
}

function isIdentityRaceError(error: unknown): boolean {
  return ["EEXIST", "ELOOP", "ENOTDIR"].includes(errorCode(error));
}

function lstatOptional(path: string): BigIntStats | null {
  try {
    return lstatSync(path, { bigint: true });
  } catch (error: unknown) {
    if (errorCode(error) === "ENOENT" || errorCode(error) === "ENOTDIR") return null;
    throw error;
  }
}

function identityOf(stat: BigIntStats): Identity {
  return { dev: stat.dev, ino: stat.ino, uid: stat.uid };
}

function sameIdentity(stat: BigIntStats, identity: Identity): boolean {
  return stat.dev === identity.dev && stat.ino === identity.ino && stat.uid === identity.uid;
}

function ownedByCurrentUser(stat: BigIntStats): boolean {
  return typeof process.geteuid !== "function" || stat.uid === BigInt(process.geteuid());
}

function requireDirectDirectory(path: string, expected?: Identity): BigIntStats {
  const stat = lstatOptional(path);
  if (stat === null || stat.isSymbolicLink() || !stat.isDirectory() || !ownedByCurrentUser(stat)
    || (expected !== undefined && !sameIdentity(stat, expected))) {
    throw new IdentityFailure("directory identity mismatch");
  }
  return stat;
}

function requireDirectRegularFile(path: string, expected?: Identity): BigIntStats {
  const stat = lstatOptional(path);
  if (stat === null || stat.isSymbolicLink() || !stat.isFile() || !ownedByCurrentUser(stat)
    || (expected !== undefined && !sameIdentity(stat, expected))) {
    throw new IdentityFailure("file identity mismatch");
  }
  return stat;
}

function stableReadRegularFile(path: string, captured: BigIntStats): StableFile {
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  let descriptor = -1;
  try {
    descriptor = openSync(path, constants.O_RDONLY | noFollow);
    const openedBefore = fstatSync(descriptor, { bigint: true });
    if (!openedBefore.isFile() || !sameIdentity(openedBefore, identityOf(captured))) {
      throw new IdentityFailure("opened file identity mismatch");
    }
    const bytes = readFileSync(descriptor);
    const openedAfter = fstatSync(descriptor, { bigint: true });
    if (!sameIdentity(openedAfter, identityOf(openedBefore)) || openedAfter.size !== openedBefore.size
      || openedAfter.mtimeNs !== openedBefore.mtimeNs || BigInt(bytes.byteLength) !== openedBefore.size) {
      throw new IdentityFailure("file changed during read");
    }
    return { identity: identityOf(openedBefore), bytes };
  } catch (error: unknown) {
    if (error instanceof IdentityFailure) throw error;
    throw new IdentityFailure("cannot capture direct regular file");
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function fsyncDirectory(path: string, expected: Identity): void {
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  const directoryOnly = "O_DIRECTORY" in constants ? constants.O_DIRECTORY : 0;
  let descriptor = -1;
  try {
    descriptor = openSync(path, constants.O_RDONLY | directoryOnly | noFollow);
    const opened = fstatSync(descriptor, { bigint: true });
    if (!opened.isDirectory() || !sameIdentity(opened, expected)) throw new IdentityFailure("opened directory identity mismatch");
    fsyncSync(descriptor);
  } catch (error: unknown) {
    if (error instanceof IdentityFailure) throw error;
    throw new DurabilityFailure("directory fsync failed");
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function createDurableSentinel(path: string, parentPath: string, parentIdentity: Identity): void {
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  let descriptor = -1;
  try {
    requireDirectDirectory(parentPath, parentIdentity);
    descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollow, 0o600);
    fchmodSync(descriptor, 0o600);
    writeFileSync(descriptor, COMPILE_SENTINEL_BYTES, { encoding: "utf8" });
    fsyncSync(descriptor);
  } catch (error: unknown) {
    if (error instanceof IdentityFailure) throw error;
    if (errorCode(error) === "EEXIST" || errorCode(error) === "ELOOP") throw new IdentityFailure("sentinel destination changed");
    throw new DurabilityFailure("sentinel creation failed");
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
  fsyncDirectory(parentPath, parentIdentity);
}

function cleanupOwnedTemp(path: string, identity: Identity | null): void {
  if (identity === null) return;
  try {
    const current = lstatOptional(path);
    if (current !== null && current.isFile() && !current.isSymbolicLink() && sameIdentity(current, identity)) unlinkSync(path);
  } catch {
    // Cleanup is limited to the proven invocation-owned temp. The primary failure remains authoritative.
  }
}

function repairSentinel(
  cwdPath: string,
  cwdIdentity: Identity,
  rootPath: string,
  rootIdentity: Identity,
  compilePath: string,
  compileIdentity: Identity,
  sentinelPath: string,
  sentinelIdentity: Identity,
): void {
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  const token = `${process.pid}-${randomBytes(12).toString("hex")}`;
  const tempPath = join(compilePath, `.gitignore.init-${token}.tmp`);
  let descriptor = -1;
  let tempIdentity: Identity | null = null;
  let renamed = false;
  try {
    descriptor = openSync(tempPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollow, 0o600);
    tempIdentity = identityOf(fstatSync(descriptor, { bigint: true }));
    try {
      fchmodSync(descriptor, 0o600);
      writeFileSync(descriptor, COMPILE_SENTINEL_BYTES, { encoding: "utf8" });
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = -1;
    } catch {
      throw new DurabilityFailure("temporary sentinel durability failed");
    }

    requireDirectDirectory(cwdPath, cwdIdentity);
    requireDirectDirectory(rootPath, rootIdentity);
    requireDirectDirectory(compilePath, compileIdentity);
    requireDirectRegularFile(sentinelPath, sentinelIdentity);
    renameSync(tempPath, sentinelPath);
    renamed = true;
    fsyncDirectory(compilePath, compileIdentity);
  } catch (error: unknown) {
    if (descriptor >= 0) {
      try { closeSync(descriptor); } catch { /* primary failure wins */ }
      descriptor = -1;
    }
    if (!renamed) cleanupOwnedTemp(tempPath, tempIdentity);
    if (error instanceof IdentityFailure || error instanceof DurabilityFailure) throw error;
    throw renamed
      ? new DurabilityFailure("sentinel replacement durability failed")
      : new IdentityFailure("sentinel replacement identity failed");
  }
}

function renderPaths(command: Init, heading: string, paths: readonly string[]): void {
  if (command.jsonEnabled()) return;
  command.log(heading);
  for (const path of paths) command.log(`  ${path}`);
}

/** `loopeix init` — create a `.loopeix/` workspace in the current directory. */
export default class Init extends Command {
  static summary = "Create a .loopeix/ workspace (workspace.yaml + loops/) in the current directory.";
  static flags = {
    "dry-run": Flags.boolean({ description: "print what would be created without writing" }),
  };
  static enableJsonFlag = true;

  private failure(reason: InitFailureReason): Extract<InitCommandResult, { ok: false }> {
    const details = {
      COMPILE_STORE_INVALID: { exit: 1, message: "Compile store is unavailable or invalid." },
      IO_IDENTITY_MISMATCH: { exit: 4, message: "Filesystem identity validation failed." },
      IO_DURABILITY_UNCONFIRMED: { exit: 4, message: "Filesystem durability could not be confirmed." },
    } as const;
    const detail = details[reason];
    process.exitCode = detail.exit;
    if (!this.jsonEnabled()) this.logToStderr(`ERROR [${reason}] ${detail.message}`);
    return { ok: false, disposition: "hold", reason, findings: [detail.message] };
  }

  public async run(): Promise<InitCommandResult> {
    const { flags } = await this.parse(Init);
    const dryRun = flags["dry-run"] === true;
    const cwdPath = process.cwd();
    const rootPath = join(cwdPath, ".loopeix");
    const compilePath = join(rootPath, "compiles");
    const sentinelPath = join(compilePath, ".gitignore");

    let cwdStat: BigIntStats;
    try {
      cwdStat = requireDirectDirectory(cwdPath);
    } catch {
      return this.failure("IO_IDENTITY_MISMATCH");
    }
    const cwdIdentity = identityOf(cwdStat);
    const rootStat = lstatOptional(rootPath);

    if (rootStat === null) {
      if (dryRun) {
        renderPaths(this, "would create:", FRESH_PATHS);
        return { created: [], dryRun: true };
      }
      try {
        requireDirectDirectory(cwdPath, cwdIdentity);
        mkdirSync(rootPath, { mode: 0o700 });
        mkdirSync(join(rootPath, "loops"), { mode: 0o700 });
        writeFileSync(join(rootPath, "workspace.yaml"), WORKSPACE_YAML, { flag: "wx" });
        mkdirSync(join(rootPath, "keys"), { mode: 0o700 });
        writeFileSync(join(rootPath, "keys", ".gitignore"), KEY_SENTINEL_BYTES, { flag: "wx" });
        mkdirSync(compilePath, { mode: 0o700 });
        const compileIdentity = identityOf(requireDirectDirectory(compilePath));
        createDurableSentinel(sentinelPath, compilePath, compileIdentity);
      } catch (error: unknown) {
        return this.failure(error instanceof IdentityFailure || isIdentityRaceError(error)
          ? "IO_IDENTITY_MISMATCH"
          : "IO_DURABILITY_UNCONFIRMED");
      }
      renderPaths(this, "created:", FRESH_PATHS);
      return { created: [...FRESH_PATHS] };
    }

    if (rootStat.isSymbolicLink() || !ownedByCurrentUser(rootStat)) return this.failure("IO_IDENTITY_MISMATCH");
    if (!rootStat.isDirectory()) return this.failure("COMPILE_STORE_INVALID");
    const rootIdentity = identityOf(rootStat);
    const compileStat = lstatOptional(compilePath);

    if (compileStat === null) {
      if (dryRun) {
        renderPaths(this, "would create:", COMPILE_PATHS);
        return { created: [], dryRun: true };
      }
      try {
        requireDirectDirectory(cwdPath, cwdIdentity);
        requireDirectDirectory(rootPath, rootIdentity);
        mkdirSync(compilePath, { mode: 0o700 });
        const createdCompile = requireDirectDirectory(compilePath);
        const compileIdentity = identityOf(createdCompile);
        fsyncDirectory(rootPath, rootIdentity);
        createDurableSentinel(sentinelPath, compilePath, compileIdentity);
      } catch (error: unknown) {
        return this.failure(error instanceof IdentityFailure || isIdentityRaceError(error)
          ? "IO_IDENTITY_MISMATCH"
          : "IO_DURABILITY_UNCONFIRMED");
      }
      renderPaths(this, "created:", COMPILE_PATHS);
      return { created: [...COMPILE_PATHS] };
    }

    if (compileStat.isSymbolicLink() || !ownedByCurrentUser(compileStat)) return this.failure("IO_IDENTITY_MISMATCH");
    if (!compileStat.isDirectory()) return this.failure("COMPILE_STORE_INVALID");
    const compileIdentity = identityOf(compileStat);
    const sentinelStat = lstatOptional(sentinelPath);

    if (sentinelStat === null) {
      if (dryRun) {
        renderPaths(this, "would create:", [SENTINEL_PATH]);
        return { created: [], dryRun: true };
      }
      try {
        requireDirectDirectory(cwdPath, cwdIdentity);
        requireDirectDirectory(rootPath, rootIdentity);
        requireDirectDirectory(compilePath, compileIdentity);
        createDurableSentinel(sentinelPath, compilePath, compileIdentity);
      } catch (error: unknown) {
        return this.failure(error instanceof IdentityFailure ? "IO_IDENTITY_MISMATCH" : "IO_DURABILITY_UNCONFIRMED");
      }
      renderPaths(this, "created:", [SENTINEL_PATH]);
      return { created: [SENTINEL_PATH] };
    }

    if (sentinelStat.isSymbolicLink() || !sentinelStat.isFile() || !ownedByCurrentUser(sentinelStat)) {
      return this.failure("IO_IDENTITY_MISMATCH");
    }

    let stableSentinel: StableFile;
    try {
      stableSentinel = stableReadRegularFile(sentinelPath, sentinelStat);
    } catch {
      return this.failure("IO_IDENTITY_MISMATCH");
    }
    if (stableSentinel.bytes.equals(Buffer.from(COMPILE_SENTINEL_BYTES))) {
      if (!this.jsonEnabled()) this.warn(".loopeix already exists; nothing created.");
      return { created: [] };
    }

    if (dryRun) {
      renderPaths(this, "would repair:", [SENTINEL_PATH]);
      return { created: [], dryRun: true, repaired: [], wouldRepair: [SENTINEL_PATH] };
    }

    try {
      repairSentinel(
        cwdPath,
        cwdIdentity,
        rootPath,
        rootIdentity,
        compilePath,
        compileIdentity,
        sentinelPath,
        stableSentinel.identity,
      );
    } catch (error: unknown) {
      return this.failure(error instanceof DurabilityFailure ? "IO_DURABILITY_UNCONFIRMED" : "IO_IDENTITY_MISMATCH");
    }
    renderPaths(this, "repaired:", [SENTINEL_PATH]);
    return { created: [], repaired: [SENTINEL_PATH] };
  }
}
