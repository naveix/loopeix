import { execFileSync, spawnSync } from "node:child_process";
import { createECDH, createHash, createPrivateKey } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  cpSync,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  opendirSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync,
  rmSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const BASE_COMMIT = "13a8906fdd32b005d29c1eb07ee54f55f80c7fc2";
const TRUSTED_EXECUTABLES = Object.freeze({
  git: Object.freeze({
    path: "/opt/homebrew/Cellar/git/2.53.0/bin/git",
    sha256: "5e5a622e407fb7deb74173cab9e47ff214952cc6bfcd036449cf9edbaa305537",
  }),
  node: Object.freeze({
    path: "/opt/homebrew/Cellar/node/26.0.0/bin/node",
    sha256: "08dad0581f00a0cabf4d49ec92ca1f25fdfd01c2c18fa8e92b35f04d4c24c164",
  }),
  pnpm: Object.freeze({
    path: "/opt/homebrew/lib/node_modules/pnpm/bin/pnpm.mjs",
    sha256: "ff3224d46b47fbb24a7e9fe15fededef7e00892d07d4e376b6762d4899906bfd",
  }),
});
const CATALOG_HASH = "sha256:4bba5fca6ce73a6d21598890001a45e03c349a3a1fa78148b802497a22eda823";
const CAPTURE_TIMESTAMP = "2026-07-09T12:00:00.000Z";
const WORKSPACE_ROOT = "/workspace/loopeix-fixture";
const PLAN_WORKSPACE_ROOT = "/tmp/loopeix-s35-v01-plan-oracle";
const EXPLICIT_DESTINATION_ROOT = "/tmp/loopeix-s35-v01-explicit-destination";
const IN_PROCESS_LIMIT_BYTES = 4_194_304;
const TARGET_OVERSIZED_BYTES = 4_196_413;
const SAFE_PROMPT = "Fix the failing date parser test and prove the fix.";
const MARKER_NAME = ".loopeix-s35-capture-marker";
const EXPECTED_PNPM_LOCK_SHA256 = "7339169a4626b2e2af3d9e9bc0d13da340f09b7ee41314a235cc9c12b484453c";
const EXPECTED_TSX_VERSION = "4.22.5";
const EXPECTED_TSX_LOCK_INTEGRITY = "sha512-F7JnSfPl5ASt6LqwWyUQ3T8BwN3q0eQEbFMYa2iRWaVQmmudo0d7fRmwM4O002gsvW1bs0yBYioutsAjqLJMvQ==";
const EXPECTED_TSX_PACKAGE_SHA256 = "7aa86133a2b573a814e45558c0317d2a94aec491960717f3d81f768dea6f9d43";
const EXPECTED_TSX_PREFLIGHT_SHA256 = "5ef95c5c4b5875dbc270b9591676a2138e4df82bcebde945eebb1eadf721b192";
const EXPECTED_TSX_LOADER_SHA256 = "f377ce5933ad7ba16a54435ac143dddb2178ffcf9e380c54048a4cfadb8959fc";
const PACKAGE_RUNTIME_TREE_EXCLUSIONS = Object.freeze(["node_modules"] as const);
const EXPECTED_TSX_TREE = Object.freeze({
  entry_count: 55,
  file_count: 50,
  byte_count: 518_641,
  tree_sha256: "45eff75d45eb095d3c351557acd9fe622fc6d6d17995cd434bcc31f2dff5f25d",
});
const EXPECTED_ESBUILD_VERSION = "0.28.1";
const EXPECTED_ESBUILD_LOCK_INTEGRITY = "sha512-HrJrvZv5ayxBzPfwphOoNzkzOIIlifzk0KJrGK2c8R4+LKpMtpYLQeUdjnwjWv/LZlkH2laZk+4w78pi99D4Vw==";
const EXPECTED_ESBUILD_PACKAGE_SHA256 = "d55d1d19fcc5b6079e4a71dd4111340c79c682bc36835ac7058a0c364c7db58a";
const EXPECTED_ESBUILD_MAIN_SHA256 = "8331fe1d8b3a07381f33cc425fcfaa94776e263113653f80ec3ba433e9657e73";
const EXPECTED_ESBUILD_TREE = Object.freeze({
  entry_count: 9,
  file_count: 7,
  byte_count: 10_711_381,
  tree_sha256: "8197885e1a8a9e929e2913c4fecbbd02abbc6b2d9ddd3e085d397bc5f582ee84",
});
const EXPECTED_ESBUILD_PLATFORM = "@esbuild/darwin-arm64";
const EXPECTED_ESBUILD_PLATFORM_LOCK_INTEGRITY = "sha512-TZbWkQY7kvTAXbXUT7uVACR5cMHsDiSz9z7ZKAX/RTq/WJEk3QyRr0wZpNhBDX+/0CtdqUIJlOiodQcta6tY3Q==";
const EXPECTED_ESBUILD_PLATFORM_PACKAGE_SHA256 = "4741fe8d75953474f275402d367368cf49c242b2bc04b85e25bad14bfd26eaad";
const EXPECTED_ESBUILD_BINARY_SHA256 = "e2dc9a52440a2a34f09434a2f4843cb1e30f84e40dcf238976ec61ef8cd7f36a";
const EXPECTED_ESBUILD_PLATFORM_TREE = Object.freeze({
  entry_count: 4,
  file_count: 3,
  byte_count: 10_574_305,
  tree_sha256: "4086a7846003b85046a13bbcbdf7e3140e62c5c177422c02b12c8cf568a99059",
});
const MAX_RUNTIME_TREE_DEPTH = 16;
const MAX_RUNTIME_TREE_ENTRIES = 256;
const MAX_RUNTIME_FILE_BYTES = 16 * 1024 * 1024;
const MAX_RUNTIME_TREE_BYTES = 32 * 1024 * 1024;
const CHILD_PROCESS_MAX_OUTPUT_BYTES = 1_048_576;
const CHILD_PROCESS_TIMEOUT_MS = 300_000;
const CREDENTIAL_RULE_ID = "CRED_COMPOSIO_CONSUMER_KEY";
const CREDENTIAL_DIGEST = "081fc9e5b37364ee0d653228e45f195a61f83bcc6de87c476c46c817bc0454b5";
const CREDENTIAL_BYTE_LENGTH = 34;
const COMPILED_PACK_MEMBERS = [
  "catalog-resolution.json",
  "compilation-record.json",
  "compile-report.md",
  "generated.loop.yaml",
  "intake-record.json",
  "pack-manifest.json",
  "work-item.json",
] as const;
const HOLD_PACK_MEMBERS = [
  "catalog-resolution.json",
  "compile-report.md",
  "intake-record.json",
  "pack-manifest.json",
  "work-item.json",
] as const;
const RUN_RECOVER_ORACLE_ROOT = "run-recover-zero-complete-event";
const RUN_RECOVER_CASE_NAMES = ["empty", "blank-only", "partial-only"] as const;
const RUN_RECOVER_MODES = ["human", "json"] as const;
const RUN_RECOVER_RAW_MEMBERS = [
  "human.exit",
  "human.stderr",
  "human.stdout",
  "json.exit",
  "json.stderr",
  "json.stdout",
  "ledger.jsonl",
] as const;
const RUN_RECOVER_VALID_HUMAN_STDOUT = [
  "run_state:  planned",
  "integrity:  valid",
  "verdict:    recoverable \u2014 chain and content verified",
  "",
].join("\n");
const RUN_RECOVER_PARTIAL_HUMAN_STDOUT = [
  "run_state:  planned",
  "integrity:  hold",
  "verdict:    HOLD \u2014 needs review before continuing",
  "findings:",
  "  - dropped a partial final ledger line during recovery",
  "",
].join("\n");
const RUN_RECOVER_VALID_JSON_STDOUT = [
  "{",
  '  "integrity_status": "valid",',
  '  "run_state": "planned",',
  '  "last_valid_sequence": 0,',
  '  "terminated": false,',
  '  "findings": [],',
  '  "recoverable": true',
  "}",
  "",
].join("\n");
const RUN_RECOVER_PARTIAL_JSON_STDOUT = [
  "{",
  '  "integrity_status": "hold",',
  '  "run_state": "planned",',
  '  "last_valid_sequence": 0,',
  '  "terminated": false,',
  '  "findings": [',
  '    "dropped a partial final ledger line during recovery"',
  "  ],",
  '  "recoverable": false',
  "}",
  "",
].join("\n");

type JsonObject = Record<string, unknown>;
type BaselineApi = typeof import("../src/index.js");
type CompileCommandModule = typeof import("../src/commands/compile.js");
type CompileResult = ReturnType<BaselineApi["compilePrompt"]>;
type SealedLedgerEvent = ReturnType<BaselineApi["appendToLedger"]>;
type LedgerEventDraft = Parameters<BaselineApi["appendToLedger"]>[1];
type ReceiptInput = Parameters<BaselineApi["buildReceipt"]>[0];
type RunRecoverMode = typeof RUN_RECOVER_MODES[number];

type RunRecoverCase = {
  name: typeof RUN_RECOVER_CASE_NAMES[number];
  ledgerBytes: Buffer;
  expectedExit: 0 | 4;
  expectedStdout: Readonly<Record<RunRecoverMode, string>>;
};

type RunRecoverInvocation = {
  args: string[];
  exit: number;
  stdout: Buffer;
  stderr: Buffer;
};

type RuntimeEnvironment = Readonly<Record<string, string | undefined>>;

type RuntimeFileIdentity = {
  requested_relative_path: string;
  resolved_relative_path: string;
  sha256: string;
};

type RuntimeTreeIdentity = {
  requested_relative_path: string;
  resolved_relative_path: string;
  entry_count: number;
  file_count: number;
  byte_count: number;
  tree_sha256: string;
};

type RuntimeTreeEntry =
  | { path: string; type: "directory"; mode: number }
  | { path: string; type: "file"; mode: number; size: number; sha256: string };

type CaptureTsxRuntimeIdentity = {
  node: {
    version: string;
    exec_path: string;
    argv: string[];
    exec_argv: string[];
  };
  pnpm_lock: RuntimeFileIdentity;
  tsx: {
    version: string;
    lock_integrity: string;
    package: RuntimeFileIdentity;
    preflight: RuntimeFileIdentity;
    loader: RuntimeFileIdentity;
    tree: RuntimeTreeIdentity;
  };
  esbuild: {
    version: string;
    lock_integrity: string;
    package: RuntimeFileIdentity;
    main: RuntimeFileIdentity;
    tree: RuntimeTreeIdentity;
    platform: {
      package_name: string;
      lock_integrity: string;
      package: RuntimeFileIdentity;
      binary: RuntimeFileIdentity;
      tree: RuntimeTreeIdentity;
    };
  };
};

function fail(message: string): never {
  throw new Error(`S35 V01 oracle capture failed: ${message}`);
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) fail(message);
}

function parseArgs(argv: readonly string[]): {
  sourceRoot: string;
  reviewedOriginRoot: string;
  sourceSnapshotSha256: string;
  out: string;
  assertedCommit: string;
  toolSourceRoot: string;
} {
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    assert(flag !== undefined && value !== undefined, "arguments must be flag/value pairs");
    assert(
      [
        "--source-root",
        "--reviewed-origin-root",
        "--source-snapshot-sha256",
        "--out",
        "--assert-base-commit",
        "--tool-source-root",
      ].includes(flag),
      `unknown argument ${flag}`,
    );
    assert(!values.has(flag), `duplicate argument ${flag}`);
    values.set(flag, value);
  }
  const sourceRoot = values.get("--source-root");
  const reviewedOriginRoot = values.get("--reviewed-origin-root");
  const sourceSnapshotSha256 = values.get("--source-snapshot-sha256");
  const out = values.get("--out");
  const assertedCommit = values.get("--assert-base-commit");
  const toolSourceRoot = values.get("--tool-source-root");
  assert(sourceRoot !== undefined, "--source-root is required");
  assert(reviewedOriginRoot !== undefined, "--reviewed-origin-root is required");
  assert(sourceSnapshotSha256 !== undefined, "--source-snapshot-sha256 is required");
  assert(out !== undefined, "--out is required");
  assert(assertedCommit !== undefined, "--assert-base-commit is required");
  assert(toolSourceRoot !== undefined, "--tool-source-root is required");
  assert(
    isAbsolute(sourceRoot) &&
      isAbsolute(reviewedOriginRoot) &&
      isAbsolute(out) &&
      isAbsolute(toolSourceRoot),
    "--source-root, --reviewed-origin-root, --out, and --tool-source-root must be absolute paths",
  );
  assert(/^[0-9a-f]{64}$/.test(sourceSnapshotSha256), "--source-snapshot-sha256 must be lowercase SHA-256");
  return {
    sourceRoot: resolve(sourceRoot),
    reviewedOriginRoot: resolve(reviewedOriginRoot),
    sourceSnapshotSha256,
    out: resolve(out),
    assertedCommit,
    toolSourceRoot: resolve(toolSourceRoot),
  };
}

type TrustedExecutableName = keyof typeof TRUSTED_EXECUTABLES;

function admittedPnpmPath(): string {
  const admittedNodePath = realpathSync(process.execPath);
  const admittedNodeRoot = dirname(dirname(admittedNodePath));
  assert(
    basename(admittedNodeRoot) === "node",
    "capture Node executable is outside the admitted runtime layout",
  );
  return join(dirname(admittedNodeRoot), "pnpm", "bin", "pnpm.mjs");
}

function assertTrustedExecutable(name: TrustedExecutableName): string {
  const trusted = TRUSTED_EXECUTABLES[name];
  const executablePath =
    name === "node" ? process.execPath : name === "pnpm" ? admittedPnpmPath() : trusted.path;
  assert(
    isAbsolute(executablePath) && realpathSync(executablePath) === executablePath,
    `trusted ${name} executable is not canonical`,
  );
  const captured = readBoundedRuntimeFile(executablePath);
  try {
    assert(
      createHash("sha256").update(captured.bytes).digest("hex") === trusted.sha256,
      `trusted ${name} executable hash drifted`,
    );
  } finally {
    captured.bytes.fill(0);
  }
  return executablePath;
}

function trustedInvocation(
  commandName: TrustedExecutableName,
  args: readonly string[],
): { executable: string; args: string[] } {
  if (commandName === "pnpm") {
    return {
      executable: assertTrustedExecutable("node"),
      args: [assertTrustedExecutable("pnpm"), ...args],
    };
  }
  return {
    executable: assertTrustedExecutable(commandName),
    args: [...args],
  };
}

function sanitizedCaptureEnvironment(
  environment: RuntimeEnvironment,
): NodeJS.ProcessEnv {
  const home = environment.HOME;
  const path = environment.PATH;
  const tmpdir = environment.TMPDIR;
  assert(typeof home === "string" && home.length > 0, "capture child HOME is required");
  assert(typeof path === "string" && path.length > 0, "capture child PATH is required");
  assert(typeof tmpdir === "string" && tmpdir.length > 0, "capture child TMPDIR is required");
  return {
    HOME: home,
    LANG: "C",
    LC_ALL: "C",
    PATH: path,
    TMPDIR: tmpdir,
  };
}

function canonicalChildWorkingDirectory(cwd: string): string {
  assert(
    isAbsolute(cwd) &&
      realpathSync(cwd) === cwd &&
      statSync(cwd).isDirectory(),
    "capture child working directory is not a canonical directory",
  );
  return cwd;
}

function command(
  commandName: TrustedExecutableName,
  args: readonly string[],
  cwd: string,
): string {
  const invocation = trustedInvocation(commandName, args);
  return execFileSync(invocation.executable, invocation.args, {
    cwd: canonicalChildWorkingDirectory(cwd),
    encoding: "utf8",
    env: sanitizedCaptureEnvironment(process.env),
    killSignal: "SIGKILL",
    maxBuffer: CHILD_PROCESS_MAX_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: CHILD_PROCESS_TIMEOUT_MS,
  }).trim();
}

function assertOrdinaryIndexEntries(sourceRoot: string): void {
  const taggedBytes = execFileSync(
    assertTrustedExecutable("git"),
    ["-C", sourceRoot, "ls-files", "--cached", "-v", "-z", "--"],
    {
      cwd: canonicalChildWorkingDirectory(sourceRoot),
      encoding: "buffer",
      env: sanitizedCaptureEnvironment(process.env),
      killSignal: "SIGKILL",
      maxBuffer: CHILD_PROCESS_MAX_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: CHILD_PROCESS_TIMEOUT_MS,
    },
  );
  const taggedRecords = taggedBytes.length === 0
    ? []
    : taggedBytes.subarray(0, -1).toString("binary").split("\0");
  assert(
    (taggedBytes.length === 0 || taggedBytes.at(-1) === 0x00) &&
      taggedRecords.every((record) => record.length >= 3 && record[1] === " "),
    "source Git index metadata is malformed",
  );
  assert(
    taggedRecords.every((record) => record[0] === "H"),
    "source Git index contains nonordinary entries",
  );

  const stagedBytes = execFileSync(
    assertTrustedExecutable("git"),
    ["-C", sourceRoot, "ls-files", "--cached", "--stage", "-z", "--"],
    {
      cwd: canonicalChildWorkingDirectory(sourceRoot),
      encoding: "buffer",
      env: sanitizedCaptureEnvironment(process.env),
      killSignal: "SIGKILL",
      maxBuffer: CHILD_PROCESS_MAX_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: CHILD_PROCESS_TIMEOUT_MS,
    },
  );
  const stagedRecords = stagedBytes.length === 0
    ? []
    : stagedBytes.subarray(0, -1).toString("binary").split("\0");
  assert(
    stagedBytes.length === 0 || stagedBytes.at(-1) === 0x00,
    "source Git index metadata is malformed",
  );
  for (const record of stagedRecords) {
    const separator = record.indexOf("\t");
    const metadata = separator === -1 ? "" : record.slice(0, separator);
    const match = /^([0-7]{6}) ([0-9a-f]{40}|[0-9a-f]{64}) ([0-3])$/.exec(metadata);
    assert(match !== null, "source Git index metadata is malformed");
    const objectId = match[2];
    const stage = match[3];
    assert(
      objectId !== undefined && stage !== undefined,
      "source Git index metadata is malformed",
    );
    assert(
      stage === "0" && !/^0+$/.test(objectId),
      "source Git index contains nonordinary entries",
    );
  }
}

function assertDetachedSourceSnapshot(
  sourceRoot: string,
  sourceIdentity: { dev: number; ino: number },
): void {
  assertSameIdentity(sourceRoot, sourceIdentity, "source root");
  assert(
    command("git", ["-C", sourceRoot, "rev-parse", "--show-toplevel"], sourceRoot) === sourceRoot,
    "source root is not the Git worktree root",
  );
  assert(
    command("git", ["-C", sourceRoot, "rev-parse", "HEAD"], sourceRoot) === BASE_COMMIT,
    "source worktree is at the wrong commit",
  );
  assert(
    command("git", ["-C", sourceRoot, "rev-parse", "--abbrev-ref", "HEAD"], sourceRoot) === "HEAD",
    "source worktree is not detached",
  );
  assertOrdinaryIndexEntries(sourceRoot);
  assert(
    command(
      "git",
      ["-C", sourceRoot, "status", "--porcelain", "--untracked-files=all"],
      sourceRoot,
    ) === "",
    "source worktree is not clean",
  );
}

function assertExactBytes(actual: Uint8Array, expected: Uint8Array, label: string): void {
  assert(actual.byteLength === expected.byteLength && Buffer.from(actual).equals(Buffer.from(expected)), `${label} bytes drifted`);
}

function writeExactBytes(path: string, bytes: Uint8Array): void {
  writeFileSync(path, bytes, { flag: "wx" });
  assertExactBytes(readFileSync(path), bytes, path);
}

function invokeRunRecoverCli(sourceRoot: string, ledgerPath: string, mode: RunRecoverMode): RunRecoverInvocation {
  const cliPath = join(sourceRoot, "bin", "dev.js");
  assert(lstatSync(cliPath).isFile(), "detached baseline bin/dev.js is not a regular file");
  assert((statSync(cliPath).mode & 0o111) !== 0, "detached baseline bin/dev.js is not executable");
  const args = ["run", "recover", ledgerPath, ...(mode === "json" ? ["--json"] : [])];
  const result = spawnSync(assertTrustedExecutable("node"), [cliPath, ...args], {
    cwd: canonicalChildWorkingDirectory(sourceRoot),
    encoding: null,
    env: sanitizedCaptureEnvironment(process.env),
    killSignal: "SIGKILL",
    maxBuffer: CHILD_PROCESS_MAX_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: CHILD_PROCESS_TIMEOUT_MS,
  });
  assert(result.error === undefined, `run recover ${mode} failed to spawn: ${result.error?.message ?? "unknown error"}`);
  assert(result.signal === null, `run recover ${mode} terminated by signal ${String(result.signal)}`);
  assert(result.status !== null && Number.isInteger(result.status), `run recover ${mode} returned no integer exit status`);
  assert(Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr), `run recover ${mode} did not return raw stream buffers`);
  return { args, exit: result.status, stdout: result.stdout, stderr: result.stderr };
}

function rawSha256(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function rawFileSha256(path: string): string {
  const captured = readBoundedRuntimeFile(path);
  try {
    return rawSha256(captured.bytes);
  } finally {
    captured.bytes.fill(0);
  }
}

function captureRuntimeFileBytes(
  sourceRoot: string,
  requestedPath: string,
  expectedSha256: string,
  escapeMessage: string,
): { bytes: Buffer; identity: RuntimeFileIdentity } {
  assert(existsSync(requestedPath), `capture runtime file is absent: ${requestedPath}`);
  const resolvedPath = realpathSync(requestedPath);
  assert(containsPath(sourceRoot, resolvedPath), escapeMessage);
  const captured = readBoundedRuntimeFile(resolvedPath);
  try {
    const sha256 = rawSha256(captured.bytes);
    assert(
      sha256 === expectedSha256,
      `capture runtime hash drifted: ${relative(sourceRoot, resolvedPath)}`,
    );
    return {
      bytes: captured.bytes,
      identity: {
        requested_relative_path: relative(sourceRoot, requestedPath),
        resolved_relative_path: relative(sourceRoot, resolvedPath),
        sha256,
      },
    };
  } catch (error) {
    captured.bytes.fill(0);
    throw error;
  }
}

function captureRuntimeFile(
  sourceRoot: string,
  requestedPath: string,
  expectedSha256: string,
  escapeMessage: string,
): RuntimeFileIdentity {
  const captured = captureRuntimeFileBytes(
    sourceRoot,
    requestedPath,
    expectedSha256,
    escapeMessage,
  );
  try {
    return captured.identity;
  } finally {
    captured.bytes.fill(0);
  }
}

function captureRuntimeJson<T>(
  sourceRoot: string,
  requestedPath: string,
  expectedSha256: string,
  escapeMessage: string,
): { identity: RuntimeFileIdentity; value: T } {
  const captured = captureRuntimeFileBytes(
    sourceRoot,
    requestedPath,
    expectedSha256,
    escapeMessage,
  );
  try {
    return {
      identity: captured.identity,
      value: JSON.parse(captured.bytes.toString("utf8")) as T,
    };
  } finally {
    captured.bytes.fill(0);
  }
}

function sameFileIdentity(
  left: { dev: number; ino: number },
  right: { dev: number; ino: number },
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameDirectoryIdentity(
  left: {
    dev: number;
    ino: number;
    mode: number;
    nlink: number;
    size: number;
    mtimeMs: number;
    ctimeMs: number;
  },
  right: {
    dev: number;
    ino: number;
    mode: number;
    nlink: number;
    size: number;
    mtimeMs: number;
    ctimeMs: number;
  },
): boolean {
  return sameFileIdentity(left, right) &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs;
}

function readBoundedRuntimeFile(path: string): { bytes: Buffer; mode: number } {
  const pathStat = lstatSync(path);
  assert(pathStat.isFile(), `capture runtime tree contains a non-regular file: ${path}`);
  assert(
    Number.isSafeInteger(pathStat.size) && pathStat.size <= MAX_RUNTIME_FILE_BYTES,
    `capture runtime file exceeds its byte limit: ${path}`,
  );
  const descriptor = openSync(
    path,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
  );
  try {
    const openedStat = fstatSync(descriptor);
    assert(
      openedStat.isFile() &&
        sameFileIdentity(pathStat, openedStat) &&
        openedStat.size === pathStat.size,
      `capture runtime file changed before read: ${path}`,
    );
    const bytes = Buffer.alloc(openedStat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      assert(count > 0, `capture runtime file ended before its recorded size: ${path}`);
      offset += count;
    }
    const growthProbe = Buffer.alloc(1);
    assert(
      readSync(descriptor, growthProbe, 0, 1, bytes.length) === 0,
      `capture runtime file grew during read: ${path}`,
    );
    const finalStat = fstatSync(descriptor);
    assert(
      sameFileIdentity(openedStat, finalStat) &&
        finalStat.size === openedStat.size &&
        finalStat.mtimeMs === openedStat.mtimeMs,
      `capture runtime file changed during read: ${path}`,
    );
    return { bytes, mode: openedStat.mode & 0o777 };
  } finally {
    closeSync(descriptor);
  }
}

function captureRuntimeTree(
  sourceRoot: string,
  requestedRoot: string,
  expected: Readonly<{
    entry_count: number;
    file_count: number;
    byte_count: number;
    tree_sha256: string;
  }>,
  label: string,
  excludedTopLevelNames: readonly string[] = [],
): RuntimeTreeIdentity {
  assert(existsSync(requestedRoot), `${label} package tree is absent`);
  const resolvedRoot = realpathSync(requestedRoot);
  assert(
    containsPath(sourceRoot, resolvedRoot),
    `${label} package tree resolved outside the detached source root`,
  );
  const rootStat = statSync(resolvedRoot);
  assert(rootStat.isDirectory(), `${label} package tree root is not a directory`);
  const entries: RuntimeTreeEntry[] = [];
  let fileCount = 0;
  let byteCount = 0;

  function walk(
    directory: string,
    relativeDirectory: string,
    depth: number,
    expectedDirectoryStat: Parameters<typeof sameDirectoryIdentity>[0],
  ): void {
    assert(depth <= MAX_RUNTIME_TREE_DEPTH, `${label} package tree exceeds its depth limit`);
    const directoryStat = lstatSync(directory);
    assert(
      directoryStat.isDirectory() &&
        sameDirectoryIdentity(expectedDirectoryStat, directoryStat),
      `${label} package tree directory identity changed before enumeration`,
    );
    const names: string[] = [];
    const directoryHandle = opendirSync(directory);
    try {
      for (
        let entry = directoryHandle.readSync();
        entry !== null;
        entry = directoryHandle.readSync()
      ) {
        assert(
          names.length < MAX_RUNTIME_TREE_ENTRIES,
          `${label} package tree exceeds its entry limit`,
        );
        names.push(entry.name);
      }
    } finally {
      directoryHandle.closeSync();
    }
    names.sort();
    for (const name of names) {
      if (relativeDirectory === "" && excludedTopLevelNames.includes(name)) {
        continue;
      }
      const path = join(directory, name);
      const relativePath = relativeDirectory === "" ? name : `${relativeDirectory}/${name}`;
      const entryStat = lstatSync(path);
      assert(
        entries.length < MAX_RUNTIME_TREE_ENTRIES,
        `${label} package tree exceeds its entry limit`,
      );
      if (entryStat.isDirectory()) {
        entries.push({
          path: relativePath,
          type: "directory",
          mode: entryStat.mode & 0o777,
        });
        walk(path, relativePath, depth + 1, entryStat);
        continue;
      }
      assert(
        entryStat.isFile(),
        `${label} package tree contains a symlink or special entry: ${relativePath}`,
      );
      const { bytes, mode } = readBoundedRuntimeFile(path);
      try {
        fileCount += 1;
        byteCount += bytes.length;
        assert(byteCount <= MAX_RUNTIME_TREE_BYTES, `${label} package tree exceeds its byte limit`);
        entries.push({
          path: relativePath,
          type: "file",
          mode,
          size: bytes.length,
          sha256: rawSha256(bytes),
        });
      } finally {
        bytes.fill(0);
      }
    }
    const finalDirectoryStat = lstatSync(directory);
    assert(
      finalDirectoryStat.isDirectory() &&
        sameDirectoryIdentity(directoryStat, finalDirectoryStat),
      `${label} package tree directory identity changed during enumeration`,
    );
  }

  walk(resolvedRoot, "", 0, rootStat);
  const finalRootStat = statSync(resolvedRoot);
  assert(
    finalRootStat.isDirectory() &&
      sameDirectoryIdentity(rootStat, finalRootStat),
    `${label} package tree root changed during capture`,
  );
  const treeSha256 = rawSha256(JSON.stringify(entries));
  assert(
    entries.length === expected.entry_count &&
      fileCount === expected.file_count &&
      byteCount === expected.byte_count &&
      treeSha256 === expected.tree_sha256,
    `${label} package tree hash drifted`,
  );
  return {
    requested_relative_path: relative(sourceRoot, requestedRoot),
    resolved_relative_path: relative(sourceRoot, resolvedRoot),
    entry_count: entries.length,
    file_count: fileCount,
    byte_count: byteCount,
    tree_sha256: treeSha256,
  };
}

function assertRuntimeSnapshot(runtimeSnapshotRoot: string): void {
  const nodeModules = join(runtimeSnapshotRoot, "node_modules");
  const tsxRoot = join(nodeModules, "tsx");
  const esbuildRoot = join(nodeModules, "esbuild");
  const platformRoot = join(nodeModules, "@esbuild", "darwin-arm64");
  assert(
    !existsSync(join(tsxRoot, "node_modules")) &&
      !existsSync(join(esbuildRoot, "node_modules")),
    "runtime snapshot contains excluded package-manager shims",
  );
  captureRuntimeTree(
    runtimeSnapshotRoot,
    tsxRoot,
    EXPECTED_TSX_TREE,
    "snapshot tsx",
    PACKAGE_RUNTIME_TREE_EXCLUSIONS,
  );
  captureRuntimeTree(
    runtimeSnapshotRoot,
    esbuildRoot,
    EXPECTED_ESBUILD_TREE,
    "snapshot esbuild",
    PACKAGE_RUNTIME_TREE_EXCLUSIONS,
  );
  captureRuntimeTree(
    runtimeSnapshotRoot,
    platformRoot,
    EXPECTED_ESBUILD_PLATFORM_TREE,
    "snapshot esbuild platform",
  );
  captureRuntimeFile(
    runtimeSnapshotRoot,
    join(tsxRoot, "dist", "preflight.cjs"),
    EXPECTED_TSX_PREFLIGHT_SHA256,
    "snapshot tsx preflight resolved outside the runtime snapshot",
  );
  captureRuntimeFile(
    runtimeSnapshotRoot,
    join(tsxRoot, "dist", "loader.mjs"),
    EXPECTED_TSX_LOADER_SHA256,
    "snapshot tsx loader resolved outside the runtime snapshot",
  );
}

function resolveAdmittedExecArgv(
  sourceRoot: string,
  runtime: {
    execArgv?: readonly string[];
    environment?: RuntimeEnvironment;
  },
  environment: RuntimeEnvironment,
): { execArgv: string[]; runtimeSnapshotRoot: string | null } {
  const execArgv = [...(runtime.execArgv ?? process.execArgv)];
  if (runtime.execArgv !== undefined) {
    const expectedSourceExecArgv = [
      "--require",
      join(sourceRoot, "node_modules", "tsx", "dist", "preflight.cjs"),
      "--import",
      join(sourceRoot, "node_modules", "tsx", "dist", "loader.mjs"),
    ];
    assert(
      JSON.stringify(execArgv) === JSON.stringify(expectedSourceExecArgv),
      "capture must use the exact admitted tsx preflight and loader hooks",
    );
    return { execArgv, runtimeSnapshotRoot: null };
  }

  assert(
    execArgv.length === 4 &&
      execArgv[0] === "--require" &&
      typeof execArgv[1] === "string" &&
      execArgv[2] === "--import" &&
      typeof execArgv[3] === "string" &&
      isAbsolute(execArgv[1]) &&
      isAbsolute(execArgv[3]),
    "capture must use the exact admitted tsx preflight and loader hooks",
  );
  const runtimeSnapshotRoot = dirname(dirname(dirname(dirname(execArgv[1]))));
  assert(
    realpathSync(runtimeSnapshotRoot) === runtimeSnapshotRoot,
    "capture runtime snapshot root is not canonical",
  );
  const expectedSnapshotExecArgv = [
    "--require",
    join(runtimeSnapshotRoot, "node_modules", "tsx", "dist", "preflight.cjs"),
    "--import",
    join(runtimeSnapshotRoot, "node_modules", "tsx", "dist", "loader.mjs"),
  ];
  assert(
    JSON.stringify(execArgv) === JSON.stringify(expectedSnapshotExecArgv),
    "capture must use the exact admitted tsx preflight and loader hooks",
  );
  assert(
    typeof environment.HOME === "string" &&
      typeof environment.TMPDIR === "string",
    "capture operation HOME and TMPDIR are required",
  );
  const operationRoot = realpathSync(environment.HOME);
  assert(
    realpathSync(environment.TMPDIR) === operationRoot,
    "capture operation HOME and TMPDIR must identify one private root",
  );
  const operationRootStat = lstatSync(operationRoot);
  const snapshotStat = lstatSync(runtimeSnapshotRoot);
  assert(
    operationRootStat.isDirectory() &&
      !operationRootStat.isSymbolicLink() &&
      (operationRootStat.mode & 0o077) === 0,
    "capture operation root is not a private direct directory",
  );
  assert(
    snapshotStat.isDirectory() &&
      !snapshotStat.isSymbolicLink() &&
      (snapshotStat.mode & 0o077) === 0 &&
      dirname(runtimeSnapshotRoot) === operationRoot &&
      basename(runtimeSnapshotRoot).startsWith("loopeix-s35-runtime."),
    "capture runtime snapshot is not a private direct child of the operation root",
  );
  assert(
    !containsPath(sourceRoot, runtimeSnapshotRoot) &&
      !containsPath(runtimeSnapshotRoot, sourceRoot),
    "capture runtime snapshot overlaps the detached source root",
  );
  assertRuntimeSnapshot(runtimeSnapshotRoot);
  return { execArgv, runtimeSnapshotRoot };
}

export function captureTsxRuntimeIdentity(
  sourceRoot: string,
  runtime: {
    execArgv?: readonly string[];
    environment?: RuntimeEnvironment;
  } = {},
): CaptureTsxRuntimeIdentity {
  const environment = runtime.environment ?? process.env;
  assert(
    environment.NODE_OPTIONS === undefined &&
      environment.NODE_PATH === undefined &&
      !Object.keys(environment).some((name) => name.startsWith("TSX_")),
    "NODE_OPTIONS, NODE_PATH, and TSX_* must be unset for capture",
  );

  const admittedRuntime = resolveAdmittedExecArgv(
    sourceRoot,
    runtime,
    environment,
  );
  const execArgv = admittedRuntime.execArgv;
  const requestedTsxRoot = join(sourceRoot, "node_modules", "tsx");
  assert(existsSync(requestedTsxRoot), "detached tsx package is absent");
  const tsxRoot = realpathSync(requestedTsxRoot);
  assert(containsPath(sourceRoot, tsxRoot), "tsx package resolved outside the detached source root");
  const requestedPreflight = join(requestedTsxRoot, "dist", "preflight.cjs");
  const requestedLoader = join(requestedTsxRoot, "dist", "loader.mjs");

  const lock = captureRuntimeFile(
    sourceRoot,
    join(sourceRoot, "pnpm-lock.yaml"),
    EXPECTED_PNPM_LOCK_SHA256,
    "pnpm lockfile resolved outside the detached source root",
  );
  const { identity: tsxPackage, value: tsxPackageJson } = captureRuntimeJson<{
    version?: unknown;
  }>(
    sourceRoot,
    join(requestedTsxRoot, "package.json"),
    EXPECTED_TSX_PACKAGE_SHA256,
    "tsx package resolved outside the detached source root",
  );
  assert(tsxPackageJson.version === EXPECTED_TSX_VERSION, `capture tsx must be ${EXPECTED_TSX_VERSION}`);
  const tsxTree = captureRuntimeTree(
    sourceRoot,
    requestedTsxRoot,
    EXPECTED_TSX_TREE,
    "tsx",
    PACKAGE_RUNTIME_TREE_EXCLUSIONS,
  );
  const preflight = captureRuntimeFile(
    sourceRoot,
    requestedPreflight,
    EXPECTED_TSX_PREFLIGHT_SHA256,
    "tsx preflight resolved outside the detached source root",
  );
  const loader = captureRuntimeFile(
    sourceRoot,
    requestedLoader,
    EXPECTED_TSX_LOADER_SHA256,
    "tsx loader resolved outside the detached source root",
  );

  const requestedEsbuildRoot = join(dirname(tsxRoot), "esbuild");
  assert(existsSync(requestedEsbuildRoot), "detached esbuild package is absent");
  const esbuildRoot = realpathSync(requestedEsbuildRoot);
  assert(containsPath(sourceRoot, esbuildRoot), "esbuild package resolved outside the detached source root");
  const esbuildPackagePath = join(requestedEsbuildRoot, "package.json");
  const { identity: esbuildPackage, value: esbuildPackageJson } = captureRuntimeJson<{
    version?: unknown;
  }>(
    sourceRoot,
    esbuildPackagePath,
    EXPECTED_ESBUILD_PACKAGE_SHA256,
    "esbuild package resolved outside the detached source root",
  );
  assert(esbuildPackageJson.version === EXPECTED_ESBUILD_VERSION, `capture esbuild must be ${EXPECTED_ESBUILD_VERSION}`);
  const esbuildTree = captureRuntimeTree(
    sourceRoot,
    requestedEsbuildRoot,
    EXPECTED_ESBUILD_TREE,
    "esbuild",
    PACKAGE_RUNTIME_TREE_EXCLUSIONS,
  );
  const esbuildMain = captureRuntimeFile(
    sourceRoot,
    join(requestedEsbuildRoot, "lib", "main.js"),
    EXPECTED_ESBUILD_MAIN_SHA256,
    "esbuild main module resolved outside the detached source root",
  );
  const requestedPlatformRoot = join(
    dirname(esbuildRoot),
    "@esbuild",
    "darwin-arm64",
  );
  const platformRoot = realpathSync(requestedPlatformRoot);
  assert(
    containsPath(sourceRoot, platformRoot),
    "esbuild platform package resolved outside the detached source root",
  );
  const { identity: platformPackage, value: platformPackageJson } = captureRuntimeJson<{
    name?: unknown;
    version?: unknown;
  }>(
    sourceRoot,
    join(requestedPlatformRoot, "package.json"),
    EXPECTED_ESBUILD_PLATFORM_PACKAGE_SHA256,
    "esbuild platform package resolved outside the detached source root",
  );
  assert(
    platformPackageJson.name === EXPECTED_ESBUILD_PLATFORM &&
      platformPackageJson.version === EXPECTED_ESBUILD_VERSION,
    `capture esbuild platform must be ${EXPECTED_ESBUILD_PLATFORM}@${EXPECTED_ESBUILD_VERSION}`,
  );
  const platformBinary = captureRuntimeFile(
    sourceRoot,
    join(requestedPlatformRoot, "bin", "esbuild"),
    EXPECTED_ESBUILD_BINARY_SHA256,
    "esbuild platform binary resolved outside the detached source root",
  );
  const platformTree = captureRuntimeTree(
    sourceRoot,
    requestedPlatformRoot,
    EXPECTED_ESBUILD_PLATFORM_TREE,
    "esbuild platform",
  );

  if (admittedRuntime.runtimeSnapshotRoot !== null) {
    assertRuntimeSnapshot(admittedRuntime.runtimeSnapshotRoot);
  }
  return {
    node: {
      version: process.version,
      exec_path: TRUSTED_EXECUTABLES.node.path,
      argv: [...process.argv],
      exec_argv: execArgv,
    },
    pnpm_lock: lock,
    tsx: {
      version: EXPECTED_TSX_VERSION,
      lock_integrity: EXPECTED_TSX_LOCK_INTEGRITY,
      package: tsxPackage,
      preflight,
      loader,
      tree: tsxTree,
    },
    esbuild: {
      version: EXPECTED_ESBUILD_VERSION,
      lock_integrity: EXPECTED_ESBUILD_LOCK_INTEGRITY,
      package: esbuildPackage,
      main: esbuildMain,
      tree: esbuildTree,
      platform: {
        package_name: EXPECTED_ESBUILD_PLATFORM,
        lock_integrity: EXPECTED_ESBUILD_PLATFORM_LOCK_INTEGRITY,
        package: platformPackage,
        binary: platformBinary,
        tree: platformTree,
      },
    },
  };
}

function fixedCaptureOnlyPrivateKeyPem(): string {
  const scalar = Buffer.alloc(32);
  scalar[scalar.length - 1] = 1;
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(scalar);
  const publicPoint = ecdh.getPublicKey(undefined, "uncompressed");
  assert(publicPoint.length === 65 && publicPoint[0] === 4, "fixed P-256 test key has an invalid public point");
  const privateKey = createPrivateKey({
    key: {
      kty: "EC",
      crv: "P-256",
      d: scalar.toString("base64url"),
      x: publicPoint.subarray(1, 33).toString("base64url"),
      y: publicPoint.subarray(33, 65).toString("base64url"),
    },
    format: "jwk",
  });
  return privateKey.export({ format: "pem", type: "pkcs8" }).toString();
}

function pathEntryExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function jsonText(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, jsonText(value), { flag: "wx" });
}

function relativeFiles(root: string): string[] {
  const files: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
      Buffer.from(left.name).compare(Buffer.from(right.name)),
    )) {
      const absolute = join(directory, entry.name);
      const rel = relative(root, absolute).split(sep).join("/");
      assert(!entry.isSymbolicLink(), `captured output contains a symlink: ${rel}`);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) files.push(rel);
      else fail(`captured output contains a non-regular member: ${rel}`);
    }
  };
  visit(root);
  return files;
}

function utf8Sort(values: readonly string[]): string[] {
  return [...values].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
}

function assertExactFiles(root: string, expected: readonly string[], label: string): void {
  const actual = relativeFiles(root);
  const normalizedExpected = utf8Sort(expected);
  assert(JSON.stringify(actual) === JSON.stringify(normalizedExpected), `${label} members drifted: ${actual.join(", ")}`);
}

function filesUnder(fixtureRoot: string, relativeRoot: string): string[] {
  return relativeFiles(join(fixtureRoot, relativeRoot)).map((path) => `${relativeRoot}/${path}`);
}

function writeCaseProvenance(
  fixtureRoot: string,
  casePath: string,
  rawPaths: readonly string[],
  metadata: JsonObject,
): void {
  const uniquePaths = utf8Sort([...new Set(rawPaths)]);
  assert(uniquePaths.length === rawPaths.length, `duplicate raw provenance path for ${casePath}`);
  for (const path of uniquePaths) {
    assert(!isAbsolute(path) && !path.split("/").includes(".."), `unsafe raw provenance path ${path}`);
    assert(lstatSync(join(fixtureRoot, path)).isFile(), `provenance target is not a regular file: ${path}`);
  }
  const provenanceRoot = join(fixtureRoot, "provenance", casePath);
  assert(!existsSync(provenanceRoot), `provenance already exists for ${casePath}`);
  mkdirSync(provenanceRoot, { recursive: true });
  writeJson(join(provenanceRoot, "capture-metadata.json"), metadata);
  const lines = uniquePaths.map((path) => `${rawFileSha256(join(fixtureRoot, path))}  ${path}`);
  writeFileSync(join(provenanceRoot, "SHA256SUMS"), `${lines.join("\n")}\n`, { flag: "wx" });
  verifyCaseProvenance(fixtureRoot, casePath, uniquePaths);
}

function verifyCaseProvenance(fixtureRoot: string, casePath: string, expectedPaths?: readonly string[]): void {
  const provenanceRoot = join(fixtureRoot, "provenance", casePath);
  assertExactFiles(provenanceRoot, ["SHA256SUMS", "capture-metadata.json"], `provenance/${casePath}`);
  const lines = readFileSync(join(provenanceRoot, "SHA256SUMS"), "utf8").trimEnd().split("\n").filter(Boolean);
  const actualPaths: string[] = [];
  for (const line of lines) {
    const match = /^([0-9a-f]{64})  (.+)$/.exec(line);
    assert(match !== null, `malformed SHA256SUMS row for ${casePath}`);
    const expected = match[1]!;
    const rel = match[2]!;
    assert(!isAbsolute(rel) && !rel.split("/").includes(".."), `unsafe SHA256SUMS path ${rel}`);
    assert(rawFileSha256(join(fixtureRoot, rel)) === expected, `SHA256 mismatch for ${rel}`);
    actualPaths.push(rel);
  }
  assert(new Set(actualPaths).size === actualPaths.length, `duplicate SHA256SUMS row for ${casePath}`);
  if (expectedPaths !== undefined) {
    assert(JSON.stringify(actualPaths) === JSON.stringify(utf8Sort(expectedPaths)), `SHA256SUMS membership drifted for ${casePath}`);
  }
}

function copyRawTree(source: string, destination: string): void {
  assert(!existsSync(destination), `capture destination already exists: ${destination}`);
  for (const file of relativeFiles(source)) assert(statSync(join(source, file)).isFile(), `not a file: ${file}`);
  cpSync(source, destination, { recursive: true, errorOnExist: true, force: false });
}

function assertCompilePackManifestHashes(packRoot: string, compiled: boolean): void {
  const manifest = JSON.parse(readFileSync(join(packRoot, "pack-manifest.json"), "utf8")) as {
    generated_loop_hash?: unknown;
    file_hashes?: unknown;
  };
  assert(typeof manifest.file_hashes === "object" && manifest.file_hashes !== null && !Array.isArray(manifest.file_hashes), "pack manifest lacks file_hashes");
  const hashes = manifest.file_hashes as Record<string, unknown>;
  const members: Record<string, string> = {
    work_item: "work-item.json",
    intake: "intake-record.json",
    catalog_resolution: "catalog-resolution.json",
    report: "compile-report.md",
    ...(compiled ? { compilation: "compilation-record.json", generated_loop: "generated.loop.yaml" } : {}),
  };
  assert(JSON.stringify(utf8Sort(Object.keys(hashes))) === JSON.stringify(utf8Sort(Object.keys(members))), "pack manifest hash keys drifted");
  for (const [key, path] of Object.entries(members)) {
    const expected = `sha256:${rawFileSha256(join(packRoot, path))}`;
    assert(hashes[key] === expected, `pack manifest hash mismatch for ${path}`);
  }
  if (compiled) assert(manifest.generated_loop_hash === hashes.generated_loop, "generated_loop_hash disagrees with file_hashes.generated_loop");
  else assert(manifest.generated_loop_hash === null, "HOLD pack unexpectedly binds generated_loop_hash");
}

function assertOversizedMembers(root: string, expected: readonly string[], exactTarget: string): void {
  const actual = relativeFiles(root).filter((path) => statSync(join(root, path)).size >= IN_PROCESS_LIMIT_BYTES);
  assert(JSON.stringify(actual) === JSON.stringify(utf8Sort(expected)), `oversized member inventory drifted in ${root}`);
  assert(statSync(join(root, exactTarget)).size === TARGET_OVERSIZED_BYTES, `${exactTarget} is not exactly ${TARGET_OVERSIZED_BYTES} bytes`);
}

function countUtf8Occurrences(path: string, candidate: string): number {
  const haystack = readFileSync(path);
  const needle = Buffer.from(candidate, "utf8");
  let count = 0;
  let offset = 0;
  while (offset <= haystack.length - needle.length) {
    const found = haystack.indexOf(needle, offset);
    if (found < 0) break;
    count += 1;
    offset = found + needle.length;
  }
  return count;
}

type PathIdentity = { dev: number; ino: number };

function pathIdentity(path: string): PathIdentity {
  const stat = lstatSync(path);
  assert(!stat.isSymbolicLink(), `refusing symlink identity for ${path}`);
  return { dev: stat.dev, ino: stat.ino };
}

function assertSameIdentity(path: string, expected: PathIdentity, label: string): void {
  const actual = pathIdentity(path);
  assert(actual.dev === expected.dev && actual.ino === expected.ino, `${label} identity changed`);
}

function containsPath(parent: string, child: string): boolean {
  return parent === child || child.startsWith(`${parent}${sep}`);
}

type TreeEntry = { path: string; kind: "directory" | "file" };

function treeEntries(root: string): TreeEntry[] {
  const entries: TreeEntry[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
      Buffer.from(left.name).compare(Buffer.from(right.name)),
    )) {
      const absolute = join(directory, entry.name);
      const path = relative(root, absolute).split(sep).join("/");
      assert(!entry.isSymbolicLink(), `fixed capture root contains a symlink: ${path}`);
      if (entry.isDirectory()) {
        entries.push({ path, kind: "directory" });
        visit(absolute);
      } else if (entry.isFile()) entries.push({ path, kind: "file" });
      else fail(`fixed capture root contains a non-regular member: ${path}`);
    }
  };
  visit(root);
  return entries;
}

type MarkedRoot = {
  root: string;
  identity: PathIdentity;
  markerText: string;
  allowedMembers: Map<string, TreeEntry["kind"]>;
};

function assertMarkedMemberPath(path: string): void {
  assert(path.length > 0 && !isAbsolute(path), `fixed-root member must be relative: ${path}`);
  assert(!path.includes("\\"), `fixed-root member must use POSIX separators: ${path}`);
  assert(
    path.split("/").every((part) => part.length > 0 && part !== "." && part !== ".."),
    `fixed-root member is not normalized: ${path}`,
  );
}

export function allowMarkedRootMembers(
  handle: MarkedRoot,
  files: readonly string[],
  directories: readonly string[],
): void {
  assertSameIdentity(handle.root, handle.identity, `fixed root ${handle.root}`);
  for (const [kind, paths] of [
    ["file", files] as const,
    ["directory", directories] as const,
  ]) {
    for (const path of paths) {
      assertMarkedMemberPath(path);
      assert(path !== MARKER_NAME, "capture marker authority cannot be registered by a caller");
      const existing = handle.allowedMembers.get(path);
      assert(existing === undefined || existing === kind, `fixed-root member kind conflicts: ${path}`);
      handle.allowedMembers.set(path, kind);
    }
  }
}

export function createMarkedRoot(root: string, captureRunId: string): MarkedRoot {
  assert(!pathEntryExists(root), `${root} already exists or is a dangling symlink`);
  mkdirSync(root, { recursive: false });
  const marker = join(root, MARKER_NAME);
  try {
    const markerText = jsonText({ base_commit: BASE_COMMIT, capture_run_id: captureRunId, root });
    writeFileSync(marker, markerText, { flag: "wx" });
    return {
      root,
      identity: pathIdentity(root),
      markerText,
      allowedMembers: new Map([[MARKER_NAME, "file"]]),
    };
  } catch (error) {
    try {
      if (pathEntryExists(marker)) {
        assert(lstatSync(marker).isFile(), `refusing to unlink non-file capture marker: ${root}`);
        unlinkSync(marker);
      }
      rmdirSync(root);
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "fixed capture root creation failed and cleanup was incomplete",
      );
    }
    throw error;
  }
}

export function removeOwnedMarkedRoot(handle: MarkedRoot | null): void {
  if (handle === null || !pathEntryExists(handle.root)) return;
  assertSameIdentity(handle.root, handle.identity, `fixed root ${handle.root}`);
  const marker = join(handle.root, MARKER_NAME);
  assert(lstatSync(marker).isFile(), `capture marker is not a regular file: ${handle.root}`);
  assert(readFileSync(marker, "utf8") === handle.markerText, `capture marker changed: ${handle.root}`);
  const entries = treeEntries(handle.root);
  for (const entry of entries) {
    assert(
      handle.allowedMembers.get(entry.path) === entry.kind,
      `unexpected fixed-root member: ${entry.path}`,
    );
  }
  const files = entries
    .filter((entry) => entry.kind === "file" && entry.path !== MARKER_NAME)
    .map((entry) => entry.path);
  const directories = entries
    .filter((entry) => entry.kind === "directory")
    .map((entry) => entry.path)
    .sort((left, right) =>
      right.split("/").length - left.split("/").length || Buffer.from(right).compare(Buffer.from(left)),
    );
  unlinkKnownFiles(handle, files);
  removeKnownDirectories(handle, directories);
  unlinkKnownFiles(handle, [MARKER_NAME]);
  assertSameIdentity(handle.root, handle.identity, `fixed root ${handle.root}`);
  rmdirSync(handle.root);
  assert(!pathEntryExists(handle.root), `fixed root cleanup was incomplete: ${handle.root}`);
}

function assertMarkedTree(handle: MarkedRoot, expectedFiles: readonly string[], expectedDirectories: readonly string[]): void {
  assertSameIdentity(handle.root, handle.identity, `fixed root ${handle.root}`);
  const marker = join(handle.root, MARKER_NAME);
  assert(lstatSync(marker).isFile(), `capture marker is not a regular file: ${handle.root}`);
  assert(readFileSync(marker, "utf8") === handle.markerText, `capture marker changed: ${handle.root}`);
  const expected: TreeEntry[] = [
    ...expectedDirectories.map((path) => ({ path, kind: "directory" as const })),
    ...expectedFiles.map((path) => ({ path, kind: "file" as const })),
  ].sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)) || left.kind.localeCompare(right.kind));
  const actual = treeEntries(handle.root).sort((left, right) =>
    Buffer.from(left.path).compare(Buffer.from(right.path)) || left.kind.localeCompare(right.kind),
  );
  assert(JSON.stringify(actual) === JSON.stringify(expected), `fixed root members drifted at ${handle.root}`);
}

function unlinkKnownFiles(handle: MarkedRoot, paths: readonly string[]): void {
  assertSameIdentity(handle.root, handle.identity, `fixed root ${handle.root}`);
  for (const path of paths) {
    const absolute = join(handle.root, path);
    assert(lstatSync(absolute).isFile(), `refusing to unlink non-file ${absolute}`);
    unlinkSync(absolute);
  }
}

function removeKnownDirectories(handle: MarkedRoot, pathsDeepestFirst: readonly string[]): void {
  assertSameIdentity(handle.root, handle.identity, `fixed root ${handle.root}`);
  for (const path of pathsDeepestFirst) rmdirSync(join(handle.root, path));
}

function assertTerminal(result: CompileResult, terminal: string, selected: string | null): void {
  assert(result.catalog_resolution.terminal_state === terminal, `expected ${terminal}, got ${result.catalog_resolution.terminal_state}`);
  assert(result.catalog_resolution.selected_item_id === selected, `unexpected selected item for ${terminal}`);
  assert(result.catalog_resolution.catalog_version_hash === CATALOG_HASH, "baseline catalog hash drifted");
  assert(result.ok === (terminal === "compiled"), `ok flag disagrees with ${terminal}`);
}

function metadataBase(
  driverPath: string,
  driverHash: string,
  reviewedOriginRoot: string,
  executionSourceRoot: string,
  sourceSnapshotSha256: string,
  versions: JsonObject,
  tsxRuntime: CaptureTsxRuntimeIdentity,
): JsonObject {
  return {
    base_commit: BASE_COMMIT,
    source_root: reviewedOriginRoot,
    execution_source_root: executionSourceRoot,
    source_snapshot_sha256: sourceSnapshotSha256,
    driver_path: driverPath,
    driver_sha256_before: driverHash,
    driver_sha256_after: driverHash,
    toolchain: versions,
    runtime_provenance: tsxRuntime,
  };
}

function fitAsciiPadding(
  render: (padding: string) => string,
  targetBytes: number,
  maxRounds = 8,
): { padding: string; text: string } {
  let padding = "";
  for (let round = 0; round < maxRounds; round += 1) {
    const text = render(padding);
    const size = Buffer.byteLength(text);
    if (size === targetBytes) return { padding, text };
    const delta = targetBytes - size;
    if (delta > 0) {
      padding += "x".repeat(delta);
    } else {
      const shrinkBy = -delta;
      assert(shrinkBy <= padding.length, `padding overshot target by ${shrinkBy} bytes before it could be reduced`);
      padding = padding.slice(0, padding.length - shrinkBy);
    }
  }
  fail(`could not reach exact ${targetBytes}-byte target`);
}

async function withFixedCurrentDate<T>(timestamp: string, operation: () => Promise<T>): Promise<T> {
  const OriginalDate = globalThis.Date;
  const FixedDate = function (...args: unknown[]): Date {
    return args.length === 0
      ? new OriginalDate(timestamp)
      : Reflect.construct(OriginalDate, args) as Date;
  } as unknown as DateConstructor;
  Object.setPrototypeOf(FixedDate, OriginalDate);
  Object.defineProperty(FixedDate, "prototype", { value: OriginalDate.prototype });
  globalThis.Date = FixedDate;
  try {
    return await operation();
  } finally {
    globalThis.Date = OriginalDate;
  }
}

type OperationFailure = { error: unknown };

export function runPrivateCleanupActions(
  operationFailure: OperationFailure | null,
  actions: ReadonlyArray<() => void>,
  aggregateMessage: string,
): void {
  const cleanupFailures: unknown[] = [];
  for (const action of actions) {
    try {
      action();
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (cleanupFailures.length === 0) return;
  if (operationFailure !== null) {
    throw new AggregateError([operationFailure.error, ...cleanupFailures], aggregateMessage);
  }
  if (cleanupFailures.length === 1) throw cleanupFailures[0];
  throw new AggregateError(cleanupFailures, aggregateMessage);
}

async function main(): Promise<void> {
  const trustedNode = assertTrustedExecutable("node");
  assert(process.execPath === trustedNode, "capture process is not running under the admitted Node executable");
  const {
    sourceRoot: requestedSourceRoot,
    reviewedOriginRoot: requestedReviewedOriginRoot,
    sourceSnapshotSha256,
    out: requestedOut,
    assertedCommit,
    toolSourceRoot: requestedToolSourceRoot,
  } = parseArgs(process.argv.slice(2));
  assert(assertedCommit === BASE_COMMIT, `asserted commit must be ${BASE_COMMIT}`);
  assert(existsSync(requestedSourceRoot), "source root does not exist");
  const sourceRoot = realpathSync(requestedSourceRoot);
  const executionSourceIdentity = pathIdentity(sourceRoot);
  assertDetachedSourceSnapshot(sourceRoot, executionSourceIdentity);
  assert(existsSync(requestedReviewedOriginRoot), "reviewed origin root does not exist");
  const reviewedOriginRoot = realpathSync(requestedReviewedOriginRoot);
  const sourceIdentity = pathIdentity(reviewedOriginRoot);
  assertDetachedSourceSnapshot(reviewedOriginRoot, sourceIdentity);
  assert(
    !containsPath(sourceRoot, reviewedOriginRoot) && !containsPath(reviewedOriginRoot, sourceRoot),
    "private execution source and reviewed origin overlap",
  );
  const requestedOutParent = dirname(requestedOut);
  assert(existsSync(requestedOutParent), "staging parent does not exist");
  const stagingParent = realpathSync(requestedOutParent);
  assert(statSync(stagingParent).isDirectory(), "staging parent is not a directory");
  const stagingParentIdentity = pathIdentity(stagingParent);
  const out = join(stagingParent, basename(requestedOut));
  assert(!containsPath(sourceRoot, out) && !containsPath(out, sourceRoot), "execution source and staging roots overlap");
  assert(
    !containsPath(reviewedOriginRoot, out) && !containsPath(out, reviewedOriginRoot),
    "reviewed origin and staging roots overlap",
  );
  assert(!pathEntryExists(requestedOut) && !pathEntryExists(out), "staging output already exists or is a dangling symlink");
  assert(!pathEntryExists(PLAN_WORKSPACE_ROOT), `${PLAN_WORKSPACE_ROOT} already exists or is a dangling symlink`);
  assert(!pathEntryExists(EXPLICIT_DESTINATION_ROOT), `${EXPLICIT_DESTINATION_ROOT} already exists or is a dangling symlink`);

  const toolSourceRoot = realpathSync(requestedToolSourceRoot);
  assert(statSync(toolSourceRoot).isDirectory(), "reviewed tool source root is not a directory");
  const admittedDriverPath = fileURLToPath(import.meta.url);
  const driverPath = join(toolSourceRoot, "capture-v01-oracles-s35.ts");
  assert(realpathSync(driverPath) === driverPath, "V01 capture driver source is not canonical");
  const driverHashBefore = rawFileSha256(driverPath);
  assert(
    rawFileSha256(admittedDriverPath) === driverHashBefore,
    "admitted V01 capture driver differs from its reviewed source",
  );
  const launcherPath = join(toolSourceRoot, "launch-v01-oracles-s35.mjs");
  assert(existsSync(launcherPath), "V01 capture launcher is absent");
  const launcherHashBefore = rawFileSha256(launcherPath);
  const packageDriverPath = join(toolSourceRoot, "capture-s35-package-oracles.mjs");
  assert(existsSync(packageDriverPath), "package-oracle driver is absent");
  const packageDriverHashBefore = rawFileSha256(packageDriverPath);
  const cleanLauncherPath = join(toolSourceRoot, "run-s35-capture-clean.sh");
  assert(existsSync(cleanLauncherPath), "clean capture process launcher is absent");
  const cleanLauncherHashBefore = rawFileSha256(cleanLauncherPath);
  const tsxRuntime = captureTsxRuntimeIdentity(sourceRoot);
  const nodeVersion = process.version;
  const pnpmVersion = command("pnpm", ["--version"], sourceRoot);
  const yamlPackage = JSON.parse(readFileSync(join(sourceRoot, "node_modules", "yaml", "package.json"), "utf8")) as { version?: unknown };
  assert(nodeVersion === "v26.0.0", `capture runtime must be Node v26.0.0, got ${nodeVersion}`);
  assert(pnpmVersion === "11.9.0", `capture pnpm must be 11.9.0, got ${pnpmVersion}`);
  assert(yamlPackage.version === "2.9.0", `capture YAML must be 2.9.0, got ${String(yamlPackage.version)}`);
  const versions = { node: nodeVersion, pnpm: pnpmVersion, yaml: yamlPackage.version };

  const api = await import(pathToFileURL(join(sourceRoot, "src", "index.ts")).href) as BaselineApi;
  const compileCommandModule = await import(pathToFileURL(join(sourceRoot, "src", "commands", "compile.ts")).href) as CompileCommandModule;
  const CompileCommand = compileCommandModule.default;
  const productRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-v01-product-"));
  let captureFailure: OperationFailure | null = null;
  let explicitRoot: MarkedRoot | null = null;
  let planRoot: MarkedRoot | null = null;
  try {
  assertSameIdentity(stagingParent, stagingParentIdentity, "staging parent before output creation");
  mkdirSync(out, { recursive: false });
  assert(realpathSync(out) === out, "staging output resolved to an unexpected path");
  assertSameIdentity(stagingParent, stagingParentIdentity, "staging parent");
  const stagingRootIdentity = pathIdentity(out);
  const baseMetadata = metadataBase(
    driverPath,
    driverHashBefore,
    reviewedOriginRoot,
    sourceRoot,
    sourceSnapshotSha256,
    versions,
    tsxRuntime,
  );
  const captureRunId = `s35-${process.pid}-${Date.now()}`;

  const compileCases: Array<{ name: string; prompt: string; terminal: string; selected: string | null }> = [
    { name: "compiled-safe-bugfix", prompt: SAFE_PROMPT, terminal: "compiled", selected: "safe-bugfix" },
    { name: "hold-risk", prompt: "Log into Stripe if needed and fix billing in production.", terminal: "hold-risk", selected: null },
    { name: "hold-ambiguous", prompt: "Fix this with an expert team.", terminal: "hold-ambiguous", selected: null },
    { name: "hold-no-item", prompt: "Polish this thing and make it nicer.", terminal: "hold-no-item", selected: null },
  ];
  for (const item of compileCases) {
    const result = api.compilePrompt({ prompt: item.prompt, workspaceRoot: WORKSPACE_ROOT, submittedAt: CAPTURE_TIMESTAMP });
    assertTerminal(result, item.terminal, item.selected);
    const productDir = join(productRoot, item.name);
    const pack = api.writeCompilePack(result, productDir);
    assert(pack.ok === result.ok, `pack status drifted for ${item.name}`);
    assertExactFiles(productDir, item.terminal === "compiled" ? COMPILED_PACK_MEMBERS : HOLD_PACK_MEMBERS, item.name);
    assertCompilePackManifestHashes(productDir, item.terminal === "compiled");
    const fixtureDir = join(out, item.name);
    copyRawTree(productDir, fixtureDir);
    writeCaseProvenance(out, item.name, filesUnder(out, item.name), {
      ...baseMetadata,
      case: item.name,
      inputs: { prompt: item.prompt, workspace_root: WORKSPACE_ROOT, submitted_at: CAPTURE_TIMESTAMP },
      expected_terminal: item.terminal,
      selected_item_id: item.selected,
      api_entrypoints: ["compilePrompt", "writeCompilePack"],
    });
  }

  explicitRoot = createMarkedRoot(EXPLICIT_DESTINATION_ROOT, captureRunId);
  const explicitOut = join(EXPLICIT_DESTINATION_ROOT, "generated.loop.yaml");
  const explicitPackDir = join(EXPLICIT_DESTINATION_ROOT, "compile-pack");
  const explicitFiles = [
    MARKER_NAME,
    "generated.loop.yaml",
    ...COMPILED_PACK_MEMBERS.map((path) => `compile-pack/${path}`),
  ];
  allowMarkedRootMembers(
    explicitRoot,
    explicitFiles.filter((path) => path !== MARKER_NAME),
    ["compile-pack"],
  );
  const explicitResult = await withFixedCurrentDate(CAPTURE_TIMESTAMP, () =>
    CompileCommand.run([
      "--prompt", SAFE_PROMPT,
      "--workspace-root", WORKSPACE_ROOT,
      "--out", explicitOut,
      "--pack-dir", explicitPackDir,
      "--json",
    ], sourceRoot),
  );
  assertTerminal(explicitResult, "compiled", "safe-bugfix");
  assert(explicitResult.output_path === explicitOut && explicitResult.pack_dir === explicitPackDir, "compile command returned unexpected destinations");
  assert(existsSync(explicitOut), "compile command did not create the explicit output");
  assertExactFiles(explicitPackDir, COMPILED_PACK_MEMBERS, "compiled-explicit-destination");
  assertCompilePackManifestHashes(explicitPackDir, true);
  const explicitFixture = join(out, "compiled-explicit-destination");
  copyRawTree(explicitPackDir, explicitFixture);
  const standaloneRelativeRoot = "standalone/compiled-explicit-destination";
  const standaloneRoot = join(out, standaloneRelativeRoot);
  mkdirSync(standaloneRoot, { recursive: true });
  cpSync(explicitOut, join(standaloneRoot, "generated.loop.yaml"), { errorOnExist: true, force: false });
  writeCaseProvenance(out, "compiled-explicit-destination", [
    ...filesUnder(out, "compiled-explicit-destination"),
    ...filesUnder(out, standaloneRelativeRoot),
  ], {
    ...baseMetadata,
    case: "compiled-explicit-destination",
    inputs: {
      prompt: SAFE_PROMPT,
      workspace_root: WORKSPACE_ROOT,
      submitted_at_via_fixed_capture_clock: CAPTURE_TIMESTAMP,
      output_path: explicitOut,
      pack_dir: explicitPackDir,
    },
    returned: { output_path: explicitResult.output_path, pack_dir: explicitResult.pack_dir },
    expected_terminal: "compiled",
    api_entrypoint: "Compile.run",
  });
  assertMarkedTree(explicitRoot, explicitFiles, ["compile-pack"]);
  unlinkKnownFiles(explicitRoot, explicitFiles.filter((path) => path !== MARKER_NAME));
  removeKnownDirectories(explicitRoot, ["compile-pack"]);
  unlinkKnownFiles(explicitRoot, [MARKER_NAME]);
  rmdirSync(explicitRoot.root);
  explicitRoot = null;

  const credentialCandidate = ["c", "k", "_", "S35Synthetic", "CaptureOnly", "00000000"].join("");
  assert(Buffer.byteLength(credentialCandidate, "utf8") === CREDENTIAL_BYTE_LENGTH, "synthetic credential length drifted");
  assert(rawSha256(Buffer.from(credentialCandidate, "utf8")) === CREDENTIAL_DIGEST, "synthetic credential digest drifted");
  const credentialPrompt = `${SAFE_PROMPT} Reference ${credentialCandidate} as inert historical text.`;
  const detectorMatches = [...credentialPrompt.matchAll(/(?:^|[^A-Za-z0-9_-])(ck_[A-Za-z0-9_-]{20,255})(?=$|[^A-Za-z0-9_-])/gm)];
  assert(detectorMatches.length === 1 && detectorMatches[0]?.[1] === credentialCandidate, "synthetic credential does not match the frozen rule exactly once");
  const credentialResult = api.compilePrompt({ prompt: credentialPrompt, workspaceRoot: WORKSPACE_ROOT, submittedAt: CAPTURE_TIMESTAMP });
  assertTerminal(credentialResult, "compiled", "safe-bugfix");
  const credentialProduct = join(productRoot, "credential-shaped-replay-pack");
  api.writeCompilePack(credentialResult, credentialProduct);
  assertExactFiles(credentialProduct, COMPILED_PACK_MEMBERS, "credential-shaped-replay-pack");
  assertCompilePackManifestHashes(credentialProduct, true);
  const credentialFixture = join(out, "credential-shaped-replay-pack");
  copyRawTree(credentialProduct, credentialFixture);
  const expectedCredentialOccurrences: Record<string, number> = {
    "catalog-resolution.json": 0,
    "compilation-record.json": 1,
    "compile-report.md": 1,
    "generated.loop.yaml": 1,
    "intake-record.json": 2,
    "pack-manifest.json": 0,
    "work-item.json": 1,
  };
  const credentialOccurrences: Record<string, number> = {};
  for (const path of relativeFiles(credentialFixture)) {
    const count = countUtf8Occurrences(join(credentialFixture, path), credentialCandidate);
    assert(count === expectedCredentialOccurrences[path], `synthetic credential occurrence count drifted for ${path}`);
    credentialOccurrences[path] = count;
  }
  assert(
    JSON.stringify(utf8Sort(Object.keys(credentialOccurrences))) === JSON.stringify(utf8Sort(Object.keys(expectedCredentialOccurrences))),
    "synthetic credential path/count multiset drifted",
  );
  writeCaseProvenance(out, "credential-shaped-replay-pack", filesUnder(out, "credential-shaped-replay-pack"), {
    ...baseMetadata,
    case: "credential-shaped-replay-pack",
    credential_detection: {
      rule_id: CREDENTIAL_RULE_ID,
      candidate_sha256: CREDENTIAL_DIGEST,
      candidate_byte_length: CREDENTIAL_BYTE_LENGTH,
      occurrences: credentialOccurrences,
    },
    expected_terminal: "compiled",
    api_entrypoints: ["compilePrompt", "writeCompilePack"],
  });

  const paddedPrompt = (padding: string): string => `${SAFE_PROMPT} ${padding}`;
  const largeCompiled = fitAsciiPadding((padding) => {
    const result = api.compilePrompt({
      prompt: paddedPrompt(padding),
      workspaceRoot: WORKSPACE_ROOT,
      submittedAt: CAPTURE_TIMESTAMP,
    });
    assertTerminal(result, "compiled", "safe-bugfix");
    return jsonText(result.work_item);
  }, TARGET_OVERSIZED_BYTES);
  const largePrompt = paddedPrompt(largeCompiled.padding);
  const largeCompileResult = api.compilePrompt({ prompt: largePrompt, workspaceRoot: WORKSPACE_ROOT, submittedAt: CAPTURE_TIMESTAMP });
  assertTerminal(largeCompileResult, "compiled", "safe-bugfix");
  const largeCompileProduct = join(productRoot, "large-compiled-pack");
  api.writeCompilePack(largeCompileResult, largeCompileProduct);
  assertExactFiles(largeCompileProduct, COMPILED_PACK_MEMBERS, "large-compiled-pack");
  assertCompilePackManifestHashes(largeCompileProduct, true);
  const largeCompileOversizedMembers = [
    "compilation-record.json",
    "compile-report.md",
    "generated.loop.yaml",
    "intake-record.json",
    "work-item.json",
  ];
  assertOversizedMembers(largeCompileProduct, largeCompileOversizedMembers, "work-item.json");
  const largeCompileFixture = join(out, "large-compiled-pack");
  copyRawTree(largeCompileProduct, largeCompileFixture);
  assertOversizedMembers(largeCompileFixture, largeCompileOversizedMembers, "work-item.json");
  writeCaseProvenance(out, "large-compiled-pack", filesUnder(out, "large-compiled-pack"), {
    ...baseMetadata,
    case: "large-compiled-pack",
    target_member: "work-item.json",
    target_byte_length: TARGET_OVERSIZED_BYTES,
    padding_byte_length: Buffer.byteLength(largeCompiled.padding),
    expected_terminal: "compiled",
    selected_item_id: "safe-bugfix",
    api_entrypoints: ["compilePrompt", "writeCompilePack"],
  });

  const planSourceResult = api.compilePrompt({
    prompt: SAFE_PROMPT,
    workspaceRoot: PLAN_WORKSPACE_ROOT,
    submittedAt: CAPTURE_TIMESTAMP,
  });
  assertTerminal(planSourceResult, "compiled", "safe-bugfix");
  const planSourceProduct = join(productRoot, "planned-run-source-pack");
  api.writeCompilePack(planSourceResult, planSourceProduct);
  assertExactFiles(planSourceProduct, COMPILED_PACK_MEMBERS, "planned-run-source-pack");
  assertCompilePackManifestHashes(planSourceProduct, true);
  const planSourceFixture = join(out, "planned-run-source-pack");
  copyRawTree(planSourceProduct, planSourceFixture);
  writeCaseProvenance(out, "planned-run-source-pack", filesUnder(out, "planned-run-source-pack"), {
    ...baseMetadata,
    case: "planned-run-source-pack",
    inputs: { prompt: SAFE_PROMPT, workspace_root: PLAN_WORKSPACE_ROOT, submitted_at: CAPTURE_TIMESTAMP },
    expected_terminal: "compiled",
    api_entrypoints: ["compilePrompt", "writeCompilePack"],
  });

  planRoot = createMarkedRoot(PLAN_WORKSPACE_ROOT, captureRunId);
  const planCompilationId = planSourceResult.compilation?.compilation_id;
  assert(typeof planCompilationId === "string", "planned-run source has no compilation ID");
  const planRunId = `run_${planCompilationId.startsWith("compilation_") ? planCompilationId.slice("compilation_".length) : planCompilationId.replace(/^[a-z]+_/, "")}`;
  const basePlanDirectories = [
    ".loopeix",
    ".loopeix/loops",
    ".loopeix/loops/minimal-bugfix",
    ".loopeix/loops/minimal-bugfix/runs",
  ];
  const planRunRelativeRoot = `.loopeix/loops/minimal-bugfix/runs/${planRunId}`;
  const planRowFiles = [
    `${planRunRelativeRoot}/work-item.json`,
    `${planRunRelativeRoot}/intake-record.json`,
    `${planRunRelativeRoot}/catalog-resolution.json`,
    `${planRunRelativeRoot}/pack-manifest.json`,
    `${planRunRelativeRoot}/compilation-record.json`,
    `${planRunRelativeRoot}/intake-brief.json`,
    `${planRunRelativeRoot}/resolved-run-plan.json`,
    `${planRunRelativeRoot}/generated.loop.yaml`,
  ];
  allowMarkedRootMembers(
    planRoot,
    planRowFiles,
    [...basePlanDirectories, planRunRelativeRoot],
  );
  const planRows: Array<{ name: string; engine: "codex" | "claude"; createdAt: string }> = [
    { name: "codex-20260710T000100Z", engine: "codex", createdAt: "2026-07-10T00:01:00Z" },
    { name: "codex-20260710T000200Z", engine: "codex", createdAt: "2026-07-10T00:02:00Z" },
    { name: "claude-20260710T000100Z", engine: "claude", createdAt: "2026-07-10T00:01:00Z" },
    { name: "claude-20260710T000200Z", engine: "claude", createdAt: "2026-07-10T00:02:00Z" },
  ];
  let firstResolvedPlan: JsonObject | undefined;
  const planOracleRoot = join(out, "planned-run-oracles");
  mkdirSync(planOracleRoot);
  for (const row of planRows) {
    const planned = api.planRunFromCompilePack({
      packDir: planSourceProduct,
      workspaceRoot: PLAN_WORKSPACE_ROOT,
      engine: row.engine,
      approved: true,
      createdAt: row.createdAt,
    });
    assert(planned.ok && planned.terminal_state === "planned" && planned.paths !== undefined && planned.run_dir !== undefined, `planning failed for ${row.name}`);
    const rowDir = join(planOracleRoot, row.name);
    mkdirSync(rowDir);
    const intakeBytes = readFileSync(planned.paths.intake_brief!);
    const planBytes = readFileSync(planned.paths.resolved_run_plan!);
    writeFileSync(join(rowDir, "intake-brief.json"), intakeBytes, { flag: "wx" });
    writeFileSync(join(rowDir, "resolved-run-plan.json"), planBytes, { flag: "wx" });
    firstResolvedPlan ??= JSON.parse(planBytes.toString("utf8")) as JsonObject;
    writeCaseProvenance(out, `planned-run-oracles/${row.name}`, filesUnder(out, `planned-run-oracles/${row.name}`), {
      ...baseMetadata,
      case: row.name,
      source_pack_root_sha256: rawFileSha256(join(out, "provenance", "planned-run-source-pack", "SHA256SUMS")),
      inputs: {
        prompt: SAFE_PROMPT,
        workspace_root: PLAN_WORKSPACE_ROOT,
        engine: row.engine,
        approved: true,
        created_at: row.createdAt,
      },
      outputs: {
        intake_brief: { byte_length: intakeBytes.byteLength, sha256: rawSha256(intakeBytes) },
        resolved_run_plan: { byte_length: planBytes.byteLength, sha256: rawSha256(planBytes) },
      },
      api_entrypoint: "planRunFromCompilePack",
    });
    const expectedRunRoot = join(PLAN_WORKSPACE_ROOT, ".loopeix", "loops", "minimal-bugfix", "runs");
    assert(planned.run_id !== undefined, `planner returned no run ID for ${row.name}`);
    assert(planned.run_id === planRunId, `planner returned an unexpected run ID for ${row.name}`);
    const expectedRunDir = join(expectedRunRoot, planned.run_id);
    assert(resolve(planned.run_dir) === resolve(expectedRunDir), "planner returned an unexpected run path");
    const runRelativeRoot = planRunRelativeRoot;
    const expectedPlannedPaths = {
      work_item: join(expectedRunDir, "work-item.json"),
      intake: join(expectedRunDir, "intake-record.json"),
      catalog_resolution: join(expectedRunDir, "catalog-resolution.json"),
      pack_manifest: join(expectedRunDir, "pack-manifest.json"),
      compilation: join(expectedRunDir, "compilation-record.json"),
      intake_brief: join(expectedRunDir, "intake-brief.json"),
      resolved_run_plan: join(expectedRunDir, "resolved-run-plan.json"),
      generated_loop: join(expectedRunDir, "generated.loop.yaml"),
    };
    for (const [key, expectedPath] of Object.entries(expectedPlannedPaths)) {
      assert(planned.paths[key as keyof typeof expectedPlannedPaths] === expectedPath, `planner returned an unexpected ${key} path`);
    }
    const rowFiles = planRowFiles;
    assertMarkedTree(planRoot, [MARKER_NAME, ...rowFiles], [...basePlanDirectories, runRelativeRoot]);
    unlinkKnownFiles(planRoot, rowFiles);
    removeKnownDirectories(planRoot, [runRelativeRoot]);
    assertMarkedTree(planRoot, [MARKER_NAME], basePlanDirectories);
  }
  assertMarkedTree(planRoot, [MARKER_NAME], [
    ".loopeix",
    ".loopeix/loops",
    ".loopeix/loops/minimal-bugfix",
    ".loopeix/loops/minimal-bugfix/runs",
  ]);
  removeKnownDirectories(planRoot, [
    ".loopeix/loops/minimal-bugfix/runs",
    ".loopeix/loops/minimal-bugfix",
    ".loopeix/loops",
    ".loopeix",
  ]);
  unlinkKnownFiles(planRoot, [MARKER_NAME]);
  rmdirSync(planRoot.root);
  planRoot = null;
  assert(firstResolvedPlan !== undefined, "planned-run oracle matrix produced no plan");

  const largePlan = fitAsciiPadding((padding) => {
    const candidate = structuredClone(firstResolvedPlan!);
    const context = candidate.context_snapshot;
    assert(typeof context === "object" && context !== null && !Array.isArray(context), "baseline plan context_snapshot is not an object");
    (context as JsonObject).padding = padding;
    api.ResolvedRunPlan.parse(candidate);
    return jsonText(candidate);
  }, TARGET_OVERSIZED_BYTES);
  const largePlanFixture = join(out, "large-profileless-plan");
  mkdirSync(largePlanFixture);
  writeFileSync(join(largePlanFixture, "resolved-run-plan.json"), largePlan.text, { flag: "wx" });
  assertOversizedMembers(largePlanFixture, ["resolved-run-plan.json"], "resolved-run-plan.json");
  writeCaseProvenance(out, "large-profileless-plan", filesUnder(out, "large-profileless-plan"), {
    ...baseMetadata,
    case: "large-profileless-plan",
    target_member: "resolved-run-plan.json",
    target_byte_length: TARGET_OVERSIZED_BYTES,
    padding_location: "/context_snapshot/padding",
    padding_byte_length: Buffer.byteLength(largePlan.padding),
    bounded_io_profile_present: false,
    parser: "ResolvedRunPlan.parse",
  });

  const sealLedger = (padding: string, runId: string): SealedLedgerEvent[] => {
    const events: SealedLedgerEvent[] = [];
    const drafts = [
      { event_type: "run.started", payload: {} },
      { event_type: "command", payload: { command: "pnpm test", exit_code: 0, padding } },
      { event_type: "run.completed", payload: {} },
    ] as const;
    for (const [index, item] of drafts.entries()) {
      const draft: LedgerEventDraft = {
        schema_version: "0.1",
        event_id: `evt_${String(index + 1).padStart(4, "0")}`,
        run_id: runId,
        timestamp: `2026-07-09T12:00:0${index}Z`,
        event_type: item.event_type,
        source: "loopeix",
        actor_id: null,
        task_run_id: null,
        risk_tier: "T1",
        payload: item.payload,
        related_ids: [],
      };
      events.push(api.appendToLedger(events, draft));
    }
    return events;
  };
  const largeLedger = fitAsciiPadding(
    (padding) => api.serializeLedger(sealLedger(padding, "run_s35_large_ledger")),
    TARGET_OVERSIZED_BYTES,
  );
  const parsedLargeLedger = api.parseLedgerText(largeLedger.text);
  const recoveredLargeLedger = api.recoverLedger(parsedLargeLedger.events, {
    partialFinalLineDropped: parsedLargeLedger.partialFinalLineDropped,
    corruptLines: parsedLargeLedger.corruptLines,
  });
  assert(recoveredLargeLedger.run_state === "completed" && recoveredLargeLedger.integrity_status === "valid", "large ledger did not recover as completed/valid");
  const largeLedgerFixture = join(out, "large-ledger");
  mkdirSync(largeLedgerFixture);
  writeFileSync(join(largeLedgerFixture, "ledger.jsonl"), largeLedger.text, { flag: "wx" });
  assertOversizedMembers(largeLedgerFixture, ["ledger.jsonl"], "ledger.jsonl");
  writeCaseProvenance(out, "large-ledger", filesUnder(out, "large-ledger"), {
    ...baseMetadata,
    case: "large-ledger",
    target_member: "ledger.jsonl",
    target_byte_length: TARGET_OVERSIZED_BYTES,
    padding_location: "event_type=command/payload/padding",
    expected_run_state: "completed",
    expected_integrity_status: "valid",
    api_entrypoints: ["appendToLedger", "serializeLedger", "parseLedgerText", "recoverLedger"],
  });

  const runRecoverCases: readonly RunRecoverCase[] = [
    {
      name: "empty",
      ledgerBytes: Buffer.alloc(0),
      expectedExit: 0,
      expectedStdout: { human: RUN_RECOVER_VALID_HUMAN_STDOUT, json: RUN_RECOVER_VALID_JSON_STDOUT },
    },
    {
      name: "blank-only",
      ledgerBytes: Buffer.from("\n  \n", "utf8"),
      expectedExit: 0,
      expectedStdout: { human: RUN_RECOVER_VALID_HUMAN_STDOUT, json: RUN_RECOVER_VALID_JSON_STDOUT },
    },
    {
      name: "partial-only",
      ledgerBytes: Buffer.from('{"incomplete":', "utf8"),
      expectedExit: 4,
      expectedStdout: { human: RUN_RECOVER_PARTIAL_HUMAN_STDOUT, json: RUN_RECOVER_PARTIAL_JSON_STDOUT },
    },
  ];
  assert(
    JSON.stringify(runRecoverCases.map((item) => item.name)) === JSON.stringify(RUN_RECOVER_CASE_NAMES),
    "run recover case order drifted",
  );
  assert(JSON.stringify(runRecoverCases.map((item) => item.expectedExit)) === "[0,0,4]", "run recover expected exits drifted");
  const runRecoverCliPath = join(sourceRoot, "bin", "dev.js");
  const runRecoverCliHashBefore = rawFileSha256(runRecoverCliPath);
  const runRecoverOracleRoot = join(out, RUN_RECOVER_ORACLE_ROOT);
  mkdirSync(runRecoverOracleRoot);
  for (const item of runRecoverCases) {
    const casePath = `${RUN_RECOVER_ORACLE_ROOT}/${item.name}`;
    const caseRoot = join(out, casePath);
    mkdirSync(caseRoot);
    const ledgerPath = join(caseRoot, "ledger.jsonl");
    writeExactBytes(ledgerPath, item.ledgerBytes);
    const inputHash = rawFileSha256(ledgerPath);
    const modeMetadata: Record<string, JsonObject> = {};
    for (const mode of RUN_RECOVER_MODES) {
      const invocation = invokeRunRecoverCli(sourceRoot, ledgerPath, mode);
      const expectedStdout = Buffer.from(item.expectedStdout[mode], "utf8");
      const expectedStderr = Buffer.alloc(0);
      assert(invocation.exit === item.expectedExit, `${item.name}/${mode} exit drifted: ${invocation.exit}`);
      assertExactBytes(invocation.stdout, expectedStdout, `${item.name}/${mode} stdout`);
      assertExactBytes(invocation.stderr, expectedStderr, `${item.name}/${mode} stderr`);
      assertExactBytes(readFileSync(ledgerPath), item.ledgerBytes, `${item.name}/${mode} ledger input`);
      writeExactBytes(join(caseRoot, `${mode}.stdout`), invocation.stdout);
      writeExactBytes(join(caseRoot, `${mode}.stderr`), invocation.stderr);
      const exitBytes = Buffer.from(`${invocation.exit}\n`, "ascii");
      writeExactBytes(join(caseRoot, `${mode}.exit`), exitBytes);
      modeMetadata[mode] = {
        args: invocation.args,
        exit: invocation.exit,
        stdout: { byte_length: invocation.stdout.byteLength, sha256: rawSha256(invocation.stdout) },
        stderr: { byte_length: invocation.stderr.byteLength, sha256: rawSha256(invocation.stderr) },
      };
    }
    assertExactFiles(caseRoot, RUN_RECOVER_RAW_MEMBERS, casePath);
    writeCaseProvenance(out, casePath, filesUnder(out, casePath), {
      ...baseMetadata,
      case: item.name,
      stage_subtree: RUN_RECOVER_ORACLE_ROOT,
      expected_complete_event_count: 0,
      input: {
        path: `${casePath}/ledger.jsonl`,
        byte_length: item.ledgerBytes.byteLength,
        sha256: inputHash,
      },
      cli: {
        entrypoint: runRecoverCliPath,
        entrypoint_sha256: runRecoverCliHashBefore,
        command_id: "run recover",
        cwd: sourceRoot,
      },
      modes: modeMetadata,
    });
  }
  assertExactFiles(
    runRecoverOracleRoot,
    RUN_RECOVER_CASE_NAMES.flatMap((caseName) => RUN_RECOVER_RAW_MEMBERS.map((member) => `${caseName}/${member}`)),
    RUN_RECOVER_ORACLE_ROOT,
  );
  assert(rawFileSha256(runRecoverCliPath) === runRecoverCliHashBefore, "detached baseline bin/dev.js changed during run recover capture");

  const reportProduct = join(productRoot, "large-report-input-run");
  const reportAssembly = api.assembleRun({
    run_id: "run_s35_large_report",
    loop_family: "minimal-bugfix",
    loopeix_version: "v001",
    started_at: "2026-07-09T12:00:00Z",
    engine: "codex_cli",
    events: [],
    capture_gaps: [{ capability: "shell_command_execution", level: "partial", note: "x" }],
    gates: [],
    risk_controls: { max_tier_without_approval: "T2", t5_allowed: false },
  });
  assert(
    JSON.stringify(reportAssembly.manifest.schema_versions) === "{}",
    "baseline run manifest schema_versions drifted from the measured empty object",
  );
  api.writeRunDir(reportProduct, reportAssembly);
  const largeReportInput = fitAsciiPadding((padding) => {
    const input = structuredClone(reportAssembly.report_input);
    const gaps = input.capture_gaps;
    assert(Array.isArray(gaps) && typeof gaps[0] === "object" && gaps[0] !== null, "report capture gap is absent");
    (gaps[0] as JsonObject).note = padding;
    return jsonText(input);
  }, TARGET_OVERSIZED_BYTES);
  writeFileSync(join(reportProduct, "report-input.json"), largeReportInput.text);
  const rebuiltReport = api.buildReportFromRunDir(reportProduct);
  assert(rebuiltReport.markdown.includes("## Verified claims"), "baseline report rebuild failed");
  const largeReportFixture = join(out, "large-report-input");
  copyRawTree(reportProduct, largeReportFixture);
  assertOversizedMembers(largeReportFixture, ["report-input.json", "report.md"], "report-input.json");
  writeCaseProvenance(out, "large-report-input", filesUnder(out, "large-report-input"), {
    ...baseMetadata,
    case: "large-report-input",
    target_member: "report-input.json",
    target_byte_length: TARGET_OVERSIZED_BYTES,
    padding_location: "/capture_gaps/0/note",
    expected_run_state: "completed",
    expected_integrity_status: "valid",
    api_entrypoints: ["assembleRun", "writeRunDir", "buildReportFromRunDir"],
  });

  const receiptPrivateKeyPem = fixedCaptureOnlyPrivateKeyPem();
  const receiptLedger = sealLedger("", "run_s35_large_receipt");
  const receiptLedgerText = api.serializeLedger(receiptLedger);
  assert(Buffer.byteLength(receiptLedgerText) < IN_PROCESS_LIMIT_BYTES, "receipt ledger unexpectedly reaches the in-process ceiling");
  const parsedReceiptLedger = api.parseLedgerText(receiptLedgerText);
  const recoveredReceiptLedger = api.recoverLedger(parsedReceiptLedger.events, {
    partialFinalLineDropped: parsedReceiptLedger.partialFinalLineDropped,
    corruptLines: parsedReceiptLedger.corruptLines,
  });
  assert(recoveredReceiptLedger.run_state === "completed" && recoveredReceiptLedger.integrity_status === "valid", "receipt ledger did not recover as completed/valid");
  const receiptInput = (note: string): ReceiptInput => ({
    run: {
      run_id: "run_s35_large_receipt",
      loop_family: "minimal-bugfix",
      loopeix_version: "v001",
      engine: "codex_cli",
      sealed_at: "2026-07-09T12:01:00Z",
    },
    brief: {
      task: "capture an oversized V01 receipt oracle",
      acceptance: [{ id: "tests-pass", label: "all tests pass", kind: "tests-pass" }],
      forbidden: [{ id: "no-test-deletion", label: "deleting tests", kind: "delete_paths", globs: ["tests/**"] }],
      scope: ["src/**"],
    },
    claims: [{ claim_id: "claim_tests_ran", family: "tests-ran", text: "tests pass", verdict: "VERIFIED", evidence_ids: ["ev_001"] }],
    brief_clauses: [{ clause_id: "clause_acceptance", clause_type: "acceptance", text: "all tests pass", verdict: "KEPT", evidence_ids: ["ev_001"] }],
    evidence: [{ evidence_id: "ev_001", type: "command", sha256: `sha256:${rawSha256("pnpm test exit 0")}`, capture_level: "full", source: "wrapper" }],
    capture_gaps: [{ engine: "codex_cli", capability: "shell_command_execution", level: "partial", note }],
    ledger: receiptLedger,
  });
  const baseReceiptText = jsonText(api.buildReceipt(receiptInput(""), receiptPrivateKeyPem));
  const nominalReceiptPadding = TARGET_OVERSIZED_BYTES - Buffer.byteLength(baseReceiptText);
  assert(nominalReceiptPadding > 0, "receipt base is already oversized");
  let receiptText: string | undefined;
  for (let attempt = 0; attempt < 512; attempt += 1) {
    const offset = attempt % 33 - 16;
    const paddingLength = nominalReceiptPadding + offset;
    if (paddingLength < 0) continue;
    const candidate = jsonText(api.buildReceipt(receiptInput("x".repeat(paddingLength)), receiptPrivateKeyPem));
    if (Buffer.byteLength(candidate) === TARGET_OVERSIZED_BYTES) {
      receiptText = candidate;
      break;
    }
  }
  assert(receiptText !== undefined, "receipt did not reach the exact target within 512 signing attempts");
  const receiptVerification = api.verifyReceipt(receiptText, { ledgerText: receiptLedgerText });
  assert(receiptVerification.ok && receiptVerification.checks.every((check) => check.ok), "captured oversized receipt failed full verification");
  const receiptObject = JSON.parse(receiptText) as { signature?: { public_key_spki_b64?: unknown } };
  assert(typeof receiptObject.signature?.public_key_spki_b64 === "string", "captured receipt has no public key");
  const largeReceiptFixture = join(out, "large-receipt");
  mkdirSync(largeReceiptFixture);
  writeFileSync(join(largeReceiptFixture, "receipt.json"), receiptText, { flag: "wx" });
  writeFileSync(join(largeReceiptFixture, "ledger.jsonl"), receiptLedgerText, { flag: "wx" });
  writeFileSync(join(largeReceiptFixture, "public-key-spki.b64"), `${receiptObject.signature.public_key_spki_b64}\n`, { flag: "wx" });
  assertOversizedMembers(largeReceiptFixture, ["receipt.json"], "receipt.json");
  writeCaseProvenance(out, "large-receipt", filesUnder(out, "large-receipt"), {
    ...baseMetadata,
    case: "large-receipt",
    target_member: "receipt.json",
    target_byte_length: TARGET_OVERSIZED_BYTES,
    padding_location: "/capture_gaps/0/note",
    paired_ledger_byte_length: Buffer.byteLength(receiptLedgerText),
    signing_key_policy: "fixed non-secret capture-only P-256 scalar 1 reused for the bounded search; private key never persisted",
    key_derivation_node_api: ["createECDH", "createPrivateKey"],
    max_signing_attempts: 512,
    verification_checks: receiptVerification.checks.map((check) => check.id),
    api_entrypoints: [
      "appendToLedger",
      "serializeLedger",
      "parseLedgerText",
      "recoverLedger",
      "buildReceipt",
      "verifyReceipt",
    ],
  });

  const commandLine = [
    `"${cleanLauncherPath}"`,
    "node",
    `"${launcherPath}"`,
    `--driver "${driverPath}"`,
    `--source-root "${reviewedOriginRoot}"`,
    `--out "${requestedOut}"`,
    `--assert-base-commit ${BASE_COMMIT}`,
  ].join(" ");
  writeJson(join(out, "capture-metadata.json"), {
    ...baseMetadata,
    requested_staging_root: requestedOut,
    canonical_staging_root: out,
    staging_parent_identity: stagingParentIdentity,
    staging_root_identity: stagingRootIdentity,
    source_identity: sourceIdentity,
    execution_source_identity: executionSourceIdentity,
    external_drivers: {
      v01_oracle_launcher: { path: launcherPath, sha256: launcherHashBefore },
      v01_oracle_capture: { path: driverPath, sha256: driverHashBefore },
      package_oracle_capture: { path: packageDriverPath, sha256: packageDriverHashBefore },
      clean_process_launcher: { path: cleanLauncherPath, sha256: cleanLauncherHashBefore },
    },
    catalog_version_hash: CATALOG_HASH,
    common_inputs: { workspace_root: WORKSPACE_ROOT, submitted_at: CAPTURE_TIMESTAMP },
    planned_run_workspace_root: PLAN_WORKSPACE_ROOT,
    explicit_destination_root: EXPLICIT_DESTINATION_ROOT,
    oversized_target_bytes: TARGET_OVERSIZED_BYTES,
    run_recover_zero_complete_event_oracles: {
      stage_subtree: RUN_RECOVER_ORACLE_ROOT,
      case_order: RUN_RECOVER_CASE_NAMES,
      expected_exit_by_case: Object.fromEntries(runRecoverCases.map((item) => [item.name, item.expectedExit])),
      modes: RUN_RECOVER_MODES,
      raw_members_per_case: RUN_RECOVER_RAW_MEMBERS,
      cli_entrypoint: { relative_path: "bin/dev.js", sha256: runRecoverCliHashBefore },
    },
    command: commandLine,
    api_entrypoints: [
      "compilePrompt", "writeCompilePack", "Compile.run", "planRunFromCompilePack",
      "ResolvedRunPlan.parse", "appendToLedger", "serializeLedger", "parseLedgerText",
      "recoverLedger", "assembleRun", "writeRunDir", "buildReportFromRunDir",
      "buildReceipt", "verifyReceipt",
    ],
    cli_entrypoints: ["bin/dev.js run recover", "bin/dev.js run recover --json"],
    capture_support_entrypoints: ["createECDH", "createPrivateKey"],
  });
  writeFileSync(join(out, "README.md"), [
    "# S35 Frozen V01 Compatibility Oracles",
    "",
    `Captured from clean detached implementation commit \`${BASE_COMMIT}\`.`,
    `Toolchain: Node \`${nodeVersion}\`, pnpm \`${pnpmVersion}\`, YAML \`${String(yamlPackage.version)}\`.`,
    `Reviewed source root: \`${reviewedOriginRoot}\`.`,
    `Private execution source: \`${sourceRoot}\` (tree SHA-256 \`${sourceSnapshotSha256}\`).`,
    `Staging root: \`${out}\`.`,
    `V01 capture driver: \`${driverPath}\` (SHA-256 \`${driverHashBefore}\`).`,
    `Package capture driver: \`${packageDriverPath}\` (SHA-256 \`${packageDriverHashBefore}\`).`,
    `Clean process launcher: \`${cleanLauncherPath}\` (SHA-256 \`${cleanLauncherHashBefore}\`).`,
    "",
    "Oracle directories contain only their declared raw input/output members. Provenance lives separately under",
    "provenance/. Tests must read committed bytes directly and never regenerate expected",
    "output with the compiler under test.",
    "The credential-shaped case deliberately omits its prompt from metadata and documentation.",
    `The ${RUN_RECOVER_ORACLE_ROOT}/ subtree freezes detached baseline bin/dev.js run recover output.`,
    `Cases: ${RUN_RECOVER_CASE_NAMES.join(", ")}.`,
    `Each case contains: ${RUN_RECOVER_RAW_MEMBERS.join(", ")}.`,
    "Human and --json stdout, stderr, and integer exit files are captured without byte normalization.",
    "",
    "Capture command:",
    "",
    "```text",
    commandLine,
    "```",
    "",
  ].join("\n"), { flag: "wx" });
  assert(!existsSync(join(out, "SHA256SUMS")), "TypeScript driver must not finalize the fixture-root checksum");

  const expectedStageCredentialOccurrences: Record<string, number> = {};
  for (const [path, count] of Object.entries(expectedCredentialOccurrences)) {
    expectedStageCredentialOccurrences[`credential-shaped-replay-pack/${path}`] = count;
  }
  const actualStageCredentialOccurrences: Record<string, number> = {};
  for (const path of relativeFiles(out)) {
    const count = countUtf8Occurrences(join(out, path), credentialCandidate);
    if (count > 0) actualStageCredentialOccurrences[path] = count;
  }
  const expectedPositiveCredentialOccurrences = Object.fromEntries(
    Object.entries(expectedStageCredentialOccurrences).filter(([, count]) => count > 0),
  );
  assert(
    JSON.stringify(actualStageCredentialOccurrences) === JSON.stringify(expectedPositiveCredentialOccurrences),
    "synthetic credential escaped its frozen raw-pack path/count multiset",
  );

  const expectedOversizedPaths = utf8Sort([
    "large-compiled-pack/compilation-record.json",
    "large-compiled-pack/compile-report.md",
    "large-compiled-pack/generated.loop.yaml",
    "large-compiled-pack/intake-record.json",
    "large-compiled-pack/work-item.json",
    "large-ledger/ledger.jsonl",
    "large-profileless-plan/resolved-run-plan.json",
    "large-receipt/receipt.json",
    "large-report-input/report-input.json",
    "large-report-input/report.md",
  ]);
  const actualOversizedPaths = relativeFiles(out).filter((path) => statSync(join(out, path)).size >= IN_PROCESS_LIMIT_BYTES);
  assert(JSON.stringify(actualOversizedPaths) === JSON.stringify(expectedOversizedPaths), "the five-family oversized member inventory drifted");
  for (const path of [
    "large-compiled-pack/work-item.json",
    "large-ledger/ledger.jsonl",
    "large-profileless-plan/resolved-run-plan.json",
    "large-receipt/receipt.json",
    "large-report-input/report-input.json",
  ]) assert(statSync(join(out, path)).size === TARGET_OVERSIZED_BYTES, `${path} has the wrong target byte length`);

  const provenanceChecksumPaths = relativeFiles(join(out, "provenance"))
    .filter((path) => path.endsWith("/SHA256SUMS") || path === "SHA256SUMS");
  for (const checksumPath of provenanceChecksumPaths) {
    const casePath = checksumPath === "SHA256SUMS" ? "" : checksumPath.slice(0, -"/SHA256SUMS".length);
    assert(casePath !== "", "root provenance checksum is not a case checksum");
    verifyCaseProvenance(out, casePath);
  }

  const driverHashAfter = rawFileSha256(driverPath);
  assert(driverHashAfter === driverHashBefore, "driver changed during capture");
  assert(
    rawFileSha256(admittedDriverPath) === driverHashBefore,
    "admitted V01 capture driver changed during capture",
  );
  assert(rawFileSha256(launcherPath) === launcherHashBefore, "V01 capture launcher changed during capture");
  assert(rawFileSha256(packageDriverPath) === packageDriverHashBefore, "package-oracle driver changed during capture");
  assert(rawFileSha256(cleanLauncherPath) === cleanLauncherHashBefore, "clean process launcher changed during capture");
  const tsxRuntimeAfter = captureTsxRuntimeIdentity(sourceRoot);
  assert(JSON.stringify(tsxRuntimeAfter) === JSON.stringify(tsxRuntime), "capture runtime changed during capture");
  assertDetachedSourceSnapshot(sourceRoot, executionSourceIdentity);
  assertDetachedSourceSnapshot(reviewedOriginRoot, sourceIdentity);
  assertSameIdentity(stagingParent, stagingParentIdentity, "staging parent");
  assertSameIdentity(out, stagingRootIdentity, "staging root");
  } catch (error) {
    captureFailure = { error };
    throw error;
  } finally {
    runPrivateCleanupActions(
      captureFailure,
      [
        () => removeOwnedMarkedRoot(planRoot),
        () => removeOwnedMarkedRoot(explicitRoot),
        () => rmSync(productRoot, { recursive: true, force: true }),
      ],
      "V01 capture failed and private product cleanup was incomplete",
    );
  }
  process.stdout.write(`Captured frozen V01 oracles at ${out}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
