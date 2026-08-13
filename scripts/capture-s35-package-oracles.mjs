import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import {
  assertSourceSnapshot,
  materializeSourceSnapshot,
  removeSourceSnapshot,
} from "./launch-v01-oracles-s35.mjs";

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
  tar: Object.freeze({
    path: "/usr/bin/bsdtar",
    sha256: "9ab7f0793033dc9dc4809d83d695118801bd687cbacda59a0cbbf151ba25dc2b",
  }),
});
const PACKAGE_EXPORTS_FILE = "package-root-runtime-exports.txt";
const PACKAGE_TYPE_EXPORTS_FILE = "package-root-type-exports.txt";
const PACKED_PATHS_FILE = "packed-paths.txt";
const BASELINE_COMMAND_SNAPSHOT_FILE = "baseline-command-snapshot.json";
const BASELINE_OCLIF_MANIFEST_FILE = "baseline-oclif-manifest.normalized.json";
const PACKAGE_METADATA_FILE = "package-oracle-metadata.json";
const ROOT_CHECKSUM_FILE = "SHA256SUMS";
const NORMALIZED_PACKAGE_MEMBER = "oclif.manifest.json";
const NORMALIZED_PACKAGE_PROOF_METHOD = "fresh-pack-normalized-content-equality-v1";
const IN_PROCESS_LIMIT_BYTES = 4_194_304;
const MAX_COMPRESSED_TAR_BYTES = 16_777_216;
const MAX_UNCOMPRESSED_TAR_BYTES = 67_108_864;
const TAR_COMMAND_MAX_OUTPUT_BYTES = 1_048_576;
const TAR_COMMAND_TIMEOUT_MS = 30_000;
const CHILD_PROCESS_MAX_OUTPUT_BYTES = 1_048_576;
const CHILD_PROCESS_TIMEOUT_MS = 300_000;
const PNPM_MODULES_METADATA_MAX_BYTES = 1_048_576;
const TAR_BLOCK_BYTES = 512;
const TAR_METADATA_PAYLOAD_TYPES = new Set(["g", "K", "L", "x"]);
const EXPECTED_RUNTIME_EXPORT_COUNT = 176;
const EXPECTED_TYPE_NAMESPACE_EXPORT_COUNT = 106;
const EXPECTED_TYPE_ONLY_EXPORT_COUNT = 93;
const EXPECTED_DUAL_NAMESPACE_EXPORT_COUNT = 13;
const EXPECTED_DISTINCT_ROOT_SYMBOL_COUNT = 269;
const EXPECTED_TYPESCRIPT_VERSION = "6.0.3";
const SOURCE_ROOT_SENTINEL = "<S35_BASELINE_SOURCE_ROOT>";
const BASELINE_SOURCE_ROOT_DEFAULTS = [
  {
    commandId: "compile",
    path: "commands.compile.flags.workspace-root.default",
  },
  {
    commandId: "run:plan",
    path: "commands.run:plan.flags.workspace-root.default",
  },
];
const EXPECTED_BASELINE_COMMAND_IDS = [
  "compile",
  "doctor",
  "init",
  "pr",
  "report:build",
  "report:open",
  "run:plan",
  "run:preflight",
  "run:prompt",
  "run:recover",
  "run:start",
  "run:status",
  "spec:inspect",
  "spec:validate",
  "verify",
];
const TARGET_OVERSIZED_BYTES = 4_196_413;
const EXPECTED_OVERSIZED_PATHS = [
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
];
const EXACT_TARGET_OVERSIZED_PATHS = [
  "large-compiled-pack/work-item.json",
  "large-ledger/ledger.jsonl",
  "large-profileless-plan/resolved-run-plan.json",
  "large-receipt/receipt.json",
  "large-report-input/report-input.json",
];
const COMPILED_PACK_MEMBERS = [
  "catalog-resolution.json",
  "compilation-record.json",
  "compile-report.md",
  "generated.loop.yaml",
  "intake-record.json",
  "pack-manifest.json",
  "work-item.json",
];
const HOLD_PACK_MEMBERS = [
  "catalog-resolution.json",
  "compile-report.md",
  "intake-record.json",
  "pack-manifest.json",
  "work-item.json",
];
const RUN_RECOVER_ORACLE_ROOT = "run-recover-zero-complete-event";
const RUN_RECOVER_CASE_NAMES = ["empty", "blank-only", "partial-only"];
const RUN_RECOVER_MODES = ["human", "json"];
const RUN_RECOVER_EXPECTED_EXITS = { empty: 0, "blank-only": 0, "partial-only": 4 };
const RUN_RECOVER_RAW_MEMBERS = [
  "human.exit",
  "human.stderr",
  "human.stdout",
  "json.exit",
  "json.stderr",
  "json.stdout",
  "ledger.jsonl",
];
const EXPECTED_PROVENANCE_CASES = [
  "compiled-explicit-destination",
  "compiled-safe-bugfix",
  "credential-shaped-replay-pack",
  "hold-ambiguous",
  "hold-no-item",
  "hold-risk",
  "large-compiled-pack",
  "large-ledger",
  "large-profileless-plan",
  "large-receipt",
  "large-report-input",
  "planned-run-oracles/claude-20260710T000100Z",
  "planned-run-oracles/claude-20260710T000200Z",
  "planned-run-oracles/codex-20260710T000100Z",
  "planned-run-oracles/codex-20260710T000200Z",
  "planned-run-source-pack",
  ...RUN_RECOVER_CASE_NAMES.map((caseName) => `${RUN_RECOVER_ORACLE_ROOT}/${caseName}`),
];
const EXPECTED_STAGE_TOP_LEVEL = [
  "README.md",
  "capture-metadata.json",
  "compiled-explicit-destination",
  "compiled-safe-bugfix",
  "credential-shaped-replay-pack",
  "hold-ambiguous",
  "hold-no-item",
  "hold-risk",
  "large-compiled-pack",
  "large-ledger",
  "large-profileless-plan",
  "large-receipt",
  "large-report-input",
  "planned-run-oracles",
  "planned-run-source-pack",
  "provenance",
  RUN_RECOVER_ORACLE_ROOT,
  "standalone",
];

function fail(message) {
  throw new Error(`S35 package oracle capture failed: ${message}`);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function assertTrustedExecutable(name) {
  const trusted = TRUSTED_EXECUTABLES[name];
  assert(trusted !== undefined, `child executable is not admitted: ${name}`);
  const executablePath =
    name === "node" ? process.execPath : name === "pnpm" ? admittedPnpmPath() : trusted.path;
  assert(
    isAbsolute(executablePath) && realpathSync(executablePath) === executablePath,
    `trusted ${name} executable is not canonical`,
  );
  const captured = readStableRegularFile(
    executablePath,
    `trusted ${name} executable`,
    MAX_COMPRESSED_TAR_BYTES,
    false,
  );
  try {
    assert(
      rawSha256(captured.bytes) === trusted.sha256,
      `trusted ${name} executable hash drifted`,
    );
  } finally {
    captured.bytes.fill(0);
  }
  return executablePath;
}

function admittedPnpmPath() {
  const admittedNodePath = realpathSync(process.execPath);
  const admittedNodeRoot = dirname(dirname(admittedNodePath));
  assert(
    basename(admittedNodeRoot) === "node",
    "package capture Node executable is outside the admitted runtime layout",
  );
  return join(dirname(admittedNodeRoot), "pnpm", "bin", "pnpm.mjs");
}

function trustedInvocation(commandName, args) {
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

function parseArgs(argv) {
  const allowed = new Set([
    "--source-root",
    "--tarball",
    "--out",
    "--assert-base-commit",
    "--tool-source-root",
    "--transactional-success-fd",
  ]);
  const required = new Set([
    "--source-root",
    "--tarball",
    "--out",
    "--assert-base-commit",
    "--tool-source-root",
  ]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    assert(flag !== undefined && value !== undefined, "arguments must be flag/value pairs");
    assert(allowed.has(flag), `unknown argument ${flag}`);
    assert(!values.has(flag), `duplicate argument ${flag}`);
    values.set(flag, value);
  }
  for (const flag of required) assert(values.has(flag), `${flag} is required`);
  const sourceRoot = values.get("--source-root");
  const tarball = values.get("--tarball");
  const out = values.get("--out");
  const assertedCommit = values.get("--assert-base-commit");
  const toolSourceRoot = values.get("--tool-source-root");
  const transactionalSuccessFdText =
    values.get("--transactional-success-fd") ?? "1";
  assert(
    isAbsolute(sourceRoot) &&
      isAbsolute(tarball) &&
      isAbsolute(out) &&
      isAbsolute(toolSourceRoot),
    "all paths must be absolute",
  );
  assert(
    transactionalSuccessFdText === "1" || transactionalSuccessFdText === "3",
    "transactional success descriptor must be 1 or 3",
  );
  return {
    sourceRoot: resolve(sourceRoot),
    tarball: resolve(tarball),
    out: resolve(out),
    assertedCommit,
    toolSourceRoot: resolve(toolSourceRoot),
    transactionalSuccessFd: Number(transactionalSuccessFdText),
  };
}

export function withProcessUmask(mask, operation) {
  assert(Number.isInteger(mask) && mask >= 0 && mask <= 0o777, "process umask is invalid");
  assert(typeof operation === "function", "process umask operation is invalid");
  const previous = process.umask(mask);
  try {
    return operation();
  } finally {
    process.umask(previous);
  }
}

function command(commandName, args, cwd, environment) {
  assert(environment !== undefined, `${commandName} child environment is not explicit`);
  if (commandName === "pnpm") {
    assert(
      JSON.stringify(Object.keys(environment).sort()) ===
        JSON.stringify(["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"]),
      "pnpm child environment is not restricted",
    );
    assert(
      realpathSync(environment.HOME) === realpathSync(cwd) &&
        environment.TMPDIR === environment.HOME,
      "pnpm child operational root is not bound to its working directory",
    );
  }
  const invocation = trustedInvocation(commandName, args);
  const canonicalCwd = canonicalCommandWorkingDirectory(cwd);
  const invoke = (commandEnvironment) =>
    execFileSync(invocation.executable, invocation.args, {
      cwd: canonicalCwd,
      encoding: "utf8",
      env: commandEnvironment,
      killSignal: "SIGKILL",
      maxBuffer: CHILD_PROCESS_MAX_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: CHILD_PROCESS_TIMEOUT_MS,
    }).trim();
  return commandName === "pnpm"
    ? withProcessUmask(0o022, () => withPrivateCommandTemporaryRoot(environment, invoke))
    : invoke(environment);
}

function assertOrdinaryIndexEntries(sourceRoot) {
  const taggedBytes = execFileSync(
    assertTrustedExecutable("git"),
    ["-C", sourceRoot, "ls-files", "--cached", "-v", "-z", "--"],
    {
      cwd: canonicalCommandWorkingDirectory(sourceRoot),
      encoding: "buffer",
      env: restrictedChildEnvironment(sourceRoot),
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
      cwd: canonicalCommandWorkingDirectory(sourceRoot),
      encoding: "buffer",
      env: restrictedChildEnvironment(sourceRoot),
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

function commandWithInput(commandName, args, input, cwd) {
  assert(Buffer.isBuffer(input), `${commandName} input must be retained bytes`);
  const invocation = trustedInvocation(commandName, args);
  const canonicalCwd = canonicalCommandWorkingDirectory(cwd);
  return execFileSync(invocation.executable, invocation.args, {
    cwd: canonicalCwd,
    env: restrictedChildEnvironment(canonicalCwd),
    input,
    encoding: "utf8",
    killSignal: "SIGKILL",
    maxBuffer: TAR_COMMAND_MAX_OUTPUT_BYTES,
    stdio: ["pipe", "pipe", "pipe"],
    timeout: TAR_COMMAND_TIMEOUT_MS,
  }).trim();
}

function rawSha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function rawFileSha256(path) {
  const captured = readStableRegularFile(
    path,
    `integrity input ${path}`,
    MAX_UNCOMPRESSED_TAR_BYTES,
    false,
  );
  try {
    return rawSha256(captured.bytes);
  } finally {
    captured.bytes.fill(0);
  }
}

function readStableRegularFile(
  path,
  label,
  maxBytes = MAX_UNCOMPRESSED_TAR_BYTES,
  requireSerializableIdentity = true,
) {
  const descriptor = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  let bytes = null;
  let result = null;
  let operationFailure = null;
  try {
    const before = fstatSync(descriptor, { bigint: true });
    assert(before.isFile() && !before.isSymbolicLink(), `${label} is not a regular file`);
    assert(
      before.size >= 0n && before.size <= BigInt(maxBytes),
      `${label} exceeds the ${maxBytes}-byte capture limit`,
    );
    const byteLength = Number(before.size);
    assert(Number.isSafeInteger(byteLength), `${label} size is not safely representable`);
    bytes = Buffer.alloc(byteLength);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, null);
      assert(count > 0, `${label} ended before its admitted size`);
      offset += count;
    }
    const extra = Buffer.alloc(1);
    try {
      assert(readSync(descriptor, extra, 0, 1, null) === 0, `${label} grew beyond its admitted size`);
    } finally {
      extra.fill(0);
    }
    const after = fstatSync(descriptor, { bigint: true });
    for (const field of ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]) {
      assert(before[field] === after[field], `${label} changed during capture`);
    }
    assert(after.size === BigInt(bytes.length), `${label} read was incomplete`);
    const named = lstatSync(path, { bigint: true });
    assert(named.isFile() && !named.isSymbolicLink(), `${label} path is not a regular file`);
    for (const field of ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]) {
      assert(after[field] === named[field], `${label} path identity changed`);
    }
    const dev = Number(after.dev);
    const ino = Number(after.ino);
    if (requireSerializableIdentity) {
      assert(
        Number.isSafeInteger(dev) && Number.isSafeInteger(ino),
        `${label} identity is not safely representable`,
      );
    }
    result = {
      bytes,
      identity: requireSerializableIdentity ? { dev, ino } : null,
    };
  } catch (error) {
    operationFailure = { error };
  }
  let closeFailure = null;
  try {
    closeSync(descriptor);
  } catch (error) {
    closeFailure = { error };
  }
  if (operationFailure !== null || closeFailure !== null) {
    const failures = [];
    if (operationFailure !== null) failures.push(operationFailure.error);
    if (closeFailure !== null) failures.push(closeFailure.error);
    if (bytes !== null) {
      try {
        bytes.fill(0);
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length === 1) throw failures[0];
    throw new AggregateError(failures, `${label} read or descriptor cleanup failed`);
  }
  return result;
}

export function pinArchive(path, label, hash = rawSha256) {
  const { bytes, identity } = readStableRegularFile(path, label, MAX_COMPRESSED_TAR_BYTES);
  try {
    const sha256 = hash(bytes);
    const machineMetadata = inspectMachineTarMetadata(bytes);
    return {
      bytes,
      identity,
      machine_metadata: machineMetadata,
      sha256,
      size_bytes: bytes.length,
    };
  } catch (error) {
    runPrivateCleanupActions(
      { error },
      [() => bytes.fill(0)],
      `${label} pin construction failed and retained-byte cleanup was incomplete`,
    );
    throw error;
  }
}

function resolveArchivePin(value, label) {
  assert(typeof value === "object" && value !== null, `${label} pin is absent`);
  assert(Buffer.isBuffer(value.bytes), `${label} pin lacks retained bytes`);
  assert(
    Number.isSafeInteger(value.identity?.dev) && Number.isSafeInteger(value.identity?.ino),
    `${label} pin has a malformed identity`,
  );
  assert(value.size_bytes === value.bytes.length, `${label} pin size does not match its retained bytes`);
  assert(value.sha256 === rawSha256(value.bytes), `${label} pin SHA-256 does not match its retained bytes`);
  assert(Array.isArray(value.machine_metadata), `${label} pin lacks bounded machine metadata`);
  assert(
    JSON.stringify(value.machine_metadata) === JSON.stringify(inspectMachineTarMetadata(value.bytes)),
    `${label} pin machine metadata does not match its retained bytes`,
  );
  return value;
}

export function assertArchiveProvenanceBinding(initiallyPinned, packageProof, retainedInspected) {
  const supplied = resolveArchivePin(initiallyPinned, "initially pinned supplied archive");
  const inspected = resolveArchivePin(retainedInspected, "retained inspected archive");
  assert(
    typeof packageProof === "object" && packageProof !== null,
    "normalized package proof is absent",
  );
  assert(
    packageProof.method === NORMALIZED_PACKAGE_PROOF_METHOD,
    "normalized package proof method is unsupported",
  );
  for (const field of [
    "supplied_sha256",
    "fresh_sha256",
    "member_listing_sha256",
    "metadata_listing_sha256",
    "normalized_manifest_sha256",
    "normalized_package_sha256",
  ]) {
    assert(/^[0-9a-f]{64}$/.test(packageProof[field]), `normalized package proof ${field} is malformed`);
  }
  for (const field of ["supplied_size_bytes", "fresh_size_bytes"]) {
    assert(
      Number.isSafeInteger(packageProof[field]) && packageProof[field] >= 0,
      `normalized package proof ${field} is malformed`,
    );
  }
  assert(
    Number.isSafeInteger(packageProof.member_count) && packageProof.member_count > 0,
    "normalized package proof member count is malformed",
  );
  assert(
    packageProof.normalized_member === NORMALIZED_PACKAGE_MEMBER,
    "normalized package proof member is unsupported",
  );
  assert(
    JSON.stringify(packageProof.nonsemantic_paths) ===
      JSON.stringify([`package/${NORMALIZED_PACKAGE_MEMBER}`]),
    "normalized package proof nonsemantic path set is unsupported",
  );
  assert(
    packageProof.supplied_sha256 === supplied.sha256,
    "normalized package proof supplied SHA-256 does not match initially pinned archive",
  );
  assert(
    packageProof.supplied_size_bytes === supplied.size_bytes,
    "normalized package proof supplied size does not match initially pinned archive",
  );
  assert(
    packageProof.fresh_sha256 === inspected.sha256,
    "retained inspected archive SHA-256 does not match normalized package proof",
  );
  assert(
    packageProof.fresh_size_bytes === inspected.size_bytes,
    "retained inspected archive size does not match normalized package proof",
  );
}

export function assertArchiveMatchesPin(path, retainedPin, label) {
  const actual = readStableRegularFile(path, label, MAX_COMPRESSED_TAR_BYTES);
  try {
    assert(
      actual.identity.dev === retainedPin.identity.dev && actual.identity.ino === retainedPin.identity.ino,
      `${label} identity does not match retained pin`,
    );
    assert(actual.bytes.length === retainedPin.size_bytes, `${label} size does not match retained pin`);
    assert(rawSha256(actual.bytes) === retainedPin.sha256, `${label} SHA-256 does not match retained pin`);
    assert(actual.bytes.equals(retainedPin.bytes), `${label} bytes do not match retained pin`);
  } finally {
    actual.bytes.fill(0);
  }
}

function archiveFingerprint(retainedPin, label) {
  assert(
    Number.isSafeInteger(retainedPin?.identity?.dev) &&
      Number.isSafeInteger(retainedPin?.identity?.ino),
    `${label} fingerprint has a malformed identity`,
  );
  assert(
    Number.isSafeInteger(retainedPin.size_bytes) && retainedPin.size_bytes >= 0,
    `${label} fingerprint has a malformed size`,
  );
  assert(/^[0-9a-f]{64}$/.test(retainedPin.sha256), `${label} fingerprint has a malformed SHA-256`);
  return Object.freeze({
    identity: Object.freeze({
      dev: retainedPin.identity.dev,
      ino: retainedPin.identity.ino,
    }),
    size_bytes: retainedPin.size_bytes,
    sha256: retainedPin.sha256,
  });
}

export function assertArchiveMatchesFingerprint(path, fingerprint, label) {
  const actual = readStableRegularFile(path, label, MAX_COMPRESSED_TAR_BYTES);
  try {
    assert(
      actual.identity.dev === fingerprint.identity.dev &&
        actual.identity.ino === fingerprint.identity.ino,
      `${label} identity does not match retained fingerprint`,
    );
    assert(
      actual.bytes.length === fingerprint.size_bytes,
      `${label} size does not match retained fingerprint`,
    );
    assert(
      rawSha256(actual.bytes) === fingerprint.sha256,
      `${label} SHA-256 does not match retained fingerprint`,
    );
  } finally {
    actual.bytes.fill(0);
  }
}

function canonicalizeJsonObjectKeyOrder(value) {
  if (Array.isArray(value)) return value.map(canonicalizeJsonObjectKeyOrder);
  if (value !== null && typeof value === "object") {
    const canonical = Object.create(null);
    for (const key of utf8Sort(Object.keys(value))) {
      canonical[key] = canonicalizeJsonObjectKeyOrder(value[key]);
    }
    return canonical;
  }
  return value;
}

function parseExactOclifManifest(bytes, label) {
  const text = bytes.toString("utf8");
  assert(Buffer.from(text, "utf8").equals(bytes), `${label} is not valid UTF-8`);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail(`${label} is not valid JSON`);
  }
  assert(
    parsed !== null && typeof parsed === "object" && !Array.isArray(parsed),
    `${label} is not a JSON object`,
  );
  const exactGeneratorBytes = Buffer.from(JSON.stringify(parsed, null, 2), "utf8");
  assert(
    exactGeneratorBytes.equals(bytes),
    `${label} differs from exact generator JSON formatting`,
  );
  return parsed;
}

export function normalizedOclifManifestHash(bytes, label) {
  const parsed = parseExactOclifManifest(bytes, label);
  const normalizedBytes = Buffer.from(
    JSON.stringify(canonicalizeJsonObjectKeyOrder(parsed), null, 2),
    "utf8",
  );
  return rawSha256(normalizedBytes);
}

export function normalizedOclifManifestSnapshot(bytes, sourceRoot, label) {
  const parsed = parseExactOclifManifest(bytes, label);
  for (const { commandId, path } of BASELINE_SOURCE_ROOT_DEFAULTS) {
    assert(
      parsed?.commands?.[commandId]?.flags?.["workspace-root"]?.default === sourceRoot,
      `baseline oclif manifest ${path} does not equal the canonical source root`,
    );
  }
  const serialized = JSON.stringify(parsed);
  assert(
    serialized.split(sourceRoot).length - 1 === BASELINE_SOURCE_ROOT_DEFAULTS.length,
    "baseline oclif manifest source root occurrence count drifted",
  );
  const normalized = canonicalizeJsonObjectKeyOrder(parsed);
  for (const { commandId } of BASELINE_SOURCE_ROOT_DEFAULTS) {
    normalized.commands[commandId].flags["workspace-root"].default = SOURCE_ROOT_SENTINEL;
  }
  const text = `${JSON.stringify(normalized, null, 2)}\n`;
  assert(!text.includes(sourceRoot), "normalized oclif manifest retains the private source root");
  return text;
}

export function buildBaselineCommandSnapshot(
  normalizedManifestText,
  expectedCommandIds = EXPECTED_BASELINE_COMMAND_IDS,
) {
  const manifest = JSON.parse(normalizedManifestText);
  assert(
    manifest !== null && typeof manifest === "object" && !Array.isArray(manifest),
    "normalized oclif manifest snapshot is not an object",
  );
  const commandIds = utf8Sort(Object.keys(manifest.commands ?? {}));
  assert(
    JSON.stringify(commandIds) === JSON.stringify(expectedCommandIds),
    "baseline oclif command inventory drifted",
  );
  const commands = commandIds.map((id) => {
    const command = manifest.commands[id];
    assert(command !== null && typeof command === "object", `baseline command ${id} is malformed`);
    assert(command.id === id, `baseline command ${id} has a mismatched manifest ID`);
    return {
      aliases: command.aliases ?? [],
      args: command.args ?? {},
      enable_json_flag: command.enableJsonFlag ?? false,
      flags: command.flags ?? {},
      hidden_aliases: command.hiddenAliases ?? [],
      id,
      relative_path: command.relativePath,
      strict: command.strict,
    };
  });
  return `${JSON.stringify(
    canonicalizeJsonObjectKeyOrder({
      baseline_commit: BASE_COMMIT,
      commands,
      manifest_file: BASELINE_OCLIF_MANIFEST_FILE,
      normalization: Object.fromEntries(
        BASELINE_SOURCE_ROOT_DEFAULTS.map(({ path }) => [path, SOURCE_ROOT_SENTINEL]),
      ),
      snapshot_version: "s35-v01-command-inventory-v1",
    }),
    null,
    2,
  )}\n`;
}

function extractPackageForComparison(root, archivePin, packedPaths, label) {
  const packageRoot = join(root, "package");
  mkdirSync(packageRoot, { mode: 0o700 });
  commandWithInput(
    "tar",
    ["-xzf", "-", "-C", packageRoot, "--strip-components=1"],
    archivePin.bytes,
    root,
  );
  assertExactTree(packageRoot, packedPaths, `${label} extracted package`);
  return packageRoot;
}

function comparePackageMemberBytes(
  suppliedPath,
  freshPath,
  memberPath,
  { suppliedSourceRoot = null, freshSourceRoot = null } = {},
) {
  let suppliedCapture = null;
  let freshCapture = null;
  let operationFailure = null;
  try {
    suppliedCapture = readStableRegularFile(suppliedPath, `supplied package member ${memberPath}`);
    freshCapture = readStableRegularFile(freshPath, `fresh package member ${memberPath}`);
    if (memberPath === NORMALIZED_PACKAGE_MEMBER) {
      if (suppliedSourceRoot !== null || freshSourceRoot !== null) {
        assert(
          typeof suppliedSourceRoot === "string" && typeof freshSourceRoot === "string",
          "both package source roots are required for source-root normalization",
        );
        const suppliedSnapshot = normalizedOclifManifestSnapshot(
          suppliedCapture.bytes,
          suppliedSourceRoot,
          "supplied oclif manifest",
        );
        const freshSnapshot = normalizedOclifManifestSnapshot(
          freshCapture.bytes,
          freshSourceRoot,
          "fresh oclif manifest",
        );
        assert(suppliedSnapshot === freshSnapshot, "oclif manifest semantic content differs");
        return rawSha256(Buffer.from(suppliedSnapshot, "utf8"));
      }
      const suppliedHash = normalizedOclifManifestHash(
        suppliedCapture.bytes,
        "supplied oclif manifest",
      );
      const freshHash = normalizedOclifManifestHash(
        freshCapture.bytes,
        "fresh oclif manifest",
      );
      assert(suppliedHash === freshHash, "oclif manifest semantic content differs");
      return suppliedHash;
    }
    assert(
      suppliedCapture.bytes.equals(freshCapture.bytes),
      `package member bytes differ: ${memberPath}`,
    );
    return rawSha256(suppliedCapture.bytes);
  } catch (error) {
    operationFailure = { error };
    throw error;
  } finally {
    runPrivateCleanupActions(
      operationFailure,
      [
        ...(suppliedCapture === null ? [] : [() => suppliedCapture.bytes.fill(0)]),
        ...(freshCapture === null ? [] : [() => freshCapture.bytes.fill(0)]),
      ],
      `package member comparison failed and retained-byte cleanup was incomplete: ${memberPath}`,
    );
  }
}

function isZeroTarBlock(block) {
  return block.every((byte) => byte === 0);
}

function parseTarString(block, start, length) {
  const field = block.subarray(start, start + length);
  const nul = field.indexOf(0);
  const bytes = nul === -1 ? field : field.subarray(0, nul);
  const text = bytes.toString("utf8");
  assert(Buffer.from(text, "utf8").equals(bytes), "tar header contains non-UTF-8 text");
  return text;
}

function parseTarNumber(field, label) {
  if ((field[0] & 0x80) !== 0) {
    let value = BigInt(field[0] & 0x7f);
    for (let index = 1; index < field.length; index += 1) {
      value = (value << 8n) | BigInt(field[index]);
    }
    assert(value <= BigInt(Number.MAX_SAFE_INTEGER), `${label} exceeds the safe integer range`);
    return Number(value);
  }
  const text = field.toString("ascii").replace(/\0.*$/s, "").trim();
  if (text === "") return 0;
  assert(/^[0-7]+$/.test(text), `${label} is not an octal tar number`);
  const value = Number.parseInt(text, 8);
  assert(Number.isSafeInteger(value), `${label} exceeds the safe integer range`);
  return value;
}

function assertTarHeaderChecksum(header) {
  const expected = parseTarNumber(header.subarray(148, 156), "tar header checksum");
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  assert(actual === expected, "tar header checksum is invalid");
}

function inspectMachineTarMetadata(gzipBytes) {
  const tarBytes = gunzipSync(gzipBytes, { maxOutputLength: MAX_UNCOMPRESSED_TAR_BYTES });
  try {
    assert(
      tarBytes.length > 0 && tarBytes.length % TAR_BLOCK_BYTES === 0,
      "uncompressed tar length is not block aligned",
    );
    const rows = [];
    let offset = 0;
    let terminated = false;
    while (offset < tarBytes.length) {
      const header = tarBytes.subarray(offset, offset + TAR_BLOCK_BYTES);
      if (isZeroTarBlock(header)) {
        const trailer = tarBytes.subarray(offset);
        assert(trailer.length >= TAR_BLOCK_BYTES * 2, "tar archive lacks two terminating zero blocks");
        assert(trailer.every((byte) => byte === 0), "tar archive contains data after its zero trailer");
        terminated = true;
        break;
      }
      assertTarHeaderChecksum(header);
      const size = parseTarNumber(header.subarray(124, 136), "tar member size");
      const type = String.fromCharCode(header[156] || 0x30);
      const name = parseTarString(header, 0, 100);
      const prefix = parseTarString(header, 345, 155);
      const path = prefix === "" ? name : `${prefix}/${name}`;
      const contentStart = offset + TAR_BLOCK_BYTES;
      const contentEnd = contentStart + size;
      assert(contentEnd <= tarBytes.length, `tar member exceeds archive bounds: ${path}`);
      const row = {
        header_sha256: rawSha256(header),
        mode: parseTarNumber(header.subarray(100, 108), "tar member mode"),
        uid: parseTarNumber(header.subarray(108, 116), "tar member uid"),
        gid: parseTarNumber(header.subarray(116, 124), "tar member gid"),
        path,
        size,
        mtime: parseTarNumber(header.subarray(136, 148), "tar member mtime"),
        type,
        linkname: parseTarString(header, 157, 100),
        magic: parseTarString(header, 257, 6),
        version: parseTarString(header, 263, 2),
        uname: parseTarString(header, 265, 32),
        gname: parseTarString(header, 297, 32),
        devmajor: parseTarNumber(header.subarray(329, 337), "tar member device major"),
        devminor: parseTarNumber(header.subarray(337, 345), "tar member device minor"),
      };
      if (TAR_METADATA_PAYLOAD_TYPES.has(type)) {
        row.metadata_payload_sha256 = rawSha256(tarBytes.subarray(contentStart, contentEnd));
      }
      rows.push(row);
      offset = contentStart + Math.ceil(size / TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES;
    }
    assert(terminated, "tar archive lacks a zero-block trailer");
    return rows;
  } finally {
    tarBytes.fill(0);
  }
}

function normalizeMachineMetadataForSourceRoot(rows) {
  const normalizedPath = `package/${NORMALIZED_PACKAGE_MEMBER}`;
  assert(
    rows.filter((row) => row.path === normalizedPath).length === 1,
    "package archive lacks one machine-metadata row for the normalized manifest",
  );
  return rows.map((row) =>
    row.path === normalizedPath
      ? {
          ...row,
          header_sha256: SOURCE_ROOT_SENTINEL,
          size: SOURCE_ROOT_SENTINEL,
        }
      : row,
  );
}

export function assertNormalizedPackageTarballs(
  suppliedValue,
  freshValue,
  {
    makeRoot = mkdtempSync,
    removeRoot = rmSync,
    suppliedSourceRoot = null,
    freshSourceRoot = null,
  } = {},
) {
  assert(typeof suppliedValue !== "string", "supplied tarball must be an owned archive pin");
  assert(typeof freshValue !== "string", "fresh tarball must be an owned archive pin");
  assert(typeof makeRoot === "function", "package comparison root factory is invalid");
  assert(typeof removeRoot === "function", "package comparison root remover is invalid");
  const supplied = resolveArchivePin(suppliedValue, "supplied tarball");
  const fresh = resolveArchivePin(freshValue, "fresh detached-checkout pack");
  let suppliedRoot = null;
  let freshRoot = null;
  let operationFailure = null;
  try {
    suppliedRoot = makeRoot(join(tmpdir(), "loopeix-s35-supplied-compare."));
    freshRoot = makeRoot(join(tmpdir(), "loopeix-s35-fresh-compare."));
    assert(suppliedRoot !== freshRoot, "package comparison roots overlap");
    const suppliedInventory = inspectPackedArchive(supplied, suppliedRoot);
    const freshInventory = inspectPackedArchive(fresh, freshRoot);
    const suppliedMachineMetadata = normalizeMachineMetadataForSourceRoot(
      suppliedInventory.machineMetadata,
    );
    const freshMachineMetadata = normalizeMachineMetadataForSourceRoot(
      freshInventory.machineMetadata,
    );
    assert(
      JSON.stringify(suppliedInventory.rawEntries) === JSON.stringify(freshInventory.rawEntries),
      "package archive member inventory differs",
    );
    assert(
      JSON.stringify(suppliedMachineMetadata) === JSON.stringify(freshMachineMetadata),
      "package archive metadata inventory differs",
    );
    assert(
      suppliedInventory.paths.includes(NORMALIZED_PACKAGE_MEMBER),
      `package archive lacks ${NORMALIZED_PACKAGE_MEMBER}`,
    );

    const suppliedPackageRoot = extractPackageForComparison(
      suppliedRoot,
      supplied,
      suppliedInventory.paths,
      "supplied",
    );
    const freshPackageRoot = extractPackageForComparison(
      freshRoot,
      fresh,
      freshInventory.paths,
      "fresh",
    );
    const normalizedRows = suppliedInventory.paths.map((memberPath) => ({
      path: memberPath,
      content_sha256: comparePackageMemberBytes(
        join(suppliedPackageRoot, memberPath),
        join(freshPackageRoot, memberPath),
        memberPath,
        { suppliedSourceRoot, freshSourceRoot },
      ),
    }));
    const normalizedManifestHash = normalizedRows.find(
      (row) => row.path === NORMALIZED_PACKAGE_MEMBER,
    )?.content_sha256;
    assert(
      typeof normalizedManifestHash === "string",
      "normalized oclif manifest hash is absent",
    );
    const metadataListingSha256 = rawSha256(
      Buffer.from(`${JSON.stringify(suppliedMachineMetadata)}\n`, "utf8"),
    );
    return {
      method: NORMALIZED_PACKAGE_PROOF_METHOD,
      supplied_sha256: supplied.sha256,
      supplied_size_bytes: supplied.size_bytes,
      fresh_sha256: fresh.sha256,
      fresh_size_bytes: fresh.size_bytes,
      member_listing_sha256: rawSha256(
        Buffer.from(`${suppliedInventory.rawEntries.join("\n")}\n`, "utf8"),
      ),
      metadata_listing_sha256: metadataListingSha256,
      normalized_manifest_sha256: normalizedManifestHash,
      normalized_package_sha256: rawSha256(
        Buffer.from(
          `${JSON.stringify({ metadata_listing_sha256: metadataListingSha256, members: normalizedRows })}\n`,
          "utf8",
        ),
      ),
      member_count: normalizedRows.length,
      normalized_member: NORMALIZED_PACKAGE_MEMBER,
      nonsemantic_paths: [`package/${NORMALIZED_PACKAGE_MEMBER}`],
    };
  } catch (error) {
    operationFailure = { error };
    throw error;
  } finally {
    runPrivateCleanupActions(
      operationFailure,
      [
        ...(suppliedRoot === null
          ? []
          : [() => removeRoot(suppliedRoot, { recursive: true, force: true })]),
        ...(freshRoot === null
          ? []
          : [() => removeRoot(freshRoot, { recursive: true, force: true })]),
      ],
      "normalized package comparison failed and private-root cleanup was incomplete",
    );
  }
}

function utf8Sort(values) {
  return [...values].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
}

function relativeFiles(root) {
  const files = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
      Buffer.from(left.name).compare(Buffer.from(right.name)),
    )) {
      const absolute = join(directory, entry.name);
      const path = relative(root, absolute).split(sep).join("/");
      assert(!entry.isSymbolicLink(), `staging contains a symlink: ${path}`);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) files.push(path);
      else fail(`staging contains a non-regular member: ${path}`);
    }
  };
  visit(root);
  return files;
}

function relativeDirectories(root) {
  const directories = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
      Buffer.from(left.name).compare(Buffer.from(right.name)),
    )) {
      const absolute = join(directory, entry.name);
      const path = relative(root, absolute).split(sep).join("/");
      assert(!entry.isSymbolicLink(), `staging contains a symlink: ${path}`);
      if (entry.isDirectory()) {
        directories.push(path);
        visit(absolute);
      } else if (!entry.isFile()) fail(`staging contains a non-regular member: ${path}`);
    }
  };
  visit(root);
  return directories;
}

function expectedDirectoriesForFiles(paths) {
  const directories = new Set();
  for (const path of paths) {
    const segments = path.split("/");
    for (let index = 1; index < segments.length; index += 1) {
      directories.add(segments.slice(0, index).join("/"));
    }
  }
  return utf8Sort(directories);
}

function assertExactTree(root, expectedFiles, label) {
  const sortedExpectedFiles = utf8Sort(expectedFiles);
  assert(new Set(sortedExpectedFiles).size === sortedExpectedFiles.length, `${label} expected file inventory contains duplicates`);
  assert(JSON.stringify(relativeFiles(root)) === JSON.stringify(sortedExpectedFiles), `${label} file inventory drifted`);
  assert(
    JSON.stringify(relativeDirectories(root)) === JSON.stringify(expectedDirectoriesForFiles(sortedExpectedFiles)),
    `${label} directory inventory drifted`,
  );
}

function containsPath(parent, child) {
  return parent === child || child.startsWith(`${parent}${sep}`);
}

function pathIdentity(path) {
  const stat = lstatSync(path);
  assert(!stat.isSymbolicLink(), `refusing symlink identity for ${path}`);
  return { dev: stat.dev, ino: stat.ino };
}

function assertSameIdentity(path, expected, label) {
  const actual = pathIdentity(path);
  assert(actual.dev === expected.dev && actual.ino === expected.ino, `${label} identity changed`);
}

function canonicalCommandWorkingDirectory(root) {
  assert(typeof root === "string" && isAbsolute(root), "child working directory must be absolute");
  const canonicalCwd = realpathSync(root);
  assert(
    statSync(canonicalCwd).isDirectory(),
    "child working directory is not a canonical directory",
  );
  return canonicalCwd;
}

function assertRecordedIdentity(value, actual, label) {
  assert(typeof value === "object" && value !== null, `${label} is absent from root metadata`);
  assert(Number.isSafeInteger(value.dev) && Number.isSafeInteger(value.ino), `${label} is malformed in root metadata`);
  assert(value.dev === actual.dev && value.ino === actual.ino, `${label} does not match the producer-recorded identity`);
}

function assertDetachedSourceSnapshot(sourceRoot, sourceIdentity) {
  assertSameIdentity(sourceRoot, sourceIdentity, "source root");
  const environment = restrictedChildEnvironment(sourceRoot);
  assert(command("git", ["-C", sourceRoot, "rev-parse", "--show-toplevel"], sourceRoot, environment) === sourceRoot, "source root is not the Git worktree root");
  assert(command("git", ["-C", sourceRoot, "rev-parse", "HEAD"], sourceRoot, environment) === BASE_COMMIT, "source worktree is at the wrong commit");
  assert(command("git", ["-C", sourceRoot, "rev-parse", "--abbrev-ref", "HEAD"], sourceRoot, environment) === "HEAD", "source worktree is not detached");
  assertOrdinaryIndexEntries(sourceRoot);
  assert(command("git", ["-C", sourceRoot, "status", "--porcelain", "--untracked-files=all"], sourceRoot, environment) === "", "source worktree is not clean");
}

function prepareVerifiedTarball(
  sourceRoot,
  sourceIdentity,
  suppliedTarballPin,
  suppliedSourceRoot,
) {
  const sourceManifestPath = join(sourceRoot, NORMALIZED_PACKAGE_MEMBER);
  const sourceManifestExisted = existsSync(sourceManifestPath);
  const sourceManifestMode = sourceManifestExisted
    ? lstatSync(sourceManifestPath).mode & 0o777
    : null;
  const sourceManifest = sourceManifestExisted
    ? readStableRegularFile(
        sourceManifestPath,
        "private source oclif manifest before fresh pack",
      )
    : null;
  let freshPackRoot = null;
  let inspected = null;
  let operationFailure = null;
  try {
    freshPackRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-fresh-pack."));
    assert(readdirSync(freshPackRoot).length === 0, "fresh pack root is not empty");
    assertDetachedSourceSnapshot(sourceRoot, sourceIdentity);
    command(
      "pnpm",
      ["--config.verify-deps-before-run=false", "pack", "--pack-destination", freshPackRoot],
      sourceRoot,
      restrictedInstallEnvironment(sourceRoot),
    );
    const members = readdirSync(freshPackRoot);
    assert(members.length === 1, "fresh pack root must contain exactly one archive");
    const freshTarball = join(freshPackRoot, members[0]);
    const freshStat = lstatSync(freshTarball);
    assert(freshStat.isFile() && !freshStat.isSymbolicLink(), "fresh pack archive is not a direct regular file");
    inspected = pinArchive(freshTarball, "retained inspected archive");
    const proof = assertNormalizedPackageTarballs(suppliedTarballPin, inspected, {
      suppliedSourceRoot,
      freshSourceRoot: sourceRoot,
    });
    return {
      root: freshPackRoot,
      archive: freshTarball,
      inspected,
      provenance: {
        method: proof.method,
        fresh_pack_filename: members[0],
        supplied_sha256: proof.supplied_sha256,
        supplied_size_bytes: proof.supplied_size_bytes,
        fresh_sha256: proof.fresh_sha256,
        fresh_size_bytes: proof.fresh_size_bytes,
        member_listing_sha256: proof.member_listing_sha256,
        metadata_listing_sha256: proof.metadata_listing_sha256,
        normalized_manifest_sha256: proof.normalized_manifest_sha256,
        normalized_package_sha256: proof.normalized_package_sha256,
        member_count: proof.member_count,
        normalized_member: proof.normalized_member,
        nonsemantic_paths: proof.nonsemantic_paths,
      },
    };
  } catch (error) {
    operationFailure = { error };
    throw error;
  } finally {
    const restorePath = join(sourceRoot, ".loopeix-s35-oclif-manifest.part");
    let sourceRestored = false;
    let sourceVerified = false;
    runPrivateCleanupActions(
      operationFailure,
      [
        () => {
          assert(!existsSync(restorePath), "private manifest restore path already exists");
          if (sourceManifest === null) {
            if (existsSync(sourceManifestPath)) {
              const generatedStat = lstatSync(sourceManifestPath);
              assert(
                generatedStat.isFile() && !generatedStat.isSymbolicLink(),
                "generated private source manifest is not a direct regular file",
              );
              rmSync(sourceManifestPath, { force: true });
            }
            assert(!existsSync(sourceManifestPath), "generated private source manifest was not removed");
          } else {
            assert(sourceManifestMode !== null, "private source manifest mode is absent");
            writeFileSync(restorePath, sourceManifest.bytes, { flag: "wx", mode: sourceManifestMode });
            chmodSync(restorePath, sourceManifestMode);
            renameSync(restorePath, sourceManifestPath);
            assert(
              rawFileSha256(sourceManifestPath) === rawSha256(sourceManifest.bytes),
              "private source manifest restoration failed",
            );
          }
          sourceRestored = true;
        },
        () => {
          assertDetachedSourceSnapshot(sourceRoot, sourceIdentity);
          sourceVerified = true;
        },
        () => {
          if (sourceManifest !== null) sourceManifest.bytes.fill(0);
        },
        () => {
          if ((operationFailure !== null || !sourceRestored || !sourceVerified) && inspected !== null) {
            inspected.bytes.fill(0);
          }
        },
        () => {
          if (
            (operationFailure !== null || !sourceRestored || !sourceVerified) &&
            freshPackRoot !== null
          ) {
            rmSync(freshPackRoot, { recursive: true, force: true });
          }
        },
      ],
      "fresh package preparation failed and cleanup was incomplete",
    );
  }
}

function expectedRawPathsForCase(casePath) {
  if (["compiled-safe-bugfix", "credential-shaped-replay-pack", "large-compiled-pack", "planned-run-source-pack"].includes(casePath)) {
    return COMPILED_PACK_MEMBERS.map((path) => `${casePath}/${path}`);
  }
  if (["hold-ambiguous", "hold-no-item", "hold-risk"].includes(casePath)) {
    return HOLD_PACK_MEMBERS.map((path) => `${casePath}/${path}`);
  }
  if (casePath === "compiled-explicit-destination") {
    return [
      ...COMPILED_PACK_MEMBERS.map((path) => `compiled-explicit-destination/${path}`),
      "standalone/compiled-explicit-destination/generated.loop.yaml",
    ];
  }
  if (casePath.startsWith("planned-run-oracles/")) {
    return [`${casePath}/intake-brief.json`, `${casePath}/resolved-run-plan.json`];
  }
  if (casePath.startsWith(`${RUN_RECOVER_ORACLE_ROOT}/`)) {
    const caseName = casePath.slice(`${RUN_RECOVER_ORACLE_ROOT}/`.length);
    assert(RUN_RECOVER_CASE_NAMES.includes(caseName), `unknown run recover oracle case ${casePath}`);
    assert(casePath === `${RUN_RECOVER_ORACLE_ROOT}/${caseName}`, `nested run recover oracle case ${casePath}`);
    return RUN_RECOVER_RAW_MEMBERS.map((path) => `${casePath}/${path}`);
  }
  if (casePath === "large-profileless-plan") return ["large-profileless-plan/resolved-run-plan.json"];
  if (casePath === "large-ledger") return ["large-ledger/ledger.jsonl"];
  if (casePath === "large-report-input") {
    return [
      "large-report-input/ledger.jsonl",
      "large-report-input/manifest.json",
      "large-report-input/report-input.json",
      "large-report-input/report.html",
      "large-report-input/report.md",
      "large-report-input/run.json",
    ];
  }
  if (casePath === "large-receipt") {
    return ["large-receipt/ledger.jsonl", "large-receipt/public-key-spki.b64", "large-receipt/receipt.json"];
  }
  fail(`no fixed raw-member inventory for ${casePath}`);
}

function expectedProvenancePaths() {
  return utf8Sort(EXPECTED_PROVENANCE_CASES.flatMap((casePath) => [
    `${casePath}/SHA256SUMS`,
    `${casePath}/capture-metadata.json`,
  ]));
}

function expectedStageFilesBeforePackage() {
  const rawPaths = EXPECTED_PROVENANCE_CASES.flatMap((casePath) => expectedRawPathsForCase(casePath));
  assert(new Set(rawPaths).size === rawPaths.length, "fixed raw-member inventories overlap");
  return utf8Sort([
    "README.md",
    "capture-metadata.json",
    ...rawPaths,
    ...expectedProvenancePaths().map((path) => `provenance/${path}`),
  ]);
}

function verifyCaseChecksums(fixtureRoot, casePath) {
  const provenanceRoot = join(fixtureRoot, "provenance", casePath);
  const sidecars = relativeFiles(provenanceRoot);
  assert(
    JSON.stringify(sidecars) === JSON.stringify(["SHA256SUMS", "capture-metadata.json"]),
    `provenance/${casePath} members drifted`,
  );
  const lines = readFileSync(join(provenanceRoot, "SHA256SUMS"), "utf8").trimEnd().split("\n").filter(Boolean);
  assert(lines.length > 0, `provenance/${casePath}/SHA256SUMS is empty`);
  const seen = new Set();
  for (const line of lines) {
    const match = /^([0-9a-f]{64})  (.+)$/.exec(line);
    assert(match !== null, `malformed checksum row for ${casePath}`);
    const [, expected, path] = match;
    const segments = path.split("/");
    assert(
      !isAbsolute(path) && segments.every((segment) => segment !== "" && segment !== "." && segment !== ".."),
      `unsafe checksum path ${path}`,
    );
    assert(!seen.has(path), `duplicate checksum path ${path}`);
    seen.add(path);
    const absolute = join(fixtureRoot, path);
    assert(lstatSync(absolute).isFile(), `checksum target is not a regular file: ${path}`);
    assert(rawFileSha256(absolute) === expected, `checksum mismatch for ${path}`);
  }
  const expectedPaths = utf8Sort(expectedRawPathsForCase(casePath));
  assert(JSON.stringify(utf8Sort(seen)) === JSON.stringify(expectedPaths), `checksum membership is incomplete or out of scope for ${casePath}`);
}

function inspectPackedArchive(inspectedTarball, cwd) {
  const machineMetadata = inspectMachineTarMetadata(inspectedTarball.bytes);
  assert(
    JSON.stringify(machineMetadata) === JSON.stringify(inspectedTarball.machine_metadata),
    "retained archive machine metadata changed",
  );
  const rawEntries = commandWithInput("tar", ["-tzf", "-"], inspectedTarball.bytes, cwd).split("\n").filter(Boolean);
  assert(rawEntries.length > 0, "tarball contains no entries");
  assert(new Set(rawEntries).size === rawEntries.length, "tarball contains duplicate raw entries");
  const verboseEntries = commandWithInput("tar", ["-tvzf", "-"], inspectedTarball.bytes, cwd).split("\n").filter(Boolean);
  assert(verboseEntries.length === rawEntries.length, "tarball type inventory count drifted");
  assert(
    verboseEntries.every((entry) => entry.startsWith("-")),
    "tarball contains a non-regular member",
  );
  const entries = rawEntries.map((entry, index) => {
    assert(!entry.startsWith("/"), `tarball contains an absolute entry: ${entry}`);
    assert(entry.startsWith("package/"), `tarball entry lacks exactly one package/ prefix: ${entry}`);
    const stripped = entry.slice("package/".length);
    assert(stripped !== "", "tarball contains the bare package/ directory");
    assert(!stripped.startsWith("/") && !stripped.endsWith("/"), `tarball entry is not a regular path: ${entry}`);
    assert(!stripped.includes("\\"), `tarball entry uses a backslash: ${entry}`);
    const segments = stripped.split("/");
    assert(segments.every((segment) => segment !== "" && segment !== "." && segment !== ".."), `tarball entry has a dot or empty segment: ${entry}`);
    assert(posix.normalize(stripped) === stripped, `tarball entry is not normalized: ${entry}`);
    return { path: stripped, raw: entry, verbose: verboseEntries[index] };
  });
  const paths = entries.map((entry) => entry.path);
  assert(new Set(paths).size === paths.length, "tarball paths collide after stripping package/");
  const structuralTypeCount = machineMetadata.filter(({ type }) =>
    TAR_METADATA_PAYLOAD_TYPES.has(type),
  ).length;
  assert(
    machineMetadata.length - structuralTypeCount === rawEntries.length,
    "machine tar metadata member count drifted",
  );
  return { entries, machineMetadata, paths: utf8Sort(paths), rawEntries, verboseEntries };
}

function listPackedPaths(inspectedTarball, cwd) {
  return inspectPackedArchive(inspectedTarball, cwd).paths;
}

function restrictedChildEnvironment(root) {
  const canonicalRoot = canonicalCommandWorkingDirectory(root);
  return {
    HOME: canonicalRoot,
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
    TMPDIR: canonicalRoot,
  };
}

function restrictedInstallEnvironment(root) {
  return {
    ...restrictedChildEnvironment(root),
    PATH: process.env.PATH ?? "",
  };
}

function parseExactGeneratedJsonObject(bytes, label) {
  const text = bytes.toString("utf8");
  assert(Buffer.from(text, "utf8").equals(bytes), `${label} is not valid UTF-8`);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail(`${label} is not valid JSON`);
  }
  assert(
    parsed !== null && typeof parsed === "object" && !Array.isArray(parsed),
    `${label} is not a JSON object`,
  );
  assert(
    Buffer.from(JSON.stringify(parsed, null, 2), "utf8").equals(bytes),
    `${label} differs from exact generator JSON formatting`,
  );
  return parsed;
}

export function readPinnedPnpmStoreBinding(sourceRoot) {
  const canonicalSourceRoot = realpathSync(sourceRoot);
  const metadataPath = join(canonicalSourceRoot, "node_modules", ".modules.yaml");
  const captured = readStableRegularFile(
    metadataPath,
    "installed pnpm modules metadata",
    PNPM_MODULES_METADATA_MAX_BYTES,
  );
  try {
    const metadata = parseExactGeneratedJsonObject(
      captured.bytes,
      "installed pnpm modules metadata",
    );
    assert(metadata.packageManager === "pnpm@11.9.0", "installed pnpm package manager drifted");
    assert(metadata.layoutVersion === 5, "installed pnpm layout version drifted");
    assert(metadata.nodeLinker === "isolated", "installed pnpm node linker drifted");
    assert(metadata.virtualStoreDir === ".pnpm", "installed pnpm virtual store drifted");
    assert(
      typeof metadata.storeDir === "string" && isAbsolute(metadata.storeDir),
      "installed pnpm store path is not absolute",
    );
    const canonicalStorePath = realpathSync(metadata.storeDir);
    assert(metadata.storeDir === canonicalStorePath, "installed pnpm store path is not canonical");
    const storeStat = lstatSync(canonicalStorePath);
    assert(
      storeStat.isDirectory() && !storeStat.isSymbolicLink(),
      "installed pnpm store path is not a direct directory",
    );
    assert(
      !containsPath(canonicalSourceRoot, canonicalStorePath) &&
        !containsPath(canonicalStorePath, canonicalSourceRoot),
      "installed pnpm store overlaps the detached source",
    );
    return Object.freeze({
      sourceRoot: canonicalSourceRoot,
      metadataPath,
      metadataIdentity: Object.freeze(captured.identity),
      metadataSha256: rawSha256(captured.bytes),
      storePath: canonicalStorePath,
      storeIdentity: Object.freeze(pathIdentity(canonicalStorePath)),
    });
  } finally {
    captured.bytes.fill(0);
  }
}

export function assertPnpmStoreBinding(binding) {
  assert(binding !== null && typeof binding === "object", "pnpm store binding is absent");
  const captured = readStableRegularFile(
    binding.metadataPath,
    "bound pnpm modules metadata",
    PNPM_MODULES_METADATA_MAX_BYTES,
  );
  try {
    assert(
      captured.identity.dev === binding.metadataIdentity.dev &&
        captured.identity.ino === binding.metadataIdentity.ino,
      "pnpm modules metadata identity changed",
    );
    assert(rawSha256(captured.bytes) === binding.metadataSha256, "pnpm modules metadata changed");
  } finally {
    captured.bytes.fill(0);
  }
  assert(realpathSync(binding.sourceRoot) === binding.sourceRoot, "bound source root is not canonical");
  assert(realpathSync(binding.storePath) === binding.storePath, "bound pnpm store path changed");
  assertSameIdentity(binding.storePath, binding.storeIdentity, "bound pnpm store");
  const storeStat = lstatSync(binding.storePath);
  assert(
    storeStat.isDirectory() && !storeStat.isSymbolicLink(),
    "bound pnpm store path is not a direct directory",
  );
  assert(
    !containsPath(binding.sourceRoot, binding.storePath) &&
      !containsPath(binding.storePath, binding.sourceRoot),
    "bound pnpm store overlaps the detached source",
  );
}

export function withPrivateCommandTemporaryRoot(
  environment,
  operation,
  {
    makeRoot = (prefix) => mkdtempSync(prefix),
    removeRoot = (root) => rmSync(root, { recursive: true, force: true }),
  } = {},
) {
  assert(typeof environment === "object" && environment !== null, "command environment is absent");
  assert(typeof operation === "function", "private command operation is absent");
  let temporaryRoot = null;
  let operationFailure = null;
  try {
    temporaryRoot = makeRoot(join(tmpdir(), "loopeix-s35-package-command."));
    assert(isAbsolute(temporaryRoot), "private command temporary root is not absolute");
    chmodSync(temporaryRoot, 0o700);
    const canonicalTemporaryRoot = realpathSync(temporaryRoot);
    const canonicalHome = realpathSync(environment.HOME);
    const temporaryStat = statSync(canonicalTemporaryRoot);
    assert(
      temporaryStat.isDirectory() && (temporaryStat.mode & 0o077) === 0,
      "private command temporary root is not a private directory",
    );
    assert(
      !containsPath(canonicalHome, canonicalTemporaryRoot) &&
        !containsPath(canonicalTemporaryRoot, canonicalHome),
      "private command temporary root overlaps its HOME",
    );
    const commandEnvironment = Object.freeze({
      ...environment,
      HOME: canonicalTemporaryRoot,
      TMPDIR: canonicalTemporaryRoot,
    });
    assert(
      JSON.stringify(Object.keys(commandEnvironment).sort()) ===
        JSON.stringify(["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"]),
      "private command environment is not restricted",
    );
    return operation(commandEnvironment);
  } catch (error) {
    operationFailure = { error };
    throw error;
  } finally {
    runPrivateCleanupActions(
      operationFailure,
      temporaryRoot === null ? [] : [() => removeRoot(temporaryRoot)],
      "private command failed and temporary-root cleanup was incomplete",
    );
  }
}

export function runRestrictedNode(root, scriptPath, args = []) {
  const canonicalRoot = realpathSync(root);
  const canonicalScriptPath = realpathSync(scriptPath);
  assert(
    containsPath(canonicalRoot, canonicalScriptPath),
    "restricted Node entrypoint resolved outside its dependency root",
  );
  const canonicalArgs = args.map((arg) => {
    if (!isAbsolute(arg)) return arg;
    const canonicalArg = realpathSync(arg);
    assert(
      containsPath(canonicalRoot, canonicalArg),
      "restricted Node file argument resolved outside its dependency root",
    );
    return canonicalArg;
  });
  return execFileSync(
    assertTrustedExecutable("node"),
    [
      "--permission",
      `--allow-fs-read=${canonicalRoot}`,
      "--no-addons",
      "--no-global-search-paths",
      canonicalScriptPath,
      ...canonicalArgs,
    ],
    {
      cwd: canonicalRoot,
      encoding: "utf8",
      env: restrictedChildEnvironment(canonicalRoot),
      killSignal: "SIGKILL",
      maxBuffer: CHILD_PROCESS_MAX_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: CHILD_PROCESS_TIMEOUT_MS,
    },
  ).trim();
}

function prepareDependencyRoot(sourceRoot, mode, storeBinding) {
  assert(mode === "runtime" || mode === "types", "unknown package probe dependency mode");
  const root = mkdtempSync(join(tmpdir(), `loopeix-s35-${mode}-dependencies.`));
  try {
    chmodSync(root, 0o700);
    for (const name of ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"]) {
      const source = join(sourceRoot, name);
      const captured = readStableRegularFile(source, `baseline ${name}`);
      writeFileSync(join(root, name), captured.bytes, { flag: "wx", mode: 0o600 });
    }
    const installArgs = [
      "install",
      "--offline",
      "--frozen-lockfile",
      "--frozen-store",
      "--ignore-scripts",
      "--ignore-pnpmfile",
      "--no-hoist",
      "--no-runtime",
      "--package-import-method=copy",
      "--verify-store-integrity",
      "--reporter=silent",
    ];
    assertPnpmStoreBinding(storeBinding);
    installArgs.push(`--store-dir=${storeBinding.storePath}`);
    if (mode === "runtime") installArgs.push("--prod");
    command("pnpm", installArgs, root, restrictedInstallEnvironment(root));
    assertPnpmStoreBinding(storeBinding);
    assert(existsSync(join(root, "node_modules")), `${mode} dependency installation is absent`);
    for (const name of ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"]) {
      assert(
        rawFileSha256(join(root, name)) === rawFileSha256(join(sourceRoot, name)),
        `${mode} dependency installation changed ${name}`,
      );
    }
    return root;
  } catch (error) {
    rethrowAfterDependencyRootCleanup(root, error);
  }
}

function extractPackedPackage(root, inspectedTarball, packedPaths) {
  const packageRoot = join(root, "node_modules", "loopeix");
  assert(!existsSync(packageRoot), "package probe target already exists");
  mkdirSync(packageRoot, { mode: 0o700 });
  commandWithInput(
    "tar",
    ["-xzf", "-", "-C", packageRoot, "--strip-components=1"],
    inspectedTarball.bytes,
    root,
  );
  assert(
    JSON.stringify(relativeFiles(packageRoot)) === JSON.stringify(packedPaths),
    "extracted package tree differs from the packed path inventory",
  );
  return realpathSync(packageRoot);
}

function assertPackedManifest(sourceRoot, packageRoot) {
  const source = JSON.parse(readFileSync(join(sourceRoot, "package.json"), "utf8"));
  const packed = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
  for (const field of ["name", "version", "main", "types", "dependencies", "exports"]) {
    assert(
      JSON.stringify(packed[field]) === JSON.stringify(source[field]),
      `packed package manifest field drifted: ${field}`,
    );
  }
  assert(packed.name === "loopeix", "packed package name is not loopeix");
  assert(packed.main === "./dist/index.js", "packed package main entrypoint drifted");
  assert(packed.types === "./dist/index.d.ts", "packed package types entrypoint drifted");
}

export function assertPackageRootExportSets(runtimeNames, typeNames, compilerValueNames, dualNames) {
  for (const [label, values] of [
    ["runtime", runtimeNames],
    ["type namespace", typeNames],
    ["compiler value", compilerValueNames],
    ["dual namespace", dualNames],
  ]) {
    assert(Array.isArray(values), `${label} export set is not an array`);
    assert(
      JSON.stringify(values) === JSON.stringify(utf8Sort(new Set(values))),
      `${label} export set is not unique and UTF-8 sorted`,
    );
  }
  assert(runtimeNames.length === EXPECTED_RUNTIME_EXPORT_COUNT, "runtime export count drifted");
  assert(typeNames.length === EXPECTED_TYPE_NAMESPACE_EXPORT_COUNT, "type namespace export count drifted");
  assert(dualNames.length === EXPECTED_DUAL_NAMESPACE_EXPORT_COUNT, "dual namespace export count drifted");
  assert(
    JSON.stringify(runtimeNames) === JSON.stringify(compilerValueNames),
    "runtime and compiler value export sets differ",
  );
  const typeOnly = typeNames.filter((name) => !new Set(runtimeNames).has(name));
  assert(typeOnly.length === EXPECTED_TYPE_ONLY_EXPORT_COUNT, "type-only export count drifted");
  const expectedDual = typeNames.filter((name) => new Set(runtimeNames).has(name));
  assert(JSON.stringify(dualNames) === JSON.stringify(expectedDual), "dual namespace export set drifted");
  assert(
    new Set([...runtimeNames, ...typeNames]).size === EXPECTED_DISTINCT_ROOT_SYMBOL_COUNT,
    "distinct package-root symbol count drifted",
  );
}

function captureRuntimeExportSet(root, packageRoot) {
  const consumerRoot = join(root, "runtime-consumer");
  mkdirSync(consumerRoot, { mode: 0o700 });
  writeFileSync(
    join(consumerRoot, "package.json"),
    `${JSON.stringify({ name: "loopeix-s35-runtime-oracle-consumer", private: true, type: "module" })}\n`,
    { flag: "wx", mode: 0o600 },
  );
  const expectedIndex = realpathSync(join(packageRoot, "dist", "index.js"));
  const probePath = join(consumerRoot, "probe.mjs");
  writeFileSync(
    probePath,
    `const expected = ${JSON.stringify(pathToFileURL(expectedIndex).href)};\n` +
      `const resolved = import.meta.resolve("loopeix");\n` +
      `if (resolved !== expected) throw new Error("bare runtime import resolved outside packed package");\n` +
      `const api = await import("loopeix");\n` +
      `process.stdout.write(JSON.stringify({ resolved, names: Object.keys(api) }));\n`,
    { flag: "wx", mode: 0o600 },
  );
  const result = JSON.parse(runRestrictedNode(root, probePath));
  assert(result.resolved === pathToFileURL(expectedIndex).href, "runtime probe resolution drifted");
  return utf8Sort(result.names);
}

function captureTypeExportSet(root, packageRoot) {
  const consumerRoot = join(root, "type-consumer");
  mkdirSync(consumerRoot, { mode: 0o700 });
  writeFileSync(
    join(consumerRoot, "package.json"),
    `${JSON.stringify({ name: "loopeix-s35-type-oracle-consumer", private: true, type: "module" })}\n`,
    { flag: "wx", mode: 0o600 },
  );
  const sourcePath = join(consumerRoot, "probe.ts");
  writeFileSync(sourcePath, 'import * as api from "loopeix";\nvoid api;\n', {
    flag: "wx",
    mode: 0o600,
  });
  const compilerPath = realpathSync(join(root, "node_modules", "typescript", "lib", "typescript.js"));
  const expectedDeclaration = realpathSync(join(packageRoot, "dist", "index.d.ts"));
  const probePath = join(consumerRoot, "probe.mjs");
  writeFileSync(
    probePath,
    `import { pathToFileURL } from "node:url";\n` +
      `const [compilerPath, sourcePath, expectedDeclaration] = process.argv.slice(2);\n` +
      `const imported = await import(pathToFileURL(compilerPath).href);\n` +
      `const ts = imported.default ?? imported;\n` +
      `if (ts.version !== ${JSON.stringify(EXPECTED_TYPESCRIPT_VERSION)}) throw new Error("compiler version drifted");\n` +
      `const options = { module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, target: ts.ScriptTarget.ES2024, strict: true, skipLibCheck: false, noEmit: true };\n` +
      `const program = ts.createProgram([sourcePath], options);\n` +
      `const diagnostics = ts.getPreEmitDiagnostics(program);\n` +
      `if (diagnostics.length !== 0) throw new Error("type probe diagnostics: " + diagnostics.map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\\n")).join(" | "));\n` +
      `const resolved = ts.resolveModuleName("loopeix", sourcePath, options, ts.sys).resolvedModule?.resolvedFileName;\n` +
      `if (!resolved || ts.sys.realpath(resolved) !== expectedDeclaration) throw new Error("bare type import resolved outside packed package");\n` +
      `const declaration = program.getSourceFile(resolved) ?? program.getSourceFile(expectedDeclaration);\n` +
      `if (!declaration) throw new Error("packed declaration source is absent");\n` +
      `const checker = program.getTypeChecker();\n` +
      `const moduleSymbol = checker.getSymbolAtLocation(declaration);\n` +
      `if (!moduleSymbol) throw new Error("packed declaration module symbol is absent");\n` +
      `const types = []; const values = []; const dual = [];\n` +
      `for (const exported of checker.getExportsOfModule(moduleSymbol)) {\n` +
      `  const target = (exported.flags & ts.SymbolFlags.Alias) !== 0 ? checker.getAliasedSymbol(exported) : exported;\n` +
      `  const hasType = (target.flags & ts.SymbolFlags.Type) !== 0;\n` +
      `  const hasValue = (target.flags & ts.SymbolFlags.Value) !== 0;\n` +
      `  const name = exported.getName();\n` +
      `  if (hasType) types.push(name);\n` +
      `  if (hasValue) values.push(name);\n` +
      `  if (hasType && hasValue) dual.push(name);\n` +
      `}\n` +
      `process.stdout.write(JSON.stringify({ version: ts.version, resolved: ts.sys.realpath(resolved), types, values, dual }));\n`,
    { flag: "wx", mode: 0o600 },
  );
  const result = JSON.parse(
    runRestrictedNode(root, probePath, [compilerPath, sourcePath, expectedDeclaration]),
  );
  assert(result.version === EXPECTED_TYPESCRIPT_VERSION, "type probe compiler version drifted");
  assert(result.resolved === expectedDeclaration, "type probe resolution drifted");
  return {
    typeNames: utf8Sort(result.types),
    compilerValueNames: utf8Sort(result.values),
    dualNames: utf8Sort(result.dual),
    compilerPath,
  };
}

export function removeDependencyRoots(roots, remove = rmSync) {
  const failures = [];
  for (const root of roots) {
    if (root === null) continue;
    try {
      remove(root, { recursive: true, force: true });
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(failures, "package probe dependency cleanup failed");
  }
}

export function runPrivateCleanupActions(operationFailure, actions, aggregateMessage) {
  const cleanupFailures = [];
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

export function rethrowAfterDependencyRootCleanup(root, operationError, remove = rmSync) {
  runPrivateCleanupActions(
    { error: operationError },
    [() => removeDependencyRoots([root], remove)],
    "package probe dependency preparation failed and cleanup was incomplete",
  );
  throw operationError;
}

function capturePackedPackageExports(sourceRoot, inspectedTarball, packedPaths) {
  let runtimeRoot = null;
  let typeRoot = null;
  let operationError;
  const storeBinding = readPinnedPnpmStoreBinding(sourceRoot);
  try {
    assertPnpmStoreBinding(storeBinding);
    runtimeRoot = prepareDependencyRoot(sourceRoot, "runtime", storeBinding);
    typeRoot = prepareDependencyRoot(sourceRoot, "types", storeBinding);
    assert(runtimeRoot !== typeRoot, "package probe dependency roots overlap");
    const runtimePackageRoot = extractPackedPackage(runtimeRoot, inspectedTarball, packedPaths);
    const typePackageRoot = extractPackedPackage(typeRoot, inspectedTarball, packedPaths);
    assertPackedManifest(sourceRoot, runtimePackageRoot);
    assertPackedManifest(sourceRoot, typePackageRoot);
    const oclifManifestCapture = readStableRegularFile(
      join(runtimePackageRoot, NORMALIZED_PACKAGE_MEMBER),
      "retained baseline oclif manifest",
    );
    let normalizedOclifManifestText;
    let baselineCommandSnapshotText;
    try {
      normalizedOclifManifestText = normalizedOclifManifestSnapshot(
        oclifManifestCapture.bytes,
        sourceRoot,
        "retained baseline oclif manifest",
      );
      baselineCommandSnapshotText = buildBaselineCommandSnapshot(normalizedOclifManifestText);
    } finally {
      oclifManifestCapture.bytes.fill(0);
    }
    const runtimeNames = captureRuntimeExportSet(runtimeRoot, runtimePackageRoot);
    const { typeNames, compilerValueNames, dualNames, compilerPath } = captureTypeExportSet(
      typeRoot,
      typePackageRoot,
    );
    assertPackageRootExportSets(runtimeNames, typeNames, compilerValueNames, dualNames);
    assertPnpmStoreBinding(storeBinding);
    return {
      packedIndexHash: rawFileSha256(join(runtimePackageRoot, "dist", "index.js")),
      packedDeclarationHash: rawFileSha256(join(typePackageRoot, "dist", "index.d.ts")),
      compilerPackageHash: rawFileSha256(join(typeRoot, "node_modules", "typescript", "package.json")),
      compilerEntrypointHash: rawFileSha256(compilerPath),
      runtimeExportsText: `${runtimeNames.join("\n")}\n`,
      typeExportsText: `${typeNames.join("\n")}\n`,
      normalizedOclifManifestText,
      baselineCommandSnapshotText,
      pnpmStoreBinding: {
        metadata_path: storeBinding.metadataPath,
        metadata_sha256: storeBinding.metadataSha256,
        metadata_identity: storeBinding.metadataIdentity,
        store_path: storeBinding.storePath,
        store_identity: storeBinding.storeIdentity,
      },
      exportCounts: {
        runtime_value: runtimeNames.length,
        type_namespace: typeNames.length,
        type_only: typeNames.filter((name) => !new Set(runtimeNames).has(name)).length,
        dual_namespace: dualNames.length,
        distinct_root_symbols: new Set([...runtimeNames, ...typeNames]).size,
      },
    };
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      removeDependencyRoots([typeRoot, runtimeRoot]);
    } catch (cleanupError) {
      if (operationError !== undefined) {
        throw new AggregateError(
          [operationError, cleanupError],
          "package probe failed and dependency cleanup was incomplete",
        );
      }
      throw cleanupError;
    }
  }
}

function assertOversizedInventory(root) {
  const actual = relativeFiles(root).filter((path) => statSync(join(root, path)).size >= IN_PROCESS_LIMIT_BYTES);
  assert(JSON.stringify(actual) === JSON.stringify(utf8Sort(EXPECTED_OVERSIZED_PATHS)), "the five-family oversized member inventory drifted");
  for (const path of EXACT_TARGET_OVERSIZED_PATHS) {
    assert(statSync(join(root, path)).size === TARGET_OVERSIZED_BYTES, `${path} has the wrong oversized byte length`);
  }
}

function verifyRootChecksums(root) {
  const target = join(root, ROOT_CHECKSUM_FILE);
  assert(lstatSync(target).isFile(), "fixture-root SHA256SUMS is not a regular file");
  const expectedPaths = relativeFiles(root).filter((path) => path !== ROOT_CHECKSUM_FILE);
  const lines = readFileSync(target, "utf8").trimEnd().split("\n").filter(Boolean);
  assert(lines.length === expectedPaths.length, "fixture-root checksum row count drifted");
  for (const [index, line] of lines.entries()) {
    const match = /^([0-9a-f]{64})  (.+)$/.exec(line);
    assert(match !== null, "fixture-root checksum contains a malformed row");
    const [, expectedHash, path] = match;
    assert(path === expectedPaths[index], `fixture-root checksum membership drifted at ${path}`);
    assert(rawFileSha256(join(root, path)) === expectedHash, `fixture-root checksum mismatch for ${path}`);
  }
}

export function writeRootChecksums(root, options = {}) {
  const {
    openFile = openSync,
    writeFile = writeFileSync,
    syncFile = fsyncSync,
    closeFile = closeSync,
    removeFile = rmSync,
    verify = verifyRootChecksums,
    afterPublish = () => {},
    announce = () => {},
  } = options;
  const target = join(root, ROOT_CHECKSUM_FILE);
  assert(!existsSync(target), "fixture-root SHA256SUMS already exists");
  const paths = relativeFiles(root);
  const lines = paths.map((path) => `${rawFileSha256(join(root, path))}  ${path}`);
  const contents = `${lines.join("\n")}\n`;
  let descriptor = null;
  let ownsTarget = false;
  let operationError = null;
  try {
    descriptor = openFile(
      target,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    ownsTarget = true;
    writeFile(descriptor, contents);
    syncFile(descriptor);
    const descriptorToClose = descriptor;
    descriptor = null;
    closeFile(descriptorToClose);
    verify(root);
    afterPublish();
    announce();
    return;
  } catch (error) {
    operationError = error;
  }

  const cleanupFailures = [];
  if (descriptor !== null) {
    try {
      closeFile(descriptor);
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (ownsTarget) {
    try {
      removeFile(target, { force: true });
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (cleanupFailures.length > 0) {
    throw new AggregateError(
      [operationError, ...cleanupFailures],
      "root checksum publication failed and cleanup was incomplete",
    );
  }
  throw operationError;
}

export function finalizePackageOracleStage(
  root,
  { beforePublish, afterPublish, announce, checksumIO = {} },
) {
  assert(typeof beforePublish === "function", "package finalizer before-publish check is absent");
  assert(typeof afterPublish === "function", "package finalizer after-publish check is absent");
  assert(typeof announce === "function", "package finalizer success callback is absent");
  beforePublish();
  writeRootChecksums(root, {
    ...checksumIO,
    afterPublish,
    announce,
  });
}

export function announceCaptureSuccess(root, write = writeSync, fd = 1) {
  assert(typeof write === "function", "package-capture announcement writer is invalid");
  assert(fd === 1 || fd === 3, "package-capture announcement descriptor is invalid");
  const message = Buffer.from(`Captured and finalized S35 package oracles at ${root}\n`, "utf8");
  assert(
    message.length <= 4_096,
    "package-capture transactional announcement exceeds its fixed output bound",
  );
  let offset = 0;
  while (offset < message.length) {
    const written = write(fd, message, offset, message.length - offset);
    assert(
      Number.isSafeInteger(written) && written > 0 && written <= message.length - offset,
      "package-capture announcement write did not make bounded progress",
    );
    offset += written;
  }
}

async function main() {
  const trustedNode = assertTrustedExecutable("node");
  assert(process.execPath === trustedNode, "capture process is not running under the admitted Node executable");
  const {
    sourceRoot: requestedSourceRoot,
    tarball: requestedTarball,
    out: requestedOut,
    assertedCommit,
    toolSourceRoot: requestedToolSourceRoot,
    transactionalSuccessFd,
  } = parseArgs(process.argv.slice(2));
  assert(assertedCommit === BASE_COMMIT, `asserted commit must be ${BASE_COMMIT}`);
  assert(existsSync(requestedSourceRoot) && existsSync(requestedTarball) && existsSync(requestedOut), "source, tarball, and staging roots must already exist");

  const sourceRoot = realpathSync(requestedSourceRoot);
  const tarball = realpathSync(requestedTarball);
  const out = realpathSync(requestedOut);
  assert(statSync(sourceRoot).isDirectory() && statSync(out).isDirectory(), "source and staging roots must be directories");
  assert(statSync(tarball).isFile(), "tarball must be a regular file");
  assert(!containsPath(sourceRoot, out) && !containsPath(out, sourceRoot), "source and staging roots overlap");
  assert(!containsPath(sourceRoot, tarball) && !containsPath(out, tarball), "tarball is inside source or staging");

  const sourceIdentity = pathIdentity(sourceRoot);
  const outIdentity = pathIdentity(out);
  const toolSourceRoot = realpathSync(requestedToolSourceRoot);
  assert(statSync(toolSourceRoot).isDirectory(), "reviewed tool source root is not a directory");
  const admittedScriptPath = fileURLToPath(import.meta.url);
  const scriptPath = join(toolSourceRoot, "capture-s35-package-oracles.mjs");
  assert(realpathSync(scriptPath) === scriptPath, "package capture driver source is not canonical");
  const scriptHashBefore = rawFileSha256(scriptPath);
  assert(
    rawFileSha256(admittedScriptPath) === scriptHashBefore,
    "admitted package capture driver differs from its reviewed source",
  );
  const cleanLauncherPath = join(toolSourceRoot, "run-s35-capture-clean.sh");
  assert(existsSync(cleanLauncherPath), "clean capture process launcher is absent");
  const cleanLauncherHashBefore = rawFileSha256(cleanLauncherPath);
  const sourceSnapshot = materializeSourceSnapshot(sourceRoot, out, process.env);
  let suppliedTarballPin = null;
  let verifiedTarball = null;
  let sourceSnapshotRemoved = false;
  let operationFailure = null;
  let tarballFingerprint = null;
  let stageFilesBeforeRootChecksum = null;
  try {
  suppliedTarballPin = pinArchive(tarball, "initially pinned supplied tarball");
  tarballFingerprint = archiveFingerprint(suppliedTarballPin, "supplied tarball");
  assertDetachedSourceSnapshot(sourceRoot, sourceIdentity);
  const executionSourceRoot = sourceSnapshot.root;
  const executionSourceIdentity = pathIdentity(executionSourceRoot);
  assertSourceSnapshot(sourceSnapshot);
  assert(process.version === "v26.0.0", `capture runtime must be Node v26.0.0, got ${process.version}`);
  const pnpmVersion = command(
    "pnpm",
    ["--version"],
    executionSourceRoot,
    restrictedInstallEnvironment(executionSourceRoot),
  );
  assert(pnpmVersion === "11.9.0", `capture pnpm must be 11.9.0, got ${pnpmVersion}`);
  verifiedTarball = prepareVerifiedTarball(sourceSnapshot.root,
    executionSourceIdentity,
    suppliedTarballPin,
    sourceRoot,
  );
  const inspectedTarballPath = verifiedTarball.archive;
  const inspectedTarballPin = verifiedTarball.inspected;
  const inspectedTarball = inspectedTarballPin;
  const inspectedTarballFingerprint = archiveFingerprint(
    inspectedTarballPin,
    "inspected tarball",
  );
  const tarballProvenance = verifiedTarball.provenance;
  assertArchiveProvenanceBinding(
    suppliedTarballPin,
    tarballProvenance,
    inspectedTarballPin,
  );
  assertArchiveMatchesPin(inspectedTarballPath, inspectedTarballPin, "retained inspected archive");

  const topLevel = utf8Sort(readdirSync(out));
  assert(JSON.stringify(topLevel) === JSON.stringify(utf8Sort(EXPECTED_STAGE_TOP_LEVEL)), "staging top-level members drifted before package finalization");
  for (const path of [PACKAGE_EXPORTS_FILE, PACKAGE_TYPE_EXPORTS_FILE, PACKED_PATHS_FILE, BASELINE_COMMAND_SNAPSHOT_FILE, BASELINE_OCLIF_MANIFEST_FILE, PACKAGE_METADATA_FILE, ROOT_CHECKSUM_FILE]) {
    assert(!existsSync(join(out, path)), `${path} already exists`);
  }
  const stageFilesBeforePackage = expectedStageFilesBeforePackage();
  assertExactTree(out, stageFilesBeforePackage, "staging before package finalization");

  const captureMetadata = JSON.parse(readFileSync(join(out, "capture-metadata.json"), "utf8"));
  assert(captureMetadata?.base_commit === BASE_COMMIT, "root capture metadata has the wrong base commit");
  assert(captureMetadata?.source_root === sourceRoot, "root capture metadata has the wrong canonical source root");
  assert(
    /^[0-9a-f]{64}$/.test(captureMetadata?.source_snapshot_sha256),
    "root capture metadata lacks the V01 private source digest",
  );
  assert(captureMetadata?.canonical_staging_root === out, "root capture metadata has the wrong canonical staging root");
  assertRecordedIdentity(captureMetadata?.source_identity, sourceIdentity, "source identity");
  assertRecordedIdentity(captureMetadata?.staging_root_identity, outIdentity, "staging root identity");
  assert(captureMetadata?.external_drivers?.package_oracle_capture?.path === scriptPath, "root metadata has the wrong package driver path");
  assert(captureMetadata?.external_drivers?.package_oracle_capture?.sha256 === scriptHashBefore, "root metadata has the wrong package driver hash");
  assert(captureMetadata?.external_drivers?.clean_process_launcher?.path === cleanLauncherPath, "root metadata has the wrong clean process launcher path");
  assert(captureMetadata?.external_drivers?.clean_process_launcher?.sha256 === cleanLauncherHashBefore, "root metadata has the wrong clean process launcher hash");
  const v01Driver = captureMetadata?.external_drivers?.v01_oracle_capture;
  assert(typeof v01Driver?.path === "string" && typeof v01Driver?.sha256 === "string", "root metadata lacks the V01 driver binding");
  assert(existsSync(v01Driver.path) && rawFileSha256(v01Driver.path) === v01Driver.sha256, "V01 driver binding no longer verifies");
  const runRecoverInventory = captureMetadata?.run_recover_zero_complete_event_oracles;
  assert(typeof runRecoverInventory === "object" && runRecoverInventory !== null, "root metadata lacks the run recover oracle inventory");
  assert(runRecoverInventory.stage_subtree === RUN_RECOVER_ORACLE_ROOT, "root metadata has the wrong run recover subtree");
  assert(JSON.stringify(runRecoverInventory.case_order) === JSON.stringify(RUN_RECOVER_CASE_NAMES), "root metadata has the wrong run recover cases");
  assert(
    JSON.stringify(runRecoverInventory.expected_exit_by_case) === JSON.stringify(RUN_RECOVER_EXPECTED_EXITS),
    "root metadata has the wrong run recover exits",
  );
  assert(JSON.stringify(runRecoverInventory.modes) === JSON.stringify(RUN_RECOVER_MODES), "root metadata has the wrong run recover modes");
  assert(
    JSON.stringify(runRecoverInventory.raw_members_per_case) === JSON.stringify(RUN_RECOVER_RAW_MEMBERS),
    "root metadata has the wrong run recover raw members",
  );
  assert(runRecoverInventory.cli_entrypoint?.relative_path === "bin/dev.js", "root metadata has the wrong run recover CLI entrypoint");
  assert(
    runRecoverInventory.cli_entrypoint?.sha256 === rawFileSha256(join(sourceRoot, "bin", "dev.js")),
    "root metadata has the wrong run recover CLI hash",
  );
  assert(
    readFileSync(join(out, "README.md"), "utf8").includes(`The ${RUN_RECOVER_ORACLE_ROOT}/ subtree`),
    "root README lacks the run recover oracle subtree",
  );

  const discoveredCases = relativeFiles(join(out, "provenance"))
    .filter((path) => path.endsWith("/SHA256SUMS") || path === "SHA256SUMS")
    .map((path) => path.slice(0, -"/SHA256SUMS".length));
  assert(JSON.stringify(discoveredCases) === JSON.stringify(utf8Sort(EXPECTED_PROVENANCE_CASES)), "provenance case inventory drifted");
  const expectedProvenanceFiles = expectedProvenancePaths();
  assert(
    JSON.stringify(relativeFiles(join(out, "provenance"))) === JSON.stringify(expectedProvenanceFiles),
    "provenance contains a missing or extra sidecar",
  );
  for (const casePath of discoveredCases) verifyCaseChecksums(out, casePath);

  const packedPaths = listPackedPaths(inspectedTarball, verifiedTarball.root);
  const {
    packedIndexHash,
    packedDeclarationHash,
    compilerPackageHash,
    compilerEntrypointHash,
    runtimeExportsText,
    typeExportsText,
    normalizedOclifManifestText,
    baselineCommandSnapshotText,
    pnpmStoreBinding,
    exportCounts,
  } = capturePackedPackageExports(
    executionSourceRoot,
    inspectedTarball,
    packedPaths,
  );
  const packedPathsText = `${packedPaths.join("\n")}\n`;
  assertArchiveMatchesFingerprint(
    inspectedTarballPath,
    inspectedTarballFingerprint,
    "verified tarball after inspection",
  );
  assertArchiveMatchesFingerprint(
    tarball,
    tarballFingerprint,
    "tarball after listing",
  );
  writeFileSync(join(out, PACKAGE_EXPORTS_FILE), runtimeExportsText, { flag: "wx" });
  writeFileSync(join(out, PACKAGE_TYPE_EXPORTS_FILE), typeExportsText, { flag: "wx" });
  writeFileSync(join(out, PACKED_PATHS_FILE), packedPathsText, { flag: "wx" });
  writeFileSync(join(out, BASELINE_COMMAND_SNAPSHOT_FILE), baselineCommandSnapshotText, { flag: "wx" });
  writeFileSync(join(out, BASELINE_OCLIF_MANIFEST_FILE), normalizedOclifManifestText, { flag: "wx" });

  const commandLine = [
    `"${cleanLauncherPath}"`,
    "node",
    `"${scriptPath}"`,
    `--source-root "${requestedSourceRoot}"`,
    `--tarball "${requestedTarball}"`,
    `--out "${requestedOut}"`,
    `--assert-base-commit ${BASE_COMMIT}`,
  ].join(" ");
  const metadata = {
    base_commit: BASE_COMMIT,
    source_root: sourceRoot,
    execution_source_snapshot: {
      root: executionSourceRoot,
      root_identity: executionSourceIdentity,
      tree_sha256: sourceSnapshot.execution_tree.tree_sha256,
      entry_count: sourceSnapshot.execution_tree.entry_count,
      byte_count: sourceSnapshot.execution_tree.byte_count,
    },
    staging_root: out,
    tarball_path: tarball,
    toolchain: { node: process.version, pnpm: pnpmVersion, typescript: EXPECTED_TYPESCRIPT_VERSION },
    tarball_provenance: tarballProvenance,
    source_hashes: {
      "package.json": rawFileSha256(join(sourceRoot, "package.json")),
      "pnpm-lock.yaml": rawFileSha256(join(sourceRoot, "pnpm-lock.yaml")),
      "pnpm-workspace.yaml": rawFileSha256(join(sourceRoot, "pnpm-workspace.yaml")),
      "packed:dist/index.js": packedIndexHash,
      "packed:dist/index.d.ts": packedDeclarationHash,
      "installed:typescript/package.json": compilerPackageHash,
      "installed:typescript/lib/typescript.js": compilerEntrypointHash,
      tarball: tarballFingerprint.sha256,
    },
    oracle_hashes: {
      [PACKAGE_EXPORTS_FILE]: rawSha256(runtimeExportsText),
      [PACKAGE_TYPE_EXPORTS_FILE]: rawSha256(typeExportsText),
      [PACKED_PATHS_FILE]: rawSha256(packedPathsText),
      [BASELINE_COMMAND_SNAPSHOT_FILE]: rawSha256(baselineCommandSnapshotText),
      [BASELINE_OCLIF_MANIFEST_FILE]: rawSha256(normalizedOclifManifestText),
    },
    export_counts: exportCounts,
    dependency_probe: {
      runtime_mode: "production-only",
      type_mode: "complete-baseline",
      install: "offline frozen-lockfile frozen-store ignore-scripts ignore-pnpmfile no-hoist no-runtime package-import-method=copy verify-store-integrity",
      child_permissions: "read-probe-root-only; no network, write, child process, worker, addon, global search path, NODE_OPTIONS, NODE_PATH, or loader variables",
      pnpm_store_binding: pnpmStoreBinding,
    },
    stage_inventory: {
      provenance_cases: EXPECTED_PROVENANCE_CASES,
      run_recover_zero_complete_event_oracles: {
        stage_subtree: RUN_RECOVER_ORACLE_ROOT,
        case_order: RUN_RECOVER_CASE_NAMES,
        expected_exit_by_case: RUN_RECOVER_EXPECTED_EXITS,
        modes: RUN_RECOVER_MODES,
        raw_members_per_case: RUN_RECOVER_RAW_MEMBERS,
        raw_paths: RUN_RECOVER_CASE_NAMES.flatMap((caseName) =>
          RUN_RECOVER_RAW_MEMBERS.map((member) => `${RUN_RECOVER_ORACLE_ROOT}/${caseName}/${member}`),
        ),
        provenance_paths: RUN_RECOVER_CASE_NAMES.flatMap((caseName) => [
          `provenance/${RUN_RECOVER_ORACLE_ROOT}/${caseName}/SHA256SUMS`,
          `provenance/${RUN_RECOVER_ORACLE_ROOT}/${caseName}/capture-metadata.json`,
        ]),
      },
    },
    commands: {
      invocation: commandLine,
      fresh_pack_proof: "pnpm pack --pack-destination <private-empty-root>; equal ordered safe member and tar-metadata inventories; byte equality for every member except exact-format oclif.manifest.json recursive object-key ordering; retained fresh bytes drive listing, extraction, and import",
      runtime_exports: "install exact production dependencies in a private offline frozen root; extract retained verified archive as node_modules/loopeix; permission-restricted bare import resolving to packed dist/index.js; Object.keys(); UTF-8 sort",
      type_exports: "install exact complete dependencies in a disjoint private offline frozen root; extract retained verified archive as node_modules/loopeix; load exact TypeScript 6.0.3 under read-only permissions; resolve bare loopeix to packed dist/index.d.ts; require zero diagnostics; classify checker exports; UTF-8 sort",
      packed_paths: "pipe exact retained verified archive bytes to tar -tzf -; strip exactly one package/ prefix; UTF-8 sort",
      command_inventory: "extract retained verified oclif.manifest.json; replace only the exact canonical source-root default with <S35_BASELINE_SOURCE_ROOT>; recursively UTF-8-sort object keys; project the exact 15 command IDs with full args, flags, aliases, strictness, JSON capability, and relative module path",
    },
    script_path: scriptPath,
    script_sha256_before: scriptHashBefore,
    script_sha256_after: scriptHashBefore,
    clean_process_launcher: {
      path: cleanLauncherPath,
      sha256_before: cleanLauncherHashBefore,
      sha256_after: cleanLauncherHashBefore,
    },
  };
  writeFileSync(join(out, PACKAGE_METADATA_FILE), `${JSON.stringify(metadata, null, 2)}\n`, { flag: "wx" });
  const packageOracleFiles = [
    PACKAGE_EXPORTS_FILE,
    PACKAGE_TYPE_EXPORTS_FILE,
    PACKED_PATHS_FILE,
    BASELINE_COMMAND_SNAPSHOT_FILE,
    BASELINE_OCLIF_MANIFEST_FILE,
    PACKAGE_METADATA_FILE,
  ];
  stageFilesBeforeRootChecksum = utf8Sort([...stageFilesBeforePackage, ...packageOracleFiles]);
  assertExactTree(out, stageFilesBeforeRootChecksum, "staging before root checksum");

  assert(rawFileSha256(scriptPath) === scriptHashBefore, "package-oracle driver changed during capture");
  assert(
    rawFileSha256(admittedScriptPath) === scriptHashBefore,
    "admitted package capture driver changed during capture",
  );
  assert(rawFileSha256(cleanLauncherPath) === cleanLauncherHashBefore, "clean process launcher changed during package capture");
  assertSourceSnapshot(sourceSnapshot);
  assertSameIdentity(sourceRoot, sourceIdentity, "source root");
  assertSameIdentity(out, outIdentity, "staging root");
  assertArchiveMatchesFingerprint(tarball, tarballFingerprint, "tarball during package capture");
  assertDetachedSourceSnapshot(sourceRoot, sourceIdentity);
  for (const casePath of discoveredCases) verifyCaseChecksums(out, casePath);
  assertOversizedInventory(out);
  assertExactTree(out, stageFilesBeforeRootChecksum, "staging before private cleanup");
  assertSameIdentity(out, outIdentity, "staging root before private cleanup");
  assertArchiveMatchesFingerprint(
    tarball,
    tarballFingerprint,
    "tarball before private cleanup",
  );
  assertArchiveMatchesFingerprint(
    inspectedTarballPath,
    inspectedTarballFingerprint,
    "verified tarball before private cleanup",
  );
  assert(rawFileSha256(scriptPath) === scriptHashBefore, "package-oracle driver changed before private cleanup");
  assert(
    rawFileSha256(admittedScriptPath) === scriptHashBefore,
    "admitted package capture driver changed before private cleanup",
  );
  assert(rawFileSha256(cleanLauncherPath) === cleanLauncherHashBefore, "clean process launcher changed before private cleanup");
  } catch (error) {
    operationFailure = { error };
    throw error;
  } finally {
    const cleanupActions = [];
    if (verifiedTarball !== null) {
      cleanupActions.push(
        () => verifiedTarball.inspected.bytes.fill(0),
        () => rmSync(verifiedTarball.root, { recursive: true, force: true }),
      );
    }
    if (suppliedTarballPin !== null) {
      cleanupActions.push(() => suppliedTarballPin.bytes.fill(0));
    }
    cleanupActions.push(() => {
      removeSourceSnapshot(sourceSnapshot);
      sourceSnapshotRemoved = true;
    });
    runPrivateCleanupActions(
      operationFailure,
      cleanupActions,
      "package oracle failed and private resource cleanup was incomplete",
    );
  }
  assert(sourceSnapshotRemoved, "private package source snapshot was not removed");
  assert(tarballFingerprint !== null, "tarball fingerprint was not retained through private cleanup");
  assert(stageFilesBeforeRootChecksum !== null, "pre-checksum inventory was not retained through private cleanup");
  finalizePackageOracleStage(out, {
    beforePublish: () => {
      assertOversizedInventory(out);
      assertExactTree(out, stageFilesBeforeRootChecksum, "staging after private cleanup");
      assertSameIdentity(sourceRoot, sourceIdentity, "source root after private cleanup");
      assertSameIdentity(out, outIdentity, "staging root after private cleanup");
      assertArchiveMatchesFingerprint(
        tarball,
        tarballFingerprint,
        "tarball after private cleanup",
      );
      assertDetachedSourceSnapshot(sourceRoot, sourceIdentity);
      assert(rawFileSha256(scriptPath) === scriptHashBefore, "package-oracle driver changed after private cleanup");
      assert(
        rawFileSha256(admittedScriptPath) === scriptHashBefore,
        "admitted package capture driver changed after private cleanup",
      );
      assert(rawFileSha256(cleanLauncherPath) === cleanLauncherHashBefore, "clean process launcher changed after private cleanup");
    },
    afterPublish: () => {
      assertOversizedInventory(out);
      assertExactTree(out, [...stageFilesBeforeRootChecksum, ROOT_CHECKSUM_FILE], "finalized staging");
      assertSameIdentity(out, outIdentity, "staging root after finalization");
      assertArchiveMatchesFingerprint(
        tarball,
        tarballFingerprint,
        "tarball after finalization",
      );
      assertDetachedSourceSnapshot(sourceRoot, sourceIdentity);
      assert(rawFileSha256(scriptPath) === scriptHashBefore, "package-oracle driver changed after finalization");
      assert(
        rawFileSha256(admittedScriptPath) === scriptHashBefore,
        "admitted package capture driver changed after finalization",
      );
      assert(rawFileSha256(cleanLauncherPath) === cleanLauncherHashBefore, "clean process launcher changed after finalization");
    },
    announce: () => {
      announceCaptureSuccess(out, writeSync, transactionalSuccessFd);
    },
  });
}

if (
  process.argv[1] &&
  realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))
) {
  await main();
}
