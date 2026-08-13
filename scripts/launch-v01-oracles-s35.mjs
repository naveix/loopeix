#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  opendirSync,
  readFileSync,
  readlinkSync,
  readSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const BASE_COMMIT = "13a8906fdd32b005d29c1eb07ee54f55f80c7fc2";
const EXPECTED_NODE_VERSION = "v26.0.0";
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
const EXPECTED_DRIVER_SHA256 = "ad1e7c54572469d8ae227337ec99dd44b66bb24d0635d66b50c8aa47ead33fb0";
const EXPECTED_PNPM_LOCK_SHA256 = "7339169a4626b2e2af3d9e9bc0d13da340f09b7ee41314a235cc9c12b484453c";
const EXPECTED_TSX_VERSION = "4.22.5";
const EXPECTED_TSX_LOCK_INTEGRITY = "sha512-F7JnSfPl5ASt6LqwWyUQ3T8BwN3q0eQEbFMYa2iRWaVQmmudo0d7fRmwM4O002gsvW1bs0yBYioutsAjqLJMvQ==";
const EXPECTED_TSX_PACKAGE_SHA256 = "7aa86133a2b573a814e45558c0317d2a94aec491960717f3d81f768dea6f9d43";
const EXPECTED_TSX_PREFLIGHT_SHA256 = "5ef95c5c4b5875dbc270b9591676a2138e4df82bcebde945eebb1eadf721b192";
const EXPECTED_TSX_LOADER_SHA256 = "f377ce5933ad7ba16a54435ac143dddb2178ffcf9e380c54048a4cfadb8959fc";
const PACKAGE_RUNTIME_TREE_EXCLUSIONS = Object.freeze(["node_modules"]);
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
const SOURCE_TREE_MAX_DEPTH = 32;
const SOURCE_TREE_MAX_ENTRIES = 20_000;
const SOURCE_TREE_MAX_BYTES = 256 * 1024 * 1024;
const PNPM_MODULES_METADATA_MAX_BYTES = 1_048_576;

function fail(message) {
  throw new Error(`S35 V01 capture launcher failed: ${message}`);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function sha256File(path) {
  const captured = readBoundedRuntimeFile(path);
  try {
    return createHash("sha256").update(captured.bytes).digest("hex");
  } finally {
    captured.bytes.fill(0);
  }
}

function containsPath(parent, child) {
  return parent === child || child.startsWith(`${parent}${sep}`);
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

function admittedPnpmPath() {
  const admittedNodePath = realpathSync(process.execPath);
  const admittedNodeRoot = dirname(dirname(admittedNodePath));
  assert(
    admittedNodeRoot.endsWith(`${sep}admitted${sep}node`),
    "capture Node executable is outside the admitted runtime layout",
  );
  return join(dirname(admittedNodeRoot), "pnpm", "bin", "pnpm.mjs");
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

function command(commandName, args, cwd, environment = sanitizedChildEnvironment(process.env)) {
  assert(
    isAbsolute(cwd) && realpathSync(cwd) === cwd,
    `${commandName} child working directory is not canonical`,
  );
  const executable = commandName === "pnpm" ? assertTrustedExecutable("node") : assertTrustedExecutable(commandName);
  const childArgs = commandName === "pnpm" ? [assertTrustedExecutable("pnpm"), ...args] : args;
  const invoke = () => execFileSync(executable, childArgs, {
      cwd,
      encoding: "utf8",
      env: environment,
      killSignal: "SIGKILL",
      maxBuffer: CHILD_PROCESS_MAX_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: CHILD_PROCESS_TIMEOUT_MS,
    }).trim();
  return commandName === "pnpm" ? withProcessUmask(0o022, invoke) : invoke();
}

function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    assert(flag !== undefined && value !== undefined, "arguments must be flag/value pairs");
    assert(
      ["--driver", "--source-root", "--out", "--assert-base-commit"].includes(flag),
      `unknown argument ${flag}`,
    );
    assert(!values.has(flag), `duplicate argument ${flag}`);
    values.set(flag, value);
  }
  const driver = values.get("--driver");
  const sourceRoot = values.get("--source-root");
  const out = values.get("--out");
  const assertedCommit = values.get("--assert-base-commit");
  assert(driver !== undefined, "--driver is required");
  assert(sourceRoot !== undefined, "--source-root is required");
  assert(out !== undefined, "--out is required");
  assert(assertedCommit !== undefined, "--assert-base-commit is required");
  assert(
    isAbsolute(driver) && isAbsolute(sourceRoot) && isAbsolute(out),
    "--driver, --source-root, and --out must be absolute paths",
  );
  return {
    driver: resolve(driver),
    sourceRoot: resolve(sourceRoot),
    out: resolve(out),
    assertedCommit,
  };
}

export function assertCleanLauncherEnvironment(environment) {
  assert(
    environment.NODE_OPTIONS === undefined &&
      environment.NODE_PATH === undefined &&
      !Object.keys(environment).some((name) => name.startsWith("TSX_")),
    "capture launcher environment must not contain NODE_OPTIONS, NODE_PATH, or TSX_*",
  );
}

function captureRuntimeFileBytes(sourceRoot, requestedPath, expectedSha256, escapeMessage) {
  assert(existsSync(requestedPath), `capture runtime file is absent: ${requestedPath}`);
  const resolvedPath = realpathSync(requestedPath);
  assert(containsPath(sourceRoot, resolvedPath), escapeMessage);
  const captured = readBoundedRuntimeFile(resolvedPath);
  try {
    const sha256 = createHash("sha256").update(captured.bytes).digest("hex");
    assert(
      sha256 === expectedSha256,
      `capture runtime hash drifted: ${relative(sourceRoot, resolvedPath)}`,
    );
    return {
      bytes: captured.bytes,
      identity: {
        requested_path: requestedPath,
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

function captureRuntimeFile(sourceRoot, requestedPath, expectedSha256, escapeMessage) {
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

function captureRuntimeJson(sourceRoot, requestedPath, expectedSha256, escapeMessage) {
  const captured = captureRuntimeFileBytes(
    sourceRoot,
    requestedPath,
    expectedSha256,
    escapeMessage,
  );
  try {
    return {
      identity: captured.identity,
      value: JSON.parse(captured.bytes.toString("utf8")),
    };
  } finally {
    captured.bytes.fill(0);
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameDirectoryIdentity(left, right) {
  return sameFileIdentity(left, right) &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs;
}

function readBoundedRuntimeFile(path) {
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
  sourceRoot,
  requestedRoot,
  expected,
  label,
  snapshotRoot = null,
  excludedTopLevelNames = [],
) {
  assert(existsSync(requestedRoot), `${label} package tree is absent`);
  const resolvedRoot = realpathSync(requestedRoot);
  assert(containsPath(sourceRoot, resolvedRoot), `${label} package tree resolved outside the detached source root`);
  const rootStat = statSync(resolvedRoot);
  assert(rootStat.isDirectory(), `${label} package tree root is not a directory`);
  if (snapshotRoot !== null) {
    assert(isAbsolute(snapshotRoot), `${label} runtime snapshot root is not absolute`);
    assert(!existsSync(snapshotRoot), `${label} runtime snapshot root already exists`);
    mkdirSync(snapshotRoot, { recursive: true, mode: rootStat.mode & 0o777 });
    chmodSync(snapshotRoot, rootStat.mode & 0o777);
  }
  const entries = [];
  let fileCount = 0;
  let byteCount = 0;

  function walk(directory, relativeDirectory, depth, expectedDirectoryStat) {
    assert(depth <= MAX_RUNTIME_TREE_DEPTH, `${label} package tree exceeds its depth limit`);
    const directoryStat = lstatSync(directory);
    assert(
      directoryStat.isDirectory() &&
        sameDirectoryIdentity(expectedDirectoryStat, directoryStat),
      `${label} package tree directory identity changed before enumeration`,
    );
    const names = [];
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
      const snapshotPath =
        snapshotRoot === null ? null : join(snapshotRoot, relativePath);
      const entryStat = lstatSync(path);
      assert(entries.length < MAX_RUNTIME_TREE_ENTRIES, `${label} package tree exceeds its entry limit`);
      if (entryStat.isDirectory()) {
        entries.push({ path: relativePath, type: "directory", mode: entryStat.mode & 0o777 });
        if (snapshotPath !== null) {
          mkdirSync(snapshotPath, { mode: entryStat.mode & 0o777 });
          chmodSync(snapshotPath, entryStat.mode & 0o777);
        }
        walk(path, relativePath, depth + 1, entryStat);
        continue;
      }
      assert(entryStat.isFile(), `${label} package tree contains a symlink or special entry: ${relativePath}`);
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
          sha256: createHash("sha256").update(bytes).digest("hex"),
        });
        if (snapshotPath !== null) {
          writeFileSync(snapshotPath, bytes, {
            flag: "wx",
            mode,
          });
          chmodSync(snapshotPath, mode);
        }
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
  const treeSha256 = createHash("sha256")
    .update(JSON.stringify(entries))
    .digest("hex");
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

export function captureRuntimeIdentity(
  sourceRoot,
  { runtimeSnapshotRoot = null } = {},
) {
  const lock = captureRuntimeFile(
    sourceRoot,
    join(sourceRoot, "pnpm-lock.yaml"),
    EXPECTED_PNPM_LOCK_SHA256,
    "pnpm lockfile resolved outside the detached source root",
  );
  const requestedTsxRoot = join(sourceRoot, "node_modules", "tsx");
  assert(existsSync(requestedTsxRoot), "detached tsx package is absent");
  const tsxRoot = realpathSync(requestedTsxRoot);
  assert(containsPath(sourceRoot, tsxRoot), "tsx package resolved outside the detached source root");
  const tsxPackagePath = join(requestedTsxRoot, "package.json");
  const preflightPath = join(requestedTsxRoot, "dist", "preflight.cjs");
  const loaderPath = join(requestedTsxRoot, "dist", "loader.mjs");
  const { identity: tsxPackage, value: tsxPackageJson } = captureRuntimeJson(
    sourceRoot,
    tsxPackagePath,
    EXPECTED_TSX_PACKAGE_SHA256,
    "tsx package resolved outside the detached source root",
  );
  assert(tsxPackageJson.version === EXPECTED_TSX_VERSION, `capture tsx must be ${EXPECTED_TSX_VERSION}`);
  const tsxTree = captureRuntimeTree(
    sourceRoot,
    requestedTsxRoot,
    EXPECTED_TSX_TREE,
    "tsx",
    runtimeSnapshotRoot === null
      ? null
      : join(runtimeSnapshotRoot, "node_modules", "tsx"),
    PACKAGE_RUNTIME_TREE_EXCLUSIONS,
  );
  const preflight = captureRuntimeFile(
    sourceRoot,
    preflightPath,
    EXPECTED_TSX_PREFLIGHT_SHA256,
    "tsx preflight resolved outside the detached source root",
  );
  const loader = captureRuntimeFile(
    sourceRoot,
    loaderPath,
    EXPECTED_TSX_LOADER_SHA256,
    "tsx loader resolved outside the detached source root",
  );

  const requestedEsbuildRoot = join(dirname(tsxRoot), "esbuild");
  assert(existsSync(requestedEsbuildRoot), "detached esbuild package is absent");
  const esbuildRoot = realpathSync(requestedEsbuildRoot);
  assert(containsPath(sourceRoot, esbuildRoot), "esbuild package resolved outside the detached source root");
  const esbuildPackagePath = join(requestedEsbuildRoot, "package.json");
  const { identity: esbuildPackage, value: esbuildPackageJson } = captureRuntimeJson(
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
    runtimeSnapshotRoot === null
      ? null
      : join(runtimeSnapshotRoot, "node_modules", "esbuild"),
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
  const { identity: platformPackage, value: platformPackageJson } = captureRuntimeJson(
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
    runtimeSnapshotRoot === null
      ? null
      : join(runtimeSnapshotRoot, "node_modules", "@esbuild", "darwin-arm64"),
  );

  return {
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

function assertRuntimeSnapshot(runtimeSnapshotRoot) {
  const nodeModules = join(runtimeSnapshotRoot, "node_modules");
  const tsxRoot = join(nodeModules, "tsx");
  const esbuildRoot = join(nodeModules, "esbuild");
  const platformRoot = join(nodeModules, "@esbuild", "darwin-arm64");
  const preflightPath = join(tsxRoot, "dist", "preflight.cjs");
  const loaderPath = join(tsxRoot, "dist", "loader.mjs");
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
    null,
    PACKAGE_RUNTIME_TREE_EXCLUSIONS,
  );
  captureRuntimeTree(
    runtimeSnapshotRoot,
    esbuildRoot,
    EXPECTED_ESBUILD_TREE,
    "snapshot esbuild",
    null,
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
    preflightPath,
    EXPECTED_TSX_PREFLIGHT_SHA256,
    "snapshot tsx preflight resolved outside the runtime snapshot",
  );
  captureRuntimeFile(
    runtimeSnapshotRoot,
    loaderPath,
    EXPECTED_TSX_LOADER_SHA256,
    "snapshot tsx loader resolved outside the runtime snapshot",
  );
  return { loader_path: loaderPath, preflight_path: preflightPath };
}

export function materializeRuntimeSnapshot(
  sourceRoot,
  out,
  environment = process.env,
) {
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
  const operationStat = lstatSync(operationRoot);
  assert(
    operationStat.isDirectory() &&
      !operationStat.isSymbolicLink() &&
      (operationStat.mode & 0o077) === 0,
    "capture operation root is not a private direct directory",
  );
  assert(
    isAbsolute(sourceRoot) && realpathSync(sourceRoot) === sourceRoot,
    "capture source root is not canonical",
  );
  const sourceInsideOperationRoot = containsPath(operationRoot, sourceRoot);
  if (sourceInsideOperationRoot) {
    const sourceStat = lstatSync(sourceRoot);
    assert(
      dirname(sourceRoot) === operationRoot &&
        sourceStat.isDirectory() &&
        !sourceStat.isSymbolicLink() &&
        (sourceStat.mode & 0o077) === 0,
      "operation-local source is not a private direct child of the operation root",
    );
  } else {
    assert(
      !containsPath(sourceRoot, operationRoot),
      "external source contains the capture operation root",
    );
  }
  assert(
    !containsPath(out, operationRoot) &&
      !containsPath(operationRoot, out) &&
      !containsPath(out, sourceRoot) &&
      !containsPath(sourceRoot, out),
    "capture source, operation, or staging roots overlap",
  );
  const root = mkdtempSync(join(operationRoot, "loopeix-s35-runtime."));
  try {
    chmodSync(root, 0o700);
    const identity = captureRuntimeIdentity(sourceRoot, {
      runtimeSnapshotRoot: root,
    });
    const hooks = assertRuntimeSnapshot(root);
    return { ...hooks, identity, root };
  } catch (error) {
    runPrivateCleanupActions(
      { error },
      [() => rmSync(root, { recursive: true, force: true })],
      "runtime snapshot construction failed and cleanup was incomplete",
    );
    throw error;
  }
}

function assertOrdinaryIndexEntries(sourceRoot) {
  const git = assertTrustedExecutable("git");
  const taggedBytes = execFileSync(
    git,
    ["-C", sourceRoot, "ls-files", "--cached", "-v", "-z", "--"],
    {
      cwd: sourceRoot,
      encoding: "buffer",
      env: sanitizedChildEnvironment(process.env),
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
    git,
    ["-C", sourceRoot, "ls-files", "--cached", "--stage", "-z", "--"],
    {
      cwd: sourceRoot,
      encoding: "buffer",
      env: sanitizedChildEnvironment(process.env),
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

function assertDetachedOriginSnapshot(sourceRoot) {
  assert(command("git", ["-C", sourceRoot, "rev-parse", "--show-toplevel"], sourceRoot) === sourceRoot, "source root is not the Git worktree root");
  assert(command("git", ["-C", sourceRoot, "rev-parse", "HEAD"], sourceRoot) === BASE_COMMIT, "source worktree is at the wrong commit");
  assert(command("git", ["-C", sourceRoot, "rev-parse", "--abbrev-ref", "HEAD"], sourceRoot) === "HEAD", "source worktree is not detached");
  assertOrdinaryIndexEntries(sourceRoot);
  assert(command("git", ["-C", sourceRoot, "status", "--porcelain", "--untracked-files=all"], sourceRoot) === "", "source worktree is not clean");
}

function directDirectoryIdentity(path, label) {
  assert(isAbsolute(path) && realpathSync(path) === path, `${label} is not canonical`);
  const stat = lstatSync(path);
  assert(stat.isDirectory() && !stat.isSymbolicLink(), `${label} is not a direct directory`);
  return Object.freeze({ dev: stat.dev, ino: stat.ino, mode: stat.mode & 0o777 });
}

function assertDirectDirectoryIdentity(path, expected, label) {
  const actual = directDirectoryIdentity(path, label);
  assert(
    actual.dev === expected.dev && actual.ino === expected.ino && actual.mode === expected.mode,
    `${label} identity changed`,
  );
}

function readSourceStoreBinding(sourceRoot) {
  const metadataPath = join(sourceRoot, "node_modules", ".modules.yaml");
  const captured = readBoundedRuntimeFile(metadataPath);
  try {
    assert(captured.bytes.length <= PNPM_MODULES_METADATA_MAX_BYTES, "installed pnpm metadata exceeds its byte limit");
    const metadata = JSON.parse(captured.bytes.toString("utf8"));
    assert(metadata.packageManager === "pnpm@11.9.0", "installed pnpm package manager drifted");
    assert(metadata.layoutVersion === 5, "installed pnpm layout version drifted");
    assert(metadata.nodeLinker === "isolated", "installed pnpm node linker drifted");
    assert(metadata.virtualStoreDir === ".pnpm", "installed pnpm virtual store drifted");
    assert(typeof metadata.storeDir === "string" && isAbsolute(metadata.storeDir), "installed pnpm store path is invalid");
    const storePath = realpathSync(metadata.storeDir);
    assert(storePath === metadata.storeDir, "installed pnpm store path is not canonical");
    assert(
      !containsPath(sourceRoot, storePath) && !containsPath(storePath, sourceRoot),
      "installed pnpm store overlaps the detached source",
    );
    return Object.freeze({
      metadata_path: metadataPath,
      metadata_sha256: createHash("sha256").update(captured.bytes).digest("hex"),
      store_path: storePath,
      store_identity: directDirectoryIdentity(storePath, "installed pnpm store"),
    });
  } finally {
    captured.bytes.fill(0);
  }
}

function assertSourceStoreBinding(binding) {
  const captured = readBoundedRuntimeFile(binding.metadata_path);
  try {
    assert(
      createHash("sha256").update(captured.bytes).digest("hex") === binding.metadata_sha256,
      "installed pnpm metadata changed",
    );
  } finally {
    captured.bytes.fill(0);
  }
  assertDirectDirectoryIdentity(binding.store_path, binding.store_identity, "installed pnpm store");
}

function normalizePrivateEsbuildBinary(root) {
  const tsxRoot = realpathSync(join(root, "node_modules", "tsx"));
  const esbuildRoot = realpathSync(join(dirname(tsxRoot), "esbuild"));
  const platformBinaryPath = join(
    dirname(esbuildRoot),
    "@esbuild",
    "darwin-arm64",
    "bin",
    "esbuild",
  );
  const destinationPath = join(esbuildRoot, "bin", "esbuild");
  const temporaryPath = join(dirname(destinationPath), ".loopeix-s35-esbuild.part");
  assert(!existsSync(temporaryPath), "private esbuild normalization temporary file already exists");
  const captured = captureRuntimeFileBytes(
    root,
    platformBinaryPath,
    EXPECTED_ESBUILD_BINARY_SHA256,
    "private esbuild platform binary resolved outside the source snapshot",
  );
  try {
    const destinationStat = lstatSync(destinationPath);
    assert(
      destinationStat.isFile() && !destinationStat.isSymbolicLink(),
      "private esbuild destination is not a direct regular file",
    );
    writeFileSync(temporaryPath, captured.bytes, { flag: "wx", mode: 0o755 });
    chmodSync(temporaryPath, 0o755);
    renameSync(temporaryPath, destinationPath);
    captureRuntimeFile(
      root,
      destinationPath,
      EXPECTED_ESBUILD_BINARY_SHA256,
      "normalized private esbuild binary resolved outside the source snapshot",
    );
  } finally {
    captured.bytes.fill(0);
    if (existsSync(temporaryPath)) rmSync(temporaryPath, { force: true });
  }
}

function captureSourceExecutionTree(root, originRoot) {
  const entries = [];
  let byteCount = 0;
  const originBytes = Buffer.from(originRoot, "utf8");

  function walk(directory, relativeDirectory, depth, expectedDirectoryStat) {
    assert(depth <= SOURCE_TREE_MAX_DEPTH, "private source tree exceeds its depth limit");
    const directoryStat = lstatSync(directory);
    assert(
      directoryStat.isDirectory() && sameDirectoryIdentity(expectedDirectoryStat, directoryStat),
      "private source directory identity changed before enumeration",
    );
    const names = [];
    const handle = opendirSync(directory);
    try {
      for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
        assert(entries.length + names.length < SOURCE_TREE_MAX_ENTRIES, "private source tree exceeds its entry limit");
        names.push(entry.name);
      }
    } finally {
      handle.closeSync();
    }
    names.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
    for (const name of names) {
      if (relativeDirectory === "" && name === ".git") continue;
      const path = join(directory, name);
      const relativePath = relativeDirectory === "" ? name : `${relativeDirectory}/${name}`;
      const stat = lstatSync(path);
      assert(entries.length < SOURCE_TREE_MAX_ENTRIES, "private source tree exceeds its entry limit");
      if (stat.isDirectory()) {
        entries.push({ path: relativePath, type: "directory", mode: stat.mode & 0o777 });
        walk(path, relativePath, depth + 1, stat);
        continue;
      }
      if (stat.isSymbolicLink()) {
        const target = readlinkSync(path);
        const resolved = realpathSync(path);
        assert(containsPath(root, resolved), `private source symlink escapes its root: ${relativePath}`);
        entries.push({ path: relativePath, type: "symlink", mode: stat.mode & 0o777, target });
        continue;
      }
      assert(stat.isFile(), `private source tree contains a special entry: ${relativePath}`);
      const captured = readBoundedRuntimeFile(path);
      try {
        byteCount += captured.bytes.length;
        assert(byteCount <= SOURCE_TREE_MAX_BYTES, "private source tree exceeds its byte limit");
        assert(
          captured.bytes.indexOf(originBytes) === -1,
          `private source file reopens the mutable origin: ${relativePath}`,
        );
        entries.push({
          path: relativePath,
          type: "file",
          mode: captured.mode,
          size: captured.bytes.length,
          sha256: createHash("sha256").update(captured.bytes).digest("hex"),
        });
      } finally {
        captured.bytes.fill(0);
      }
    }
    assert(
      sameDirectoryIdentity(directoryStat, lstatSync(directory)),
      "private source directory identity changed during enumeration",
    );
  }

  const rootStat = lstatSync(root);
  walk(root, "", 0, rootStat);
  return Object.freeze({
    entry_count: entries.length,
    byte_count: byteCount,
    tree_sha256: createHash("sha256").update(JSON.stringify(entries)).digest("hex"),
  });
}

export function materializeSourceSnapshot(sourceRoot, out, environment = process.env) {
  assertDetachedOriginSnapshot(sourceRoot);
  assert(typeof environment.HOME === "string" && typeof environment.TMPDIR === "string", "capture operation HOME and TMPDIR are required");
  const operationRoot = realpathSync(environment.HOME);
  assert(realpathSync(environment.TMPDIR) === operationRoot, "capture operation HOME and TMPDIR must identify one private root");
  const operationIdentity = directDirectoryIdentity(operationRoot, "capture operation root");
  assert((operationIdentity.mode & 0o077) === 0, "capture operation root is not private");
  assert(
    !containsPath(sourceRoot, operationRoot) && !containsPath(operationRoot, sourceRoot) &&
      !containsPath(out, operationRoot) && !containsPath(operationRoot, out),
    "private source root overlaps source or staging",
  );
  const originIdentity = directDirectoryIdentity(sourceRoot, "detached source root");
  const storeBinding = readSourceStoreBinding(sourceRoot);
  const root = mkdtempSync(join(operationRoot, "loopeix-s35-source."));
  try {
    chmodSync(root, 0o700);
    command(
      "git",
      ["-c", "core.hooksPath=/dev/null", "clone", "--no-local", "--no-hardlinks", "--no-checkout", "--", sourceRoot, root],
      operationRoot,
    );
    command(
      "git",
      ["-c", "core.hooksPath=/dev/null", "-C", root, "checkout", "--detach", BASE_COMMIT, "--"],
      root,
    );
    const installArgs = [
      "install",
      "--offline",
      "--frozen-lockfile",
      "--frozen-store",
      "--trust-lockfile",
      "--ignore-scripts",
      "--ignore-pnpmfile",
      "--no-hoist",
      "--package-import-method=copy",
      "--verify-store-integrity",
      "--reporter=silent",
      `--store-dir=${storeBinding.store_path}`,
    ];
    command("pnpm", installArgs, root);
    normalizePrivateEsbuildBinary(root);
    command("pnpm", ["--config.verify-deps-before-run=false", "run", "build"], root);
    assertDetachedOriginSnapshot(sourceRoot);
    assertSourceStoreBinding(storeBinding);
    assertDirectDirectoryIdentity(operationRoot, operationIdentity, "capture operation root");
    const snapshot = Object.freeze({
      root: realpathSync(root),
      root_identity: directDirectoryIdentity(realpathSync(root), "private source root"),
      origin_root: sourceRoot,
      origin_identity: originIdentity,
      operation_root: operationRoot,
      operation_identity: operationIdentity,
      store_binding: storeBinding,
      execution_tree: captureSourceExecutionTree(realpathSync(root), sourceRoot),
    });
    assertSourceSnapshot(snapshot);
    return snapshot;
  } catch (error) {
    runPrivateCleanupActions(
      { error },
      [() => rmSync(root, { recursive: true, force: true })],
      "private source materialization failed and cleanup was incomplete",
    );
    throw error;
  }
}

export function assertSourceSnapshot(snapshot) {
  assert(snapshot !== null && typeof snapshot === "object", "private source snapshot is absent");
  assertDirectDirectoryIdentity(snapshot.operation_root, snapshot.operation_identity, "capture operation root");
  assertDirectDirectoryIdentity(snapshot.origin_root, snapshot.origin_identity, "detached source root");
  assertDetachedOriginSnapshot(snapshot.origin_root);
  assertSourceStoreBinding(snapshot.store_binding);
  assertDirectDirectoryIdentity(snapshot.root, snapshot.root_identity, "private source root");
  assertDetachedOriginSnapshot(snapshot.root);
  assert(
    JSON.stringify(captureSourceExecutionTree(snapshot.root, snapshot.origin_root)) ===
      JSON.stringify(snapshot.execution_tree),
    "private source execution tree changed",
  );
}

export function removeSourceSnapshot(snapshot) {
  if (snapshot === null) return;
  assertSourceSnapshot(snapshot);
  rmSync(snapshot.root, { recursive: true, force: true });
  assert(!existsSync(snapshot.root), "private source cleanup was incomplete");
}

function buildChildExecArgv(
  runtimeSnapshot,
  admittedDriverPath,
  toolSourceRoot,
  executionSourceRoot,
  reviewedOriginRoot,
  sourceSnapshotSha256,
  out,
  assertedCommit,
) {
  return [
    "--require", runtimeSnapshot.preflight_path,
    "--import", runtimeSnapshot.loader_path,
    admittedDriverPath,
    "--source-root", executionSourceRoot,
    "--reviewed-origin-root", reviewedOriginRoot,
    "--source-snapshot-sha256", sourceSnapshotSha256,
    "--out", out,
    "--assert-base-commit", assertedCommit,
    "--tool-source-root", toolSourceRoot,
  ];
}

export function assertExactChildExecArgv(actual, expected) {
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    "capture must use the exact admitted tsx preflight and loader hooks",
  );
}

function sanitizedChildEnvironment(environment) {
  const child = {
    LANG: "C",
    LC_ALL: "C",
  };
  for (const name of ["HOME", "PATH", "TMPDIR"]) {
    if (typeof environment[name] === "string") child[name] = environment[name];
  }
  return child;
}

export function runPrivateCleanupActions(
  operationFailure,
  actions,
  aggregateMessage,
) {
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
    throw new AggregateError(
      [operationFailure.error, ...cleanupFailures],
      aggregateMessage,
    );
  }
  if (cleanupFailures.length === 1) throw cleanupFailures[0];
  throw new AggregateError(cleanupFailures, aggregateMessage);
}

async function main() {
  assertCleanLauncherEnvironment(process.env);
  assert(process.version === EXPECTED_NODE_VERSION, `capture runtime must be ${EXPECTED_NODE_VERSION}`);
  const trustedNode = assertTrustedExecutable("node");
  assert(process.execPath === trustedNode, "capture process is not running under the admitted Node executable");
  const { driver: requestedDriver, sourceRoot: requestedSourceRoot, out, assertedCommit } = parseArgs(process.argv.slice(2));
  assert(assertedCommit === BASE_COMMIT, `asserted commit must be ${BASE_COMMIT}`);
  assert(existsSync(requestedSourceRoot), "source root does not exist");
  const sourceRoot = realpathSync(requestedSourceRoot);
  const launcherPath = fileURLToPath(import.meta.url);
  const launcherHashBefore = sha256File(launcherPath);
  const toolSourceRoot = dirname(requestedDriver);
  const sourceLauncherPath = join(toolSourceRoot, "launch-v01-oracles-s35.mjs");
  const expectedDriverPath = join(toolSourceRoot, "capture-v01-oracles-s35.ts");
  const admittedDriverPath = join(dirname(launcherPath), "capture-v01-oracles-s35.ts");
  assert(requestedDriver === expectedDriverPath, "capture driver must be the reviewed source sibling");
  assert(
    sha256File(sourceLauncherPath) === launcherHashBefore,
    "admitted launcher differs from its reviewed source",
  );
  assert(statSync(requestedDriver).isFile(), "capture driver is not a regular file");
  assert(sha256File(requestedDriver) === EXPECTED_DRIVER_SHA256, "capture driver hash drifted");
  assert(
    sha256File(admittedDriverPath) === EXPECTED_DRIVER_SHA256,
    "admitted capture driver hash drifted",
  );
  assertDetachedOriginSnapshot(sourceRoot);
  const sourceSnapshot = materializeSourceSnapshot(sourceRoot, out, process.env);
  let runtimeSnapshot = null;
  let operationFailure = null;
  try {
    runtimeSnapshot = materializeRuntimeSnapshot(
      sourceSnapshot.root,
      out,
      process.env,
    );
    const runtimeIdentity = runtimeSnapshot.identity;
    const expectedChildExecArgv = buildChildExecArgv(
      runtimeSnapshot,
      admittedDriverPath,
      toolSourceRoot,
      sourceSnapshot.root,
      sourceSnapshot.origin_root,
      sourceSnapshot.execution_tree.tree_sha256,
      out,
      assertedCommit,
    );
    const childExecArgv = [...expectedChildExecArgv];
    assertExactChildExecArgv(childExecArgv, expectedChildExecArgv);

    const result = spawnSync(trustedNode, childExecArgv, {
      cwd: dirname(toolSourceRoot),
      encoding: "utf8",
      env: sanitizedChildEnvironment(process.env),
      killSignal: "SIGKILL",
      maxBuffer: CHILD_PROCESS_MAX_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: CHILD_PROCESS_TIMEOUT_MS,
    });

    assertTrustedExecutable("node");
    assert(sha256File(launcherPath) === launcherHashBefore, "capture launcher changed during execution");
    assert(
      sha256File(sourceLauncherPath) === launcherHashBefore,
      "capture launcher source changed during execution",
    );
    assert(sha256File(requestedDriver) === EXPECTED_DRIVER_SHA256, "capture driver changed during execution");
    assert(
      sha256File(admittedDriverPath) === EXPECTED_DRIVER_SHA256,
      "admitted capture driver changed during execution",
    );
    assertDetachedOriginSnapshot(sourceRoot);
    assertSourceSnapshot(sourceSnapshot);
    assert(
      JSON.stringify(captureRuntimeIdentity(sourceSnapshot.root)) === JSON.stringify(runtimeIdentity),
      "capture runtime changed before or during child execution",
    );
    assertRuntimeSnapshot(runtimeSnapshot.root);
    assert(result.error === undefined, `capture child failed to spawn: ${result.error?.message ?? "unknown error"}`);
    assert(result.signal === null, `capture child terminated by signal ${String(result.signal)}`);
    if (result.status !== 0) {
      if (result.stderr.length > 0) process.stderr.write(result.stderr);
      fail(`capture child exited ${String(result.status)}`);
    }
    assert(result.stderr === "", "capture child wrote unexpected stderr");
    process.stdout.write(result.stdout);
  } catch (error) {
    operationFailure = { error };
    throw error;
  } finally {
    runPrivateCleanupActions(
      operationFailure,
      [
        ...(runtimeSnapshot === null
          ? []
          : [() => rmSync(runtimeSnapshot.root, { recursive: true, force: true })]),
        () => removeSourceSnapshot(sourceSnapshot),
      ],
      "capture launcher failed and private snapshot cleanup was incomplete",
    );
  }
}

if (
  process.argv[1] &&
  realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))
) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
