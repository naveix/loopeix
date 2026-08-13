#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const implementationRoot = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), ".."));
const planningRoot = realpathSync(resolve(implementationRoot, "../loopeix-specs"));
const receiptPath = resolve(planningRoot, "docs/sprints/s36-verification-receipt-v01.json");
const excluded = /(^|\/)(?:\.claude|\.playwright-mcp)(?:\/|$)/u;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;

function fail(message) {
  throw new Error(`S36 verification failed: ${message}`);
}

function run(executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    cwd: options.cwd ?? implementationRoot,
    encoding: "buffer",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      LANG: "C",
      LC_ALL: "C",
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      ...(options.env ?? {}),
    },
    maxBuffer: 64 * 1024 * 1024,
    shell: false,
    timeout: options.timeout ?? 600_000,
  });
  const stdout = result.stdout ?? Buffer.alloc(0);
  const stderr = result.stderr ?? Buffer.alloc(0);
  if (result.error !== undefined || result.status !== 0) {
    process.stderr.write(stdout);
    process.stderr.write(stderr);
    fail(`${options.id ?? executable} exited ${result.status ?? "without status"}: ${result.error?.message ?? "no spawn error"}`);
  }
  return {
    id: options.id,
    status: "passed",
    exit_code: result.status,
    stdout_bytes: stdout.byteLength,
    stdout_sha256: sha256(stdout),
    stderr_bytes: stderr.byteLength,
    stderr_sha256: sha256(stderr),
  };
}

function git(root, args, encoding = "utf8") {
  const result = spawnSync("git", ["-C", root, ...args], {
    encoding,
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      LANG: "C",
      LC_ALL: "C",
      PATH: process.env.PATH ?? "/usr/bin:/bin",
    },
    maxBuffer: 64 * 1024 * 1024,
    shell: false,
    timeout: 30_000,
  });
  if (result.error !== undefined || result.status !== 0) fail(`git ${args[0]} failed for ${basename(root)}`);
  return result.stdout;
}

function stableBytes(path) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) fail(`unsafe evidence input: ${path}`);
  const bytes = readFileSync(path);
  const after = statSync(path, { bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs) {
    fail(`evidence input changed during read: ${path}`);
  }
  return bytes;
}

function sourceSnapshot() {
  const repositories = [implementationRoot, planningRoot].map((root) => {
    const changed = git(root, ["ls-files", "-m", "-d", "-o", "--exclude-standard", "-z"], "buffer")
      .toString("utf8").split("\0").filter(Boolean)
      .filter((path) => !excluded.test(path) && resolve(root, path) !== receiptPath)
      .sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
    const files = changed.map((path) => {
      const absolute = resolve(root, path);
      const rel = relative(root, absolute);
      if (rel.startsWith("..") || isAbsolute(rel)) fail(`source path escaped repository: ${path}`);
      try {
        const bytes = stableBytes(absolute);
        return { path, size: bytes.byteLength, sha256: sha256(bytes) };
      } catch (error) {
        if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return { path, deleted: true };
        throw error;
      }
    });
    return { repository_id: basename(root), head: git(root, ["rev-parse", "HEAD"]).toString("utf8").trim(), files };
  });
  return { repositories, sha256: sha256(Buffer.from(canonical(repositories))) };
}

function scriptHash(root, path) {
  return sha256(stableBytes(resolve(root, path)));
}

function command(id, executable, args, cwd, script = null) {
  return {
    id,
    executable,
    args,
    cwd: cwd === implementationRoot ? "loopeix" : "loopeix-specs",
    ...(script === null ? {} : { script_sha256: scriptHash(cwd, script) }),
  };
}

function receiptCommand(gate, scratch) {
  const sanitize = (value) => value
    .replaceAll(scratch, "<private-scratch>")
    .replaceAll(planningRoot, "<loopeix-specs>")
    .replaceAll(implementationRoot, "<loopeix>");
  return {
    ...gate,
    executable: gate.executable === process.execPath ? "node" : basename(gate.executable),
    args: gate.args.map(sanitize),
  };
}

if (process.argv.length !== 2) fail("this command accepts no arguments");
try { lstatSync(receiptPath); fail(`receipt already exists: ${receiptPath}`); }
catch (error) { if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error; }

const node = process.execPath;
const pnpmLookup = spawnSync("which", ["pnpm"], { encoding: "utf8", shell: false });
if (pnpmLookup.error !== undefined || pnpmLookup.status !== 0 || pnpmLookup.stdout.trim() === "") {
  fail(`pnpm executable lookup failed: ${pnpmLookup.error?.message ?? `exit ${pnpmLookup.status ?? "without status"}`}`);
}
const pnpm = realpathSync(pnpmLookup.stdout.trim());
const sourceBefore = sourceSnapshot();
const scratch = mkdtempSync(resolve(tmpdir(), "loopeix-s36-verify-"));
chmodSync(scratch, 0o700);
const packRoot = resolve(scratch, "pack");
const renderRoot = resolve(scratch, "render");
mkdirSync(packRoot, { mode: 0o700 });
mkdirSync(renderRoot, { mode: 0o700 });
const tarball = resolve(packRoot, "loopeix-0.1.0.tgz");
const gatePlan = [
  command("full-test-suite", pnpm, ["test"], implementationRoot),
  command("typecheck", pnpm, ["typecheck"], implementationRoot),
  command("build", pnpm, ["build"], implementationRoot),
  command("s36-boundary-proof", node, ["scripts/check-s36-boundaries.mjs"], implementationRoot, "scripts/check-s36-boundaries.mjs"),
  command("planning-and-documentation", node, ["scripts/check-s35-planning.mjs"], planningRoot, "scripts/check-s35-planning.mjs"),
  command("two-repository-secret-scan", node, [
    "scripts/scan-secrets-s35.mjs", "--allowlist", "scripts/secret-scan-allowlist-s35.json",
    "--filenames-only", "--exclude-env", "--exclude-playwright", implementationRoot, planningRoot,
  ], implementationRoot, "scripts/scan-secrets-s35.mjs"),
  command("v02-fixture-verification", node, [
    "scripts/verify-v02-fixtures-s35.mjs", "--fixtures-root", resolve(implementationRoot, "tests/fixtures/compat/s35"),
  ], implementationRoot, "scripts/verify-v02-fixtures-s35.mjs"),
  command("package-build", pnpm, ["pack", "--out", tarball, "--json"], implementationRoot),
  command("installed-package-smoke", node, [
    "scripts/smoke-packed-package-s35.mjs", "--mode", "full", "--tarball", tarball,
    "--fixtures-root", resolve(implementationRoot, "tests/fixtures/compat/s35"),
  ], implementationRoot, "scripts/smoke-packed-package-s35.mjs"),
  command("canonical-mermaid-render", node, [
    "scripts/check-system-visual-architecture-render.mjs", "--output-dir", renderRoot,
  ], planningRoot, "scripts/check-system-visual-architecture-render.mjs"),
];

let operationError;
try {
  const gateResults = gatePlan.map((gate) => run(gate.executable, gate.args, {
    cwd: gate.cwd === "loopeix" ? implementationRoot : planningRoot,
    id: gate.id,
    timeout: gate.id === "full-test-suite" || gate.id === "package-build" || gate.id === "installed-package-smoke" ? 900_000 : 600_000,
  }));
  const sourceAfter = sourceSnapshot();
  if (sourceAfter.sha256 !== sourceBefore.sha256 || canonical(sourceAfter.repositories) !== canonical(sourceBefore.repositories)) {
    fail("source snapshot changed during verification");
  }
  const runnerBytes = stableBytes(fileURLToPath(import.meta.url));
  const body = {
    schema_version: "0.1",
    purpose: "s36-pre-review-verification-receipt",
    sprint_id: "S36",
    overall_status: "passed",
    source_snapshot_sha256: sourceBefore.sha256,
    repositories: sourceBefore.repositories.map(({ repository_id, head }) => ({ repository_id, head })),
    runner: {
      path: "scripts/run-s36-verification.mjs",
      sha256: sha256(runnerBytes),
      node_version: process.version,
    pnpm_executable: basename(pnpm),
      pnpm_sha256: sha256(stableBytes(pnpm)),
    },
    gate_plan: gatePlan.map((gate) => receiptCommand(gate, scratch)),
    gate_results: gateResults,
  };
  const receipt = { ...body, receipt_sha256: sha256(Buffer.from(canonical(body))) };
  writeFileSync(receiptPath, canonical(receipt), { flag: "wx", mode: 0o600 });
  chmodSync(receiptPath, 0o600);
  process.stdout.write(`${receipt.receipt_sha256}\n`);
} catch (error) {
  operationError = error;
} finally {
  try { rmSync(scratch, { recursive: true, force: false }); }
  catch (cleanupError) {
    if (operationError === undefined) operationError = cleanupError;
    else operationError = new AggregateError([operationError, cleanupError], "verification and cleanup both failed");
  }
}
if (operationError !== undefined) {
  process.stderr.write(`${operationError instanceof Error ? operationError.message : String(operationError)}\n`);
  process.exitCode = 1;
}
