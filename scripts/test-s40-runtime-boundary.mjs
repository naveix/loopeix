import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { runBoundaryCheck } from "./check-s40-runtime-boundary.mjs";

const repositoryRoot = resolve(dirname(new URL(import.meta.url).pathname), "..");
const temporaryRoots = [];

function cloneBoundaryTree() {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s40-boundary-"));
  temporaryRoots.push(root);
  for (const path of ["src", "dist"]) cpSync(resolve(repositoryRoot, path), resolve(root, path), { recursive: true });
  for (const path of ["package.json"]) cpSync(resolve(repositoryRoot, path), resolve(root, path));
  return root;
}

function write(root, path, contents) {
  const target = resolve(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
}

function append(root, path, contents) {
  write(root, path, `${readFileSync(resolve(root, path), "utf8")}\n${contents}\n`);
}

function mutatePackage(root, mutation) {
  const path = resolve(root, "package.json");
  const metadata = JSON.parse(readFileSync(path, "utf8"));
  mutation(metadata);
  writeFileSync(path, `${JSON.stringify(metadata, null, 2)}\n`);
}

function expectViolation(name, mutate, expected) {
  const root = cloneBoundaryTree();
  mutate(root);
  const result = runBoundaryCheck({ rootDir: root });
  assert.ok(result.violations.some((violation) => violation.includes(expected)),
    `${name}: expected ${expected}; received:\n${result.violations.join("\n")}`);
  process.stderr.write(`s40-boundary-self-test-ok:${name}\n`);
}

try {
  const baseline = runBoundaryCheck({ rootDir: repositoryRoot });
  assert.deepEqual(baseline.violations, [], `baseline must pass:\n${baseline.violations.join("\n")}`);
  process.stderr.write("s40-boundary-self-test-ok:baseline\n");

  expectViolation("node-host-import", (root) => append(root, "src/run/runtime-manifest-v03.ts", 'import "node:fs";'), "filesystem-module");
  expectViolation("process-env", (root) => append(root, "src/run/runtime-manifest-v03.ts", "void process.env.S40;"), "ambient-environment");
  expectViolation("dynamic-import", (root) => append(root, "src/run/runtime-manifest-v03.ts", 'void import("./runtime-ledger-v03.js");'), "dynamic-import");
  expectViolation("dynamic-require", (root) => append(root, "src/run/runtime-manifest-v03.ts", 'require("./runtime-ledger-v03.js");'), "dynamic-require");
  expectViolation("eval", (root) => append(root, "src/run/runtime-manifest-v03.ts", 'eval("0");'), "runtime-evaluation");
  expectViolation("fetch", (root) => append(root, "src/run/runtime-manifest-v03.ts", 'fetch("https://invalid.example");'), "runtime-evaluation");
  expectViolation("direct-effect-entry", (root) => append(root, "src/run/runtime-manifest-v03.ts", "state.dispatch(invocation);"), "direct-effect-entry-outside-common-broker");
  expectViolation("unauthorized-termination-import", (root) => append(
    root,
    "src/run/runtime-manifest-v03.ts",
    'import { terminateRuntimeActionV03 } from "./runtime-termination-v03.js";',
  ), "private-module-import-owner");

  expectViolation("root-export", (root) => append(root, "src/index.ts", 'export * from "./run/runtime-execution-coordinator-v03.js";'), "public-export-reaches-private-module");
  expectViolation("barrel-export", (root) => {
    write(root, "src/run/s40-leak-barrel.ts", 'export * from "./runtime-execution-coordinator-v03.js";\n');
    append(root, "src/index.ts", 'export * from "./run/s40-leak-barrel.js";');
  }, "private-module-export-laundering");
  expectViolation("type-only-export", (root) => append(root, "src/index.ts", 'export type { RuntimeExecutionCoordinatorV03 } from "./run/runtime-execution-coordinator-v03.js";'), "private-module-export-laundering");
  expectViolation("alias-export", (root) => append(root, "src/index.ts", 'export { captureRuntimeExecutionCoordinatorV03 as captureRun } from "./run/runtime-execution-coordinator-v03.js";'), "private-module-export-laundering");
  expectViolation("commonjs-laundering", (root) => append(root, "src/index.ts", 'module.exports = require("./run/runtime-execution-coordinator-v03.js");'), "private-module-commonjs-laundering");

  expectViolation("package-private-subpath", (root) => mutatePackage(root, (metadata) => {
    metadata.exports["./run/runtime-execution-coordinator-v03"] = "./dist/run/runtime-execution-coordinator-v03.js";
  }), "public-private-subpath-export");
  expectViolation("public-private-wildcard-resolution", (root) => mutatePackage(root, (metadata) => {
    metadata.exports["./run/*"] = "./dist/run/*.js";
  }), "public-private-subpath-export");
  expectViolation("dist-index-types-leak", (root) => append(root, "dist/index.d.ts", 'export * from "./run/runtime-execution-coordinator-v03.js";'), "private-runtime-in-public-types");
  expectViolation("missing-packaged-private-artifact", (root) => {
    rmSync(resolve(root, "dist/run/runtime-execution-coordinator-v03.d.ts"));
  }, "missing-private-dist-artifact");
  expectViolation("dist-excluded-from-package", (root) => mutatePackage(root, (metadata) => {
    metadata.files = metadata.files.filter((entry) => entry !== "dist");
  }), "private-dist-artifacts-not-packaged");

  expectViolation("legacy-root-hash", (root) => append(root, "src/index.ts", "// changed"), "package-root-source-digest");
  expectViolation("legacy-orchestrate-hash", (root) => append(root, "src/run/orchestrate.ts", "// changed"), "orchestrate-source-digest");
  expectViolation("production-test-helper", (root) => append(root, "src/run/runtime-manifest-v03.ts", 'import { fixtureForTest } from "../../tests/helpers/runtime-action-admission-v03-fixture.js";'), "production-test-helper-import");
  expectViolation("host-vps-import", (root) => append(root, "src/run/runtime-manifest-v03.ts", 'import "./vps-client.js";'), "forbidden-host-import");
  expectViolation("host-systemd-import", (root) => append(root, "src/run/runtime-manifest-v03.ts", 'import "./systemd-controller.js";'), "forbidden-host-import");
  expectViolation("host-cgroup-import", (root) => append(root, "src/run/runtime-manifest-v03.ts", 'import "./cgroup-controller.js";'), "forbidden-host-import");

  process.stdout.write("s40 runtime boundary self-test completed: 25/25 cases passed\n");
} finally {
  for (const root of temporaryRoots) rmSync(root, { recursive: true, force: true });
}
