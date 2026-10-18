import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runS37ProductHostActivationBoundaryCheck } from "./check-s37-product-host-activation-boundary.mjs";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const temporaryRoots = [];
const contractModule = "src/run/s37-product-host-activation-contract-v01.ts";
const storeModule = "src/run/s37-product-host-activation-store-v01.ts";
const activationModule = "src/run/s37-product-host-activation-v01.ts";
const brokerModule = "src/run/s37-product-host-launch-broker-v01.ts";
const stableActivationAdapter = "scripts/s37-linux-product-host-v03/activate-stable.mjs";
const qualificationHoldAdapter = "scripts/s37-linux-product-host-v03/issue-qualification.mjs";
const activationAdapterModule = "../../dist/run/s37-product-host-activation-v01.js";
const activationAdapterTransportModule = "./activation-adapter-transport-v01.mjs";
const activationAdapterTransport = "scripts/s37-linux-product-host-v03/activation-adapter-transport-v01.mjs";
const adapterPolicies = new Map([
  ["scripts/s37-linux-product-host-v03/install-anchor.mjs", ["installS37ProductHostV01", "commandS37ProductHostInstallAnchorV03", true]],
  ["scripts/s37-linux-product-host-v03/transition-anchor.mjs", ["transitionS37ProductHostV01", "commandS37ProductHostTransitionAnchorV03", true]],
  [stableActivationAdapter, ["activateStableS37ProductHostV01", "commandS37ProductHostActivateStableV01", true]],
  ["scripts/s37-linux-product-host-v03/reconcile-anchor.mjs", ["reconcileS37ProductHostActivationV01", "commandS37ProductHostReconcileAnchorV03", true]],
]);

function write(root, path, contents) {
  const target = resolve(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
}

function clonePassingFixture() {
  const root = mkdtempSync(resolve(tmpdir(), "loopeix-s37-activation-boundary-"));
  temporaryRoots.push(root);
  cpSync(resolve(repositoryRoot, "src"), resolve(root, "src"), { recursive: true });
  cpSync(resolve(repositoryRoot, "package.json"), resolve(root, "package.json"));
  write(root, contractModule, "export type ActivationRecordV01 = Readonly<{ id: string }>;\n");
  write(root, storeModule, [
    "import type { ActivationRecordV01 } from \"./s37-product-host-activation-contract-v01.js\";",
    "export type CapturedActivationStoreV01 = Readonly<{ record: ActivationRecordV01 }>;",
    "",
  ].join("\n"));
  write(root, brokerModule, [
    "import type { ActivationRecordV01 } from \"./s37-product-host-activation-contract-v01.js\";",
    "export type CapturedLaunchBrokerV01 = Readonly<{ record: ActivationRecordV01 }>;",
    "",
  ].join("\n"));
  write(root, activationModule, [
    "import type { ActivationRecordV01 } from \"./s37-product-host-activation-contract-v01.js\";",
    "import type { CapturedActivationStoreV01 } from \"./s37-product-host-activation-store-v01.js\";",
    "import type { CapturedLaunchBrokerV01 } from \"./s37-product-host-launch-broker-v01.js\";",
    "void (null as ActivationRecordV01 | CapturedActivationStoreV01 | CapturedLaunchBrokerV01 | null);",
    "export async function installS37ProductHostV01(input: Readonly<{ bundle_bytes: Uint8Array; proof_request_bytes: Uint8Array; qualification_intent_bytes: Uint8Array }>) { return { ok: false as const, outcome: \"NOT_STARTED\" as const, input }; }",
    "export async function transitionS37ProductHostV01(input: Readonly<{ bundle_bytes: Uint8Array; proof_request_bytes: Uint8Array; qualification_intent_bytes: Uint8Array }>) { return { ok: false as const, outcome: \"NOT_STARTED\" as const, input }; }",
    "export async function activateStableS37ProductHostV01(input: Readonly<{ proof_request_bytes: Uint8Array; qualification_intent_bytes: Uint8Array }>) { return { ok: false as const, outcome: \"NOT_STARTED\" as const, input }; }",
    "export async function reconcileS37ProductHostActivationV01() { return { ok: false as const, outcome: \"NOT_STARTED\" as const }; }",
    "",
  ].join("\n"));
  write(root, activationAdapterTransport,
    "export async function runS37ProductHostActivationAdapterTransportV01() { return 64; }\n");
  for (const [path, [api, command, transport]] of adapterPolicies) {
    write(root, path, [
      `import { ${api} } from "${activationAdapterModule}";`,
      ...(transport ? [`import { runS37ProductHostActivationAdapterTransportV01 } from "${activationAdapterTransportModule}";`] : []),
      "import { resolve } from \"node:path\";",
      "import { fileURLToPath } from \"node:url\";",
      "const HOLD = Object.freeze({ ok: false, outcome: \"HOLD_PRECONDITION\" });",
      `export function ${command}(input) { if (input === undefined) return HOLD; return ${api}(${api.startsWith("reconcile") ? "" : "input"}); }`,
      "if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = 64;",
      "",
    ].join("\n"));
  }
  cpSync(resolve(repositoryRoot, qualificationHoldAdapter), resolve(root, qualificationHoldAdapter));
  return root;
}

function append(root, path, contents) {
  write(root, path, readFileSync(resolve(root, path), "utf8") + "\n" + contents + "\n");
}

function replace(root, path, before, after) {
  const current = readFileSync(resolve(root, path), "utf8");
  assert.ok(current.includes(before), "mutation precondition missing: " + path + ": " + before);
  write(root, path, current.replace(before, after));
}

function mutatePackage(root, mutate) {
  const path = resolve(root, "package.json");
  const metadata = JSON.parse(readFileSync(path, "utf8"));
  mutate(metadata);
  writeFileSync(path, JSON.stringify(metadata, null, 2) + "\n");
}

function expectViolation(name, mutate, expected) {
  const root = clonePassingFixture();
  mutate(root);
  const result = runS37ProductHostActivationBoundaryCheck({ rootDir: root });
  assert.ok(result.violations.some((violation) => violation.includes(expected)),
    name + ": expected " + expected + "; received:\n" + result.violations.join("\n"));
  process.stderr.write("s37-activation-boundary-self-test-ok:" + name + "\n");
}

try {
  const baselineRoot = clonePassingFixture();
  const baseline = runS37ProductHostActivationBoundaryCheck({ rootDir: baselineRoot });
  assert.deepEqual(baseline.violations, [], "fixture baseline must pass:\n" + baseline.violations.join("\n"));
  process.stderr.write("s37-activation-boundary-self-test-ok:baseline\n");

  expectViolation("missing-module", (root) => rmSync(resolve(root, brokerModule)), "missing-s37-activation-module");
  expectViolation("missing-adapter", (root) => rmSync(resolve(root, stableActivationAdapter)), "missing-s37-activation-adapter");
  expectViolation("missing-adapter-transport", (root) => rmSync(resolve(root, activationAdapterTransport)), "missing-s37-activation-adapter-transport");
  expectViolation("missing-adapter-transport-import", (root) => replace(root, stableActivationAdapter,
    `import { runS37ProductHostActivationAdapterTransportV01 } from "${activationAdapterTransportModule}";`, ""),
  "activation-adapter-transport-import-must-be-exact");
  expectViolation("missing-direct-hold-compatibility", (root) => replace(root, stableActivationAdapter,
    "if (input === undefined) return HOLD;", ""), "activation-adapter-direct-hold-compatibility-missing");
  expectViolation("public-root-export", (root) => append(root, "src/index.ts", "export * from \"./run/s37-product-host-activation-v01.js\";"), "public-export-reaches-private-module");
  expectViolation("package-subpath", (root) => mutatePackage(root, (metadata) => {
    metadata.exports["./run/s37-activation"] = "./dist/run/s37-product-host-activation-v01.js";
  }), "package-export-private-artifact");
  expectViolation("unauthorized-private-import", (root) => append(root, "src/run/orchestrate.ts", "import \"./s37-product-host-activation-store-v01.js\";"), "private-module-import-owner");
  expectViolation("non-exact-private-import", (root) => replace(root, activationModule, "from \"./s37-product-host-activation-store-v01.js\"", "from \"./s37-product-host-activation-store-v01\""), "non-exact-private-import");
  expectViolation("production-test-seam", (root) => append(root, activationModule, "import { createSyntheticRuntimeRunStoreV03ForTest } from \"./runtime-write-session-v03.js\";"), "production-test-seam-import");
  expectViolation("caller-path", (root) => replace(root, activationModule, "proof_request_bytes: Uint8Array", "proof_request_bytes: Uint8Array; path: string"), "composition-input-keys");
  expectViolation("caller-clock", (root) => replace(root, activationModule, "qualification_intent_bytes: Uint8Array", "qualification_intent_bytes: Uint8Array; clock: () => number"), "composition-input-keys");
  expectViolation("caller-decision", (root) => replace(root, activationModule, "qualification_intent_bytes: Uint8Array", "qualification_intent_bytes: Uint8Array; decision_input_bytes: Uint8Array"), "composition-input-keys");
  expectViolation("caller-callback", (root) => replace(root, activationModule, "bundle_bytes: Uint8Array", "bundle_bytes: Uint8Array; callback: () => void"), "composition-input-keys");
  expectViolation("caller-filesystem", (root) => replace(root, activationModule, "bundle_bytes: Uint8Array", "bundle_bytes: Uint8Array; filesystem: object"), "composition-input-keys");
  expectViolation("caller-key", (root) => replace(root, activationModule, "bundle_bytes: Uint8Array", "bundle_bytes: Uint8Array; private_key: Uint8Array"), "composition-input-keys");
  expectViolation("standalone-qualification-api", (root) => append(root, activationModule, "export async function issueS37ProductHostQualificationV01() { return { ok: false, outcome: \"NOT_STARTED\" }; }"), "standalone-production-qualification-api");
  expectViolation("qualification-command-enabled", (root) => replace(root, "scripts/s37-linux-product-host-v03/issue-qualification.mjs", "return HOLD;", "return { ok: true };"), "qualification-command-not-unconditional-hold");
  expectViolation("s40-bootstrap", (root) => append(root, activationModule, "import { admitRuntimeActionV03 } from \"./runtime-action-admission-v03.js\";"), "s40-s41-bootstrap-dependency");
  expectViolation("s41-bootstrap", (root) => append(root, activationModule, "import { captureRuntimeFileStoreV04 } from \"./runtime-file-store-v04.js\";"), "s40-s41-bootstrap-dependency");
  expectViolation("s40-dispatch-permit", (root) => append(root, activationModule, "type DispatchPermitV01 = Readonly<{ id: string }>; void (null as DispatchPermitV01 | null);"), "non-activation-launch-permit");
  expectViolation("raw-key-transport", (root) => append(root, storeModule, "const forbidden = \"-----BEGIN PRIVATE KEY-----\"; void forbidden;"), "raw-private-key-transport");
  expectViolation("raw-key-parameter", (root) => append(root, storeModule, "export function loadAuthority(privateKeyPem: Uint8Array) { return privateKeyPem; }"), "raw-private-key-parameter");
  expectViolation("store-capture-input", (root) => append(root, storeModule, "export function captureProductHostActivationStoreV01(path: string) { return path; }"), "caller-controlled-store-capture");
  expectViolation("ambient-environment", (root) => append(root, storeModule, "void process.env.ACTIVATION_KEY;"), "raw-key-transport-surface");
  expectViolation("network-import", (root) => append(root, brokerModule, "import \"node:net\";"), "remote-or-network-import");
  expectViolation("remote-surface", (root) => append(root, brokerModule, "const transport = \"ssh\"; void transport;"), "remote-or-container-surface");
  expectViolation("v02-fallback", (root) => append(root, activationModule, "import \"./linux-host-enforcement-v02.js\";"), "v02-host-fallback");
  expectViolation("spawn-outside-broker", (root) => append(root, storeModule, "import { spawn } from \"node:child_process\"; spawn(\"id\");"), "process-entry-import-outside-broker");
  expectViolation("broker-process-alias", (root) => append(root, brokerModule, "import { spawn as launch } from \"node:child_process\"; void launch;"), "broker-process-entry-import-must-be-sole-unaliased-spawn");
  expectViolation("broker-process-extra", (root) => append(root, brokerModule, "import { spawn, execFile } from \"node:child_process\"; void spawn; void execFile;"), "broker-process-entry-import-must-be-sole-unaliased-spawn");
  expectViolation("broker-process-unprefixed", (root) => append(root, brokerModule, "import { spawn } from \"child_process\"; void spawn;"), "broker-process-entry-import-must-be-sole-unaliased-spawn");
  expectViolation("adapter-process-import", (root) => append(root, stableActivationAdapter, "import { spawn } from \"node:child_process\";"), "activation-adapter-import-not-allowlisted");
  expectViolation("adapter-process-call", (root) => append(root, stableActivationAdapter, "spawn(\"id\");"), "activation-adapter-process-entry");
  expectViolation("adapter-wrong-api", (root) => replace(root, stableActivationAdapter, "activateStableS37ProductHostV01", "installS37ProductHostV01"), "activation-adapter-api-import-must-be-exact");
  expectViolation("adapter-wrong-module", (root) => replace(root, stableActivationAdapter, activationAdapterModule, "../../dist/run/s37-product-host-activation-store-v01.js"), "activation-adapter-api-import-must-be-exact");
  expectViolation("adapter-extra-export", (root) => append(root, stableActivationAdapter, "export function bypass() {}"), "activation-adapter-export-surface-must-be-exact");
  expectViolation("adapter-reexport", (root) => append(root, stableActivationAdapter, `export { activateStableS37ProductHostV01 } from "${activationAdapterModule}";`), "activation-adapter-reexport-forbidden");
  expectViolation("adapter-dynamic-import", (root) => append(root, stableActivationAdapter, "void import(\"node:fs\");"), "activation-adapter-dynamic-import");
  expectViolation("adapter-require", (root) => append(root, stableActivationAdapter, "void require(\"node:fs\");"), "activation-adapter-require");
  expectViolation("adapter-duplicate-call", (root) => append(root, stableActivationAdapter, "void activateStableS37ProductHostV01();"), "activation-adapter-api-call-must-be-exactly-once-in-command");
  expectViolation("adapter-call-outside-command", (root) => replace(root, stableActivationAdapter,
    "export function commandS37ProductHostActivateStableV01(input) { if (input === undefined) return HOLD; return activateStableS37ProductHostV01(input); }",
    "void activateStableS37ProductHostV01(); export function commandS37ProductHostActivateStableV01(input) { if (input === undefined) return HOLD; return null; }"),
  "activation-adapter-api-call-must-be-exactly-once-in-command");
  expectViolation("adapter-call-in-nested-function", (root) => replace(root, stableActivationAdapter,
    "export function commandS37ProductHostActivateStableV01(input) { if (input === undefined) return HOLD; return activateStableS37ProductHostV01(input); }",
    "export function commandS37ProductHostActivateStableV01(input) { if (input === undefined) return HOLD; function neverCalled() { return activateStableS37ProductHostV01(input); } return null; }"),
  "activation-adapter-api-call-must-be-exactly-once-in-command");
  expectViolation("adapter-default-export", (root) => append(root, stableActivationAdapter, "export default function bypass() {}"), "activation-adapter-default-export-forbidden");
  expectViolation("adapter-command-not-function", (root) => replace(root, stableActivationAdapter,
    "export function commandS37ProductHostActivateStableV01(input) { if (input === undefined) return HOLD; return activateStableS37ProductHostV01(input); }",
    "export const commandS37ProductHostActivateStableV01 = activateStableS37ProductHostV01; void activateStableS37ProductHostV01();"),
  "activation-adapter-command-must-be-function");
  expectViolation("adapter-unapproved-import", (root) => append(root, stableActivationAdapter, "import \"node:crypto\";"), "activation-adapter-import-not-allowlisted");
  expectViolation("shell-entry", (root) => append(root, brokerModule, "const options = { shell: true }; void options;"), "shell-process-entry");
  expectViolation("missing-api", (root) => replace(root, activationModule, "installS37ProductHostV01", "removedInstallS37ProductHostV01"), "missing-composition-function");

  process.stdout.write("S37 product-host activation boundary self-test completed: 50/50 cases passed\n");
} finally {
  for (const root of temporaryRoots) rmSync(root, { recursive: true, force: true });
}
