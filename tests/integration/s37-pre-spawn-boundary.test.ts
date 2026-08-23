import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";

const roots: string[] = [];
const boundaryScript = resolve(process.cwd(), "scripts/check-s37-boundaries.mjs");

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function runBoundary(options: { cwd?: string; files?: string[] } = {}) {
  return spawnSync(process.execPath, [boundaryScript, ...(options.files ?? [])], {
    cwd: options.cwd ?? process.cwd(),
    encoding: "utf8",
    shell: false,
    timeout: 15_000,
    maxBuffer: 2 * 1024 * 1024,
  });
}

function writeFixture(root: string, entries: Record<string, string>) {
  for (const [relativePath, content] of Object.entries(entries)) {
    const file = join(root, relativePath);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, content);
  }
}

function createBaselineRepo(prefix: string, extraEntries: Record<string, string> = {}) {
  const root = mkdtempSync(join(tmpdir(), prefix));
  roots.push(root);
  writeFixture(root, {
    "src/index.ts": 'export * from "./run/engine.js";\n',
    "src/run/pre-spawn-capability-broker-v02.ts": "export function enforceS37PreSpawnProbeV02() { return null; }\n",
    "src/run/engine.ts": "export function runEngine() { return null; }\n",
    "src/commands/run/start.ts": "export function runStart() { return null; }\n",
    ...extraEntries,
  });
  return root;
}

describe("S37 static pre-spawn boundary", () => {
  it("keeps the broker and compatibility engine free of execution capabilities", () => {
    const result = runBoundary();
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });

  it("rejects process, filesystem, network, ambient environment, and tool-server traps", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s37-boundary-"));
    roots.push(root);
    const trap = join(root, "trap.ts");
    writeFileSync(trap, [
      'import "node:child_process";',
      'void import("node:fs");',
      'const network = require("node:https");',
      'import "./mcp-connector.js";',
      'import { createRequire } from "node:module";',
      'import { env } from "node:process";',
      "void process.env.SECRET;",
      'spawnSync("sh", []);',
      'void fetch("https://example.com");',
      'new WebSocket("wss://example.com");',
      'void import(moduleName);',
      'eval("ignored");',
    ].join("\n"));

    const result = runBoundary({ files: [trap] });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("child-process-module");
    expect(result.stderr).toContain("filesystem-module");
    expect(result.stderr).toContain("network-module");
    expect(result.stderr).toContain("module-loader");
    expect(result.stderr).toContain("spawn-or-exec");
    expect(result.stderr).toContain("ambient-environment");
    expect(result.stderr).toContain("global-network-api");
    expect(result.stderr).toContain("runtime-evaluation");
    expect(result.stderr).toContain("tool-or-connector-import");
  });

  it("ignores capability words that occur only in comments and strings", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s37-boundary-clean-"));
    roots.push(root);
    const clean = join(root, "clean.ts");
    writeFileSync(clean, [
      "// Never read process.env or call fetch here.",
      'const policyNote = "spawnSync( and WebSocket are prohibited";',
      "void policyNote;",
    ].join("\n"));

    const result = runBoundary({ files: [clean] });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
  });

  it("rejects package-root exports of pre-spawn broker and Linux boundary names", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-export-", {
      "src/index.ts": 'export { prepareS37LinuxProbeAdmissionV02 } from "./run/pre-spawn-capability-broker-v02.js";\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-forbidden-export:prepareS37LinuxProbeAdmissionV02");
  });

  it("rejects package-root exports of the Phase C local product entry", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-product-export-", {
      "src/index.ts": 'export { runS37LocalLinuxProductProbeV02 } from "./run/linux-host-enforcement-v02.js";\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-linux-export: src/index.ts");
    expect(result.stderr).toContain("package-root-forbidden-export:runS37LocalLinuxProductProbeV02");
  });

  it("rejects package-root wildcard exports of the package-private broker", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-export-all-", {
      "src/index.ts": 'export * from "./run/pre-spawn-capability-broker-v02.js";\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-broker-wildcard-export: src/index.ts");
  });

  it("rejects bounded launcher imports outside the Linux owner module", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-import-", {
      "src/run/not-allowed.ts": 'import "./bounded-linux-probe-v02.js";\n',
      "src/run/bounded-linux-probe-v02.ts": "export function runBoundedS37LinuxProbeV02() { return null; }\n",
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("bounded-launcher-import-outside-linux-owner: src/run/not-allowed.ts");
  });

  it.each([
    'import "../../run/linux-host-enforcement-v02.js";',
    'import { runS37LocalLinuxProductProbeV02 } from "../../run/linux-host-enforcement-v02.js";',
    'import localBackend from "../../run/linux-host-enforcement-v02.js";',
  ])("rejects real-path Linux module imports inside the compatibility CLI: %s", (statement) => {
    const root = createBaselineRepo("loopeix-s37-boundary-cli-", {
      "src/commands/run/start.ts": `${statement}\nexport function runStart() { return null; }\n`,
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("linux-module-import-in-engine-or-cli: src/commands/run/start.ts");
  });

  it("rejects shell:true and forbidden launcher commands inside Linux modules", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-shell-", {
      "src/run/linux-host-enforcement-v02.ts": 'export const launch = { shell: true };\n',
      "src/run/bounded-linux-probe-v02.ts": 'export function runBoundedS37LinuxProbeV02() { return null; }\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("shell-true-in-linux-module: src/run/linux-host-enforcement-v02.ts");
  });

  it("rejects direct OS and spawn capabilities outside the sole Phase C Linux owner", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-linux-os-", {
      "src/run/bounded-linux-probe-v02.ts": 'import { spawn } from "node:child_process";\nexport const launch = () => spawn("/bin/true");\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("child-process-module: src/run/bounded-linux-probe-v02.ts");
    expect(result.stderr).toContain("spawn-or-exec: src/run/bounded-linux-probe-v02.ts");
  });

  it("rejects dynamic loading, scope, pipe, or shell widening in the Phase C owner", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-owner-widening-", {
      "src/run/linux-host-enforcement-v02.ts": [
        'const child = require("node:child_process");',
        'export const widened = ["--scope", "--pipe", { shell: true }, child];',
      ].join("\n"),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("module-loader: src/run/linux-host-enforcement-v02.ts");
    expect(result.stderr).toContain('forbidden-phase-c-owner-contract:"--scope"');
    expect(result.stderr).toContain('forbidden-phase-c-owner-contract:"--pipe"');
    expect(result.stderr).toContain("shell-true-in-linux-module: src/run/linux-host-enforcement-v02.ts");
  });

  it("rejects manager observation or process creation outside the admitted controller", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-preadmission-spawn-", {
      "src/run/linux-host-enforcement-v02.ts": [
        "export async function observeBeforeAdmission() {",
        "  await observeSystemdManagerVersion(1001);",
        "  return spawn('/usr/bin/systemctl', []);",
        "}",
      ].join("\n"),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-manager-observation-before-admitted-controller");
    expect(result.stderr).toContain("phase-c-spawn-outside-admitted-controller:observeBeforeAdmission");
  });

  it.each([
    ["manager observer", "      child = spawn(\n        SYSTEMCTL_PATH,", "      void spawn('/bin/sh', ['-c', 'true']);\n      child = spawn(\n        SYSTEMCTL_PATH,"],
    ["transient controller", "      child = spawn(invocation.command, [...invocation.args], invocation.options);", "      void spawn('/bin/sh', ['-c', 'true']);\n      child = spawn(invocation.command, [...invocation.args], invocation.options);"],
  ])("rejects an extra spawn inside the allowlisted %s", (_name, needle, replacement) => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-extra-owner-spawn-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, replacement),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-spawn-call-count:expected-2:actual-3");
  });

  it("rejects local indirection of the spawn capability", () => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const needle = "      child = spawn(\n        SYSTEMCTL_PATH,";
    const replacement = "      const launch = spawn;\n      void launch('/bin/sh', []);\n      child = spawn(\n        SYSTEMCTL_PATH,";
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-spawn-alias-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, replacement),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-spawn-reference-must-be-direct-callee");
  });

  it("rejects an additional aliased child-process import", () => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const needle = 'import { spawn } from "node:child_process";';
    const replacement = `${needle}\nimport { spawn as launch } from "node:child_process";`;
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-spawn-import-alias-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, replacement),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-child-process-import-must-be-sole-unaliased-spawn");
  });

  it("rejects any extra OS-capability import in the Phase C owner", () => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const needle = 'import { lstatSync, readFileSync } from "node:fs";';
    const replacement = 'import { lstatSync, readFileSync, writeFileSync } from "node:fs";';
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-extra-os-import-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, replacement),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-owner-import-surface-must-be-exact");
  });

  it.each([
    ["getBuiltinModule", '      const load = (process as any)["getBuiltinModule"];\n      const cp = load("node:child_process");\n      void cp["spawn"]("/bin/sh", []);'],
    ["binding", '      const load = (process as any)["binding"];\n      void load("spawn_sync");'],
  ])("rejects indirect ambient process capability acquisition through %s", (_name, extraCode) => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const needle = "      child = spawn(\n        SYSTEMCTL_PATH,";
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-process-loader-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, `${extraCode}\n${needle}`),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-process-reference-must-be-current-uid-only");
  });

  it.each([
    ["Function", '      const Build = Function;\n      void Build("return process")();'],
    ["eval", '      const run = eval;\n      void run("process.getBuiltinModule(\\"node:child_process\\")");'],
  ])("rejects indirect runtime evaluation through %s", (name, extraCode) => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const needle = "      child = spawn(\n        SYSTEMCTL_PATH,";
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-runtime-eval-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, `${extraCode}\n${needle}`),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`phase-c-runtime-evaluation-reference-forbidden:${name}`);
    expect(result.stderr).toContain("phase-c-owner-source-digest:mismatch");
  });

  it.each([
    [
      'import * as cp from "child_process";',
      '      void cp["spawn"]("/bin/sh", []);',
    ],
    [
      'import { execFile as launch } from "child_process";',
      '      void launch("/bin/sh", []);',
    ],
  ])("rejects a bare-specifier process-capability bypass: %s", (extraImport, extraCall) => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const importNeedle = 'import { spawn } from "node:child_process";';
    const callNeedle = "      child = spawn(\n        SYSTEMCTL_PATH,";
    expect(canonical).toContain(importNeedle);
    expect(canonical).toContain(callNeedle);
    const mutated = canonical
      .replace(importNeedle, `${importNeedle}\n${extraImport}`)
      .replace(callNeedle, `${extraCall}\n${callNeedle}`);
    const root = createBaselineRepo("loopeix-s37-boundary-bare-process-import-", {
      "src/run/linux-host-enforcement-v02.ts": mutated,
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-child-process-import-must-be-sole-unaliased-spawn");
  });

  it("rejects broker access to direct OS capability modules", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-os-", {
      "src/run/pre-spawn-capability-broker-v02.ts": 'import "node:os";\nexport function enforceS37PreSpawnProbeV02() { return null; }\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("os-module: src/run/pre-spawn-capability-broker-v02.ts");
  });
});
