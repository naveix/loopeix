import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

  it("rejects Linux module imports inside the compatibility engine or CLI", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-cli-", {
      "src/commands/run/start.ts": 'import "./linux-host-enforcement-v02.js";\nexport function runStart() { return null; }\n',
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

  it("rejects direct OS and spawn capabilities inside Phase A Linux modules", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-linux-os-", {
      "src/run/linux-host-enforcement-v02.ts": 'import { spawn } from "node:child_process";\nexport const launch = () => spawn("/bin/true");\n',
      "src/run/bounded-linux-probe-v02.ts": "export function runBoundedS37LinuxProbeV02() { return null; }\n",
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("child-process-module: src/run/linux-host-enforcement-v02.ts");
    expect(result.stderr).toContain("spawn-or-exec: src/run/linux-host-enforcement-v02.ts");
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
