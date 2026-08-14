import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function runBoundary(...files: string[]) {
  return spawnSync(process.execPath, ["scripts/check-s37-boundaries.mjs", ...files], {
    cwd: process.cwd(),
    encoding: "utf8",
    shell: false,
    timeout: 15_000,
    maxBuffer: 2 * 1024 * 1024,
  });
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

    const result = runBoundary(trap);
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

    const result = runBoundary(clean);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
  });
});
