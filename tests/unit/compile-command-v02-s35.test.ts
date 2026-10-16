import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import Compile, { type CompileCommandResult } from "../../src/commands/compile.js";
import {
  S35_PROJECTION_ORACLES,
  bindingInputForProjectionOracle,
} from "../helpers/s35-projection-oracles.js";

const REPOSITORY_ROOT = join(import.meta.dirname, "..", "..");
const SENTINEL = "*\n!.gitignore\n";

type RunResult = Readonly<{
  result: CompileCommandResult;
  exit: number;
  stdout: string;
  stderr: string;
}>;

let workspace: string;

function safeBugfixPayload(): string {
  const oracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "safe-bugfix");
  if (oracle === undefined) throw new Error("safe-bugfix projection oracle is missing");
  const record = bindingInputForProjectionOracle(oracle) as {
    bindings: Array<Record<string, unknown> & { approved_by: string }>;
  };
  return JSON.stringify({
    bindings: record.bindings.map(({ approved_by: _approvedBy, ...binding }) => binding),
  });
}

beforeEach(() => {
  workspace = mkdtempSync(join(tmpdir(), "loopeix-compile-command-v02-"));
  mkdirSync(join(workspace, ".loopeix", "compiles"), { recursive: true });
  writeFileSync(join(workspace, ".loopeix", "compiles", ".gitignore"), SENTINEL);
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(workspace, { recursive: true, force: true });
});

async function runCompile(argv: string[]): Promise<RunResult> {
  const prior = process.exitCode;
  process.exitCode = 0;
  const stdout: string[] = [];
  const stderr: string[] = [];
  const log = vi.spyOn(Compile.prototype, "log").mockImplementation((message?: unknown) => stdout.push(String(message ?? "")));
  const logJson = vi.spyOn(Compile.prototype as never, "logJson" as never).mockImplementation(((value: unknown) => {
    stdout.push(JSON.stringify(value));
  }) as never);
  const logToStderr = vi.spyOn(Compile.prototype, "logToStderr").mockImplementation((message?: unknown) => stderr.push(String(message ?? "")));
  try {
    const result = (await Compile.run(argv, REPOSITORY_ROOT)) as CompileCommandResult;
    return {
      result,
      exit: Number(process.exitCode ?? 0),
      stdout: stdout.join("\n"),
      stderr: stderr.join("\n"),
    };
  } finally {
    log.mockRestore();
    logJson.mockRestore();
    logToStderr.mockRestore();
    process.exitCode = prior;
  }
}

describe("S35 V02 compile command", () => {
  it("writes a new V02 pack and standalone through the coordinator", async () => {
    const output = join(workspace, "generated.loop.yaml");
    const bindingPath = join(workspace, "bindings.json");
    writeFileSync(bindingPath, safeBugfixPayload());
    const run = await runCompile([
      "--prompt", "Fix the failing date parser test and prove the fix.",
      "--workspace-root", workspace,
      "--bindings", bindingPath,
      "--out", output,
    ]);

    expect(run.exit).toBe(0);
    expect(run.result).toMatchObject({
      ok: true,
      disposition: "compiled",
      terminal_state: "compiled",
      reason: null,
      standalone_ref: "generated.loop.yaml",
      findings: [],
    });
    if (!run.result.ok) throw new Error("expected compiled result");
    expect(existsSync(join(workspace, ".loopeix", "compiles", run.result.pack_ref, "pack-manifest.json"))).toBe(true);
    expect(readFileSync(output)).toEqual(readFileSync(join(workspace, ".loopeix", "compiles", run.result.pack_ref, "generated.loop.yaml")));
    expect(run.stdout).toContain(`COMPILED  ${run.result.pack_ref}`);
    expect(run.stdout).toContain(`Wrote ${output}`);
    expect(run.stderr).toBe("");
  });

  it("captures strict bindings once and returns the exact closed JSON result", async () => {
    const bindingPath = join(workspace, "bindings.json");
    writeFileSync(bindingPath, safeBugfixPayload());
    const run = await runCompile([
      "--prompt", "Fix the failing date parser test and prove the fix.",
      "--workspace-root", workspace,
      "--bindings", bindingPath,
      "--include-internal",
      "--json",
    ]);

    expect(run.exit).toBe(0);
    expect(run.result).toMatchObject({ ok: true, disposition: "compiled", terminal_state: "compiled" });
    expect(run.stdout).toBe(JSON.stringify(run.result));
    expect(run.stderr).toBe("");
    expect(Object.keys(run.result).sort()).toEqual([
      "disposition", "findings", "ok", "pack_ref", "reason", "standalone_ref", "terminal_state",
    ]);
  });

  it("writes the contracted HOLD pack and no requested standalone", async () => {
    const output = join(workspace, "held.loop.yaml");
    const run = await runCompile([
      "--prompt", "Use whatever tools you need and don't ask me.",
      "--workspace-root", workspace,
      "--out", output,
    ]);

    expect(run.exit).toBe(1);
    expect(run.result).toMatchObject({
      ok: false,
      disposition: "hold",
      terminal_state: "hold-risk",
      reason: "RISK_BOUNDARY_UNRESOLVED",
      standalone_ref: null,
    });
    if (run.result.disposition !== "hold") throw new Error("expected HOLD result");
    expect(existsSync(output)).toBe(false);
    expect(existsSync(join(workspace, ".loopeix", "compiles", run.result.pack_ref, "pack-manifest.json"))).toBe(true);
    expect(run.stdout).toContain("HOLD  hold-risk [RISK_BOUNDARY_UNRESOLVED]");
    expect(run.stderr).toBe("");
  });

  it("sanitizes privacy failures and emits no pack", async () => {
    const run = await runCompile([
      "--prompt", "Use token ghp_abcdefghijklmnopqrstuvwxyz1234567890 to fix the parser",
      "--workspace-root", workspace,
    ]);

    expect(run.exit).toBe(4);
    expect(run.result).toMatchObject({
      ok: false,
      disposition: "rejected",
      reason: "SENSITIVE_INPUT_REJECTED",
      pack_ref: null,
      standalone_ref: null,
      findings: [],
      location: "prompt",
    });
    expect(run.stdout).toBe("");
    expect(run.stderr).toBe("ERROR [SENSITIVE_INPUT_REJECTED] Sensitive input was rejected.");
    expect(run.stderr).not.toContain("ghp_");
    expect(readFileSync(join(workspace, ".loopeix", "compiles", ".gitignore"), "utf8")).toBe(SENTINEL);
  });

  it("rejects legacy pack paths and internal disclosure without JSON as usage errors", async () => {
    await expect(Compile.run([
      "--prompt", "Fix the parser",
      "--workspace-root", workspace,
      "--pack-dir", join(workspace, "pack"),
    ], REPOSITORY_ROOT)).rejects.toThrow(/Nonexistent flag: --pack-dir/u);

    await expect(Compile.run([
      "--prompt", "Fix the parser",
      "--workspace-root", workspace,
      "--include-internal",
    ], REPOSITORY_ROOT)).rejects.toThrow(/provided when using --include-internal: --json/u);
    expect(readFileSync(join(workspace, ".loopeix", "compiles", ".gitignore"), "utf8")).toBe(SENTINEL);
  });
});
