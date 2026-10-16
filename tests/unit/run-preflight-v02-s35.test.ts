import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const capture = vi.hoisted(() => ({
  result: { ok: true, captured: Object.freeze({ run_id: "run_preflight_01" }) } as unknown,
  consumed: {
    plan: {
      run_id: "run_preflight_01",
      adapter_plan: { engine: "codex_cli" },
    },
    member_bytes: new Map(),
  } as unknown,
}));

vi.mock("../../src/run/capture-planned-v02.js", () => ({
  capturePlannedRunV02: vi.fn(async () => capture.result),
  consumeCapturedPlannedRunV02: vi.fn(() => capture.consumed),
}));

vi.mock("../../src/run/present-planned-v02.js", () => ({
  presentPlannedRunV02: vi.fn((plan: { run_id: string }) => ({
    schema_version: "0.2",
    execution_profile: "bounded-v02",
    run_id: plan.run_id,
    run_state: "planned",
    execution_supported: false,
    controls_enforced: false,
    reason: "UNSUPPORTED_EXECUTION_PROFILE",
    work_execution: "NOT EXECUTED",
    control_enforcement: "NOT ENFORCED",
    next_action: null,
    controls: [{ category: "engine", control_ref: "adapter-plan", label: "Adapter plan", value: "{}" }],
  })),
}));

import RunPreflight, { type RunPreflightCommandResult } from "../../src/commands/run/preflight.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const roots: string[] = [];

afterEach(() => {
  vi.clearAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function run(argv: string[]): Promise<{ result: RunPreflightCommandResult; exit: number; output: string }> {
  const previous = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const log = vi.spyOn(RunPreflight.prototype, "log").mockImplementation((message?: unknown) => lines.push(String(message ?? "")));
  const logJson = vi.spyOn(RunPreflight.prototype as never, "logJson" as never).mockImplementation(((value: unknown) => lines.push(JSON.stringify(value))) as never);
  try {
    const result = await RunPreflight.run(argv, repoRoot) as RunPreflightCommandResult;
    return { result, exit: Number(process.exitCode ?? 0), output: lines.join("\n") };
  } finally {
    log.mockRestore();
    logJson.mockRestore();
    process.exitCode = previous;
  }
}

function emptyRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "loopeix-preflight-v02-"));
  roots.push(root);
  return root;
}

describe("S35 V02 run preflight command", () => {
  it("returns truthful unsupported HOLD with all projected controls and no next action", async () => {
    const root = emptyRoot();
    const before = readdirSync(root);
    const output = await run([root, "--engine", "codex", "--json"]);
    expect(output.exit).toBe(1);
    expect(output.result).toMatchObject({
      ok: false,
      status: "hold-unsupported-execution-profile",
      reason: "UNSUPPORTED_EXECUTION_PROFILE",
      execution_supported: false,
      controls_enforced: false,
      next_action: null,
    });
    expect(output.output).toBe(JSON.stringify(output.result));
    expect(output.output).not.toContain("run start");
    expect(readdirSync(root)).toEqual(before);
  });

  it("checks engine binding before the unsupported-profile verdict", async () => {
    const output = await run([emptyRoot(), "--engine", "claude"]);
    expect(output).toMatchObject({ exit: 1, result: { reason: "ENGINE_MISMATCH", status: "hold-engine-mismatch" } });
    expect(output.output).not.toContain("READY");
  });

  it("maps V02 contamination and invalid plans to integrity exits", async () => {
    capture.result = { ok: false, reason: "V02_RUN_LAYOUT_CONTAMINATED", message: "contaminated" };
    await expect(run([emptyRoot(), "--engine", "codex"])).resolves.toMatchObject({
      exit: 4,
      result: { reason: "V02_RUN_LAYOUT_CONTAMINATED" },
    });
    capture.result = { ok: false, reason: "INVALID_V02_PLAN", message: "invalid" };
    await expect(run([emptyRoot(), "--engine", "codex"])).resolves.toMatchObject({
      exit: 4,
      result: { reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT" },
    });
  });
});
