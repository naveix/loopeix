import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  capture: { ok: true, captured: Object.freeze({ run_id: "run_status_01" }) } as unknown,
  consumed: { plan: { run_id: "run_status_01", adapter_plan: { engine: "codex_cli" } }, member_bytes: new Map() } as unknown,
}));

vi.mock("../../src/run/capture-planned-v02.js", () => ({
  capturePlannedRunV02: vi.fn(async () => state.capture),
  consumeCapturedPlannedRunV02: vi.fn(() => state.consumed),
}));

vi.mock("../../src/run/present-planned-v02.js", () => ({
  presentPlannedRunV02: vi.fn((plan: { run_id: string }) => ({
    schema_version: "0.2", execution_profile: "bounded-v02", run_id: plan.run_id,
    run_state: "planned", execution_supported: false, controls_enforced: false,
    reason: "UNSUPPORTED_EXECUTION_PROFILE", work_execution: "NOT EXECUTED",
    control_enforcement: "NOT ENFORCED", next_action: null,
    controls: [{ category: "limit", control_ref: "limits", label: "Limits", value: "{}" }],
  })),
}));

import RunStatus, { type RunStatusResult } from "../../src/commands/run/status.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const roots: string[] = [];

afterEach(() => {
  vi.clearAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "loopeix-status-v02-"));
  roots.push(value);
  return value;
}

async function run(argv: string[]): Promise<{ result: RunStatusResult; exit: number; output: string }> {
  const previous = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const log = vi.spyOn(RunStatus.prototype, "log").mockImplementation((message?: unknown) => lines.push(String(message ?? "")));
  const logJson = vi.spyOn(RunStatus.prototype as never, "logJson" as never).mockImplementation(((value: unknown) => lines.push(JSON.stringify(value))) as never);
  try {
    const result = await RunStatus.run(argv, repoRoot) as RunStatusResult;
    return { result, exit: Number(process.exitCode ?? 0), output: lines.join("\n") };
  } finally {
    log.mockRestore(); logJson.mockRestore(); process.exitCode = previous;
  }
}

describe("S35 V02 run status", () => {
  it("reports a clean plan truthfully with controls and no next action", async () => {
    const directory = root();
    const before = readdirSync(directory);
    const output = await run([directory, "--json"]);
    expect(output.exit).toBe(0);
    expect(output.result).toMatchObject({
      source: "planned", run_state: "planned", execution_supported: false,
      controls_enforced: false, reason: "UNSUPPORTED_EXECUTION_PROFILE", next_action: null,
    });
    expect(output.output).toBe(JSON.stringify(output.result));
    expect(output.output).not.toContain("run start");
    expect(readdirSync(directory)).toEqual(before);
  });

  it("rejects V02 contamination before ledger recovery", async () => {
    state.capture = { ok: false, reason: "V02_RUN_LAYOUT_CONTAMINATED", message: "contaminated" };
    const output = await run([root()]);
    expect(output).toMatchObject({ exit: 4, result: { reason: "V02_RUN_LAYOUT_CONTAMINATED", integrity_status: "invalid" } });
  });
});
