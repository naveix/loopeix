import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  capture: { ok: true, captured: Object.freeze({ run_id: "run_recover_01" }) } as unknown,
  consumed: { plan: { run_id: "run_recover_01", adapter_plan: { engine: "codex_cli" } }, member_bytes: new Map() } as unknown,
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
    control_enforcement: "NOT ENFORCED", next_action: null, controls: [],
  })),
}));

import RunRecover, { type RunRecoverResult } from "../../src/commands/run/recover.js";
import { capturePlannedRunV02 } from "../../src/run/capture-planned-v02.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const roots: string[] = [];

afterEach(() => {
  vi.clearAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "loopeix-recover-v02-"));
  roots.push(value);
  return value;
}

async function run(argv: string[]): Promise<{ result: RunRecoverResult; exit: number }> {
  const previous = process.exitCode;
  process.exitCode = 0;
  const log = vi.spyOn(RunRecover.prototype, "log").mockImplementation(() => {});
  const logJson = vi.spyOn(RunRecover.prototype as never, "logJson" as never).mockImplementation((() => {}) as never);
  try {
    const result = await RunRecover.run(argv, repoRoot) as RunRecoverResult;
    return { result, exit: Number(process.exitCode ?? 0) };
  } finally {
    log.mockRestore(); logJson.mockRestore(); process.exitCode = previous;
  }
}

describe("S35 V02 run recover", () => {
  it("returns unsupported for a clean planned V02 directory without writing", async () => {
    const output = await run([root(), "--json"]);
    expect(output).toMatchObject({
      exit: 1,
      result: { recoverable: false, reason: "UNSUPPORTED_EXECUTION_PROFILE", next_action: null },
    });
  });

  it("rejects contaminated V02 before ledger recovery", async () => {
    state.capture = { ok: false, reason: "V02_RUN_LAYOUT_CONTAMINATED", message: "contaminated" };
    await expect(run([root()])).resolves.toMatchObject({
      exit: 4,
      result: { reason: "V02_RUN_LAYOUT_CONTAMINATED", integrity_status: "invalid" },
    });
  });

  it("preserves direct-ledger precedence without probing the V02 directory facade", async () => {
    const directory = root();
    const ledger = join(directory, "ledger.jsonl");
    writeFileSync(ledger, "");
    state.capture = { ok: false, reason: "V02_RUN_LAYOUT_CONTAMINATED", message: "must not win" };
    const output = await run([ledger]);
    expect(capturePlannedRunV02).not.toHaveBeenCalled();
    expect(output.result).not.toHaveProperty("reason", "V02_RUN_LAYOUT_CONTAMINATED");
  });
});
