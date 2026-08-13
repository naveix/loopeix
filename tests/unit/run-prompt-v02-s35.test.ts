import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  capture: { ok: true, captured: Object.freeze({ run_id: "run_prompt_01" }) } as unknown,
  consumed: { plan: { run_id: "run_prompt_01", adapter_plan: { engine: "codex_cli" } }, member_bytes: new Map() } as unknown,
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
    controls: [
      { category: "goal", control_ref: "goal", label: "Goal | hostile", value: '{"statement":"<script>"}' },
      { category: "proof-boundary", control_ref: "authority-subject", label: "Authority", value: '{"policy_digest":"sha256:test"}' },
    ],
  })),
}));

import RunPrompt, { type RunPromptCommandResult } from "../../src/commands/run/prompt.js";
import { runEngine } from "../../src/run/engine.js";

vi.mock("../../src/run/engine.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/run/engine.js")>();
  return { ...actual, runEngine: vi.fn() };
});

const repoRoot = join(import.meta.dirname, "..", "..");
const roots: string[] = [];

afterEach(() => {
  vi.clearAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "loopeix-prompt-v02-")); roots.push(value); return value;
}

async function run(argv: string[]): Promise<{ result: RunPromptCommandResult; exit: number; output: string }> {
  const previous = process.exitCode; process.exitCode = 0; const lines: string[] = [];
  const log = vi.spyOn(RunPrompt.prototype, "log").mockImplementation((message?: unknown) => lines.push(String(message ?? "")));
  const logJson = vi.spyOn(RunPrompt.prototype as never, "logJson" as never).mockImplementation(((value: unknown) => lines.push(JSON.stringify(value))) as never);
  try {
    const result = await RunPrompt.run(argv, repoRoot) as RunPromptCommandResult;
    return { result, exit: Number(process.exitCode ?? 0), output: lines.join("\n") };
  } finally { log.mockRestore(); logJson.mockRestore(); process.exitCode = previous; }
}

describe("S35 V02 run prompt", () => {
  it("renders a non-runnable complete control projection without writes or execution", async () => {
    const directory = root(); const before = readdirSync(directory);
    const output = await run([directory]);
    expect(output.exit).toBe(0);
    expect(output.result).toMatchObject({ ok: true, status: "planned-non-runnable", execution_supported: false, next_action: null });
    expect(output.output).toContain("NOT EXECUTED");
    expect(output.output).toContain("NOT ENFORCED");
    expect(output.output).toContain("UNSUPPORTED_EXECUTION_PROFILE");
    expect(output.output).toContain("authority-subject");
    expect(output.output).not.toContain("loopeix run start");
    expect(runEngine).not.toHaveBeenCalled();
    expect(readdirSync(directory)).toEqual(before);
  });

  it("prints no prompt projection when the V02 layout is contaminated", async () => {
    state.capture = { ok: false, reason: "V02_RUN_LAYOUT_CONTAMINATED", message: "contaminated" };
    const output = await run([root()]);
    expect(output).toMatchObject({ exit: 4, result: { reason: "V02_RUN_LAYOUT_CONTAMINATED" } });
    expect(output.output).not.toContain("planned-run projection");
  });
});
