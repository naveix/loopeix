import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import RunPlan, { type RunPlanCommandResult } from "../../src/commands/run/plan.js";
import { ResolvedRunPlan } from "../../src/index.js";
import { compilePrompt } from "../../src/compiler/compile.js";
import { writeCompilePack } from "../../src/compiler/pack.js";

const repoRoot = join(import.meta.dirname, "..", "..");

async function runPlanCommand(argv: string[]): Promise<{ result: RunPlanCommandResult; exitCode: number; out: string }> {
  const before = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const spy = vi.spyOn(RunPlan.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    const result = (await RunPlan.run(argv, repoRoot)) as RunPlanCommandResult;
    return { result, exitCode: Number(process.exitCode ?? 0), out: lines.join("\n") };
  } finally {
    spy.mockRestore();
    process.exitCode = before;
  }
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "loopeix-run-plan-command-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("loopeix run plan", () => {
  it("plans a compiled pack into a run directory", async () => {
    const pack = writeCompilePack(
      compilePrompt({
        prompt: "Fix the failing date parser test and prove the fix.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:00:00.000Z",
      }),
      join(dir, "compile-pack"),
    );

    const { exitCode, out, result } = await runPlanCommand([
      pack.pack_dir,
      "--workspace-root", dir,
      "--engine", "codex",
      "--approve-compiled-pack",
    ]);

    expect(exitCode).toBe(0);
    expect(result.ok).toBe(true);
    expect(out).toContain("PLANNED");
    expect(out).toContain("resolved-run-plan.json");
    const runPlan = JSON.parse(readFileSync(result.paths!.resolved_run_plan, "utf8"));
    expect(ResolvedRunPlan.safeParse(runPlan).success).toBe(true);
  });

  it("returns HOLD for a HOLD compile pack and writes no run plan", async () => {
    const pack = writeCompilePack(
      compilePrompt({
        prompt: "Use whatever tools you need and don't ask me.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:00:00.000Z",
      }),
      join(dir, "hold-pack"),
    );

    const { exitCode, out, result } = await runPlanCommand([
      pack.pack_dir,
      "--workspace-root", dir,
      "--engine", "codex",
      "--approve-compiled-pack",
    ]);

    expect(exitCode).toBe(1);
    expect(result.ok).toBe(false);
    expect(result.terminal_state).toBe("hold-risk");
    expect(out).toContain("HOLD  hold-risk");
    expect(existsSync(join(dir, ".loopeix", "loops"))).toBe(false);
  });

  it("requires explicit approval before planning a compiled pack", async () => {
    const pack = writeCompilePack(
      compilePrompt({
        prompt: "Fix the failing date parser test and prove the fix.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:00:00.000Z",
      }),
      join(dir, "compile-pack"),
    );

    const { exitCode, out, result } = await runPlanCommand([pack.pack_dir, "--workspace-root", dir, "--engine", "codex"]);

    expect(exitCode).toBe(1);
    expect(result.ok).toBe(false);
    expect(result.terminal_state).toBe("hold-approval-required");
    expect(out).toContain("HOLD  hold-approval-required");
    expect(existsSync(join(dir, ".loopeix", "loops"))).toBe(false);
  });
});
