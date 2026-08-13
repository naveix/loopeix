import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import RunPrompt, { type RunPromptCommandResult } from "../../src/commands/run/prompt.js";
import RunStart from "../../src/commands/run/start.js";
import { buildPlannedRunPrompt, planRunFromCompilePack } from "../../src/index.js";
import { compilePrompt } from "../../src/compiler/compile.js";
import { writeCompilePack } from "../../src/compiler/pack.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const codexEvents = join(repoRoot, "tests", "fixtures", "adapter-events", "codex", "s1-codex-exec-json.redacted.jsonl");

async function runPrompt(argv: string[]): Promise<{ result: RunPromptCommandResult; exitCode: number; out: string }> {
  const before = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const spy = vi.spyOn(RunPrompt.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    const result = (await RunPrompt.run(argv, repoRoot)) as RunPromptCommandResult;
    return { result, exitCode: Number(process.exitCode ?? 0), out: lines.join("\n") };
  } finally {
    spy.mockRestore();
    process.exitCode = before;
  }
}

async function runStart(argv: string[]): Promise<number> {
  const before = process.exitCode;
  process.exitCode = 0;
  const spy = vi.spyOn(RunStart.prototype, "log").mockImplementation(() => {});
  try {
    await RunStart.run(argv, repoRoot);
    return Number(process.exitCode ?? 0);
  } finally {
    spy.mockRestore();
    process.exitCode = before;
  }
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "loopeix-run-prompt-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function createPlannedRun(): string {
  const pack = writeCompilePack(
    compilePrompt({
      prompt: "Fix the failing date parser test and prove the fix.",
      workspaceRoot: dir,
      submittedAt: "2026-07-10T00:00:00.000Z",
    }),
    join(dir, "compile-pack"),
  );
  const planned = planRunFromCompilePack({
    packDir: pack.pack_dir,
    workspaceRoot: dir,
    engine: "codex",
    createdAt: "2026-07-10T00:01:00Z",
    approved: true,
  });
  expect(planned.ok).toBe(true);
  return planned.run_dir!;
}

describe("buildPlannedRunPrompt", () => {
  it("renders a bounded expert prompt from the approved planned run records", () => {
    const runDir = createPlannedRun();

    const result = buildPlannedRunPrompt({ runDir });

    expect(result.ok).toBe(true);
    expect(result.run_id).toBe("run_fix_the_failing_date_parser_test_and_prove_the_f");
    expect(result.engine).toBe("codex_cli");
    expect(result.prompt).toContain("Loopeix planned run prompt");
    expect(result.prompt).toContain("Objective");
    expect(result.prompt).toContain("Fix the failing date parser test and prove the fix.");
    expect(result.prompt).toContain("Workspace boundary");
    expect(result.prompt).toContain(dir);
    expect(result.prompt).toContain("Allowed tools");
    expect(result.prompt).toContain("Forbidden context");
    expect(result.prompt).toContain("Do not claim unsupported proof");
    expect(result.prompt).toContain("Gate plan");
    expect(result.prompt).toContain("Evaluation plan");
  });

  it("rejects malformed intake briefs before rendering a prompt", () => {
    const runDir = createPlannedRun();
    writeFileSync(join(runDir, "intake-brief.json"), '{"schema_version":"0.1"}\n');

    const result = buildPlannedRunPrompt({ runDir });

    expect(result.ok).toBe(false);
    expect(result.status).toBe("hold-invalid-plan");
    expect(result.findings.join("\n")).toContain("intake-brief.json is invalid");
  });
});

describe("loopeix run prompt <planned-run-dir>", () => {
  it("prints the bounded prompt for a startable planned run", async () => {
    const runDir = createPlannedRun();

    const { exitCode, out, result } = await runPrompt([runDir]);

    expect(exitCode).toBe(0);
    expect(result.ok).toBe(true);
    expect(out).toContain("Loopeix planned run prompt");
    expect(out).toContain("Fix the failing date parser test and prove the fix.");
    expect(out).toContain("Do not claim unsupported proof");
  });

  it("refuses to print a prompt for an already-started planned run", async () => {
    const runDir = createPlannedRun();
    expect(await runStart([runDir, "--engine", "codex", "--events-file", codexEvents])).toBe(4);

    const { exitCode, out, result } = await runPrompt([runDir]);

    expect(exitCode).toBe(1);
    expect(result.ok).toBe(false);
    expect(out).toContain("HOLD  hold-already-started");
    expect(out).not.toContain("Loopeix planned run prompt");
  });
});
