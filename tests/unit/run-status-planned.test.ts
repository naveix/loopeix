import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import RunStart from "../../src/commands/run/start.js";
import RunStatus, { type RunStatusResult } from "../../src/commands/run/status.js";
import { compilePrompt, planRunFromCompilePack, writeCompilePack } from "../../src/index.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const codexEvents = join(repoRoot, "tests", "fixtures", "adapter-events", "codex", "s1-codex-exec-json.redacted.jsonl");

async function runStatus(argv: string[]): Promise<{ result: RunStatusResult; exitCode: number; out: string }> {
  const before = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const spy = vi.spyOn(RunStatus.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    const result = (await RunStatus.run(argv, repoRoot)) as RunStatusResult;
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
  dir = mkdtempSync(join(tmpdir(), "loopeix-run-status-planned-"));
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

describe("loopeix run status <planned-run-dir>", () => {
  it("reports planned state before a ledger exists", async () => {
    const runDir = createPlannedRun();

    const { exitCode, out, result } = await runStatus([runDir]);

    expect(exitCode).toBe(0);
    expect(result.source).toBe("planned");
    expect(result.run_state).toBe("planned");
    expect(result.integrity_status).toBe("unknown");
    expect(result.run_id).toBe("run_fix_the_failing_date_parser_test_and_prove_the_f");
    expect(out).toContain("run_state:     planned");
    expect(out).toContain("next action:");
    expect(out).toContain("run start");
    expect(out).not.toContain("--events-file");
  });

  it("reports ledger-backed state after planned replay starts", async () => {
    const runDir = createPlannedRun();
    const startExit = await runStart([runDir, "--engine", "codex", "--events-file", codexEvents]);
    expect(startExit).toBe(4);

    const { exitCode, out, result } = await runStatus([runDir]);

    expect(exitCode).toBe(0);
    expect(result.source).toBe("ledger");
    expect(result.run_state).toBe("held");
    expect(result.integrity_status).toBe("valid");
    expect(out).toContain("run_state:     held");
    expect(out).toContain("integrity:     valid");
  });
});
