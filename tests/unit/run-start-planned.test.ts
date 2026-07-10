import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import RunStart from "../../src/commands/run/start.js";
import { RUN_DIR_FILES } from "../../src/run/run-dir.js";
import { compilePrompt, planRunFromCompilePack, writeCompilePack } from "../../src/index.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const codexEvents = join(repoRoot, "tests", "fixtures", "adapter-events", "codex", "s1-codex-exec-json.redacted.jsonl");

async function runStart(argv: string[]): Promise<{ exitCode: number; out: string }> {
  const before = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const spy = vi.spyOn(RunStart.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    await RunStart.run(argv, repoRoot);
    return { exitCode: Number(process.exitCode ?? 0), out: lines.join("\n") };
  } finally {
    spy.mockRestore();
    process.exitCode = before;
  }
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "loopeix-run-start-planned-"));
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

describe("loopeix run start <planned-run-dir>", () => {
  it("replays captured events into the planned run directory", async () => {
    const runDir = createPlannedRun();

    const { exitCode, out } = await runStart([runDir, "--engine", "codex", "--events-file", codexEvents]);

    expect(exitCode).toBe(4);
    expect(out).toContain(`Run dir: ${runDir}`);
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(true);
    expect(existsSync(join(runDir, RUN_DIR_FILES.manifest))).toBe(true);
    expect(existsSync(join(runDir, RUN_DIR_FILES.reportMd))).toBe(true);
    const summary = JSON.parse(readFileSync(join(runDir, RUN_DIR_FILES.runSummary), "utf8"));
    expect(summary.run_id).toBe("run_fix_the_failing_date_parser_test_and_prove_the_f");
  });

  it("refuses to live-run a planned run directory in S27", async () => {
    const runDir = createPlannedRun();

    const { exitCode, out } = await runStart([runDir, "--engine", "codex", "--prompt", "do it"]);

    expect(exitCode).toBe(1);
    expect(out).toContain("planned run directories require --events-file");
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(false);
  });

  it("refuses to overwrite existing execution artifacts", async () => {
    const runDir = createPlannedRun();
    const first = await runStart([runDir, "--engine", "codex", "--events-file", codexEvents]);
    expect(first.exitCode).toBe(4);

    const second = await runStart([runDir, "--engine", "codex", "--events-file", codexEvents]);

    expect(second.exitCode).toBe(1);
    expect(second.out).toContain("execution artifacts already exist");
  });
});
