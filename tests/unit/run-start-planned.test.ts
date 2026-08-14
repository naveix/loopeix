import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/run/engine.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/run/engine.js")>();
  return {
    ...actual,
    runEngine: vi.fn(),
  };
});

vi.mock("../../src/run/id.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/run/id.js")>();
  return {
    ...actual,
    reserveRawRunDirectory: vi.fn(actual.reserveRawRunDirectory),
  };
});

import RunStart from "../../src/commands/run/start.js";
import { runEngine } from "../../src/run/engine.js";
import { reserveRawRunDirectory } from "../../src/run/id.js";
import { RUN_DIR_FILES } from "../../src/run/run-dir.js";
import { planRunFromCompilePack } from "../../src/index.js";
import { compilePrompt } from "../../src/compiler/compile.js";
import { writeCompilePack } from "../../src/compiler/pack.js";

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
  vi.mocked(runEngine).mockReset();
  vi.mocked(reserveRawRunDirectory).mockClear();
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function createPlannedRun(engine: "codex" | "claude" = "codex"): string {
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
    engine,
    createdAt: "2026-07-10T00:01:00Z",
    approved: true,
  });
  expect(planned.ok).toBe(true);
  return planned.run_dir!;
}

describe("loopeix run start <planned-run-dir>", () => {
  it("advertises replay-only S37 behavior without live-run examples", () => {
    expect(RunStart.summary).toBe(
      "Replay captured engine events into a run directory; live execution is held in S37.",
    );
    expect(RunStart.flags.engine.description).toContain("captured engine identity");
    expect(RunStart.flags["events-file"].description).toContain("required for executable S37 replay");
    expect(RunStart.flags.prompt.description).toContain("all live execution is held in S37");
    expect(RunStart.flags["max-budget-usd"].description).toContain("all live execution is held in S37");
    expect(RunStart.examples).toHaveLength(3);
    expect(RunStart.examples.every((example) => example.includes("--events-file"))).toBe(true);
  });

  it("replays captured events into the planned run directory", async () => {
    const runDir = createPlannedRun();

    const { exitCode, out } = await runStart([runDir, "--engine", "codex", "--events-file", codexEvents]);

    expect(exitCode).toBe(4);
    expect(out).not.toContain("Invoking");
    expect(out).toContain(`Run dir: ${runDir}`);
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(true);
    expect(existsSync(join(runDir, RUN_DIR_FILES.manifest))).toBe(true);
    expect(existsSync(join(runDir, RUN_DIR_FILES.reportMd))).toBe(true);
    expect(existsSync(join(runDir, "ledger.lock"))).toBe(false);
    const summary = JSON.parse(readFileSync(join(runDir, RUN_DIR_FILES.runSummary), "utf8"));
    expect(summary.run_id).toBe("run_fix_the_failing_date_parser_test_and_prove_the_f");
    expect(runEngine).not.toHaveBeenCalled();
    expect(reserveRawRunDirectory).not.toHaveBeenCalled();
  });

  it("refuses to start when the planned run ledger lock is already held", async () => {
    const runDir = createPlannedRun();
    writeFileSync(join(runDir, "ledger.lock"), `${JSON.stringify({ pid: process.pid, acquired_at: Date.now(), host: "test" })}\n`);

    const { exitCode, out } = await runStart([runDir, "--engine", "codex", "--events-file", codexEvents]);

    expect(exitCode).toBe(1);
    expect(out).toContain("run lock is held");
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(false);
    expect(runEngine).not.toHaveBeenCalled();
  });

  it("refuses live planned execution under a held run lock before engine launch", async () => {
    const runDir = createPlannedRun();
    writeFileSync(join(runDir, "ledger.lock"), `${JSON.stringify({ pid: process.pid, acquired_at: Date.now(), host: "test" })}\n`);

    const { exitCode, out } = await runStart([runDir, "--engine", "codex"]);

    expect(exitCode).toBe(1);
    expect(out).toContain("run lock is held");
    expect(out).not.toContain("Invoking");
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(false);
    expect(runEngine).not.toHaveBeenCalled();
  });

  it("does not steal an older run lock while the holder pid is still alive", async () => {
    const runDir = createPlannedRun();
    writeFileSync(join(runDir, "ledger.lock"), `${JSON.stringify({ pid: process.pid, acquired_at: Date.now() - 60_000, host: "test" })}\n`);

    const { exitCode, out } = await runStart([runDir, "--engine", "codex", "--events-file", codexEvents]);

    expect(exitCode).toBe(1);
    expect(out).toContain("run lock is held");
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(false);
    expect(runEngine).not.toHaveBeenCalled();
  });

  it("replays captured events even when intake brief rendering would fail", async () => {
    const runDir = createPlannedRun();
    writeFileSync(join(runDir, "intake-brief.json"), '{"schema_version":"0.1"}\n');

    const { exitCode, out } = await runStart([runDir, "--engine", "codex", "--events-file", codexEvents]);

    expect(exitCode).toBe(4);
    expect(out).toContain("Replaying");
    expect(out).not.toContain("planned run prompt failed");
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(true);
    expect(existsSync(join(runDir, "ledger.lock"))).toBe(false);
    expect(runEngine).not.toHaveBeenCalled();
  });

  it("S37 holds a Codex planned live run before the legacy engine boundary", async () => {
    const runDir = createPlannedRun();

    const { exitCode, out } = await runStart([runDir, "--engine", "codex"]);

    expect(exitCode).toBe(1);
    expect(out).toContain("reason: GENERAL_AGENT_PROHIBITED");
    expect(out).toContain("S37 prohibits general-agent execution");
    expect(out).not.toContain("Invoking");
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(false);
    expect(existsSync(join(runDir, "ledger.lock"))).toBe(false);
    expect(runEngine).not.toHaveBeenCalled();
    expect(reserveRawRunDirectory).not.toHaveBeenCalled();
  });

  it("S37 holds a Claude planned live run before budget or engine invocation", async () => {
    const runDir = createPlannedRun("claude");

    const { exitCode, out } = await runStart([runDir, "--engine", "claude", "--max-budget-usd", "0.25"]);

    expect(exitCode).toBe(1);
    expect(out).toContain("reason: GENERAL_AGENT_PROHIBITED");
    expect(out).not.toContain("Invoking");
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(false);
    expect(existsSync(join(runDir, "ledger.lock"))).toBe(false);
    expect(runEngine).not.toHaveBeenCalled();
  });

  it("refuses prompt overrides for planned run directories", async () => {
    const runDir = createPlannedRun();

    const { exitCode, out } = await runStart([runDir, "--engine", "codex", "--prompt", "do it"]);

    expect(exitCode).toBe(1);
    expect(out).toContain("planned run directories use the approved generated prompt");
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(false);
    expect(runEngine).not.toHaveBeenCalled();
  });

  it("refuses live planned runs with malformed intake brief before engine launch", async () => {
    const runDir = createPlannedRun();
    writeFileSync(join(runDir, "intake-brief.json"), '{"schema_version":"0.1"}\n');

    const { exitCode, out } = await runStart([runDir, "--engine", "codex"]);

    expect(exitCode).toBe(1);
    expect(out).toContain("planned run prompt failed (hold-invalid-plan)");
    expect(out).toContain("intake-brief.json is invalid");
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(false);
    expect(runEngine).not.toHaveBeenCalled();
  });

  it("refuses planned runs prepared for a different engine from the command surface", async () => {
    const runDir = createPlannedRun();

    const { exitCode, out } = await runStart([runDir, "--engine", "claude"]);

    expect(exitCode).toBe(1);
    expect(out).toContain("planned run preflight failed (hold-engine-mismatch)");
    expect(out).toContain("planned run was prepared for codex_cli");
    expect(existsSync(join(runDir, RUN_DIR_FILES.ledger))).toBe(false);
    expect(runEngine).not.toHaveBeenCalled();
  });

  it("refuses to overwrite existing execution artifacts", async () => {
    const runDir = createPlannedRun();
    const first = await runStart([runDir, "--engine", "codex", "--events-file", codexEvents]);
    expect(first.exitCode).toBe(4);

    const second = await runStart([runDir, "--engine", "codex", "--events-file", codexEvents]);

    expect(second.exitCode).toBe(1);
    expect(second.out).toContain("hold-already-started");
    expect(second.out).toContain("execution artifact already exists");
  });
});
