import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import RunPreflight, { type RunPreflightCommandResult } from "../../src/commands/run/preflight.js";
import RunStart from "../../src/commands/run/start.js";
import { compilePrompt, preflightPlannedRun, writeCompilePack, planRunFromCompilePack } from "../../src/index.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const codexEvents = join(repoRoot, "tests", "fixtures", "adapter-events", "codex", "s1-codex-exec-json.redacted.jsonl");

async function runPreflight(argv: string[]): Promise<{ result: RunPreflightCommandResult; exitCode: number; out: string }> {
  const before = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const spy = vi.spyOn(RunPreflight.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    const result = (await RunPreflight.run(argv, repoRoot)) as RunPreflightCommandResult;
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
  dir = mkdtempSync(join(tmpdir(), "loopeix-run-preflight-"));
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

describe("preflightPlannedRun", () => {
  it("returns ready for a complete unexecuted planned run", () => {
    const runDir = createPlannedRun();

    const result = preflightPlannedRun({ runDir, engine: "codex_cli" });

    expect(result.ok).toBe(true);
    expect(result.status).toBe("ready");
    expect(result.run_id).toBe("run_fix_the_failing_date_parser_test_and_prove_the_f");
    expect(result.next_action).toContain("run start");
    expect(result.next_action).not.toContain("--events-file");
  });

  it("rejects wrong engine before execution can start", () => {
    const runDir = createPlannedRun();

    const result = preflightPlannedRun({ runDir, engine: "claude_code_cli" });

    expect(result.ok).toBe(false);
    expect(result.status).toBe("hold-engine-mismatch");
    expect(result.findings.join("\n")).toContain("codex_cli");
  });

  it("rejects missing planned files without throwing", () => {
    const runDir = createPlannedRun();
    rmSync(join(runDir, "generated.loop.yaml"), { force: true });

    const result = preflightPlannedRun({ runDir, engine: "codex_cli" });

    expect(result.ok).toBe(false);
    expect(result.status).toBe("hold-missing-file");
    expect(result.findings.join("\n")).toContain("generated.loop.yaml");
  });

  it("rejects executed planned runs as already started", async () => {
    const runDir = createPlannedRun();
    expect(await runStart([runDir, "--engine", "codex", "--events-file", codexEvents])).toBe(4);

    const result = preflightPlannedRun({ runDir, engine: "codex_cli" });

    expect(result.ok).toBe(false);
    expect(result.status).toBe("hold-already-started");
    expect(result.findings.join("\n")).toContain("ledger.jsonl");
  });
});

describe("loopeix run preflight", () => {
  it("prints READY for a startable planned run", async () => {
    const runDir = createPlannedRun();

    const { exitCode, out, result } = await runPreflight([runDir, "--engine", "codex"]);

    expect(exitCode).toBe(0);
    expect(result.ok).toBe(true);
    expect(out).toContain("READY");
    expect(out).toContain("run start");
    expect(out).not.toContain("--events-file");
  });

  it("prints HOLD for an already executed planned run", async () => {
    const runDir = createPlannedRun();
    expect(await runStart([runDir, "--engine", "codex", "--events-file", codexEvents])).toBe(4);

    const { exitCode, out, result } = await runPreflight([runDir, "--engine", "codex"]);

    expect(exitCode).toBe(1);
    expect(result.ok).toBe(false);
    expect(out).toContain("HOLD  hold-already-started");
  });
});
