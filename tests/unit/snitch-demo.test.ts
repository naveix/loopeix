import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import Pr from "../../src/commands/pr.js";
import RunStart from "../../src/commands/run/start.js";
import Verify from "../../src/commands/verify.js";
import { assertWellFormedXml } from "../helpers/render.js";

/**
 * The 60-second-demo proof (delta-card-and-pr-spec.md §3, Test obligations §Demo test):
 * execute the examples/snitch-demo/README.md sequence end-to-end in a temp workspace — replay →
 * seal → verify (deep) → pr + card — through the REAL command classes over the committed
 * run-seal fixtures. If this test passes, the README's claim is real, not aspirational.
 */

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const fixtures = join(here, "..", "fixtures", "run-seal");
const readmePath = join(repoRoot, "examples", "snitch-demo", "README.md");

const CAPTION = "My agent reported 34/34 passing. It had deleted the failing test. The receipt caught it.";

async function runCommand(
  cls: typeof RunStart | typeof Verify | typeof Pr,
  argv: string[],
): Promise<{ exitCode: number; out: string }> {
  const before = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const spy = vi.spyOn(cls.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    await cls.run(argv, repoRoot);
    return { exitCode: Number(process.exitCode ?? 0), out: lines.join("\n") };
  } finally {
    spy.mockRestore();
    process.exitCode = before;
  }
}

describe("examples/snitch-demo — the README sequence, end to end", () => {
  let ws: string;
  beforeAll(() => {
    ws = mkdtempSync(join(tmpdir(), "loopeix-snitch-demo-"));
  });
  afterAll(() => {
    rmSync(ws, { recursive: true, force: true });
  });

  it("README step 2: run start --events-file --seal produces a sealed run with a receipt", async () => {
    const { exitCode, out } = await runCommand(RunStart, [
      join(fixtures, "seal-loop.yaml"),
      "--engine", "codex",
      "--events-file", join(fixtures, "snitch-events.jsonl"),
      "--seal", join(fixtures, "snitch-brief.yaml"),
      "--workspace", ws,
    ]);
    expect(exitCode).toBe(0);
    expect(out).toContain("UNSUPPORTED  34/34 tests passing");
    expect(out).toContain("PROMISE_BROKEN  deleting or skipping tests");
    const runs = readdirSync(join(ws, ".loopeix", "runs"));
    expect(runs).toHaveLength(1);
    expect(existsSync(join(ws, ".loopeix", "runs", runs[0]!, "receipt.json"))).toBe(true);
  });

  it("README step 3: loopeix verify --run-dir passes every check including the deep ledger checks", async () => {
    const runDir = join(ws, ".loopeix", "runs", readdirSync(join(ws, ".loopeix", "runs"))[0]!);
    const { exitCode, out } = await runCommand(Verify, [join(runDir, "receipt.json"), "--run-dir", runDir]);
    expect(exitCode).toBe(0);
    for (const id of ["parse", "schema", "invariants", "doctrine", "signature", "ledger_hash", "ledger_head", "ledger_chain"]) {
      expect(out).toMatch(new RegExp(`^PASS  ${id}: `, "m"));
    }
    expect(out).not.toContain("FAIL");
    expect(out).toContain("VERIFIED");
  });

  it("README step 4: loopeix pr <run-dir> --card renders the red row and writes the Delta Card", async () => {
    const runDir = join(ws, ".loopeix", "runs", readdirSync(join(ws, ".loopeix", "runs"))[0]!);
    const cardPath = join(ws, "delta-card.svg");
    const { exitCode, out } = await runCommand(Pr, [runDir, "--card", cardPath]);
    expect(exitCode).toBe(0);
    // The red line is the headline: the broken promise leads the table.
    const rows = out.split("\n").filter((l) => l.startsWith("|")).slice(2);
    expect(rows[0]).toContain("🟥 `PROMISE BROKEN`");
    expect(rows[0]).toContain("deleting or skipping tests");
    expect(out).toContain("⬜ `UNSUPPORTED`");
    expect(out).toContain("npx loopeix verify receipt.json");

    const svg = readFileSync(cardPath, "utf8");
    assertWellFormedXml(svg);
    expect(svg).toContain("LOOPEIX CLAIMS CHECK");
    expect(svg).toContain('fill="#f85149">deleting or skipping tests —');
  });

  it("the README carries the exact commands, fixture paths, honesty note, and caption", () => {
    const readme = readFileSync(readmePath, "utf8");
    expect(readme).toContain("tests/fixtures/run-seal/seal-loop.yaml");
    expect(readme).toContain("tests/fixtures/run-seal/snitch-events.jsonl");
    expect(readme).toContain("tests/fixtures/run-seal/snitch-brief.yaml");
    expect(readme).toContain("--events-file");
    expect(readme).toContain("--seal");
    expect(readme).toContain("--run-dir");
    expect(readme).toContain("--card");
    expect(readme).toContain("captured-events replay");
    expect(readme).toContain(CAPTION);
  });
});
