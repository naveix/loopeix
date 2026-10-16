import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Pr, { type PrCommandResult } from "../../src/commands/pr.js";

const repoRoot = join(import.meta.dirname, "../..");
const receipts = join(import.meta.dirname, "../fixtures/receipts");
let root: string;
let runDir: string;

const validPolicy = {
  max_member_bytes: 16_384,
  max_pack_bytes: 65_536,
  max_heap_bytes: 134_217_728,
  deadline_ms: 30_000,
} as const;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "loopeix-s35-pr-policy-"));
  runDir = join(root, "run");
  mkdirSync(runDir);
  copyFileSync(join(receipts, "snitch.receipt.json"), join(runDir, "receipt.json"));
  copyFileSync(join(receipts, "snitch.ledger.jsonl"), join(runDir, "ledger.jsonl"));
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(root, { recursive: true, force: true });
});

async function runPr(argv: string[]): Promise<{ result: PrCommandResult; exit: number; lines: string[] }> {
  const prior = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  vi.spyOn(Pr.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    const result = (await Pr.run(argv, repoRoot)) as PrCommandResult;
    return { result, exit: Number(process.exitCode ?? 0), lines };
  } finally {
    process.exitCode = prior;
  }
}

function policyFile(value: unknown, name = "policy.json"): string {
  const path = join(root, name);
  writeFileSync(path, `${JSON.stringify(value)}\n`);
  return path;
}

describe("S35 pr --legacy-replay-policy", () => {
  it("preserves the exact V01 result and rendered human bytes after sufficient finite admission", async () => {
    const baseline = await runPr([runDir]);
    vi.restoreAllMocks();
    const admitted = await runPr([runDir, "--legacy-replay-policy", policyFile(validPolicy)]);
    expect(admitted).toEqual(baseline);
  });

  it("rejects direct-receipt policy use with the closed usage result", async () => {
    const outcome = await runPr([
      join(receipts, "snitch.receipt.json"),
      "--legacy-replay-policy",
      policyFile(validPolicy),
    ]);
    expect(outcome).toMatchObject({
      result: {
        ok: false,
        reason: "INVALID_LEGACY_COMPATIBILITY_POLICY",
        message: "Legacy replay policy is invalid for this command or input family.",
      },
      exit: 2,
    });
  });

  it("writes neither Markdown nor card when policy admission fails", async () => {
    const markdown = join(root, "pr.md");
    const card = join(root, "card.svg");
    const outcome = await runPr([
      runDir,
      "--out",
      markdown,
      "--card",
      card,
      "--legacy-replay-policy",
      policyFile({ ...validPolicy, max_member_bytes: 1, max_pack_bytes: 1 }),
    ]);
    expect(outcome).toMatchObject({
      result: {
        ok: false,
        reason: "LEGACY_REPLAY_RESOURCE_LIMIT",
        message: "Legacy replay exceeded its approved finite resource policy.",
      },
      exit: 1,
    });
    expect(existsSync(markdown)).toBe(false);
    expect(existsSync(card)).toBe(false);
    expect(JSON.stringify(outcome)).not.toContain("run_snitch_01");
  });
});
