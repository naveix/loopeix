import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Verify from "../../src/commands/verify.js";
import type { VerifyReceiptResult } from "../../src/receipt.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const receipts = join(here, "..", "fixtures", "receipts");

/**
 * Runs the oclif command class directly (no spawned process). The command signals failure via
 * `process.exitCode = 1`, so we capture and restore it around each run — vitest must never
 * inherit a stale exit code from an intentionally failing verification.
 */
async function runVerify(argv: string[]): Promise<{ result: VerifyReceiptResult; exitCode: number }> {
  const before = process.exitCode;
  process.exitCode = 0;
  try {
    const result = (await Verify.run(argv, repoRoot)) as VerifyReceiptResult;
    return { result, exitCode: Number(process.exitCode ?? 0) };
  } finally {
    process.exitCode = before;
  }
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "loopeix-verify-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("loopeix verify — exit-code semantics", () => {
  it("a clean golden receipt verifies with exit 0", async () => {
    const { result, exitCode } = await runVerify([join(receipts, "clean-pass.receipt.json")]);
    expect(result.ok).toBe(true);
    expect(exitCode).toBe(0);
    expect(result.checks.map((c) => c.id)).toEqual(["parse", "schema", "invariants", "doctrine", "signature"]);
  });

  it("a tampered receipt exits 1 with the signature check failed", async () => {
    const { result, exitCode } = await runVerify([join(receipts, "snitch.tampered-verdict.receipt.json")]);
    expect(result.ok).toBe(false);
    expect(exitCode).toBe(1);
    expect(result.checks.filter((c) => !c.ok).map((c) => c.id)).toEqual(["signature"]);
  });

  it("a missing file exits 1 with a parse check failure (never a stack trace)", async () => {
    const { result, exitCode } = await runVerify([join(dir, "does-not-exist.receipt.json")]);
    expect(exitCode).toBe(1);
    const parse = result.checks.find((c) => c.id === "parse");
    expect(parse?.ok).toBe(false);
    expect(parse?.detail).toContain("cannot read receipt");
  });
});

describe("loopeix verify --run-dir — the deep ledger check", () => {
  it("verifies the snitch receipt against its run dir with exit 0", async () => {
    copyFileSync(join(receipts, "snitch.ledger.jsonl"), join(dir, "ledger.jsonl"));
    const { result, exitCode } = await runVerify([join(receipts, "snitch.receipt.json"), "--run-dir", dir]);
    expect(result.ok).toBe(true);
    expect(exitCode).toBe(0);
    expect(result.checks.map((c) => c.id)).toEqual([
      "parse", "schema", "invariants", "doctrine", "signature", "ledger_hash", "ledger_head", "ledger_chain",
    ]);
  });

  it("a run dir without a ledger FAILS the ledger checks (no vacuous pass) and exits 1", async () => {
    const { result, exitCode } = await runVerify([join(receipts, "snitch.receipt.json"), "--run-dir", dir]);
    expect(exitCode).toBe(1);
    const failed = result.checks.filter((c) => !c.ok).map((c) => c.id);
    expect(failed).toEqual(["ledger_hash", "ledger_head", "ledger_chain"]);
    for (const c of result.checks.filter((x) => !x.ok)) expect(c.detail).toContain("cannot read ledger");
  });

  it("a MISMATCHED ledger (clean-pass ledger vs snitch receipt) exits 1", async () => {
    copyFileSync(join(receipts, "clean-pass.ledger.jsonl"), join(dir, "ledger.jsonl"));
    const { result, exitCode } = await runVerify([join(receipts, "snitch.receipt.json"), "--run-dir", dir]);
    expect(exitCode).toBe(1);
    const byId = new Map(result.checks.map((c) => [c.id, c.ok]));
    expect(byId.get("ledger_hash")).toBe(false);
    expect(byId.get("ledger_head")).toBe(false);
    expect(byId.get("ledger_chain")).toBe(true); // the other ledger is intact — just not the bound one
  });
});

describe("loopeix verify — human-readable output (M2 P3c)", () => {
  async function runCapturingStdout(argv: string[]): Promise<string> {
    // Capture at the command's own log seam — stdout itself is already intercepted by vitest.
    const lines: string[] = [];
    const spy = vi.spyOn(Verify.prototype, "log").mockImplementation(function (message?: unknown): void {
      lines.push(String(message ?? ""));
    });
    try {
      await runVerify(argv);
    } finally {
      spy.mockRestore();
    }
    return lines.join("\n");
  }

  it("prints one PASS line per check and a final VERIFIED line for a clean receipt", async () => {
    const path = join(receipts, "clean-pass.receipt.json");
    const out = await runCapturingStdout([path]);
    for (const id of ["parse", "schema", "invariants", "doctrine", "signature"]) {
      expect(out).toMatch(new RegExp(`^PASS  ${id}: `, "m"));
    }
    expect(out).not.toContain("FAIL");
    expect(out).toContain(`VERIFIED  ${path}`);
    expect(out).not.toContain("NOT VERIFIED");
  });

  it("singular failed-count: one failing check prints '(1 check failed)'", async () => {
    const path = join(receipts, "snitch.bad-signature.receipt.json");
    const out = await runCapturingStdout([path]);
    expect(out).toMatch(/^FAIL  signature: /m);
    expect(out).toContain(`NOT VERIFIED  ${path} (1 check failed)`);
  });

  it("plural failed-count: four failing checks print '(4 checks failed)'", async () => {
    const path = join(receipts, "snitch.uncited-contradiction.receipt.json");
    const out = await runCapturingStdout([path]);
    expect(out).toContain(`NOT VERIFIED  ${path} (4 checks failed)`);
  });
});

describe("loopeix verify --json — stable output shape", () => {
  it("returns { ok, checks: [{ id, ok, detail }] } exactly", async () => {
    const { result } = await runVerify([join(receipts, "clean-pass.receipt.json"), "--json"]);
    expect(Object.keys(result).sort()).toEqual(["checks", "ok"]);
    expect(typeof result.ok).toBe("boolean");
    for (const c of result.checks) {
      expect(Object.keys(c).sort()).toEqual(["detail", "id", "ok"]);
      expect(typeof c.id).toBe("string");
      expect(typeof c.ok).toBe("boolean");
      expect(typeof c.detail).toBe("string");
    }
  });
});
