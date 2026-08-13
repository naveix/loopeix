import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Verify, { type VerifyCommandResult } from "../../src/commands/verify.js";
import {
  captureStructuredFile,
  releaseCapturedStructuredFile,
} from "../../src/io/captured-file.js";
import { loadLegacyReplayPolicy } from "../../src/io/legacy-policy.js";

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
  root = mkdtempSync(join(tmpdir(), "loopeix-s35-verify-policy-"));
  runDir = join(root, "run");
  mkdirSync(runDir);
  copyFileSync(join(receipts, "snitch.ledger.jsonl"), join(runDir, "ledger.jsonl"));
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(root, { recursive: true, force: true });
});

async function runVerify(argv: string[]): Promise<{ result: VerifyCommandResult; exit: number; lines: string[] }> {
  const prior = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  vi.spyOn(Verify.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    const result = (await Verify.run(argv, repoRoot)) as VerifyCommandResult;
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

describe("S35 verify --legacy-replay-policy", () => {
  it("fails closed when the helper terminal response is invalid after a successful policy read", async () => {
    const outcome = await loadLegacyReplayPolicy(policyFile(validPolicy), {
      captureStructuredFile,
      releaseCapturedStructuredFile: async (capture) => {
        await releaseCapturedStructuredFile(capture);
        return {
          ok: false,
          reason: "IO_HELPER_UNAVAILABLE",
          message: "Injected invalid terminal response.",
        };
      },
    });

    expect(outcome).toEqual({
      ok: false,
      reason: "IO_HELPER_UNAVAILABLE",
      message: "Required filesystem helper is unavailable.",
    });
  });

  it("preserves the exact ordinary V01 result and human output after sufficient finite admission", async () => {
    const receipt = join(receipts, "snitch.receipt.json");
    const baseline = await runVerify([receipt, "--run-dir", runDir]);
    vi.restoreAllMocks();
    const admitted = await runVerify([
      receipt,
      "--run-dir",
      runDir,
      "--legacy-replay-policy",
      policyFile(validPolicy),
    ]);
    expect(admitted).toEqual(baseline);
  });

  it("rejects direct-receipt use and malformed or inconsistent policies with one closed usage result", async () => {
    const receipt = join(receipts, "snitch.receipt.json");
    const invalidPolicies = [
      { ...validPolicy, max_member_bytes: 0 },
      { ...validPolicy, max_pack_bytes: validPolicy.max_member_bytes - 1 },
      { ...validPolicy, max_heap_bytes: validPolicy.max_member_bytes + 67_108_863 },
      { ...validPolicy, deadline_ms: 1.5 },
      { ...validPolicy, extra: true },
    ];
    const direct = await runVerify([receipt, "--legacy-replay-policy", policyFile(validPolicy)]);
    expect(direct).toMatchObject({
      result: {
        ok: false,
        reason: "INVALID_LEGACY_COMPATIBILITY_POLICY",
        message: "Legacy replay policy is invalid for this command or input family.",
      },
      exit: 2,
    });
    for (const [index, value] of invalidPolicies.entries()) {
      vi.restoreAllMocks();
      const outcome = await runVerify([
        receipt,
        "--run-dir",
        runDir,
        "--legacy-replay-policy",
        policyFile(value, `invalid-${index}.json`),
      ]);
      expect(outcome).toMatchObject({
        result: { ok: false, reason: "INVALID_LEGACY_COMPATIBILITY_POLICY" },
        exit: 2,
      });
      expect(JSON.stringify(outcome)).not.toContain(JSON.stringify(value));
    }
  });

  it("maps an insufficient member ceiling to the closed resource result without echoing paths or bytes", async () => {
    const receipt = join(receipts, "snitch.receipt.json");
    const path = policyFile({ ...validPolicy, max_member_bytes: 1, max_pack_bytes: 1 });
    const outcome = await runVerify([
      receipt,
      "--run-dir",
      runDir,
      "--legacy-replay-policy",
      path,
    ]);
    expect(outcome).toMatchObject({
      result: {
        ok: false,
        reason: "LEGACY_REPLAY_RESOURCE_LIMIT",
        message: "Legacy replay exceeded its approved finite resource policy.",
      },
      exit: 1,
    });
    expect(JSON.stringify(outcome)).not.toContain(path);
    expect(JSON.stringify(outcome)).not.toContain("run_snitch_01");
  });

  it("keeps the policy inert for a V02 first event", async () => {
    writeFileSync(
      join(runDir, "ledger.jsonl"),
      '{"schema_version":"0.2","run_id":"run_snitch_01","event_type":"run.started"}\n',
    );
    const outcome = await runVerify([
      join(receipts, "snitch.receipt.json"),
      "--run-dir",
      runDir,
      "--legacy-replay-policy",
      policyFile(validPolicy),
    ]);
    expect(outcome).toMatchObject({
      result: { ok: false, reason: "INVALID_LEGACY_COMPATIBILITY_POLICY" },
      exit: 2,
    });
  });
});
