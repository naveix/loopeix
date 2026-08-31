import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import RunRecover, { type RunRecoverResult } from "../../src/commands/run/recover.js";
import { createRuntimeCommandFixtureV04 } from "../helpers/runtime-v04-command-fixture.js";

const repoRoot = import.meta.dirname;
const cleanups: Array<() => void> = [];

afterEach(() => {
  vi.clearAllMocks();
  for (const cleanup of cleanups.splice(0)) cleanup();
});

async function run(argv: string[]): Promise<{ result: RunRecoverResult; exit: number; output: string }> {
  const previous = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const log = vi.spyOn(RunRecover.prototype, "log").mockImplementation((message?: unknown) => lines.push(String(message ?? "")));
  const logJson = vi.spyOn(RunRecover.prototype as never, "logJson" as never).mockImplementation(((value: unknown) => lines.push(JSON.stringify(value))) as never);
  try {
    const result = await RunRecover.run(argv, repoRoot) as RunRecoverResult;
    return { result, exit: Number(process.exitCode ?? 0), output: lines.join("\n") };
  } finally {
    log.mockRestore();
    logJson.mockRestore();
    process.exitCode = previous;
  }
}

describe("S41-D run recover command", () => {
  it("reports a valid V04 directory honestly even when recovery is still held on the current boundary", async () => {
    const fixture = createRuntimeCommandFixtureV04();
    cleanups.push(fixture.cleanup);
    const output = await run([fixture.root, "--json"]);
    expect(output.exit).toBe(4);
    expect(output.output).toBe(JSON.stringify(output.result));
    expect(output.result).toMatchObject({
      source: "runtime-v04",
      recoverable: false,
      integrity_status: "valid",
      reason: "owner-ambiguous",
      status: {
        run: { state: "running" },
        owner: { status: "ambiguous", reason: "stale-owner-proof-missing" },
        next_action: { disposition: "hold", reason_code: "owner-ambiguous" },
      },
    });
  });

  it("fails closed for a tampered V04 manifest", async () => {
    const fixture = createRuntimeCommandFixtureV04({ tamperManifest: true });
    cleanups.push(fixture.cleanup);
    const output = await run([fixture.root]);
    expect(output.exit).toBe(4);
    expect(output.result).toMatchObject({
      source: "runtime-v04",
      recoverable: false,
      integrity_status: "invalid",
      reason: "INVALID_RUNTIME_V04_DIRECTORY",
    });
  });

  it("exposes no public resume surface and leaves the inspected runtime unchanged", async () => {
    const fixture = createRuntimeCommandFixtureV04();
    cleanups.push(fixture.cleanup);
    const before = readFileSync(join(fixture.root, "ledger.jsonl"), "utf8");

    expect(Object.hasOwn(RunRecover, "flags")).toBe(false);
    await expect(RunRecover.run([fixture.root, "--resume"], repoRoot)).rejects.toMatchObject({
      oclif: { exit: 2 },
    });

    expect(readFileSync(join(fixture.root, "ledger.jsonl"), "utf8")).toBe(before);
  });
});
