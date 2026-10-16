import { afterEach, describe, expect, it, vi } from "vitest";

import RunStatus, { type RunStatusResult } from "../../src/commands/run/status.js";
import { createRuntimeCommandFixtureV04 } from "../helpers/runtime-v04-command-fixture.js";

const repoRoot = import.meta.dirname;
const cleanups: Array<() => void> = [];

afterEach(() => {
  vi.clearAllMocks();
  for (const cleanup of cleanups.splice(0)) cleanup();
});

async function run(argv: string[]): Promise<{ result: RunStatusResult; exit: number; output: string }> {
  const previous = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const log = vi.spyOn(RunStatus.prototype, "log").mockImplementation((message?: unknown) => lines.push(String(message ?? "")));
  const logJson = vi.spyOn(RunStatus.prototype as never, "logJson" as never).mockImplementation(((value: unknown) => lines.push(JSON.stringify(value))) as never);
  try {
    const result = await RunStatus.run(argv, repoRoot) as RunStatusResult;
    return { result, exit: Number(process.exitCode ?? 0), output: lines.join("\n") };
  } finally {
    log.mockRestore();
    logJson.mockRestore();
    process.exitCode = previous;
  }
}

describe("S41-D run status command", () => {
  it("projects a V04 directory truthfully and holds conservatively when staleness is unproven", async () => {
    const fixture = createRuntimeCommandFixtureV04();
    cleanups.push(fixture.cleanup);
    const output = await run([fixture.root, "--json"]);
    expect(output.exit).toBe(0);
    expect(output.output).toBe(JSON.stringify(output.result));
    expect(output.result).toMatchObject({
      source: "runtime-v04",
      run_state: "running",
      integrity_status: "valid",
      status: {
        owner: { status: "ambiguous", reason: "stale-owner-proof-missing" },
        attempt: { current_attempt_ordinal: 1 },
        next_action: { disposition: "hold", reason_code: "owner-ambiguous" },
      },
    });
  });

  it("fails closed when run-manifest.json is present but tampered", async () => {
    const fixture = createRuntimeCommandFixtureV04({ tamperManifest: true });
    cleanups.push(fixture.cleanup);
    const output = await run([fixture.root]);
    expect(output.exit).toBe(4);
    expect(output.result).toMatchObject({
      source: "runtime-v04",
      run_state: "unknown",
      integrity_status: "invalid",
      reason: "INVALID_RUNTIME_V04_DIRECTORY",
    });
  });
});
