import { describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  expected: Object.freeze({
    ok: true as const,
    terminal: "completed" as const,
    outcome: "exited" as const,
    process_started: true as const,
    exit_code: 0,
    signal: null,
    stdout: Uint8Array.from([1]),
    stderr: new Uint8Array(),
  }),
  runBounded: vi.fn(async () => undefined as unknown),
}));

vi.mock("../../src/run/bounded-linux-probe-v02.js", () => ({
  runBoundedS37LinuxProbeV02: state.runBounded,
}));

import { runS37LinuxHostProbeV02 } from "../../src/run/linux-host-enforcement-v02.js";

describe("S37.1 Linux host enforcement wrapper", () => {
  it("delegates exactly once to the bounded runtime seam and returns the exact result", async () => {
    state.runBounded.mockResolvedValueOnce(state.expected);
    const admission = Object.freeze({ admission: "opaque" });
    const runtime = Object.freeze({ start: vi.fn() });

    const result = await runS37LinuxHostProbeV02(admission as never, runtime as never);

    expect(state.runBounded).toHaveBeenCalledTimes(1);
    expect(state.runBounded).toHaveBeenCalledWith(admission, runtime);
    expect(result).toBe(state.expected);
  });
});
