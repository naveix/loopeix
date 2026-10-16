import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { runS37LocalLinuxProductProbeV03 } from "../../src/run/linux-host-enforcement-v03.js";

describe("S37.1-F4 V03 production runtime boundary", () => {
  it("always returns the exact content-free activation HOLD", async () => {
    await expect(runS37LocalLinuxProductProbeV03(Object.freeze({}) as never)).resolves.toEqual({
      ok: false,
      reason: "ENFORCEMENT_UNAVAILABLE",
      terminal: "hold",
      retryable: false,
      process_started: false,
    });
  });

  it("uses only the frozen V02 owner and admission imports, never the bounded implementation", () => {
    const source = readFileSync("src/run/linux-host-enforcement-v03.ts", "utf8");
    expect(source).toContain('import { runS37LinuxHostProbeV02 } from "./linux-host-enforcement-v02.js";');
    expect(source).toContain("prepareS37LinuxProbeAdmissionV02");
    expect(source).not.toContain("bounded-linux-probe-v02");
    expect(source).not.toContain("createS37LocalLinuxProductProbeV02");
  });
});
