import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

function runConformance(...args: string[]) {
  return spawnSync(process.execPath, ["scripts/check-s37-linux-conformance.mjs", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    shell: false,
    timeout: 15_000,
    maxBuffer: 2 * 1024 * 1024,
  });
}

describe("S37 Linux host conformance static gate", () => {
  it("passes the local Phase A static gate without claiming live host verification", () => {
    const result = runConformance();
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("S37.1 Phase A static gate: PASS");
    expect(result.stdout).toContain("live host conformance not executed");
    expect(result.stderr).toBe("");
  });

  it("rejects live, VPS, and SSH flags as out-of-scope for Phase A", () => {
    for (const flag of ["--live", "--vps", "--ssh"]) {
      const result = runConformance(flag);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(`HOLD: ${flag} is out of scope for the Phase A static gate`);
      expect(result.stderr).toContain("live host conformance not executed");
    }
  });
});
