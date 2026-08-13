import { describe, expect, it, vi } from "vitest";

import { allocateAndCommitPlanIdentityV02 } from "../../src/run/plan-id-v02.js";

describe("S35 plan identity allocation", () => {
  it("samples one clock and fresh eight-byte entropy only after EEXIST", async () => {
    const now = vi.fn().mockReturnValueOnce(146).mockReturnValue(147);
    const values = [
      Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]),
      Uint8Array.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
    ];
    const randomBytes = vi.fn(() => values.shift()!);
    const commitCandidate = vi.fn(async (identity) => identity.run_id === "run_42_deadbeefcafebabe"
      ? { ok: false as const, reason: "DESTINATION_EXISTS" as const, message: "collision" }
      : { ok: true as const, run_id: identity.run_id });

    await expect(allocateAndCommitPlanIdentityV02({ now, randomBytes, commitCandidate })).resolves.toEqual({
      ok: true,
      identity: {
        plan_token: "42_1122334455667788",
        run_id: "run_42_1122334455667788",
        created_at: "1970-01-01T00:00:00Z",
      },
    });
    expect(now).toHaveBeenCalledOnce();
    expect(randomBytes.mock.calls).toEqual([[8], [8]]);
    expect(commitCandidate).toHaveBeenCalledTimes(2);
  });

  it("stops after exactly 16 collisions", async () => {
    const randomBytes = vi.fn(() => new Uint8Array(8));
    const commitCandidate = vi.fn(async () => ({
      ok: false as const,
      reason: "DESTINATION_EXISTS" as const,
      message: "collision",
    }));
    await expect(allocateAndCommitPlanIdentityV02({ now: () => 1, randomBytes, commitCandidate })).resolves.toEqual({
      ok: false,
      reason: "PLAN_ID_COLLISION_LIMIT",
      message: "Plan identity allocation exhausted its collision limit.",
    });
    expect(randomBytes).toHaveBeenCalledTimes(16);
    expect(commitCandidate).toHaveBeenCalledTimes(16);
  });

  it("does not retry non-EEXIST failure and rejects a mismatched success identity", async () => {
    const failedCommit = vi.fn(async () => ({
      ok: false as const,
      reason: "IO_DURABILITY_UNCONFIRMED" as const,
      message: "durability uncertain",
    }));
    await expect(allocateAndCommitPlanIdentityV02({ now: () => 1, commitCandidate: failedCommit })).resolves.toEqual({
      ok: false,
      reason: "IO_DURABILITY_UNCONFIRMED",
      message: "durability uncertain",
    });
    expect(failedCommit).toHaveBeenCalledOnce();

    await expect(allocateAndCommitPlanIdentityV02({
      now: () => 1,
      randomBytes: () => new Uint8Array(8),
      commitCandidate: async () => ({ ok: true, run_id: "run_wrong" }),
    })).resolves.toMatchObject({ ok: false, reason: "INVALID_OUTPUT_CAPTURE" });
  });

  it.each([
    ["negative clock", () => -1, () => new Uint8Array(8)],
    ["out-of-range clock", () => 253_402_300_800_000, () => new Uint8Array(8)],
    ["wrong entropy length", () => 1, () => new Uint8Array(7)],
  ] as const)("fails closed on %s before candidate commit", async (_label, now, randomBytes) => {
    const commitCandidate = vi.fn();
    await expect(allocateAndCommitPlanIdentityV02({ now, randomBytes, commitCandidate })).resolves.toEqual({
      ok: false,
      reason: "IO_HELPER_UNAVAILABLE",
      message: "Plan identity entropy or clock generation failed.",
    });
    expect(commitCandidate).not.toHaveBeenCalled();
  });
});
