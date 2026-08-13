import { mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { allocateAndCommitCompileIdentityV02 } from "../../src/compiler/compile-id.js";
import { COMPILE_STORE_SENTINEL_TEXT, verifyCompileStoreV02 } from "../../src/compiler/compile-store.js";

const roots: string[] = [];

async function verifiedStore() {
  const workspace = mkdtempSync(join(tmpdir(), "loopeix-s35-compile-id-"));
  roots.push(workspace);
  const store = join(workspace, ".loopeix", "compiles");
  mkdirSync(store, { recursive: true });
  writeFileSync(join(store, ".gitignore"), COMPILE_STORE_SENTINEL_TEXT, { mode: 0o600 });
  const verified = await verifyCompileStoreV02(workspace);
  if (!verified.ok) throw new Error(verified.message);
  return { store, verified: verified.store };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 compile identity allocation", () => {
  it("samples the clock once and derives every identity from the exact admitted token", async () => {
    const { store, verified } = await verifiedStore();
    const now = vi.fn(() => 36 ** 6 + 36 ** 3 + 35);
    const randomBytes = vi.fn(() => Uint8Array.from([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70]));
    const commitCandidate = vi.fn(async (_store, identity) => {
      expect(identity.compile_dir).toBe(join(realpathSync(store), identity.compile_id));
      expect(readdirSync(store)).toEqual([".gitignore"]);
      return { ok: true as const, pack_ref: identity.compile_id };
    });

    const result = await allocateAndCommitCompileIdentityV02(verified, { now, randomBytes, commitCandidate });

    expect(result).toEqual({
      ok: true,
      identity: {
        compile_token: "100100z_0010203040506070",
        compile_id: "compile_100100z_0010203040506070",
        compile_dir: join(realpathSync(store), "compile_100100z_0010203040506070"),
        submitted_at: "1970-01-26T04:40:29Z",
        work_item_id: "wi_100100z_0010203040506070",
        intake_record_id: "intake_100100z_0010203040506070",
        catalog_resolution_id: "resolution_100100z_0010203040506070",
        binding_input_id: "binding_100100z_0010203040506070",
        compilation_record_id: "compilation_100100z_0010203040506070",
        intake_brief_id: "brief_100100z_0010203040506070",
        pack_manifest_id: "pack_100100z_0010203040506070",
      },
    });
    expect(now).toHaveBeenCalledOnce();
    expect(randomBytes.mock.calls).toEqual([[8]]);
    expect(commitCandidate).toHaveBeenCalledOnce();
    expect(readdirSync(store)).toEqual([".gitignore"]);
  });

  it("reuses the first clock value and consumes fresh entropy only after EEXIST", async () => {
    const { store, verified } = await verifiedStore();
    mkdirSync(join(store, "compile_42_deadbeefcafebabe"));
    const now = vi.fn().mockReturnValueOnce(146).mockReturnValue(147);
    const entropy = [
      Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]),
      Uint8Array.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
    ];
    const randomBytes = vi.fn(() => entropy.shift()!);
    const commitCandidate = vi.fn(async (_store, identity) => identity.compile_id === "compile_42_deadbeefcafebabe"
      ? { ok: false as const, reason: "DESTINATION_EXISTS" as const, message: "collision" }
      : { ok: true as const, pack_ref: identity.compile_id });

    const result = await allocateAndCommitCompileIdentityV02(verified, { now, randomBytes, commitCandidate });

    expect(result).toMatchObject({ ok: true, identity: { compile_id: "compile_42_1122334455667788" } });
    expect(now).toHaveBeenCalledOnce();
    expect(randomBytes.mock.calls).toEqual([[8], [8]]);
    expect(commitCandidate).toHaveBeenCalledTimes(2);
    expect(readdirSync(store).sort()).toEqual([".gitignore", "compile_42_deadbeefcafebabe"]);
  });

  it("stops after exactly 16 collisions without writing a member", async () => {
    const { store, verified } = await verifiedStore();
    const randomBytes = vi.fn(() => new Uint8Array(8));
    mkdirSync(join(store, "compile_1_0000000000000000"));
    const commitCandidate = vi.fn(async () => ({
      ok: false as const,
      reason: "DESTINATION_EXISTS" as const,
      message: "collision",
    }));

    const result = await allocateAndCommitCompileIdentityV02(verified, { now: () => 1, randomBytes, commitCandidate });

    expect(result).toEqual({
      ok: false,
      reason: "COMPILE_ID_COLLISION_LIMIT",
      message: "Compile identity allocation exhausted its collision limit.",
    });
    expect(randomBytes).toHaveBeenCalledTimes(16);
    expect(commitCandidate).toHaveBeenCalledTimes(16);
    expect(readdirSync(join(store, "compile_1_0000000000000000"))).toEqual([]);
  });

  it("does not retry a non-EEXIST reservation failure", async () => {
    const { verified } = await verifiedStore();
    const randomBytes = vi.fn(() => new Uint8Array(8));
    const commitCandidate = vi.fn(async () => ({
      ok: false as const,
      reason: "IO_DURABILITY_UNCONFIRMED" as const,
      message: "The destination directory could not be durably created.",
    }));

    const result = await allocateAndCommitCompileIdentityV02(verified, {
      now: () => 1,
      randomBytes,
      commitCandidate,
    });

    expect(result).toEqual({
      ok: false,
      reason: "IO_DURABILITY_UNCONFIRMED",
      message: "Filesystem durability could not be confirmed.",
    });
    expect(commitCandidate).toHaveBeenCalledOnce();
    expect(randomBytes).toHaveBeenCalledOnce();
  });

  it("rejects a commit success bound to another compile identity", async () => {
    const { verified } = await verifiedStore();
    const commitCandidate = vi.fn(async () => ({ ok: true as const, pack_ref: "compile_wrong" as never }));

    const result = await allocateAndCommitCompileIdentityV02(verified, {
      now: () => 1,
      randomBytes: () => new Uint8Array(8),
      commitCandidate,
    });

    expect(result).toEqual({
      ok: false,
      reason: "INVALID_OUTPUT_CAPTURE",
      message: "The compiler output authority or captured output is invalid.",
    });
  });

  it("propagates a typed candidate abort without retrying or relabeling it", async () => {
    const { verified } = await verifiedStore();
    const randomBytes = vi.fn(() => new Uint8Array(8));
    const candidateFailure = Object.freeze({
      reason: "SENSITIVE_OUTPUT_REJECTED" as const,
      member_id: "compile-report.md",
      rule_id: "CRED_PRIVATE_KEY_PEM",
    });
    const commitCandidate = vi.fn(async () => ({
      ok: false as const,
      reason: "CANDIDATE_ABORTED" as const,
      failure: candidateFailure,
    }));

    const result = await allocateAndCommitCompileIdentityV02(verified, {
      now: () => 1,
      randomBytes,
      commitCandidate,
    });

    expect(result).toEqual({
      ok: false,
      reason: "CANDIDATE_ABORTED",
      failure: candidateFailure,
    });
    expect(commitCandidate).toHaveBeenCalledOnce();
    expect(randomBytes).toHaveBeenCalledOnce();
  });

  it.each([
    ["invalid clock", () => -1, () => new Uint8Array(8)],
    ["out-of-contract UTC clock", () => 253_402_300_800_000, () => new Uint8Array(8)],
    ["invalid entropy", () => 1, () => new Uint8Array(7)],
  ] as const)("fails closed on %s before reservation", async (_label, now, randomBytesImpl) => {
    const { verified } = await verifiedStore();
    const commitCandidate = vi.fn();

    const result = await allocateAndCommitCompileIdentityV02(verified, {
      now,
      randomBytes: vi.fn(randomBytesImpl),
      commitCandidate,
    });

    expect(result).toEqual({
      ok: false,
      reason: "IO_HELPER_UNAVAILABLE",
      message: "Compile identity entropy or clock generation failed.",
    });
    expect(commitCandidate).not.toHaveBeenCalled();
  });
});
