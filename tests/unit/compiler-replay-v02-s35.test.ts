import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { compileV02ForTest } from "../../src/compiler/compile-v02.js";
import { COMPILE_STORE_SENTINEL_TEXT } from "../../src/compiler/compile-store.js";
import { readCompilePackV02, type ReadCompilePackV02Success } from "../../src/compiler/read-pack-v02.js";
import {
  consumeExactV02ReplayForPlanning,
  isRegisteredExactV02ReplaySuccess,
  replayCompilePackV02,
} from "../../src/compiler/replay-v02.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function writtenHoldPack(): Promise<string> {
  const workspace = mkdtempSync(join(tmpdir(), "loopeix-s35-replay-v02-"));
  roots.push(workspace);
  const store = join(workspace, ".loopeix", "compiles");
  mkdirSync(store, { recursive: true });
  writeFileSync(join(store, ".gitignore"), COMPILE_STORE_SENTINEL_TEXT, { mode: 0o600 });
  const result = await compileV02ForTest({
    prompt: "Fix the failing parser bug and prove the correction.",
    workspace_root: workspace,
  }, {
    now: () => 146,
    randomBytes: () => Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]),
  });
  if (result.pack_ref === null) throw new Error("expected a persisted HOLD pack");
  return join(store, result.pack_ref);
}

describe("S35 exact V02 replay", () => {
  it("replays every compiler-derived HOLD member from one genuine captured reader success", async () => {
    const read = await readCompilePackV02(await writtenHoldPack());
    expect(read.ok).toBe(true);
    if (!read.ok) return;

    const result = replayCompilePackV02(read);
    expect(result).toMatchObject({
      ok: true,
      disposition: "replayed",
      reason: null,
      replay: {
        schema_version: "0.2",
        terminal_state: "hold-project-binding-required",
        compared_member_count: 5,
      },
    });
    if (!result.ok) return;
    expect(isRegisteredExactV02ReplaySuccess(result.replay)).toBe(true);
    expect(consumeExactV02ReplayForPlanning(result.replay)).toBe(read);
    expect(isRegisteredExactV02ReplaySuccess(result.replay)).toBe(false);
    expect(consumeExactV02ReplayForPlanning(result.replay)).toBeNull();
  });

  it("does not release planning source for a structural replay lookalike", async () => {
    const read = await readCompilePackV02(await writtenHoldPack());
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    const result = replayCompilePackV02(read);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const forged = Object.freeze({ ...result.replay }) as typeof result.replay;
    expect(consumeExactV02ReplayForPlanning(forged)).toBeNull();
    expect(consumeExactV02ReplayForPlanning(result.replay)).toBe(read);
  });

  it("rejects forged reader lookalikes and reuse without exposing a root hash", async () => {
    const read = await readCompilePackV02(await writtenHoldPack());
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    const forged = Object.freeze({ ...read }) as ReadCompilePackV02Success;

    expect(replayCompilePackV02(forged)).toEqual({
      ok: false,
      disposition: "hold",
      schema_version: "0.2",
      source_pack_root_hash: null,
      compared_member_count: 0,
      reason: "INVALID_COMPILE_PACK",
      findings: [],
    });
    expect(replayCompilePackV02(read).ok).toBe(true);
    expect(replayCompilePackV02(read)).toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });
  });

  it("treats noncanonical but hash-bound binding JSON as replay input", async () => {
    const root = await writtenHoldPack();
    const bindingPath = join(root, "binding-input.json");
    const binding = JSON.parse(readFileSync(bindingPath, "utf8")) as unknown;
    const noncanonical = `${JSON.stringify(binding)}\n`;
    writeFileSync(bindingPath, noncanonical);
    const manifestPath = join(root, "pack-manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { file_hashes: { binding_input: string } };
    manifest.file_hashes.binding_input = `sha256:${createHash("sha256").update(noncanonical).digest("hex")}`;
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    const read = await readCompilePackV02(root);
    expect(read.ok, read.ok ? undefined : read).toBe(true);
    if (!read.ok) return;
    expect(replayCompilePackV02(read).ok).toBe(true);
  });

  it("rejects changed binding bytes with a stale manifest hash before replay", async () => {
    const root = await writtenHoldPack();
    const bindingPath = join(root, "binding-input.json");
    const binding = JSON.parse(readFileSync(bindingPath, "utf8")) as unknown;
    writeFileSync(bindingPath, `${JSON.stringify(binding)}\n`);

    await expect(readCompilePackV02(root)).resolves.toMatchObject({
      ok: false,
      reason: "INVALID_COMPILE_PACK",
    });
  });
});
