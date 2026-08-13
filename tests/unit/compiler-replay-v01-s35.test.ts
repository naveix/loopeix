import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readCompilePackV01 } from "../../src/compiler/read-pack.js";
import { replayCompilePackV01 } from "../../src/compiler/replay-v01.js";

const roots: string[] = [];
const fixture = join(import.meta.dirname, "../fixtures/compat/s35/v01/compiled-safe-bugfix");

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 exact V01 compile-pack replay", () => {
  it("mints replay authority only after exact frozen regeneration", async () => {
    const read = await readCompilePackV01(fixture);
    expect(read.ok, read.ok ? undefined : read.message).toBe(true);
    if (!read.ok) return;
    const replay = await replayCompilePackV01(read);
    expect(replay.ok, replay.ok ? undefined : replay.message).toBe(true);
    if (!replay.ok) return;
    expect(replay.authority.selector).toEqual(read.selector);
    expect(replay.authority.source_pack_root_hash).toBe(read.identity.source_pack_root_hash);
    await expect(replayCompilePackV01(read)).resolves.toMatchObject({
      ok: false,
      reason: "INVALID_V01_REPLAY_OUTPUT",
    });
  });

  it("exactly replays the five-member frozen HOLD branch", async () => {
    const read = await readCompilePackV01(join(import.meta.dirname, "../fixtures/compat/s35/v01/hold-risk"));
    expect(read.ok, read.ok ? undefined : read.message).toBe(true);
    if (!read.ok) return;
    const replay = await replayCompilePackV01(read);
    expect(replay.ok, replay.ok ? undefined : replay.message).toBe(true);
  });

  it("preserves credential-shaped historical bytes through exact V01 replay", async () => {
    const read = await readCompilePackV01(join(import.meta.dirname, "../fixtures/compat/s35/v01/credential-shaped-replay-pack"));
    expect(read.ok, read.ok ? undefined : read.message).toBe(true);
    if (!read.ok) return;
    const replay = await replayCompilePackV01(read);
    expect(replay.ok, replay.ok ? undefined : replay.message).toBe(true);
  });

  it("rejects byte-different regeneration after attacker-controlled hashes are recomputed", async () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-replay-v01-mismatch-"));
    roots.push(root);
    cpSync(fixture, root, { recursive: true });
    const reportPath = join(root, "compile-report.md");
    writeFileSync(reportPath, `${readFileSync(reportPath, "utf8")}attacker-note\n`);
    const manifestPath = join(root, "pack-manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { file_hashes: { report: string } };
    manifest.file_hashes.report = `sha256:${createHash("sha256").update(readFileSync(reportPath)).digest("hex")}`;
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    const read = await readCompilePackV01(root);
    expect(read.ok, read.ok ? undefined : read.message).toBe(true);
    if (!read.ok) return;
    await expect(replayCompilePackV01(read)).resolves.toMatchObject({
      ok: false,
      reason: "INVALID_V01_REPLAY_OUTPUT",
    });
  });
});
