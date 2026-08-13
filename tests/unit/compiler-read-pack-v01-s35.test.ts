import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readCompilePackV01 } from "../../src/compiler/read-pack.js";

const roots: string[] = [];
const fixtures = join(import.meta.dirname, "../fixtures/compat/s35/v01");

function copyFixture(name: string): string {
  const root = mkdtempSync(join(tmpdir(), "loopeix-read-pack-v01-"));
  roots.push(root);
  cpSync(join(fixtures, name), root, { recursive: true });
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 strict V01 compile-pack reader", () => {
  it.each([
    ["compiled-safe-bugfix", "compiled", 7],
    ["large-compiled-pack", "compiled", 7],
    ["hold-risk", "hold-risk", 5],
  ] as const)("captures %s through the V01 identity registry", async (fixture, terminalState, memberCount) => {
    const result = await readCompilePackV01(join(fixtures, fixture));
    expect(result.ok, result.ok ? undefined : result.message).toBe(true);
    if (!result.ok) return;
    expect(result.manifest.terminal_state).toBe(terminalState);
    expect(result.identity.members).toHaveLength(memberCount);
    expect(result.selector).toEqual({
      schema_version: "0.1",
      catalog_version_hash: "sha256:4bba5fca6ce73a6d21598890001a45e03c349a3a1fa78148b802497a22eda823",
    });
  });

  it("rejects missing and extra members before registration", async () => {
    const missing = copyFixture("compiled-safe-bugfix");
    rmSync(join(missing, "generated.loop.yaml"));
    await expect(readCompilePackV01(missing)).resolves.toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });

    const extra = copyFixture("compiled-safe-bugfix");
    writeFileSync(join(extra, "unexpected.json"), "{}\n");
    await expect(readCompilePackV01(extra)).resolves.toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });
  });

  it("rejects a recognized symlink without following its target", async () => {
    const root = copyFixture("compiled-safe-bugfix");
    rmSync(join(root, "compile-report.md"));
    symlinkSync("work-item.json", join(root, "compile-report.md"));
    await expect(readCompilePackV01(root)).resolves.toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });
  });

  it("returns the fixed unavailable-bundle result for an unregistered catalog selector", async () => {
    const root = copyFixture("compiled-safe-bugfix");
    const catalogPath = join(root, "catalog-resolution.json");
    const catalog = JSON.parse(readFileSync(catalogPath, "utf8")) as { catalog_version_hash: string };
    catalog.catalog_version_hash = `sha256:${"d".repeat(64)}`;
    writeFileSync(catalogPath, `${JSON.stringify(catalog, null, 2)}\n`);
    const manifestPath = join(root, "pack-manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { file_hashes: { catalog_resolution: string } };
    manifest.file_hashes.catalog_resolution = `sha256:${createHash("sha256").update(readFileSync(catalogPath)).digest("hex")}`;
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    await expect(readCompilePackV01(root)).resolves.toEqual({
      ok: false,
      reason: "UNAVAILABLE_REPLAY_BUNDLE",
      message: "The exact replay bundle is unavailable.",
    });
  });
});
