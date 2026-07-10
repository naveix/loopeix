import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { compilePrompt, validateLoopeix, writeCompilePack } from "../../src/index.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "loopeix-pack-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("writeCompilePack", () => {
  it("writes a complete auditable pack for a compiled loop", () => {
    const result = compilePrompt({
      prompt: "Fix the failing date parser test and prove the fix.",
      workspaceRoot: dir,
      submittedAt: "2026-07-10T00:00:00.000Z",
    });
    const pack = writeCompilePack(result, join(dir, "compiled"));

    expect(pack.ok).toBe(true);
    expect(Object.keys(pack.paths).sort()).toEqual([
      "catalog_resolution",
      "compilation",
      "generated_loop",
      "intake",
      "manifest",
      "report",
      "work_item",
    ]);
    expect(JSON.parse(readFileSync(pack.paths.work_item, "utf8")).prompt).toContain("date parser");
    expect(JSON.parse(readFileSync(pack.paths.catalog_resolution, "utf8")).selected_item_id).toBe("safe-bugfix");
    expect(JSON.parse(readFileSync(pack.paths.compilation!, "utf8")).selected_loop_family).toBe("minimal-bugfix");
    expect(validateLoopeix(parseYaml(readFileSync(pack.paths.generated_loop!, "utf8"))).ok).toBe(true);
    const manifest = JSON.parse(readFileSync(pack.paths.manifest, "utf8"));
    expect(manifest.terminal_state).toBe("compiled");
    expect(manifest.compilation_id).toBe(JSON.parse(readFileSync(pack.paths.compilation!, "utf8")).compilation_id);
    expect(manifest.file_hashes.generated_loop).toMatch(/^sha256:[0-9a-f]{64}$/);
    const report = readFileSync(pack.paths.report, "utf8");
    expect(report).toContain("# Loopeix Compile Report");
    expect(report).toContain("Terminal state: compiled");
    expect(report).toContain("Selected item: safe-bugfix");
    expect(report).toContain("Can prove");
    expect(report).toContain("Cannot prove");
    expect(report).toContain("Next action");
  });

  it("writes HOLD records and report but never writes runnable YAML", () => {
    const result = compilePrompt({
      prompt: "Use whatever tools you need and don't ask me.",
      workspaceRoot: dir,
      submittedAt: "2026-07-10T00:00:00.000Z",
    });
    const pack = writeCompilePack(result, join(dir, "hold"));

    expect(pack.ok).toBe(false);
    expect(pack.paths.compilation).toBeUndefined();
    expect(pack.paths.generated_loop).toBeUndefined();
    expect(existsSync(pack.paths.manifest)).toBe(true);
    expect(existsSync(join(dir, "hold", "compilation-record.json"))).toBe(false);
    expect(existsSync(join(dir, "hold", "generated.loop.yaml"))).toBe(false);
    expect(JSON.parse(readFileSync(pack.paths.catalog_resolution, "utf8")).terminal_state).toBe("hold-risk");
    const report = readFileSync(pack.paths.report, "utf8");
    expect(report).toContain("Terminal state: hold-risk");
    expect(report).toContain("Clarification questions");
    expect(report).toContain("human approval");
  });

  it("removes stale runnable files when an existing pack directory is reused for HOLD", () => {
    const packDir = join(dir, "reused");
    writeCompilePack(
      compilePrompt({
        prompt: "Fix the failing date parser test and prove the fix.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:00:00.000Z",
      }),
      packDir,
    );

    const hold = writeCompilePack(
      compilePrompt({
        prompt: "Use whatever tools you need and don't ask me.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:01:00.000Z",
      }),
      packDir,
    );

    expect(hold.ok).toBe(false);
    expect(existsSync(join(packDir, "compilation-record.json"))).toBe(false);
    expect(existsSync(join(packDir, "generated.loop.yaml"))).toBe(false);
    expect(JSON.parse(readFileSync(hold.paths.manifest, "utf8")).terminal_state).toBe("hold-risk");
  });
});
