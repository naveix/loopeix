import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Compile, { type CompileCommandResult } from "../../src/commands/compile.js";
import { validateLoopeix } from "../../src/index.js";

const repoRoot = join(import.meta.dirname, "..", "..");

async function runCompile(argv: string[]): Promise<{ result: CompileCommandResult; exitCode: number; out: string }> {
  const before = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const spy = vi.spyOn(Compile.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    const result = (await Compile.run(argv, repoRoot)) as CompileCommandResult;
    return { result, exitCode: Number(process.exitCode ?? 0), out: lines.join("\n") };
  } finally {
    spy.mockRestore();
    process.exitCode = before;
  }
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "loopeix-compile-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("loopeix compile", () => {
  it("writes a valid generated loop for a safe prompt", async () => {
    const outFile = join(dir, "bugfix.loop.yaml");
    const { exitCode, out, result } = await runCompile([
      "--prompt", "Fix the failing date parser test and prove the fix.",
      "--out", outFile,
      "--workspace-root", dir,
    ]);

    expect(exitCode).toBe(0);
    expect(result.ok).toBe(true);
    expect(result.output_path).toBe(outFile);
    expect(out).toContain("COMPILED  safe-bugfix");
    expect(out).toContain(`Wrote ${outFile}`);
    expect(validateLoopeix(parseYaml(readFileSync(outFile, "utf8"))).ok).toBe(true);
  });

  it("does not write an output file when the compiler returns HOLD", async () => {
    const outFile = join(dir, "blocked.loop.yaml");
    const { exitCode, out, result } = await runCompile([
      "--prompt", "Use whatever tools you need and don't ask me.",
      "--out", outFile,
      "--workspace-root", dir,
    ]);

    expect(exitCode).toBe(1);
    expect(result.ok).toBe(false);
    expect(result.catalog_resolution.terminal_state).toBe("hold-risk");
    expect(existsSync(outFile)).toBe(false);
    expect(out).toContain("HOLD  hold-risk");
  });

  it("--json returns machine-readable compiler records and suppresses human logs", async () => {
    const { exitCode, out, result } = await runCompile([
      "--prompt", "Compare agent receipt tools and summarize the gaps.",
      "--workspace-root", dir,
      "--json",
    ]);

    expect(exitCode).toBe(0);
    expect(out).toBe("");
    expect(result.ok).toBe(true);
    expect(result.catalog_resolution.selected_item_id).toBe("research-need-cluster");
    expect(result.work_item.prompt).toContain("Compare agent receipt tools");
    expect(result.intake.objective).toContain("Compare agent receipt tools");
  });

  it("--pack-dir writes compile records, report, and generated loop on success", async () => {
    const packDir = join(dir, "packs", "date-parser");
    const { exitCode, out, result } = await runCompile([
      "--prompt", "Fix the failing date parser test and prove the fix.",
      "--workspace-root", dir,
      "--pack-dir", packDir,
    ]);

    expect(exitCode).toBe(0);
    expect(result.ok).toBe(true);
    expect(result.pack_dir).toBe(packDir);
    expect(result.pack_paths?.manifest).toBe(join(packDir, "pack-manifest.json"));
    expect(result.pack_paths?.generated_loop).toBe(join(packDir, "generated.loop.yaml"));
    expect(out).toContain(`Pack ${packDir}`);
    expect(out).not.toContain("schema_version:");
    expect(validateLoopeix(parseYaml(readFileSync(join(packDir, "generated.loop.yaml"), "utf8"))).ok).toBe(true);
    expect(readFileSync(join(packDir, "compile-report.md"), "utf8")).toContain("Selected item: safe-bugfix");
  });

  it("--pack-dir writes HOLD records and report but no generated loop", async () => {
    const packDir = join(dir, "packs", "hold");
    const { exitCode, out, result } = await runCompile([
      "--prompt", "Use whatever tools you need and don't ask me.",
      "--workspace-root", dir,
      "--pack-dir", packDir,
    ]);

    expect(exitCode).toBe(1);
    expect(result.ok).toBe(false);
    expect(result.pack_dir).toBe(packDir);
    expect(result.pack_paths?.generated_loop).toBeUndefined();
    expect(existsSync(join(packDir, "generated.loop.yaml"))).toBe(false);
    expect(existsSync(join(packDir, "compilation-record.json"))).toBe(false);
    expect(existsSync(join(packDir, "pack-manifest.json"))).toBe(true);
    expect(readFileSync(join(packDir, "compile-report.md"), "utf8")).toContain("Terminal state: hold-risk");
    expect(out).toContain(`Pack ${packDir}`);
  });
});
