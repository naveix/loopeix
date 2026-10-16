import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ApprovedIntakeBrief,
  hashBytes,
  planRunFromCompilePack,
  ResolvedRunPlan,
} from "../../src/index.js";
import { compilePrompt } from "../../src/compiler/compile.js";
import { writeCompilePack } from "../../src/compiler/pack.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "loopeix-run-plan-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("planRunFromCompilePack", () => {
  it("creates an approved intake brief and resolved run plan from a compiled pack", () => {
    const compiled = compilePrompt({
      prompt: "Fix the failing date parser test and prove the fix.",
      workspaceRoot: dir,
      submittedAt: "2026-07-10T00:00:00.000Z",
    });
    const pack = writeCompilePack(compiled, join(dir, "compile-pack"));

    const planned = planRunFromCompilePack({
      packDir: pack.pack_dir,
      workspaceRoot: dir,
      engine: "codex",
      createdAt: "2026-07-10T00:01:00Z",
      approved: true,
    });

    expect(planned.ok).toBe(true);
    expect(planned.run_dir).toBe(join(dir, ".loopeix", "loops", "minimal-bugfix", "runs", planned.run_id));
    expect(planned.paths?.resolved_run_plan).toBe(join(planned.run_dir!, "resolved-run-plan.json"));
    expect(ApprovedIntakeBrief.safeParse(JSON.parse(readFileSync(planned.paths!.intake_brief, "utf8"))).success).toBe(true);
    const runPlan = JSON.parse(readFileSync(planned.paths!.resolved_run_plan, "utf8"));
    expect(ResolvedRunPlan.safeParse(runPlan).success).toBe(true);
    expect(runPlan.loop_family).toBe("minimal-bugfix");
    expect(runPlan.work_item_id).toBe(compiled.work_item.work_item_id);
    expect(runPlan.adapter_plan.engine).toBe("codex_cli");
    expect(existsSync(join(planned.run_dir!, "work-item.json"))).toBe(true);
    expect(existsSync(join(planned.run_dir!, "generated.loop.yaml"))).toBe(true);
  });

  it("refuses a HOLD compile pack and does not create a run directory", () => {
    const hold = compilePrompt({
      prompt: "Use whatever tools you need and don't ask me.",
      workspaceRoot: dir,
      submittedAt: "2026-07-10T00:00:00.000Z",
    });
    const pack = writeCompilePack(hold, join(dir, "hold-pack"));

    const planned = planRunFromCompilePack({
      packDir: pack.pack_dir,
      workspaceRoot: dir,
      engine: "codex",
      createdAt: "2026-07-10T00:01:00Z",
      approved: true,
    });

    expect(planned.ok).toBe(false);
    expect(planned.terminal_state).toBe("hold-risk");
    expect(planned.run_dir).toBeUndefined();
    expect(existsSync(join(dir, ".loopeix", "loops"))).toBe(false);
  });

  it("requires explicit approval before creating an approved intake brief", () => {
    const pack = writeCompilePack(
      compilePrompt({
        prompt: "Fix the failing date parser test and prove the fix.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:00:00.000Z",
      }),
      join(dir, "compile-pack"),
    );

    const planned = planRunFromCompilePack({
      packDir: pack.pack_dir,
      workspaceRoot: dir,
      engine: "codex",
      createdAt: "2026-07-10T00:01:00Z",
    });

    expect(planned.ok).toBe(false);
    expect(planned.terminal_state).toBe("hold-approval-required");
    expect(existsSync(join(dir, ".loopeix", "loops"))).toBe(false);
  });

  it("refuses a pack when the manifest no longer matches the generated loop", () => {
    const pack = writeCompilePack(
      compilePrompt({
        prompt: "Fix the failing date parser test and prove the fix.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:00:00.000Z",
      }),
      join(dir, "compile-pack"),
    );
    writeFileSync(pack.paths.generated_loop!, `${readFileSync(pack.paths.generated_loop!, "utf8")}\n# tampered\n`);

    const planned = planRunFromCompilePack({
      packDir: pack.pack_dir,
      workspaceRoot: dir,
      engine: "codex",
      createdAt: "2026-07-10T00:01:00Z",
      approved: true,
    });

    expect(planned.ok).toBe(false);
    expect(planned.terminal_state).toBe("hold-pack-integrity");
    expect(planned.message).toContain("generated.loop.yaml hash mismatch");
    expect(existsSync(join(dir, ".loopeix", "loops"))).toBe(false);
  });

  it("refuses a pack when tampered files are rehashed into the manifest", () => {
    const pack = writeCompilePack(
      compilePrompt({
        prompt: "Fix the failing date parser test and prove the fix.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:00:00.000Z",
      }),
      join(dir, "compile-pack"),
    );
    const tamperedYaml = `${readFileSync(pack.paths.generated_loop!, "utf8")}\n# tampered but rehashed\n`;
    writeFileSync(pack.paths.generated_loop!, tamperedYaml);
    const manifest = JSON.parse(readFileSync(pack.paths.manifest, "utf8"));
    manifest.generated_loop_hash = hashBytes(tamperedYaml);
    manifest.file_hashes.generated_loop = hashBytes(tamperedYaml);
    writeFileSync(pack.paths.manifest, `${JSON.stringify(manifest, null, 2)}\n`);

    const planned = planRunFromCompilePack({
      packDir: pack.pack_dir,
      workspaceRoot: dir,
      engine: "codex",
      createdAt: "2026-07-10T00:01:00Z",
      approved: true,
    });

    expect(planned.ok).toBe(false);
    expect(planned.terminal_state).toBe("hold-pack-integrity");
    expect(planned.message).toContain("deterministic compiler replay");
    expect(existsSync(join(dir, ".loopeix", "loops"))).toBe(false);
  });

  it("refuses a compiled pack when the approved workspace root differs from the pack root", () => {
    const otherWorkspace = join(dir, "other-workspace");
    const pack = writeCompilePack(
      compilePrompt({
        prompt: "Fix the failing date parser test and prove the fix.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:00:00.000Z",
      }),
      join(dir, "compile-pack"),
    );

    const planned = planRunFromCompilePack({
      packDir: pack.pack_dir,
      workspaceRoot: otherWorkspace,
      engine: "codex",
      createdAt: "2026-07-10T00:01:00Z",
      approved: true,
    });

    expect(planned.ok).toBe(false);
    expect(planned.terminal_state).toBe("hold-workspace-mismatch");
    expect(existsSync(join(otherWorkspace, ".loopeix", "loops"))).toBe(false);
  });

  it("preflights every required pack file before creating a run directory", () => {
    const pack = writeCompilePack(
      compilePrompt({
        prompt: "Fix the failing date parser test and prove the fix.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:00:00.000Z",
      }),
      join(dir, "compile-pack"),
    );
    rmSync(pack.paths.intake, { force: true });

    const planned = planRunFromCompilePack({
      packDir: pack.pack_dir,
      workspaceRoot: dir,
      engine: "codex",
      createdAt: "2026-07-10T00:01:00Z",
      approved: true,
    });

    expect(planned.ok).toBe(false);
    expect(planned.terminal_state).toBe("hold-pack-integrity");
    expect(existsSync(join(dir, ".loopeix", "loops"))).toBe(false);
  });

  it("refuses to overwrite an existing planned run directory", () => {
    const pack = writeCompilePack(
      compilePrompt({
        prompt: "Fix the failing date parser test and prove the fix.",
        workspaceRoot: dir,
        submittedAt: "2026-07-10T00:00:00.000Z",
      }),
      join(dir, "compile-pack"),
    );
    const first = planRunFromCompilePack({
      packDir: pack.pack_dir,
      workspaceRoot: dir,
      engine: "codex",
      createdAt: "2026-07-10T00:01:00Z",
      approved: true,
    });

    const second = planRunFromCompilePack({
      packDir: pack.pack_dir,
      workspaceRoot: dir,
      engine: "claude",
      createdAt: "2026-07-10T00:02:00Z",
      approved: true,
    });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(false);
    expect(second.terminal_state).toBe("hold-run-exists");
    const runPlan = JSON.parse(readFileSync(first.paths!.resolved_run_plan, "utf8"));
    expect(runPlan.adapter_plan.engine).toBe("codex_cli");
  });
});
