import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { z } from "zod";
import { hashBytes } from "../hash.js";
import { Hash, HumanId, MachineId, SchemaVersion } from "../schema/scalars.js";
import type { CompilePromptResult } from "./compile.js";
import { CompilerTerminalState } from "./records.js";

export interface CompilePackPaths {
  work_item: string;
  intake: string;
  catalog_resolution: string;
  report: string;
  manifest: string;
  compilation?: string;
  generated_loop?: string;
}

export interface CompilePackResult {
  ok: boolean;
  pack_dir: string;
  paths: CompilePackPaths;
}

export const CompilePackManifest = z
  .object({
    schema_version: SchemaVersion,
    pack_manifest_id: MachineId,
    terminal_state: CompilerTerminalState,
    work_item_id: MachineId,
    intake_id: MachineId,
    resolution_id: MachineId,
    selected_item_id: HumanId.nullable(),
    compilation_id: MachineId.nullable(),
    generated_loop_hash: Hash.nullable(),
    file_hashes: z
      .object({
        work_item: Hash,
        intake: Hash,
        catalog_resolution: Hash,
        report: Hash,
        compilation: Hash.optional(),
        generated_loop: Hash.optional(),
      })
      .strict(),
  })
  .strict()
  .superRefine((manifest, ctx) => {
    if (manifest.terminal_state === "compiled") {
      if (manifest.compilation_id === null) {
        ctx.addIssue({ code: "custom", path: ["compilation_id"], message: "compiled pack requires compilation_id" });
      }
      if (manifest.generated_loop_hash === null || manifest.file_hashes.generated_loop === undefined || manifest.file_hashes.compilation === undefined) {
        ctx.addIssue({ code: "custom", path: ["file_hashes"], message: "compiled pack requires generated loop and compilation hashes" });
      }
    } else {
      if (manifest.compilation_id !== null || manifest.generated_loop_hash !== null) {
        ctx.addIssue({ code: "custom", path: ["compilation_id"], message: "HOLD pack cannot reference compiled artifacts" });
      }
      if (manifest.file_hashes.generated_loop !== undefined || manifest.file_hashes.compilation !== undefined) {
        ctx.addIssue({ code: "custom", path: ["file_hashes"], message: "HOLD pack cannot hash compiled artifacts" });
      }
    }
  });

export type CompilePackManifest = z.infer<typeof CompilePackManifest>;

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function hashFile(path: string): string {
  return hashBytes(readFileSync(path, "utf8"));
}

function list(values: readonly string[]): string {
  if (values.length === 0) return "- None recorded\n";
  return values.map((value) => `- ${value}`).join("\n") + "\n";
}

function renderCompileReport(result: CompilePromptResult): string {
  const selected = result.catalog_resolution.selected_item_id ?? "none";
  const lines: string[] = [
    "# Loopeix Compile Report",
    "",
    `Terminal state: ${result.catalog_resolution.terminal_state}`,
    `Selected item: ${selected}`,
    `Work item: ${result.work_item.work_item_id}`,
    `Catalog hash: ${result.catalog_resolution.catalog_version_hash}`,
    "",
    "## Selection Evidence",
    "",
    list(result.catalog_resolution.selection_evidence),
    "## Ranked Candidates",
    "",
    list(result.catalog_resolution.ranked_candidates.map((candidate) => `${candidate.item_id} (${candidate.score}): ${candidate.reasons.join(", ")}`)),
  ];

  if (result.compilation !== undefined) {
    lines.push(
      "## Bound Inputs",
      "",
      list(Object.entries(result.compilation.input_bindings).map(([key, value]) => `${key}: ${value}`)),
      "## Risk Controls",
      "",
      `- Max tier without approval: ${result.compilation.effective_risk_controls.max_tier_without_approval}`,
      `- T5 allowed: ${String(result.compilation.effective_risk_controls.t5_allowed)}`,
      "",
      "## Can prove",
      "",
      list(result.compilation.proof_boundary.can_prove),
      "## Cannot prove",
      "",
      list(result.compilation.proof_boundary.cannot_prove),
    );
  }

  if (result.clarification_questions.length > 0) {
    lines.push("## Clarification questions", "", list(result.clarification_questions));
  }

  lines.push(
    "## Next action",
    "",
    result.ok
      ? "- Review `generated.loop.yaml`, then approve it before creating a run plan."
      : "- Resolve the HOLD questions, then run `loopeix compile` again.",
    "",
  );

  return lines.join("\n");
}

function tokenFromMachineId(id: string, prefix: string): string {
  return id.startsWith(`${prefix}_`) ? id.slice(prefix.length + 1) : id.replace(/^[a-z]+_/, "");
}

function buildManifest(result: CompilePromptResult, paths: CompilePackPaths): CompilePackManifest {
  const fileHashes: CompilePackManifest["file_hashes"] = {
    work_item: hashFile(paths.work_item),
    intake: hashFile(paths.intake),
    catalog_resolution: hashFile(paths.catalog_resolution),
    report: hashFile(paths.report),
  };
  if (paths.compilation !== undefined) fileHashes.compilation = hashFile(paths.compilation);
  if (paths.generated_loop !== undefined) fileHashes.generated_loop = hashFile(paths.generated_loop);

  return CompilePackManifest.parse({
    schema_version: "0.1",
    pack_manifest_id: `pack_${tokenFromMachineId(result.catalog_resolution.resolution_id, "resolution")}`,
    terminal_state: result.catalog_resolution.terminal_state,
    work_item_id: result.work_item.work_item_id,
    intake_id: result.intake.intake_id,
    resolution_id: result.catalog_resolution.resolution_id,
    selected_item_id: result.catalog_resolution.selected_item_id,
    compilation_id: result.compilation?.compilation_id ?? null,
    generated_loop_hash: paths.generated_loop === undefined ? null : fileHashes.generated_loop,
    file_hashes: fileHashes,
  });
}

export function writeCompilePack(result: CompilePromptResult, targetDir: string): CompilePackResult {
  const packDir = resolve(targetDir);
  mkdirSync(packDir, { recursive: true });

  const compiledOnlyPaths = {
    compilation: join(packDir, "compilation-record.json"),
    generated_loop: join(packDir, "generated.loop.yaml"),
  };
  const paths: CompilePackPaths = {
    work_item: join(packDir, "work-item.json"),
    intake: join(packDir, "intake-record.json"),
    catalog_resolution: join(packDir, "catalog-resolution.json"),
    report: join(packDir, "compile-report.md"),
    manifest: join(packDir, "pack-manifest.json"),
  };

  writeJson(paths.work_item, result.work_item);
  writeJson(paths.intake, result.intake);
  writeJson(paths.catalog_resolution, result.catalog_resolution);

  if (result.ok && result.compilation !== undefined && result.yaml !== undefined) {
    paths.compilation = compiledOnlyPaths.compilation;
    paths.generated_loop = compiledOnlyPaths.generated_loop;
    writeJson(paths.compilation, result.compilation);
    writeFileSync(paths.generated_loop, result.yaml);
  } else {
    rmSync(compiledOnlyPaths.compilation, { force: true });
    rmSync(compiledOnlyPaths.generated_loop, { force: true });
  }

  writeFileSync(paths.report, renderCompileReport(result));
  writeJson(paths.manifest, buildManifest(result, paths));
  return { ok: result.ok, pack_dir: packDir, paths };
}
