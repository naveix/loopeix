import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { hashBytes, hashCanonical } from "../hash.js";
import type { Loopeix } from "../schema/loopeix.js";
import { ResolvedRunPlan } from "../schema/runtime.js";
import { validateLoopeix } from "../validate.js";
import { compilePrompt } from "../compiler/compile.js";
import { CompilePackManifest } from "../compiler/pack.js";
import {
  ApprovedIntakeBrief,
  CatalogResolution,
  CompilationRecord,
  type ApprovedIntakeBrief as ApprovedIntakeBriefRecord,
  type CatalogResolution as CatalogResolutionRecord,
  type CompilationRecord as CompilationRecordRecord,
  IntakeRecord,
  type IntakeRecord as IntakeRecordRecord,
  type WorkItemRecord,
  WorkItemRecord as WorkItemRecordSchema,
} from "../compiler/records.js";

export type PlanEngine = "codex" | "claude";

export interface PlanRunInput {
  packDir: string;
  workspaceRoot: string;
  engine: PlanEngine;
  approved?: boolean;
  createdAt?: string;
}

export interface PlannedRunPaths {
  work_item: string;
  intake: string;
  catalog_resolution: string;
  pack_manifest: string;
  compilation: string;
  intake_brief: string;
  resolved_run_plan: string;
  generated_loop: string;
}

export interface PlanRunResult {
  ok: boolean;
  terminal_state: string;
  run_id?: string;
  run_dir?: string;
  intake_brief_id?: string;
  paths?: PlannedRunPaths;
  message?: string;
}

function loadJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function fileHash(path: string): string {
  return hashBytes(readFileSync(path, "utf8"));
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  return hashCanonical(left) === hashCanonical(right);
}

function tokenFromMachineId(id: string, prefix: string): string {
  return id.startsWith(`${prefix}_`) ? id.slice(prefix.length + 1) : id.replace(/^[a-z]+_/, "");
}

function adapterPlan(engine: PlanEngine): Record<string, unknown> {
  if (engine === "claude") {
    return {
      engine: "claude_code_cli",
      command: "claude -p --output-format stream-json --include-hook-events",
      permission_mode: "default",
      known_gaps: ["token and usage counts may be incomplete", "raw transcript is not primary evidence"],
    };
  }
  return {
    engine: "codex_cli",
    command: "codex exec --json",
    permission_mode: "workspace-write",
    known_gaps: ["token and usage counts may be incomplete", "raw transcript is not primary evidence"],
  };
}

function readCompiledPack(packDir: string):
  | {
      ok: true;
      workItem: WorkItemRecord;
      intake: IntakeRecordRecord;
      catalogResolution: CatalogResolutionRecord;
      compilation: CompilationRecordRecord;
      manifest: CompilePackManifest;
      loop: Loopeix;
      yaml: string;
    }
  | { ok: false; terminalState: string; message: string } {
  const manifestPath = join(packDir, "pack-manifest.json");
  if (!existsSync(manifestPath)) {
    return { ok: false, terminalState: "hold-pack-integrity", message: "compile pack is missing pack-manifest.json" };
  }

  let manifest: CompilePackManifest;
  try {
    manifest = CompilePackManifest.parse(loadJson(manifestPath));
  } catch (error) {
    return {
      ok: false,
      terminalState: "hold-pack-integrity",
      message: `pack-manifest.json is invalid: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  const requiredHashes: Array<[path: string, hash: string, label: string]> = [
    [join(packDir, "work-item.json"), manifest.file_hashes.work_item, "work-item.json"],
    [join(packDir, "intake-record.json"), manifest.file_hashes.intake, "intake-record.json"],
    [join(packDir, "catalog-resolution.json"), manifest.file_hashes.catalog_resolution, "catalog-resolution.json"],
    [join(packDir, "compile-report.md"), manifest.file_hashes.report, "compile-report.md"],
  ];
  if (manifest.terminal_state === "compiled") {
    requiredHashes.push(
      [join(packDir, "compilation-record.json"), manifest.file_hashes.compilation ?? "", "compilation-record.json"],
      [join(packDir, "generated.loop.yaml"), manifest.file_hashes.generated_loop ?? "", "generated.loop.yaml"],
    );
  }
  for (const [path, expectedHash, label] of requiredHashes) {
    if (expectedHash === "" || !existsSync(path)) {
      return { ok: false, terminalState: "hold-pack-integrity", message: `compile pack is missing ${label}` };
    }
    if (fileHash(path) !== expectedHash) {
      return { ok: false, terminalState: "hold-pack-integrity", message: `${label} hash mismatch` };
    }
  }

  let workItem: WorkItemRecord;
  let intake: IntakeRecordRecord;
  let catalogResolution: CatalogResolutionRecord;
  try {
    workItem = WorkItemRecordSchema.parse(loadJson(join(packDir, "work-item.json")));
    intake = IntakeRecord.parse(loadJson(join(packDir, "intake-record.json")));
    catalogResolution = CatalogResolution.parse(loadJson(join(packDir, "catalog-resolution.json")));
  } catch (error) {
    return {
      ok: false,
      terminalState: "hold-pack-integrity",
      message: `compile pack record is invalid: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  if (
    manifest.work_item_id !== workItem.work_item_id ||
    manifest.intake_id !== intake.intake_id ||
    manifest.resolution_id !== catalogResolution.resolution_id ||
    manifest.selected_item_id !== catalogResolution.selected_item_id ||
    intake.work_item_id !== workItem.work_item_id ||
    manifest.terminal_state !== catalogResolution.terminal_state
  ) {
    return { ok: false, terminalState: "hold-pack-integrity", message: "compile pack lineage records do not match the manifest" };
  }

  if (catalogResolution.terminal_state !== "compiled") {
    return {
      ok: false,
      terminalState: catalogResolution.terminal_state,
      message: "compile pack is not compiled; resolve HOLD before planning a run",
    };
  }

  let compilation: CompilationRecordRecord;
  try {
    compilation = CompilationRecord.parse(loadJson(join(packDir, "compilation-record.json")));
  } catch (error) {
    return {
      ok: false,
      terminalState: "hold-pack-integrity",
      message: `compilation-record.json is invalid: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  if (manifest.compilation_id !== compilation.compilation_id) {
    return { ok: false, terminalState: "hold-pack-integrity", message: "compilation record does not match the selected catalog resolution" };
  }

  const loopPath = join(packDir, "generated.loop.yaml");
  const yaml = readFileSync(loopPath, "utf8");
  const parsedYaml = parseYaml(yaml);
  const validation = validateLoopeix(parsedYaml);
  if (!validation.ok) {
    return {
      ok: false,
      terminalState: "hold-pack-integrity",
      message: `generated.loop.yaml is invalid: ${validation.errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
    };
  }
  const loop = parsedYaml as Loopeix;
  if (
    compilation.selected_loop_family !== loop.loop_family ||
    compilation.selected_loop_version !== loop.version ||
    compilation.effective_risk_controls.max_tier_without_approval !== loop.risk_controls.max_tier_without_approval ||
    compilation.effective_risk_controls.t5_allowed !== loop.risk_controls.t5_allowed
  ) {
    return { ok: false, terminalState: "hold-pack-integrity", message: "compiled loop does not match compilation record" };
  }

  const replay = compilePrompt({
    prompt: workItem.prompt,
    workspaceRoot: workItem.workspace_root,
    submittedAt: workItem.submitted_at,
  });
  if (
    !replay.ok ||
    replay.compilation === undefined ||
    replay.yaml === undefined ||
    !canonicalEqual(replay.work_item, workItem) ||
    !canonicalEqual(replay.intake, intake) ||
    !canonicalEqual(replay.catalog_resolution, catalogResolution) ||
    !canonicalEqual(replay.compilation, compilation) ||
    hashBytes(replay.yaml) !== hashBytes(yaml)
  ) {
    return { ok: false, terminalState: "hold-pack-integrity", message: "compile pack does not match deterministic compiler replay" };
  }

  return {
    ok: true,
    workItem,
    intake,
    catalogResolution,
    compilation,
    manifest,
    loop,
    yaml,
  };
}

export function planRunFromCompilePack(input: PlanRunInput): PlanRunResult {
  const packDir = resolve(input.packDir);
  const loaded = readCompiledPack(packDir);
  if (!loaded.ok) {
    return {
      ok: false,
      terminal_state: loaded.terminalState,
      message: loaded.message,
    };
  }
  if (input.approved !== true) {
    return {
      ok: false,
      terminal_state: "hold-approval-required",
      message: "planning requires --approve-compiled-pack after human review of the compile pack",
    };
  }

  const createdAt = input.createdAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const token = tokenFromMachineId(loaded.compilation.compilation_id, "compilation");
  const runId = `run_${token}`;
  const intakeBriefId = `ib_${token}`;
  const workspaceRoot = resolve(input.workspaceRoot);
  if (workspaceRoot !== resolve(loaded.workItem.workspace_root)) {
    return {
      ok: false,
      terminal_state: "hold-workspace-mismatch",
      message: "workspace root must match the compile pack work-item workspace_root",
    };
  }
  const runDir = join(workspaceRoot, ".loopeix", "loops", loaded.loop.loop_family, "runs", runId);
  if (existsSync(runDir)) {
    return {
      ok: false,
      terminal_state: "hold-run-exists",
      message: "run directory already exists; refusing to overwrite an immutable planned run",
    };
  }

  const intakeBrief: ApprovedIntakeBriefRecord = {
    schema_version: "0.1",
    intake_brief_id: intakeBriefId,
    objective: loaded.workItem.prompt,
    scope: [loaded.loop.outcome.summary],
    allowed_context: loaded.loop.context_contract.required,
    forbidden_context: loaded.loop.context_contract.forbidden,
    allowed_tools: loaded.loop.tool_grants.map((grant) => grant.id),
    allowed_connectors: [],
    max_risk_tier: loaded.loop.risk_controls.max_tier_without_approval,
    approval_bindings: ["compiler-pack-approved"],
    terminal_states: ["compiled"],
  };
  ApprovedIntakeBrief.parse(intakeBrief);

  const resolvedRunPlan = {
    schema_version: "0.1",
    run_id: runId,
    loop_family: loaded.loop.loop_family,
    loopeix_version: loaded.loop.version,
    loopeix_version_hash: hashBytes(loaded.yaml),
    work_item_id: loaded.workItem.work_item_id,
    intake_brief_id: intakeBriefId,
    created_at: createdAt,
    assurance_profile: { id: "base", tightens: [] },
    context_snapshot: loaded.loop.context_contract,
    role_assignments: loaded.loop.roles.map((role) => ({
      role: role.id,
      actor_id: `actor_${role.id.replaceAll("-", "_")}`,
      actor_type: "ai_agent",
    })),
    task_plan: loaded.loop.tasks.map((task) => ({
      task_id: task.id,
      role: task.role,
      depends_on: task.depends_on,
      artifacts: task.artifacts,
      acceptance_checks: task.acceptance_checks,
    })),
    tool_grants: loaded.loop.tool_grants,
    workspace_boundary: {
      workspace_root: workspaceRoot,
      read: ["."],
      write: ["artifacts", "evidence", "evaluations", "handoffs", "findings"],
    },
    adapter_plan: adapterPlan(input.engine),
    gate_plan: loaded.loop.gates.map((gate) => ({
      gate_id: gate.id,
      blocking: gate.blocking,
      inputs_required: gate.inputs_required,
      waiver_allowed: gate.waiver_allowed,
    })),
    evaluation_plan: loaded.loop.evaluations.map((evaluation) => ({
      evaluation_id: evaluation.id,
      type: evaluation.type,
      required: evaluation.required,
      ...(evaluation.command === undefined ? {} : { command: evaluation.command }),
    })),
    risk_controls: loaded.loop.risk_controls,
  };
  const parsedRunPlan = ResolvedRunPlan.parse(resolvedRunPlan);

  mkdirSync(runDir, { recursive: true });
  const paths: PlannedRunPaths = {
    work_item: join(runDir, "work-item.json"),
    intake: join(runDir, "intake-record.json"),
    catalog_resolution: join(runDir, "catalog-resolution.json"),
    pack_manifest: join(runDir, "pack-manifest.json"),
    compilation: join(runDir, "compilation-record.json"),
    intake_brief: join(runDir, "intake-brief.json"),
    resolved_run_plan: join(runDir, "resolved-run-plan.json"),
    generated_loop: join(runDir, "generated.loop.yaml"),
  };
  copyFileSync(join(packDir, "work-item.json"), paths.work_item);
  copyFileSync(join(packDir, "intake-record.json"), paths.intake);
  copyFileSync(join(packDir, "catalog-resolution.json"), paths.catalog_resolution);
  copyFileSync(join(packDir, "pack-manifest.json"), paths.pack_manifest);
  copyFileSync(join(packDir, "compilation-record.json"), paths.compilation);
  copyFileSync(join(packDir, "generated.loop.yaml"), paths.generated_loop);
  writeFileSync(paths.intake_brief, `${JSON.stringify(intakeBrief, null, 2)}\n`);
  writeFileSync(paths.resolved_run_plan, `${JSON.stringify(parsedRunPlan, null, 2)}\n`);

  return {
    ok: true,
    terminal_state: "planned",
    run_id: runId,
    run_dir: runDir,
    intake_brief_id: intakeBriefId,
    paths,
  };
}
