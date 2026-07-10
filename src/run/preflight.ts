import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import type { EngineId } from "../adapters/index.js";
import { RUN_DIR_FILES } from "./run-dir.js";
import { ResolvedRunPlan } from "../schema/runtime.js";
import { validateLoopeix } from "../validate.js";

export type PlannedRunPreflightStatus =
  | "ready"
  | "hold-not-planned"
  | "hold-missing-file"
  | "hold-invalid-plan"
  | "hold-invalid-loop"
  | "hold-engine-mismatch"
  | "hold-already-started";

export interface PlannedRunPreflightInput {
  runDir: string;
  engine: EngineId;
}

export interface PlannedRunPreflightResult {
  ok: boolean;
  status: PlannedRunPreflightStatus;
  run_dir: string;
  run_id?: string;
  engine?: string;
  workspace_root?: string;
  spec_path?: string;
  next_action?: string;
  findings: string[];
}

const PLANNED_REQUIRED_FILES = [
  "work-item.json",
  "intake-record.json",
  "catalog-resolution.json",
  "pack-manifest.json",
  "compilation-record.json",
  "intake-brief.json",
  "resolved-run-plan.json",
  "generated.loop.yaml",
] as const;

const EXECUTION_ARTIFACTS = [
  RUN_DIR_FILES.ledger,
  RUN_DIR_FILES.manifest,
  RUN_DIR_FILES.reportMd,
  RUN_DIR_FILES.reportHtml,
  RUN_DIR_FILES.reportInput,
  RUN_DIR_FILES.runSummary,
] as const;

function shortEngine(engine: EngineId): "codex" | "claude" {
  return engine === "codex_cli" ? "codex" : "claude";
}

function plannedWorkspaceRoot(plan: unknown): string | undefined {
  const boundary = (plan as { workspace_boundary?: unknown }).workspace_boundary;
  if (typeof boundary !== "object" || boundary === null) return undefined;
  const root = (boundary as { workspace_root?: unknown }).workspace_root;
  return typeof root === "string" && root.length > 0 ? root : undefined;
}

function plannedEngine(plan: unknown): string | undefined {
  const adapter = (plan as { adapter_plan?: unknown }).adapter_plan;
  if (typeof adapter !== "object" || adapter === null) return undefined;
  const engine = (adapter as { engine?: unknown }).engine;
  return typeof engine === "string" ? engine : undefined;
}

function hold(status: PlannedRunPreflightStatus, runDir: string, findings: string[]): PlannedRunPreflightResult {
  return { ok: false, status, run_dir: runDir, findings };
}

export function preflightPlannedRun(input: PlannedRunPreflightInput): PlannedRunPreflightResult {
  const runDir = resolve(input.runDir);
  if (!existsSync(runDir) || !statSync(runDir).isDirectory()) {
    return hold("hold-not-planned", runDir, [`planned run directory not found: ${runDir}`]);
  }

  const missing = PLANNED_REQUIRED_FILES.filter((file) => !existsSync(join(runDir, file)));
  if (missing.length > 0) {
    return hold("hold-missing-file", runDir, missing.map((file) => `missing planned run file: ${file}`));
  }

  let resolvedPlan: ReturnType<typeof ResolvedRunPlan.parse>;
  try {
    resolvedPlan = ResolvedRunPlan.parse(JSON.parse(readFileSync(join(runDir, "resolved-run-plan.json"), "utf8")));
  } catch (error) {
    return hold("hold-invalid-plan", runDir, [`resolved-run-plan.json is invalid: ${error instanceof Error ? error.message : String(error)}`]);
  }

  const planEngine = plannedEngine(resolvedPlan);
  if (planEngine !== undefined && planEngine !== input.engine) {
    return {
      ok: false,
      status: "hold-engine-mismatch",
      run_dir: runDir,
      run_id: resolvedPlan.run_id,
      engine: planEngine,
      workspace_root: plannedWorkspaceRoot(resolvedPlan),
      spec_path: join(runDir, "generated.loop.yaml"),
      findings: [`planned run was prepared for ${planEngine}, not ${input.engine}`],
    };
  }

  const executionArtifacts = EXECUTION_ARTIFACTS.filter((file) => existsSync(join(runDir, file)));
  if (executionArtifacts.length > 0) {
    return {
      ok: false,
      status: "hold-already-started",
      run_dir: runDir,
      run_id: resolvedPlan.run_id,
      engine: planEngine,
      workspace_root: plannedWorkspaceRoot(resolvedPlan),
      spec_path: join(runDir, "generated.loop.yaml"),
      findings: executionArtifacts.map((file) => `execution artifact already exists: ${file}`),
    };
  }

  const specPath = join(runDir, "generated.loop.yaml");
  const parsedYaml = parseYaml(readFileSync(specPath, "utf8"));
  const validation = validateLoopeix(parsedYaml);
  if (!validation.ok) {
    return {
      ok: false,
      status: "hold-invalid-loop",
      run_dir: runDir,
      run_id: resolvedPlan.run_id,
      engine: planEngine,
      workspace_root: plannedWorkspaceRoot(resolvedPlan),
      spec_path: specPath,
      findings: validation.errors.map((error) => `${error.path}: ${error.message}`),
    };
  }

  return {
    ok: true,
    status: "ready",
    run_dir: runDir,
    run_id: resolvedPlan.run_id,
    engine: planEngine,
    workspace_root: plannedWorkspaceRoot(resolvedPlan),
    spec_path: specPath,
    next_action: `loopeix run start ${runDir} --engine ${shortEngine(input.engine)}`,
    findings: [],
  };
}
