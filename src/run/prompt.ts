import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import type { EngineId } from "../adapters/index.js";
import { ApprovedIntakeBrief, type ApprovedIntakeBrief as ApprovedIntakeBriefRecord } from "../compiler/records.js";
import { ResolvedRunPlan } from "../schema/runtime.js";
import { preflightPlannedRun, type PlannedRunPreflightStatus } from "./preflight.js";

export interface PlannedRunPromptInput {
  runDir: string;
}

export type PlannedRunPromptResult =
  | {
      ok: true;
      status: "ready";
      run_dir: string;
      run_id: string;
      engine: EngineId;
      prompt: string;
    }
  | {
      ok: false;
      status: PlannedRunPreflightStatus;
      run_dir: string;
      run_id?: string;
      engine?: string;
      findings: string[];
    };

type ResolvedPlan = ReturnType<typeof ResolvedRunPlan.parse>;

function hold(status: PlannedRunPreflightStatus, runDir: string, findings: string[], extra?: { run_id?: string; engine?: string }): PlannedRunPromptResult {
  return { ok: false, status, run_dir: runDir, findings, ...extra };
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function plannedEngine(plan: ResolvedPlan): EngineId | undefined {
  const engine = (plan.adapter_plan as { engine?: unknown }).engine;
  return engine === "codex_cli" || engine === "claude_code_cli" ? engine : undefined;
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringArray(value: unknown): string[] {
  return asArray(value).map((item) => (typeof item === "string" ? item : JSON.stringify(item)));
}

function list(values: string[]): string {
  return values.length === 0 ? "- none" : values.map((value) => `- ${value}`).join("\n");
}

function inlineList(values: unknown): string {
  const items = stringArray(values);
  return items.length === 0 ? "none" : items.join(", ");
}

function formatTaskPlan(plan: ResolvedPlan): string {
  const tasks = asArray(plan.task_plan);
  if (tasks.length === 0) return "- none";
  return tasks
    .map((task, index) => {
      const record = asRecord(task);
      return [
        `${index + 1}. ${String(record.task_id ?? "<task>")} (${String(record.role ?? "unassigned")})`,
        `   depends_on: ${inlineList(record.depends_on)}`,
        `   artifacts: ${inlineList(record.artifacts)}`,
        `   acceptance_checks: ${inlineList(record.acceptance_checks)}`,
      ].join("\n");
    })
    .join("\n");
}

function formatGatePlan(plan: ResolvedPlan): string {
  const gates = asArray(plan.gate_plan);
  if (gates.length === 0) return "- none";
  return gates
    .map((gate) => {
      const record = asRecord(gate);
      const blocking = record.blocking === true ? "blocking" : "non-blocking";
      return `- ${String(record.gate_id ?? "<gate>")} (${blocking}); inputs_required: ${inlineList(record.inputs_required)}; waiver_allowed: ${
        record.waiver_allowed === true ? "yes" : "no"
      }`;
    })
    .join("\n");
}

function formatEvaluationPlan(plan: ResolvedPlan): string {
  const evaluations = asArray(plan.evaluation_plan);
  if (evaluations.length === 0) return "- none";
  return evaluations
    .map((evaluation) => {
      const record = asRecord(evaluation);
      const required = record.required === true ? "required" : "optional";
      const command = typeof record.command === "string" ? `; command: ${record.command}` : "";
      return `- ${String(record.evaluation_id ?? "<evaluation>")} (${String(record.type ?? "unknown")}, ${required})${command}`;
    })
    .join("\n");
}

function formatToolGrants(plan: ResolvedPlan): string {
  const grants = asArray(plan.tool_grants);
  if (grants.length === 0) return "- none";
  return grants
    .map((grant) => {
      const record = asRecord(grant);
      return `- ${String(record.id ?? "<tool>")} (risk_tier: ${String(record.risk_tier ?? "unknown")}; purpose: ${String(record.purpose ?? "unspecified")})`;
    })
    .join("\n");
}

function buildPrompt(runDir: string, plan: ResolvedPlan, intake: ApprovedIntakeBriefRecord, engine: EngineId): string {
  const workspace = asRecord(plan.workspace_boundary);
  const adapter = asRecord(plan.adapter_plan);
  const knownGaps = stringArray(adapter.known_gaps);
  return [
    "# Loopeix planned run prompt",
    "",
    "You are executing an approved Loopeix planned run. Treat the planned records as the authority, not the user's original vague request.",
    "",
    "## Objective",
    intake.objective,
    "",
    "## Scope",
    list(intake.scope),
    "",
    "## Workspace boundary",
    `- run_id: ${plan.run_id}`,
    `- run_dir: ${runDir}`,
    `- workspace_root: ${String(workspace.workspace_root ?? "<unknown>")}`,
    `- read: ${inlineList(workspace.read)}`,
    `- write: ${inlineList(workspace.write)}`,
    "",
    "## Context contract",
    "Allowed context:",
    list(intake.allowed_context),
    "",
    "Forbidden context:",
    list(intake.forbidden_context),
    "",
    "## Tools and connectors",
    "Allowed tools:",
    list(intake.allowed_tools),
    "",
    "Allowed connectors:",
    list(intake.allowed_connectors),
    "",
    "Resolved tool grants:",
    formatToolGrants(plan),
    "",
    "## Risk controls",
    `- max_risk_tier_without_approval: ${plan.risk_controls.max_tier_without_approval}`,
    `- t5_allowed: ${plan.risk_controls.t5_allowed ? "yes" : "no"}`,
    `- approved terminal states: ${intake.terminal_states.join(", ")}`,
    `- approval bindings: ${intake.approval_bindings.join(", ")}`,
    "",
    "## Engine adapter",
    `- engine: ${engine}`,
    `- command shape: ${String(adapter.command ?? "<unknown>")}`,
    `- permission_mode: ${String(adapter.permission_mode ?? "<unknown>")}`,
    "Known capture gaps:",
    list(knownGaps),
    "",
    "## Task plan",
    formatTaskPlan(plan),
    "",
    "## Gate plan",
    formatGatePlan(plan),
    "",
    "## Evaluation plan",
    formatEvaluationPlan(plan),
    "",
    "## Execution rules",
    "- Stay inside the workspace boundary and planned write targets.",
    "- Do not access forbidden context, secrets, credentials, browser sessions, or external accounts unless explicitly granted.",
    "- Do not use tools or connectors outside the resolved grants.",
    "- Do not install packages, deploy, delete files, or call production services unless the loop grants that authority and a gate approves it.",
    "- Produce concrete evidence for every strong claim, including files changed, tests run, and unresolved risks.",
    "- Do not claim unsupported proof. If evidence capture is incomplete, say exactly what is missing.",
    "- Preserve the run id and planned scope in any handoff or final report.",
  ].join("\n");
}

export function buildPlannedRunPrompt(input: PlannedRunPromptInput): PlannedRunPromptResult {
  const runDir = resolve(input.runDir);
  if (!existsSync(runDir) || !statSync(runDir).isDirectory()) {
    return hold("hold-not-planned", runDir, [`planned run directory not found: ${runDir}`]);
  }

  const planPath = join(runDir, "resolved-run-plan.json");
  if (!existsSync(planPath)) {
    return hold("hold-missing-file", runDir, ["missing planned run file: resolved-run-plan.json"]);
  }

  let plan: ResolvedPlan;
  try {
    plan = ResolvedRunPlan.parse(readJson(planPath));
  } catch (error) {
    return hold("hold-invalid-plan", runDir, [`resolved-run-plan.json is invalid: ${error instanceof Error ? error.message : String(error)}`]);
  }

  const engine = plannedEngine(plan);
  if (engine === undefined) {
    return hold("hold-invalid-plan", runDir, ["resolved-run-plan.json adapter_plan.engine must be codex_cli or claude_code_cli"], {
      run_id: plan.run_id,
      engine: typeof (plan.adapter_plan as { engine?: unknown }).engine === "string" ? (plan.adapter_plan as { engine: string }).engine : undefined,
    });
  }

  const preflight = preflightPlannedRun({ runDir, engine });
  if (!preflight.ok) {
    return hold(preflight.status, runDir, preflight.findings, { run_id: preflight.run_id, engine: preflight.engine });
  }

  let intake: ApprovedIntakeBriefRecord;
  try {
    intake = ApprovedIntakeBrief.parse(readJson(join(runDir, "intake-brief.json")));
  } catch (error) {
    return hold("hold-invalid-plan", runDir, [`intake-brief.json is invalid: ${error instanceof Error ? error.message : String(error)}`], {
      run_id: plan.run_id,
      engine,
    });
  }

  return {
    ok: true,
    status: "ready",
    run_dir: runDir,
    run_id: plan.run_id,
    engine,
    prompt: buildPrompt(runDir, plan, intake, engine),
  };
}
