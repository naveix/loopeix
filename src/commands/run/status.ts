import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { resolve } from "node:path";
import { Args, Command } from "@oclif/core";
import { parseLedgerText, recoverLedger, type RecoveryResult } from "../../ledger.js";
import { ResolvedRunPlan } from "../../schema/runtime.js";
import {
  capturePlannedRunV02,
  consumeCapturedPlannedRunV02,
} from "../../run/capture-planned-v02.js";
import { presentPlannedRunV02, type PlannedRunPresentationV02 } from "../../run/present-planned-v02.js";

export type RunStatusResult =
  | (RecoveryResult & { source: "ledger"; ledger_path: string })
  | {
      source: "planned";
      run_id: string;
      run_state: "planned";
      integrity_status: "unknown";
      last_valid_sequence: 0;
      terminated: false;
      findings: string[];
      run_dir: string;
      engine: string | null;
      next_action: string;
    }
  | (PlannedRunPresentationV02 & {
      source: "planned";
      integrity_status: "unknown";
      last_valid_sequence: 0;
      terminated: false;
      findings: [];
      run_dir: string;
      engine: string;
    })
  | {
      source: "planned";
      run_state: "planned";
      integrity_status: "invalid";
      last_valid_sequence: 0;
      terminated: false;
      findings: string[];
      run_dir: string;
      reason: "V02_RUN_LAYOUT_CONTAMINATED" | "INVALID_RESOLVED_RUN_PLAN_DOCUMENT";
    };

function resolveLedgerPath(p: string): string {
  if (existsSync(p) && statSync(p).isDirectory()) return join(p, "ledger.jsonl");
  return p;
}

function plannedRunPath(p: string): string | undefined {
  if (!existsSync(p) || !statSync(p).isDirectory()) return undefined;
  const resolvedPlan = join(p, "resolved-run-plan.json");
  return existsSync(resolvedPlan) ? resolvedPlan : undefined;
}

function plannedEngine(plan: unknown): string | null {
  const adapter = (plan as { adapter_plan?: unknown }).adapter_plan;
  if (typeof adapter !== "object" || adapter === null) return null;
  const engine = (adapter as { engine?: unknown }).engine;
  return typeof engine === "string" ? engine : null;
}

function shortEngine(engine: string | null): string {
  if (engine === "codex_cli") return "codex";
  if (engine === "claude_code_cli") return "claude";
  return "<engine>";
}

/** `loopeix run status <run>` — show a run's state, integrity, and findings. */
export default class RunStatus extends Command {
  static summary = "Show a run's state, integrity, and findings from its ledger.";
  static description = "Reads the run's ledger.jsonl, recovers it, and reports. Exit 4 if integrity is not valid.";
  static args = {
    run: Args.string({ description: "run directory or ledger.jsonl path", required: true }),
  };
  static enableJsonFlag = true;

  public async run(): Promise<RunStatusResult> {
    const { args } = await this.parse(RunStatus);
    const runDir = resolve(args.run);
    const captured = await capturePlannedRunV02(runDir);
    if (captured.ok) {
      const value = consumeCapturedPlannedRunV02(captured.captured);
      if (value === null) {
        const result: RunStatusResult = {
          source: "planned",
          run_state: "planned",
          integrity_status: "invalid",
          last_valid_sequence: 0,
          terminated: false,
          findings: ["The captured V02 planned run could not be consumed safely."],
          run_dir: runDir,
          reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
        };
        process.exitCode = 4;
        return result;
      }
      const result: RunStatusResult = {
        ...presentPlannedRunV02(value.plan),
        source: "planned",
        integrity_status: "unknown",
        last_valid_sequence: 0,
        terminated: false,
        findings: [],
        run_dir: runDir,
        engine: value.plan.adapter_plan.engine,
      };
      if (!this.jsonEnabled()) {
        this.log("run_state:     planned");
        this.log("execution:     NOT EXECUTED");
        this.log("enforcement:   NOT ENFORCED");
        this.log(`reason:        ${result.reason}`);
      }
      return result;
    }
    if (captured.reason !== "NOT_V02_PLANNED_RUN") {
      const result: RunStatusResult = {
        source: "planned",
        run_state: "planned",
        integrity_status: "invalid",
        last_valid_sequence: 0,
        terminated: false,
        findings: [captured.message],
        run_dir: runDir,
        reason: captured.reason === "V02_RUN_LAYOUT_CONTAMINATED"
          ? "V02_RUN_LAYOUT_CONTAMINATED"
          : "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
      };
      if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
      process.exitCode = 4;
      return result;
    }
    const ledgerPath = resolveLedgerPath(args.run);
    const plannedPlanPath = plannedRunPath(args.run);
    if (!existsSync(ledgerPath)) {
      if (plannedPlanPath === undefined) {
        this.error(`ledger not found: ${ledgerPath}`, { exit: 2 });
      }
      const plan = ResolvedRunPlan.parse(JSON.parse(readFileSync(plannedPlanPath, "utf8")));
      const engine = plannedEngine(plan);
      const result: RunStatusResult = {
        source: "planned",
        run_id: plan.run_id,
        run_state: "planned",
        integrity_status: "unknown",
        last_valid_sequence: 0,
        terminated: false,
        findings: [],
        run_dir: args.run,
        engine,
        next_action: `loopeix run start ${args.run} --engine ${shortEngine(engine)}`,
      };
      if (!this.jsonEnabled()) {
        this.log(`run_state:     ${result.run_state}`);
        this.log(`integrity:     ${result.integrity_status}`);
        this.log(`last sequence: ${result.last_valid_sequence}`);
        this.log(`terminated:    ${result.terminated}`);
        this.log(`run_id:        ${result.run_id}`);
        this.log(`source:        ${result.source}`);
        this.log(`next action:   ${result.next_action}`);
      }
      return result;
    }
    let recovery: RecoveryResult;
    try {
      const { events, partialFinalLineDropped, corruptLines } = parseLedgerText(readFileSync(ledgerPath, "utf8"));
      recovery = recoverLedger(events, { partialFinalLineDropped, corruptLines });
    } catch (err) {
      this.error(`corrupt ledger: ${(err as Error).message}`, { exit: 4 });
    }
    if (!this.jsonEnabled()) {
      this.log(`run_state:     ${recovery.run_state}`);
      this.log(`integrity:     ${recovery.integrity_status}`);
      this.log(`last sequence: ${recovery.last_valid_sequence}`);
      this.log(`terminated:    ${recovery.terminated}`);
      if (recovery.findings.length > 0) {
        this.log("findings:");
        for (const f of recovery.findings) this.log(`  - ${f}`);
      }
    }
    if (recovery.integrity_status !== "valid") process.exitCode = 4;
    return { ...recovery, source: "ledger", ledger_path: ledgerPath };
  }
}
