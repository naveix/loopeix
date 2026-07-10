import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { Args, Command } from "@oclif/core";
import { parseLedgerText, recoverLedger, type RecoveryResult } from "../../ledger.js";
import { ResolvedRunPlan } from "../../schema/runtime.js";

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
        next_action: `loopeix run start ${args.run} --engine ${shortEngine(engine)} --events-file <jsonl>`,
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
