import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { resolve } from "node:path";
import { Args, Command } from "@oclif/core";
import { parseLedgerText, recoverLedger, type RecoveryResult } from "../../ledger.js";
import {
  capturePlannedRunV02,
  consumeCapturedPlannedRunV02,
} from "../../run/capture-planned-v02.js";
import { presentPlannedRunV02, type PlannedRunPresentationV02 } from "../../run/present-planned-v02.js";

export type RunRecoverResult =
  | (RecoveryResult & { recoverable: boolean })
  | (PlannedRunPresentationV02 & {
      recoverable: false;
      integrity_status: "unknown";
      findings: [];
      run_dir: string;
    })
  | {
      recoverable: false;
      integrity_status: "invalid";
      findings: string[];
      run_dir: string;
      reason: "V02_RUN_LAYOUT_CONTAMINATED" | "INVALID_RESOLVED_RUN_PLAN_DOCUMENT";
    };

function resolveLedgerPath(p: string): string {
  if (existsSync(p) && statSync(p).isDirectory()) return join(p, "ledger.jsonl");
  return p;
}

/**
 * `loopeix run recover <run>` — assess whether an interrupted run can be recovered.
 * V1 is read-only: it reports integrity findings and a verdict; it does not rewrite history
 * (recovery events are written by later sprints). Exit 4 if the run is held/unrecoverable.
 */
export default class RunRecover extends Command {
  static summary = "Assess and report the recoverability of a run from its ledger (read-only in V1).";
  static args = {
    run: Args.string({ description: "run directory or ledger.jsonl path", required: true }),
  };
  static enableJsonFlag = true;

  public async run(): Promise<RunRecoverResult> {
    const { args } = await this.parse(RunRecover);
    const candidateRunDir = resolve(args.run);
    const directLedgerInput = !(existsSync(args.run) && statSync(args.run).isDirectory());
    if (!directLedgerInput) {
      const captured = await capturePlannedRunV02(candidateRunDir);
      if (captured.ok) {
        const value = consumeCapturedPlannedRunV02(captured.captured);
        if (value === null) {
          const result: RunRecoverResult = {
            recoverable: false,
            integrity_status: "invalid",
            findings: ["The captured V02 planned run could not be consumed safely."],
            run_dir: candidateRunDir,
            reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
          };
          process.exitCode = 4;
          return result;
        }
        const result: RunRecoverResult = {
          ...presentPlannedRunV02(value.plan),
          recoverable: false,
          integrity_status: "unknown",
          findings: [],
          run_dir: candidateRunDir,
        };
        if (!this.jsonEnabled()) {
          this.log("verdict:    HOLD — V02 execution is not available in S35");
          this.log(`reason:     ${result.reason}`);
        }
        process.exitCode = 1;
        return result;
      }
      if (captured.reason !== "NOT_V02_PLANNED_RUN") {
        const result: RunRecoverResult = {
          recoverable: false,
          integrity_status: "invalid",
          findings: [captured.message],
          run_dir: candidateRunDir,
          reason: captured.reason === "V02_RUN_LAYOUT_CONTAMINATED"
            ? "V02_RUN_LAYOUT_CONTAMINATED"
            : "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
        };
        if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
        process.exitCode = 4;
        return result;
      }
    }
    const ledgerPath = resolveLedgerPath(args.run);
    if (!existsSync(ledgerPath)) {
      this.error(`ledger not found: ${ledgerPath}`, { exit: 2 });
    }
    let recovery: RecoveryResult;
    try {
      const { events, partialFinalLineDropped, corruptLines } = parseLedgerText(readFileSync(ledgerPath, "utf8"));
      recovery = recoverLedger(events, { partialFinalLineDropped, corruptLines });
    } catch (err) {
      this.error(`corrupt ledger (unrecoverable): ${(err as Error).message}`, { exit: 4 });
    }
    const recoverable = recovery.integrity_status === "valid";
    if (!this.jsonEnabled()) {
      this.log(`run_state:  ${recovery.run_state}`);
      this.log(`integrity:  ${recovery.integrity_status}`);
      this.log(`verdict:    ${recoverable ? "recoverable — chain and content verified" : "HOLD — needs review before continuing"}`);
      if (recovery.findings.length > 0) {
        this.log("findings:");
        for (const f of recovery.findings) this.log(`  - ${f}`);
      }
    }
    if (!recoverable) process.exitCode = 4;
    return { ...recovery, recoverable };
  }
}
