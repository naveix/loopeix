import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { Args, Command } from "@oclif/core";
import { parseLedgerText, recoverLedger, type RecoveryResult } from "../../ledger.js";

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

  public async run(): Promise<RecoveryResult & { recoverable: boolean }> {
    const { args } = await this.parse(RunRecover);
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
