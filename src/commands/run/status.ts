import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { Args, Command } from "@oclif/core";
import { parseLedgerText, recoverLedger, type RecoveryResult } from "../../ledger.js";

function resolveLedgerPath(p: string): string {
  if (existsSync(p) && statSync(p).isDirectory()) return join(p, "ledger.jsonl");
  return p;
}

/** `loopspec run status <run>` — show a run's state, integrity, and findings. */
export default class RunStatus extends Command {
  static summary = "Show a run's state, integrity, and findings from its ledger.";
  static description = "Reads the run's ledger.jsonl, recovers it, and reports. Exit 4 if integrity is not valid.";
  static args = {
    run: Args.string({ description: "run directory or ledger.jsonl path", required: true }),
  };
  static enableJsonFlag = true;

  public async run(): Promise<RecoveryResult> {
    const { args } = await this.parse(RunStatus);
    const ledgerPath = resolveLedgerPath(args.run);
    if (!existsSync(ledgerPath)) {
      this.error(`ledger not found: ${ledgerPath}`, { exit: 2 });
    }
    let recovery: RecoveryResult;
    try {
      const { events, partialFinalLineDropped } = parseLedgerText(readFileSync(ledgerPath, "utf8"));
      recovery = recoverLedger(events, { partialFinalLineDropped });
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
    return recovery;
  }
}
