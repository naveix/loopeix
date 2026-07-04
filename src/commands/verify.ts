import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Args, Command, Flags } from "@oclif/core";
import { verifyReceipt, type VerifyReceiptOptions, type VerifyReceiptResult } from "../receipt.js";
import { RUN_DIR_FILES } from "../run/run-dir.js";

/**
 * `loopeix verify <receipt>` — verify a signed receipt, completely offline.
 * One line per check (PASS/FAIL + detail), then a final VERIFIED / NOT VERIFIED line.
 * Exit 0 when every check passes, 1 when any check fails; an unreadable or missing
 * file is a `parse` check failure (never a stack trace).
 */
export default class Verify extends Command {
  static summary = "Verify a signed Loopeix receipt offline (schema, invariants, doctrine, signature).";
  static description =
    "Completely offline — no network access, no account, no server. Checks the receipt's schema, " +
    "cross-field invariants, the conservative-verdict doctrine (CONTRADICTED/PROMISE_BROKEN must cite " +
    "evidence), and the embedded ECDSA P-256 signature. With --run-dir, additionally re-derives the " +
    "ledger binding from the run's ledger.jsonl (bytes hash, chain head, full chain integrity). " +
    "Exit 0 if every check passes, 1 if any check fails.";
  static args = {
    receipt: Args.string({ description: "path to the receipt JSON file", required: true }),
  };
  static flags = {
    "run-dir": Flags.string({
      description: "run directory containing ledger.jsonl, for the deep ledger check",
    }),
  };
  static examples = [
    "<%= config.bin %> verify receipt.json",
    "<%= config.bin %> verify receipt.json --run-dir .loopeix/runs/run_abc123",
  ];
  static enableJsonFlag = true;

  public async run(): Promise<VerifyReceiptResult> {
    const { args, flags } = await this.parse(Verify);

    let text = "";
    const opts: VerifyReceiptOptions = {};
    try {
      text = readFileSync(args.receipt, "utf8");
    } catch (err) {
      opts.receiptError = (err as Error).message;
    }
    const runDir = flags["run-dir"];
    if (runDir !== undefined) {
      try {
        opts.ledgerText = readFileSync(join(runDir, RUN_DIR_FILES.ledger), "utf8");
      } catch (err) {
        opts.ledgerError = (err as Error).message;
      }
    }

    const result = verifyReceipt(text, opts);

    if (!this.jsonEnabled()) {
      for (const c of result.checks) this.log(`${c.ok ? "PASS" : "FAIL"}  ${c.id}: ${c.detail}`);
      const failed = result.checks.filter((c) => !c.ok).length;
      this.log(result.ok ? `VERIFIED  ${args.receipt}` : `NOT VERIFIED  ${args.receipt} (${failed} check${failed === 1 ? "" : "s"} failed)`);
    }
    if (!result.ok) process.exitCode = 1;
    return result;
  }
}
