import { readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Args, Command, Flags } from "@oclif/core";
import { renderDeltaCard } from "../render/delta-card.js";
import { renderPrMarkdown, type PrModel } from "../render/pr.js";
import { gateReceipt, type RenderGateOptions } from "../render/shared.js";
import { RUN_DIR_FILES } from "../run/run-dir.js";

/**
 * `loopeix pr <receipt.json | run-dir>` — render a VERIFIED receipt as the PR verdict table
 * (delta-card-and-pr-spec.md §1), optionally alongside the Delta Card SVG (`--card`, spec §2's
 * chosen command surface: the card ships as a flag of `pr`, there is no separate `card` command).
 *
 * Verify-first, always: if the receipt does not verify, the command prints a single failure block
 * naming the failed checks and exits 1 — no table, no card, no partial output. A run-dir argument
 * turns on the DEEP gate (the run's ledger.jsonl is re-checked against the receipt's binding).
 * Unreadable input is a failed check, never a stack trace. Exit 0 = rendered; 1 = refused.
 */
export type PrCommandResult =
  | ({ ok: true } & PrModel)
  | { ok: false; failed_checks: { id: string; detail: string }[] };

export default class Pr extends Command {
  static summary = "Render a verified receipt as a PR-body verdict table (Markdown), plus an optional Delta Card SVG.";
  static description =
    "Completely offline — no network access, no GitHub permissions; the output is plain text you paste " +
    "(or a CI step writes) into the PR body. The receipt is verified FIRST (schema, invariants, doctrine, " +
    "signature; with a run-dir argument also the deep ledger binding): an unverified receipt gets a " +
    "failure block naming the failed checks and exit 1 — never a verdict table. " +
    "Exit 0 when rendered, 1 when the receipt did not verify or the input was unreadable.";
  static args = {
    input: Args.string({
      description: "path to a receipt.json, or a run directory containing receipt.json (+ ledger.jsonl for the deep check)",
      required: true,
    }),
  };
  static flags = {
    out: Flags.string({ description: "write the Markdown to a file instead of stdout" }),
    card: Flags.string({ description: "also write the Delta Card SVG to this path (e.g. delta-card.svg)" }),
  };
  static examples = [
    "<%= config.bin %> pr receipt.json",
    "<%= config.bin %> pr .loopeix/runs/run_abc123 --card delta-card.svg",
    "<%= config.bin %> pr receipt.json --out pr-comment.md --json",
  ];
  static enableJsonFlag = true;

  public async run(): Promise<PrCommandResult> {
    const { args, flags } = await this.parse(Pr);

    // Resolve the input: a directory means "run dir" (receipt.json + ledger.jsonl → deep gate).
    let receiptPath = args.input;
    let ledgerPath: string | undefined;
    try {
      if (statSync(args.input).isDirectory()) {
        receiptPath = join(args.input, RUN_DIR_FILES.receipt);
        ledgerPath = join(args.input, RUN_DIR_FILES.ledger);
      }
    } catch {
      // Missing path: fall through — the receipt read below fails the parse check, fail-closed.
    }

    let text = "";
    const opts: RenderGateOptions = {};
    try {
      text = readFileSync(receiptPath, "utf8");
    } catch (err) {
      opts.receiptError = (err as Error).message;
    }
    if (ledgerPath !== undefined) {
      try {
        opts.ledgerText = readFileSync(ledgerPath, "utf8");
      } catch (err) {
        opts.ledgerError = (err as Error).message;
      }
    }

    // Single gate call: verify once, then pass _preGated to both renderers so neither re-verifies.
    const gate = gateReceipt(text, opts);
    if (!gate.ok) {
      if (!this.jsonEnabled()) this.log(gate.failure ?? "receipt did not verify");
      process.exitCode = 1;
      return { ok: false, failed_checks: gate.failedChecks.map((c) => ({ id: c.id, detail: c.detail })) };
    }
    const preGatedOpts: RenderGateOptions = { ...opts, _preGated: gate.receipt };

    const rendered = renderPrMarkdown(text, preGatedOpts);
    if (!rendered.ok || rendered.markdown === undefined || rendered.model === undefined) {
      // Unreachable when _preGated is set — defensive fail-closed.
      process.exitCode = 1;
      return { ok: false, failed_checks: [] };
    }

    // Render the card BEFORE writing anything: either both artifacts render or nothing is written.
    let svg: string | undefined;
    if (flags.card !== undefined) {
      const card = renderDeltaCard(text, preGatedOpts);
      if (!card.ok || card.svg === undefined) {
        // Unreachable when _preGated is set — defensive fail-closed.
        process.exitCode = 1;
        return { ok: false, failed_checks: [] };
      }
      svg = card.svg;
    }

    try {
      if (flags.out !== undefined) writeFileSync(flags.out, rendered.markdown);
      if (flags.card !== undefined && svg !== undefined) writeFileSync(flags.card, svg);
    } catch (err) {
      this.log(`ERROR: cannot write output: ${(err as Error).message}`);
      process.exitCode = 1;
      return { ok: false, failed_checks: [{ id: "write", detail: (err as Error).message }] };
    }

    if (!this.jsonEnabled()) {
      if (flags.out === undefined) this.log(rendered.markdown);
      else this.log(`Wrote ${flags.out}`);
      if (flags.card !== undefined) this.log(`Wrote ${flags.card}`);
    }
    return { ok: true, ...rendered.model };
  }
}
