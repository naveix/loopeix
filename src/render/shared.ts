import { verifyReceipt, type ReceiptCheck, type VerifyReceiptOptions } from "../receipt.js";
import { ReceiptShape, type Receipt } from "../schema/receipt.js";
import { mdEsc } from "../report.js";

/**
 * The RENDERING GATE shared by both M3 renderers (delta-card-and-pr-spec.md §1 rule 2, §2 rule 3).
 *
 * Both the PR verdict table and the Delta Card are VIEWS over a verified receipt: they render only
 * what `verifyReceipt` has passed and compute nothing themselves. If any check fails, NO table and
 * NO card are produced — instead a single failure block names the failed checks. A pretty artifact
 * over an unverified receipt would be the exact dishonesty this product exists to kill.
 *
 * Options mirror `VerifyReceiptOptions` (including `receiptError`/`ledgerError`) so callers that
 * read files — the `pr` command — can delegate ALL fail-closed handling to the verifier: an
 * unreadable receipt or ledger FAILS the corresponding check, it never skips it.
 */

export interface RenderGateOptions {
  /** Ledger JSONL text: providing it turns on the deep ledger checks (same as `verify --run-dir`). */
  ledgerText?: string;
  /** A deep check was requested but the ledger could not be read: the ledger checks fail. */
  ledgerError?: string;
  /** The receipt file itself could not be read: the parse check fails (text is ignored). */
  receiptError?: string;
  /**
   * @internal Command-layer single-gate reuse only. The `pr` command calls `gateReceipt` once,
   * then passes the already-verified receipt here so both `renderPrMarkdown` and `renderDeltaCard`
   * skip a second full verify call. Never use this to bypass the gate from outside the command layer.
   */
  _preGated?: Receipt;
}

export type RenderGateResult =
  | { ok: true; receipt: Receipt; checks: ReceiptCheck[] }
  | { ok: false; failedChecks: ReceiptCheck[]; failure: string };

/**
 * The Markdown failure block emitted instead of a table/card when the gate refuses.
 * Check details pass through `mdEsc` — a hostile receipt can surface bytes of itself inside
 * verifier details (e.g. `JSON.parse` error snippets), and those must render inert too.
 */
export function buildFailureBlock(failedChecks: readonly ReceiptCheck[]): string {
  const lines: string[] = [];
  lines.push("### Loopeix Claims Check — receipt NOT verified", "");
  lines.push("No verdict table or card can be rendered: this receipt failed offline verification,");
  lines.push("and rendering verdicts from an unverified receipt would be dishonest.", "");
  lines.push("Failed checks:", "");
  for (const c of failedChecks) lines.push(`- \`${c.id}\` — ${mdEsc(c.detail)}`);
  lines.push("", "Run the full check list offline:", "", "    npx loopeix verify receipt.json", "");
  return lines.join("\n");
}

/** Run the gate: verify first, then (and only then) hand back the typed receipt. */
export function gateReceipt(receiptJsonText: string, opts: RenderGateOptions = {}): RenderGateResult {
  // Single-gate reuse: if a pre-verified receipt was passed by the `pr` command layer, skip the
  // verifier entirely — it already ran once for this invocation and approved this exact receipt.
  if (opts._preGated !== undefined) return { ok: true, receipt: opts._preGated, checks: [] };

  const verifyOpts: VerifyReceiptOptions = {};
  if (opts.ledgerText !== undefined) verifyOpts.ledgerText = opts.ledgerText;
  if (opts.ledgerError !== undefined) verifyOpts.ledgerError = opts.ledgerError;
  if (opts.receiptError !== undefined) verifyOpts.receiptError = opts.receiptError;

  const result = verifyReceipt(receiptJsonText, verifyOpts);
  if (!result.ok) {
    const failedChecks = result.checks.filter((c) => !c.ok);
    return { ok: false, failedChecks, failure: buildFailureBlock(failedChecks) };
  }
  // The schema check passed, so this parse cannot fail; the throw is a defensive invariant.
  const parsed = ReceiptShape.safeParse(JSON.parse(receiptJsonText));
  if (!parsed.success) throw new Error("rendering gate invariant broken: verified receipt failed to re-parse");
  return { ok: true, receipt: parsed.data, checks: result.checks };
}
