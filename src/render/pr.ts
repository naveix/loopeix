import { mdEsc } from "../report.js";
import type { ReceiptCheck } from "../receipt.js";
import type { Receipt, ReceiptSummaryRecord } from "../schema/receipt.js";
import { gateReceipt, type RenderGateOptions } from "./shared.js";

/**
 * PR-body verdict table renderer (delta-card-and-pr-spec.md §1). Plain Markdown the author pastes
 * (or a CI step writes) into the PR body — zero GitHub permissions by design.
 *
 * Discipline (normative, from the spec):
 *  - RENDERING GATE (rule 2): `verifyReceipt` runs FIRST via `gateReceipt`; on any failure the
 *    result carries the failure block instead of a table. Never a partial table.
 *  - FIXED GLYPHS (rule 1): ✅ VERIFIED/KEPT · 🟥 CONTRADICTED/PROMISE BROKEN · ⬜
 *    UNSUPPORTED/UNEVALUATED, always with the enum beside the glyph — never colour-only.
 *  - ORDERING (rule 4): condemning rows first, then UNSUPPORTED/UNEVALUATED, then VERIFIED/KEPT.
 *    Within a band: claims before clauses, each in receipt order (deterministic).
 *  - ESCAPING (rule 3): every freeform field goes through the repo `mdEsc` idiom. Identifier-ish
 *    fields render in code spans ONLY when they match a safe charset (backslash escapes do not
 *    work inside code spans), else they degrade to escaped plain text.
 *  - EVIDENCE (rule 5): above 4 cited ids, CONTIGUOUS numeric runs compress to `first…last`
 *    (`ev_002…ev_029`); non-contiguous ids stay listed. `—` renders only for an empty list, which
 *    the doctrine guarantees can never be a condemning verdict on a verified receipt.
 *
 * `brief_hash` prefix: the first 12 HEX chars of the digest (after the `sha256:` marker) + `…` —
 * enough to eyeball-match against `receipt.json` without pasting a full hash into prose.
 */

export type PrGlyph = "✅" | "🟥" | "⬜";

/** Ordering bands (rule 4): 0 = condemning (red), 1 = unsupported/unevaluated, 2 = verified/kept. */
export type PrBand = 0 | 1 | 2;

export interface PrRow {
  kind: "claim" | "clause";
  id: string;
  verdict: string;
  /** Enum rendered for humans: underscores become spaces (`PROMISE BROKEN`). */
  verdict_display: string;
  glyph: PrGlyph;
  band: PrBand;
  /** Raw (unescaped) claim/clause text; the Markdown layer escapes. */
  text: string;
  evidence_ids: string[];
  /** Raw (unescaped) reason, when the receipt carries one. */
  note?: string;
}

/** The render-model behind `--json` (spec §1 rule 6): rows in render order, ordering bands, counts. */
export interface PrModel {
  run: { run_id: string; engine: string; run_state: string; integrity_status: string };
  brief: { brief_hash: string; brief_hash_prefix: string; task: string };
  rows: PrRow[];
  counts: ReceiptSummaryRecord;
  capture_gaps: { engine: string; capability: string; level: string; note: string }[];
}

export interface RenderPrResult {
  ok: boolean;
  markdown?: string;
  model?: PrModel;
  /** Markdown failure block (gate refused): failed check ids + escaped details. */
  failure?: string;
  failedChecks?: ReceiptCheck[];
}

const GLYPH: Record<string, PrGlyph> = {
  VERIFIED: "✅",
  KEPT: "✅",
  CONTRADICTED: "🟥",
  PROMISE_BROKEN: "🟥",
  UNSUPPORTED: "⬜",
  UNEVALUATED: "⬜",
};

const BAND: Record<string, PrBand> = {
  CONTRADICTED: 0,
  PROMISE_BROKEN: 0,
  UNSUPPORTED: 1,
  UNEVALUATED: 1,
  VERIFIED: 2,
  KEPT: 2,
};

/** Code spans cannot carry backslash escapes, so only this charset may render inside backticks. */
const CODE_SAFE = /^[A-Za-z0-9_.:\-…]+$/;

/** Render in a code span when safe; otherwise degrade to escaped plain text (never a broken span). */
const codeSpan = (s: string): string => (CODE_SAFE.test(s) ? `\`${s}\`` : mdEsc(s));

/** True when `b` is the numeric successor of `a` under a shared prefix (ev_002 → ev_003). */
function isSuccessor(a: string, b: string): boolean {
  const ma = /^(.*_)(\d+)$/.exec(a);
  const mb = /^(.*_)(\d+)$/.exec(b);
  if (!ma || !mb || ma[1] !== mb[1]) return false;
  return Number(mb[2]) === Number(ma[2]) + 1;
}

/**
 * Evidence cell (rule 5). ≤4 ids: all listed. >4 ids: contiguous numeric runs of 3+ compress to
 * `first…last`; everything else stays listed. Compression only ever ELIDES ids that are provably
 * in-sequence — it never implies a range that is not actually contiguous in the citation list.
 */
export function compressEvidence(ids: readonly string[]): string {
  if (ids.length === 0) return "—";
  if (ids.length <= 4) return ids.map(codeSpan).join(", ");
  const parts: string[] = [];
  let i = 0;
  while (i < ids.length) {
    let j = i;
    while (j + 1 < ids.length && isSuccessor(ids[j]!, ids[j + 1]!)) j += 1;
    if (j - i >= 2) {
      const range = `${ids[i]!}…${ids[j]!}`;
      parts.push(CODE_SAFE.test(range) ? `\`${range}\`` : mdEsc(range));
    } else {
      for (let k = i; k <= j; k += 1) parts.push(codeSpan(ids[k]!));
    }
    i = j + 1;
  }
  return parts.join(", ");
}

/** Build the render-model from an ALREADY-VERIFIED receipt (rows band-ordered, red first). */
export function buildPrModel(receipt: Receipt): PrModel {
  const toRow = (kind: "claim" | "clause", id: string, verdict: string, text: string, evidence_ids: readonly string[], note?: string): PrRow => ({
    kind,
    id,
    verdict,
    verdict_display: verdict.replace(/_/g, " "),
    glyph: GLYPH[verdict] ?? "⬜",
    band: BAND[verdict] ?? 1,
    text,
    evidence_ids: [...evidence_ids],
    ...(note !== undefined ? { note } : {}),
  });

  const unordered: PrRow[] = [
    ...receipt.claims.map((c) => toRow("claim", c.claim_id, c.verdict, c.text, c.evidence_ids, c.reason)),
    ...receipt.brief_clauses.map((c) => toRow("clause", c.clause_id, c.verdict, c.text, c.evidence_ids, c.reason)),
  ];
  // Stable band sort: red first, then unsupported/unevaluated, then verified/kept; within a band
  // the claims-then-clauses receipt order above is preserved (Array.prototype.sort is stable).
  const rows = [...unordered].sort((a, b) => a.band - b.band);

  const digest = receipt.brief.brief_hash.replace(/^sha256:/, "");
  return {
    run: {
      run_id: receipt.run.run_id,
      engine: receipt.run.engine,
      run_state: receipt.run.run_state,
      integrity_status: receipt.run.integrity_status,
    },
    brief: {
      brief_hash: receipt.brief.brief_hash,
      brief_hash_prefix: `${digest.slice(0, 12)}…`,
      task: receipt.brief.task,
    },
    rows,
    counts: structuredClone(receipt.summary),
    capture_gaps: receipt.capture_gaps.map((g) => ({ ...g })),
  };
}

function markdownFromModel(model: PrModel): string {
  const lines: string[] = [];
  lines.push("### Loopeix Claims Check", "");
  lines.push(
    `**Run** ${codeSpan(model.run.run_id)} · engine ${codeSpan(model.run.engine)} · ` +
      `state **${mdEsc(model.run.run_state)}** · integrity **${mdEsc(model.run.integrity_status)}**`,
  );
  lines.push(`**Sealed brief** ${codeSpan(model.brief.brief_hash_prefix)} — ${mdEsc(model.brief.task)}`, "");

  lines.push("| Verdict | Claim / Clause | Evidence | Note |");
  lines.push("|---|---|---|---|");
  for (const row of model.rows) {
    const verdict = `${row.glyph} \`${row.verdict_display}\``;
    const note = row.note === undefined || row.note === "" ? "—" : mdEsc(row.note);
    lines.push(`| ${verdict} | ${mdEsc(row.text)} | ${compressEvidence(row.evidence_ids)} | ${note} |`);
  }
  lines.push("");

  const partial = model.capture_gaps.filter((g) => g.level !== "full");
  const gapsLine =
    partial.length === 0
      ? "none"
      : `${partial.length} partial (${partial.map((g) => `${mdEsc(g.engine)} ${mdEsc(g.capability)}`).join(", ")})`;
  lines.push(`**Capture gaps:** ${gapsLine}`);
  lines.push("**Receipt:** `receipt.json` (attached/committed) — verify offline:", "");
  lines.push("    npx loopeix verify receipt.json", "");
  lines.push("<sub>Receipts or it didn't happen. Loopeix records locally; only this signed receipt travels.</sub>");
  lines.push("");
  return lines.join("\n");
}

/**
 * Render the PR verdict table. Runs the rendering gate FIRST: if the receipt does not verify
 * (optionally deep against `opts.ledgerText`), no table is produced — `failure` carries the
 * failure block naming the failed checks. Deterministic: same receipt bytes → same Markdown bytes.
 */
export function renderPrMarkdown(receiptJsonText: string, opts: RenderGateOptions = {}): RenderPrResult {
  const gate = gateReceipt(receiptJsonText, opts);
  if (!gate.ok) return { ok: false, failure: gate.failure, failedChecks: gate.failedChecks };
  const model = buildPrModel(gate.receipt);
  return { ok: true, markdown: markdownFromModel(model), model };
}
