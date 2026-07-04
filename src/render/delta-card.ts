import type { ReceiptCheck } from "../receipt.js";
import type { Receipt } from "../schema/receipt.js";
import { gateReceipt, type RenderGateOptions } from "./shared.js";

/**
 * Delta Card renderer (delta-card-and-pr-spec.md §2): ONE static, self-contained SVG — viewBox
 * 1200×630 (og-image ratio), `#0d1117` background, `#30363d` border, ui-monospace stack, four
 * content rows SEALED / BROKE / CLAIMED / VERDICT, footer verify-pill + tagline.
 *
 * Hard rules (normative):
 *  - RENDERING GATE: same as the PR table — `verifyReceipt` first, no card for an unverified
 *    receipt, a failure block instead.
 *  - STATIC MARKUP ONLY: no `<script>`, no `<foreignObject>`, no external href/url() references of
 *    any kind. The only URL in the file is the SVG namespace declaration itself.
 *  - ESCAPING: all freeform text is XML-escaped (& < > " ') AFTER truncation, so an entity can
 *    never be cut in half and hostile labels can never become markup.
 *  - DETERMINISM: pure function of the receipt bytes — identical receipt → identical SVG bytes.
 *
 * TRUTHFULNESS DEVIATION FROM THE SPEC (deliberate, documented): the spec (written before the
 * "presence convicts; absence never acquits" doctrine of claim-families-v1.md) says the BROKE row
 * falls back to green "nothing — all promises kept" whenever no clause is broken. Under the v1
 * doctrine, absence of PROMISE_BROKEN does NOT prove promises were kept — containment clauses in
 * engine-stream/replay runs resolve UNEVALUATED. So:
 *  - green `nothing — all promises kept` renders ONLY when there is at least one clause and EVERY
 *    clause is KEPT (a positively-evidenced full keep);
 *  - otherwise (any UNEVALUATED, or no clauses at all) the row renders neutral
 *    `no broken promise recorded` in `#8b949e` — an honest statement about the record, not an
 *    acquittal the evidence cannot support.
 *
 * TRUNCATION (character budgets, documented per spec): values are single-line and ellipsized by
 * CODE-POINT count. The ui-monospace advance width is ≈0.62× the font size; the value column spans
 * x=250..1136 (886px), so at 28px (≈17.4px/char) 50 chars fit with margin. Header run-id gets 24
 * chars at 22px against its right-anchored slack. Newlines/whitespace collapse to single spaces
 * before truncation (single-line rule: never wrap, never overflow the viewBox).
 */

export interface RenderDeltaCardResult {
  ok: boolean;
  svg?: string;
  /** Markdown failure block (gate refused) — same content as the PR renderer's. */
  failure?: string;
  failedChecks?: ReceiptCheck[];
}

/** Colours (spec §2, GitHub-dark palette). */
const COLOR = {
  bg: "#0d1117",
  border: "#30363d",
  muted: "#8b949e",
  text: "#e6edf3",
  red: "#f85149",
  green: "#3fb950",
  amber: "#d29922",
  pill: "#161b22",
} as const;

/** Character budgets — see the truncation note in the module header. */
const VALUE_BUDGET = 50;
const HASH_BUDGET = 60;
const RUN_ID_BUDGET = 24;

const xmlEsc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");

/** Collapse to one line, then ellipsize at `budget` CODE POINTS. Escape AFTER calling this. */
function oneLine(s: string, budget: number): string {
  const flat = s.replace(/\s+/g, " ").trim();
  const points = Array.from(flat);
  return points.length <= budget ? flat : `${points.slice(0, budget - 1).join("")}…`;
}

/** Escaped, truncated, single-line text ready to interpolate into markup. */
const svgText = (s: string, budget: number = VALUE_BUDGET): string => xmlEsc(oneLine(s, budget));

interface RowSpec {
  label: string;
  value: string;
  color: string;
  /** Optional second, smaller line (SEALED uses it for the brief-hash prefix). */
  sub?: string;
}

/** BROKE row severity order when several clauses are broken: forbidden > scope > acceptance —
 *  a forbidden-action violation is always the headline. Ties keep receipt order. */
const CLAUSE_SEVERITY: Record<string, number> = { forbidden: 0, scope: 1, acceptance: 2 };

function brokeRow(receipt: Receipt): Pick<RowSpec, "value" | "color"> {
  const broken = receipt.brief_clauses
    .map((c, i) => ({ c, i }))
    .filter(({ c }) => c.verdict === "PROMISE_BROKEN")
    .sort((a, b) => (CLAUSE_SEVERITY[a.c.clause_type] ?? 3) - (CLAUSE_SEVERITY[b.c.clause_type] ?? 3) || a.i - b.i);
  const top = broken[0]?.c;
  if (top) {
    // Doctrine (gate-enforced): a PROMISE_BROKEN clause always cites at least one evidence id.
    return { value: `${top.text} — ${top.evidence_ids[0] ?? ""}`, color: COLOR.red };
  }
  const allKept = receipt.brief_clauses.length > 0 && receipt.brief_clauses.every((c) => c.verdict === "KEPT");
  return allKept
    ? { value: "nothing — all promises kept", color: COLOR.green }
    : { value: "no broken promise recorded", color: COLOR.muted }; // absence never acquits (see header)
}

const VERDICT_COLOR: Record<string, string> = {
  VERIFIED: COLOR.green,
  CONTRADICTED: COLOR.red,
  UNSUPPORTED: COLOR.amber,
};

/** Render the Delta Card SVG from an ALREADY-VERIFIED receipt. */
function svgFromReceipt(receipt: Receipt): string {
  // CLAIMED row: the headline agent claim — the first tests-ran claim if present, else the first
  // claim of any family; a claimless receipt states that neutrally and the VERDICT row renders `—`.
  const headline = receipt.claims.find((c) => c.family === "tests-ran") ?? receipt.claims[0];
  const broke = brokeRow(receipt);
  const digest = receipt.brief.brief_hash.replace(/^sha256:/, "");

  const rows: RowSpec[] = [
    {
      label: "SEALED",
      value: receipt.brief.task,
      color: COLOR.text,
      sub: `sha256:${digest.slice(0, 12)}…`,
    },
    { label: "BROKE", value: broke.value, color: broke.color },
    headline
      ? { label: "CLAIMED", value: `"${headline.text}"`, color: COLOR.text }
      : { label: "CLAIMED", value: "no agent claims recorded", color: COLOR.muted },
    headline
      ? {
          label: "VERDICT",
          value: `${headline.verdict}${headline.reason !== undefined && headline.reason !== "" ? ` — ${headline.reason}` : ""}`,
          color: VERDICT_COLOR[headline.verdict] ?? COLOR.muted,
        }
      : { label: "VERDICT", value: "—", color: COLOR.muted },
  ];

  const rowMarkup = rows
    .map((row, i) => {
      const y = 176 + i * 92; // four ~92px rows, first value baseline at y=176
      const sub =
        row.sub !== undefined
          ? `\n    <text x="250" y="${y + 28}" font-size="16" fill="${COLOR.muted}">${svgText(row.sub, HASH_BUDGET)}</text>`
          : "";
      return (
        `    <text x="64" y="${y}" font-size="20" letter-spacing="3" fill="${COLOR.muted}">${row.label}</text>\n` +
        `    <text x="250" y="${y}" font-size="28" fill="${row.color}">${svgText(row.value)}</text>` +
        sub
      );
    })
    .join("\n");

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630" role="img" aria-label="Loopeix Claims Check delta card">
  <rect x="0" y="0" width="1200" height="630" fill="${COLOR.bg}"/>
  <rect x="16.5" y="16.5" width="1167" height="597" rx="16" fill="none" stroke="${COLOR.border}" stroke-width="1"/>
  <g font-family="ui-monospace, SFMono-Regular, Menlo, monospace">
    <text x="64" y="84" font-size="22" letter-spacing="6" fill="${COLOR.muted}">LOOPEIX CLAIMS CHECK</text>
    <text x="1136" y="84" text-anchor="end" font-size="22" fill="${COLOR.muted}">${svgText(receipt.run.run_id, RUN_ID_BUDGET)}</text>
${rowMarkup}
    <rect x="64" y="516" width="470" height="52" rx="26" fill="${COLOR.pill}" stroke="${COLOR.border}" stroke-width="1"/>
    <text x="299" y="549" text-anchor="middle" font-size="20" fill="${COLOR.text}">npx loopeix verify receipt.json</text>
    <text x="1136" y="549" text-anchor="end" font-size="20" fill="${COLOR.muted}">receipts or it didn${"&apos;"}t happen.</text>
  </g>
</svg>
`;
}

/**
 * Render the Delta Card. Runs the rendering gate FIRST (optionally deep against `opts.ledgerText`);
 * an unverified receipt gets a failure block and NO svg. Deterministic bytes.
 */
export function renderDeltaCard(receiptJsonText: string, opts: RenderGateOptions = {}): RenderDeltaCardResult {
  const gate = gateReceipt(receiptJsonText, opts);
  if (!gate.ok) return { ok: false, failure: gate.failure, failedChecks: gate.failedChecks };
  return { ok: true, svg: svgFromReceipt(gate.receipt) };
}
