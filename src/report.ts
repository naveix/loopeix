/**
 * Local report builder (architecture-plan.md §Report Builder, schema-evidence-gates.md §Report Rule,
 * redaction-retention-policy.md §Report Rule).
 *
 * Every report MUST include: verified claims, unverified claims, capture gaps, waivers, unresolved
 * findings, redaction/retention state, and known limitations. Sections are always emitted (empty →
 * an explicit "None"), so a reader can never mistake omission for absence. The Markdown is truthful
 * by construction — the verified section is exactly the evidence verifier's verified set. BOTH output
 * formats escape freeform values (HTML via `esc`, Markdown via `mdEsc`) so a hostile field cannot
 * corrupt a required disclosure, inject structure, or add a network reference. Output is static.
 */

export interface ReportInput {
  run_id: string;
  loop_family: string;
  loopspec_version: string;
  run_state: string;
  integrity_status: string;
  evidence: {
    verified: readonly string[];
    unverified: readonly string[];
    claims: readonly { claim_id: string; strength: string; resolved_status: string }[];
  };
  capture_gaps: readonly { engine: string; capability: string; level: string; note: string }[];
  waivers: readonly { gate_id: string; approver: string }[];
  findings: readonly { finding_id: string; title: string; classification: string; severity: string }[];
  redaction: { policy_version: string; quarantined: number; raw_excluded: boolean; limitations: readonly string[] };
  timeline: readonly { sequence: number; event_type: string; timestamp: string }[];
}

export interface Report {
  markdown: string;
  html: string;
  /** Section titles actually present in the rendered Markdown, in order (derived, not assumed). */
  sections: string[];
}

const REQUIRED_SECTIONS = [
  "Verified claims",
  "Unverified claims",
  "Capture gaps",
  "Waivers",
  "Unresolved findings",
  "Redaction and retention state",
  "Known limitations",
] as const;

const esc = (s: string): string =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/**
 * Neutralize freeform text for Markdown: collapse newlines (no structural line/heading injection) and
 * escape table/link/code/HTML metacharacters so `|`, `![](url)`, `` ` ``, and `<...>` render inert.
 */
const mdEsc = (s: string): string =>
  String(s)
    .replace(/\r?\n+/g, " ")
    .replace(/([`|[\]<>])/g, "\\$1");

const arr = <T>(v: readonly T[] | undefined): readonly T[] => (Array.isArray(v) ? v : []);

function markdown(input: ReportInput): string {
  const lines: string[] = [];
  const gaps = arr(input.capture_gaps);
  const waivers = arr(input.waivers);
  const findings = arr(input.findings);
  const verified = arr(input.evidence?.verified);
  const unverified = arr(input.evidence?.unverified);
  const redaction = input.redaction ?? { policy_version: "unknown", quarantined: 0, raw_excluded: false, limitations: [] };
  const limitations = arr(redaction.limitations);

  lines.push(`# LoopSpec Run Report — ${mdEsc(input.loop_family)}`, "");
  lines.push(`- Run: \`${mdEsc(input.run_id)}\``);
  lines.push(`- Version: \`${mdEsc(input.loopspec_version)}\``);
  lines.push(`- Run state: **${mdEsc(input.run_state)}**`);
  lines.push(`- Integrity: **${mdEsc(input.integrity_status)}**`, "");

  lines.push("## Verified claims", "");
  if (verified.length === 0) lines.push("None.");
  else for (const id of verified) lines.push(`- \`${mdEsc(id)}\``);
  lines.push("");

  lines.push("## Unverified claims", "");
  if (unverified.length === 0) lines.push("None.");
  else for (const id of unverified) lines.push(`- \`${mdEsc(id)}\` (unverified — not backed by independent evidence)`);
  lines.push("");

  lines.push("## Capture gaps", "");
  const partial = gaps.filter((g) => g.level !== "full");
  if (partial.length === 0) lines.push("None recorded.");
  else {
    lines.push("| Engine | Capability | Level | Note |", "|---|---|---|---|");
    for (const g of partial) lines.push(`| ${mdEsc(g.engine)} | ${mdEsc(g.capability)} | ${mdEsc(g.level)} | ${mdEsc(g.note)} |`);
  }
  lines.push("");

  lines.push("## Waivers", "");
  if (waivers.length === 0) lines.push("None.");
  else for (const w of waivers) lines.push(`- \`${mdEsc(w.gate_id)}\` — approved by ${mdEsc(w.approver)}`);
  lines.push("");

  lines.push("## Unresolved findings", "");
  const unresolved = findings.filter((f) => f.classification === "blocking");
  if (unresolved.length === 0) lines.push("None blocking.");
  else for (const f of unresolved) lines.push(`- \`${mdEsc(f.finding_id)}\` [${mdEsc(f.severity)}] ${mdEsc(f.title)}`);
  if (findings.length > unresolved.length) {
    lines.push("", "Other (non-blocking):");
    for (const f of findings.filter((f) => f.classification !== "blocking"))
      lines.push(`- \`${mdEsc(f.finding_id)}\` [${mdEsc(f.classification)}/${mdEsc(f.severity)}] ${mdEsc(f.title)}`);
  }
  lines.push("");

  lines.push("## Redaction and retention state", "");
  lines.push(`- Redaction policy version: \`${mdEsc(redaction.policy_version)}\`.`);
  lines.push(`- Quarantined artifacts: ${Number(redaction.quarantined) || 0}.`);
  lines.push(`- Raw evidence excluded from this report: ${redaction.raw_excluded ? "yes" : "no"}.`);
  lines.push(`- Known redaction limitations: ${limitations.length === 0 ? "none" : limitations.map(mdEsc).join("; ")}.`);
  lines.push(`- Adapter capture gaps: ${partial.length === 0 ? "none" : `${partial.length} partial (see Capture gaps above)`}.`);
  lines.push("");

  lines.push("## Known limitations", "");
  lines.push("- Identifiers, hashes, and timestamps may be normalized placeholders in fixtures.");
  lines.push("- Adapter capture gaps above bound what can be claimed as verified.");
  lines.push("");

  return lines.join("\n");
}

function html(input: ReportInput): string {
  const items = arr(input.timeline)
    .map(
      (e) =>
        `    <li><span class="seq">${String(e.sequence).padStart(2, "0")}</span> <span class="type">${esc(e.event_type)}</span> <span class="ts">${esc(e.timestamp)}</span></li>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LoopSpec Timeline — ${esc(input.run_id)}</title>
  <style>
    body { font: 14px/1.5 system-ui, sans-serif; margin: 2rem; color: #111; background: #fff; }
    h1 { font-size: 1.25rem; }
    .meta { color: #555; margin-bottom: 1rem; }
    ol { list-style: none; padding-left: 0; border-left: 2px solid #ccc; }
    li { position: relative; padding: 0.5rem 0 0.5rem 1rem; }
    li::before { content: ""; position: absolute; left: -0.4rem; top: 0.9rem; width: 0.6rem; height: 0.6rem; border-radius: 50%; background: #333; }
    .seq { color: #888; font-variant-numeric: tabular-nums; }
    .type { font-weight: 600; }
    .ts { color: #888; }
    footer { margin-top: 1.5rem; color: #888; font-size: 12px; }
  </style>
</head>
<body>
  <h1>LoopSpec Timeline</h1>
  <div class="meta">Run <code>${esc(input.run_id)}</code> &middot; ${esc(input.loop_family)} &middot; state <strong>${esc(input.run_state)}</strong> &middot; integrity <strong>${esc(input.integrity_status)}</strong></div>
  <ol>
${items}
  </ol>
  <footer>Static timeline. No scripts, no network calls.</footer>
</body>
</html>
`;
}

export function buildReport(input: ReportInput): Report {
  const md = markdown(input);
  // Derive the section list from what was actually rendered, so the contract check cannot lie.
  const sections = [...md.matchAll(/^## (.+)$/gm)].map((m) => m[1]!);
  return { markdown: md, html: html(input), sections };
}

/**
 * Report-truthfulness gate (unwaivable). A report may not assert a claim as verified that the
 * evidence verifier did not verify. Exact set membership — any mismatch (case/whitespace/typo) fails
 * toward HOLD, never a false PASS. Returns HOLD with the over-claimed ids if it over-claims.
 */
export function checkReportTruthfulness(input: {
  reported_verified: readonly string[];
  evidence_verified: readonly string[];
}): { status: "PASS" | "HOLD"; over_claimed: string[] } {
  const backed = new Set(input.evidence_verified);
  const over_claimed = input.reported_verified.filter((c) => !backed.has(c));
  return { status: over_claimed.length === 0 ? "PASS" : "HOLD", over_claimed };
}
