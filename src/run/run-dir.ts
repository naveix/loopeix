import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseLedgerText, recoverLedger } from "../ledger.js";
import { buildReport, type Report, type ReportInput } from "../report.js";
import type { RunAssembly } from "./orchestrate.js";

/** Canonical file names inside a run directory (.loopspec/runs/<run-id>/). */
export const RUN_DIR_FILES = {
  ledger: "ledger.jsonl",
  manifest: "manifest.json",
  reportMd: "report.md",
  reportHtml: "report.html",
  reportInput: "report-input.json",
  runSummary: "run.json",
} as const;

/** Persist a full run assembly to a run directory (created if needed). */
export function writeRunDir(dir: string, a: RunAssembly): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, RUN_DIR_FILES.ledger), a.ledger_text);
  writeFileSync(join(dir, RUN_DIR_FILES.manifest), `${JSON.stringify(a.manifest, null, 2)}\n`);
  writeFileSync(join(dir, RUN_DIR_FILES.reportMd), a.report.markdown);
  writeFileSync(join(dir, RUN_DIR_FILES.reportHtml), a.report.html);
  writeFileSync(join(dir, RUN_DIR_FILES.reportInput), `${JSON.stringify(a.report_input, null, 2)}\n`);
  writeFileSync(
    join(dir, RUN_DIR_FILES.runSummary),
    `${JSON.stringify({ run_id: a.run_id, integrity: a.integrity, gate_report: a.gate_report, evidence: a.evidence }, null, 2)}\n`,
  );
}

/**
 * Rebuild the Markdown + HTML report from a run dir's persisted report input, and rewrite them.
 * This is what `loopspec report build <run-dir>` calls.
 *
 * The report's trust-critical status (`run_state`, `integrity_status`) is ANCHORED to the SEALED
 * ledger, not to the (unauthenticated) `report-input.json` sidecar: they are re-derived by recovering
 * `ledger.jsonl`, so a tampered or stale sidecar cannot render a report that claims a completed/valid
 * run when the sealed ledger says held/hold. Any divergence is disclosed in the report's limitations.
 * (V1 note: `evidence.verified` is always empty; when the evidence layer produces verified claims,
 * they too must be re-derived here rather than trusted from the sidecar.)
 */
export function buildReportFromRunDir(dir: string): Report {
  const input = JSON.parse(readFileSync(join(dir, RUN_DIR_FILES.reportInput), "utf8")) as ReportInput;
  const parsed = parseLedgerText(readFileSync(join(dir, RUN_DIR_FILES.ledger), "utf8"));
  const recovery = recoverLedger(parsed.events, {
    partialFinalLineDropped: parsed.partialFinalLineDropped,
    corruptLines: parsed.corruptLines,
  });

  const limitations = [...(input.redaction?.limitations ?? [])];
  if (input.run_state !== recovery.run_state || input.integrity_status !== recovery.integrity_status) {
    limitations.push(
      `report-input.json diverged from the sealed ledger (input: run_state=${input.run_state}/integrity=${input.integrity_status}; ledger: run_state=${recovery.run_state}/integrity=${recovery.integrity_status}); using the ledger's authoritative values.`,
    );
  }

  const anchored: ReportInput = {
    ...input,
    run_state: recovery.run_state,
    integrity_status: recovery.integrity_status,
    redaction: {
      policy_version: input.redaction?.policy_version ?? "0.1",
      quarantined: input.redaction?.quarantined ?? 0,
      raw_excluded: input.redaction?.raw_excluded ?? false,
      limitations,
    },
  };

  const report = buildReport(anchored);
  writeFileSync(join(dir, RUN_DIR_FILES.reportMd), report.markdown);
  writeFileSync(join(dir, RUN_DIR_FILES.reportHtml), report.html);
  return report;
}

/** Absolute-ish path to a run dir's HTML report (what `loopspec report open <run-dir>` opens). */
export function reportHtmlPath(dir: string): string {
  return join(dir, RUN_DIR_FILES.reportHtml);
}
