import type { CaptureGap, EngineId, NormalizedEvent } from "../adapters/index.js";
import { evaluateGates, type GateReport, type GateSpecInput } from "../gates.js";
import {
  appendToLedger,
  recoverLedger,
  serializeLedger,
  type LedgerEventDraft,
  type RecoveryResult,
  type SealedLedgerEvent,
} from "../ledger.js";
import { buildRunManifest } from "../manifest.js";
import { buildReport, type Report, type ReportInput } from "../report.js";
import { IsoTimestamp } from "../schema/scalars.js";
import type { RunManifestRecord } from "../schema/runtime.js";

/**
 * Run orchestration (the run-execution layer's core). Given a resolved spec + the normalized event
 * stream from an engine adapter, it seals a hash-chained ledger, derives integrity, evaluates gates,
 * extracts evidence, and builds a truthful report + manifest — the exact chain the CLI `loopspec run`
 * wires. It is engine-agnostic and pure (no I/O, no live calls), so it is fully fixture-testable.
 *
 * V1 honesty: claim↔evidence linkage is NOT auto-derived (which command proves which acceptance
 * check is loop-specific), so captured evidence is recorded but no claim is auto-marked verified —
 * the report lists evidence and states this limitation rather than fabricating verification.
 */

/** Normalized kinds that constitute evidence, mapped to an EvidenceItem type. */
const EVIDENCE_KIND_TO_TYPE: Record<string, string> = {
  command: "command",
  file_change: "file",
  tool_call: "tool_call",
};

export interface ExtractedEvidence {
  evidence_id: string;
  type: string;
  raw_type: string;
  outcome?: "pass" | "fail";
  exit_code?: number;
}

export function extractEvidence(events: readonly NormalizedEvent[]): ExtractedEvidence[] {
  const out: ExtractedEvidence[] = [];
  for (const e of events) {
    const type = EVIDENCE_KIND_TO_TYPE[e.kind];
    if (!type) continue;
    const p = (e.payload ?? {}) as Record<string, unknown>;
    const exit_code = typeof p.exit_code === "number" ? p.exit_code : undefined;
    const outcome = exit_code === 0 ? "pass" : typeof exit_code === "number" ? "fail" : undefined;
    out.push({
      evidence_id: `ev_${String(out.length + 1).padStart(4, "0")}`,
      type,
      raw_type: e.raw_type,
      ...(outcome !== undefined ? { outcome } : {}),
      ...(exit_code !== undefined ? { exit_code } : {}),
    });
  }
  return out;
}

export interface RunInput {
  run_id: string; // MachineId, e.g. run_abc123
  loop_family: string;
  loopspec_version: string;
  started_at: string; // ISO UTC, e.g. 2026-01-01T00:00:00Z
  engine: EngineId;
  events: readonly NormalizedEvent[];
  capture_gaps: readonly CaptureGap[];
  gates: readonly GateSpecInput[];
  risk_controls: { max_tier_without_approval: string; t5_allowed: boolean };
  tool_grant_tiers?: readonly string[];
  workspace_root?: string;
  run_dir?: string;
}

export interface RunAssembly {
  run_id: string;
  ledger: SealedLedgerEvent[];
  ledger_text: string;
  integrity: RecoveryResult;
  gate_report: GateReport;
  evidence: ExtractedEvidence[];
  report: Report;
  report_input: ReportInput;
  manifest: RunManifestRecord;
}

export function assembleRun(input: RunInput): RunAssembly {
  IsoTimestamp.parse(input.started_at); // fail fast + clearly on a malformed timestamp
  const base = Date.parse(input.started_at);
  const tsAt = (i: number): string => new Date(base + i * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

  const evidence = extractEvidence(input.events);

  const gate_report = evaluateGates({
    gates: input.gates,
    risk_controls: input.risk_controls,
    tool_grant_tiers: input.tool_grant_tiers,
    available_inputs: evidence.map((e) => e.evidence_id),
  });

  // Seal the ledger: run.started → one event per normalized event → gate.result per decision → terminal.
  const ledger: SealedLedgerEvent[] = [];
  const addEvent = (event_type: string, source: LedgerEventDraft["source"], payload: Record<string, unknown>): void => {
    const draft: LedgerEventDraft = {
      schema_version: "0.1",
      event_id: `evt_${String(ledger.length + 1).padStart(4, "0")}`,
      run_id: input.run_id,
      timestamp: tsAt(ledger.length),
      event_type,
      source,
      actor_id: null,
      task_run_id: null,
      risk_tier: "T1",
      payload,
      related_ids: [],
    };
    ledger.push(appendToLedger(ledger, draft));
  };

  addEvent("run.started", "loopspec", { engine: input.engine });
  for (const e of input.events) addEvent(e.kind, e.source, (e.payload ?? {}) as Record<string, unknown>);
  for (const d of gate_report.decisions) {
    addEvent("gate.result", "loopspec", { gate_id: d.gate_id, status: d.status, blocking: d.blocking });
  }
  const terminal = gate_report.blocking_hold_or_fail ? "run.held" : "run.completed";
  addEvent(terminal, "loopspec", {});

  const ledger_text = serializeLedger(ledger);
  const integrity = recoverLedger(ledger);

  const reportInput: ReportInput = {
    run_id: input.run_id,
    loop_family: input.loop_family,
    loopspec_version: input.loopspec_version,
    run_state: integrity.run_state,
    integrity_status: integrity.integrity_status,
    // V1: no auto claim↔evidence linkage → no auto-verified claims (see module note).
    evidence: { verified: [], unverified: [], claims: [] },
    capture_gaps: input.capture_gaps.map((g) => ({
      engine: input.engine,
      capability: g.capability,
      level: g.level,
      note: g.note,
    })),
    waivers: [],
    findings: [],
    redaction: {
      policy_version: "0.1",
      quarantined: 0,
      raw_excluded: false,
      limitations: [
        `Captured ${evidence.length} evidence item(s); claim↔evidence linkage is manual in V1 (evidence is listed, not auto-verified against claims).`,
      ],
    },
    timeline: ledger.map((e) => ({ sequence: e.sequence, event_type: e.event_type, timestamp: e.timestamp })),
  };
  const report = buildReport(reportInput);

  const manifest = buildRunManifest({
    run_id: input.run_id,
    loop_family: input.loop_family,
    loopspec_version: input.loopspec_version,
    workspace_root: input.workspace_root ?? ".",
    run_dir: input.run_dir ?? `.loopspec/runs/${input.run_id}`,
    created_at: input.started_at,
    updated_at: tsAt(ledger.length),
    events: ledger,
    file_inventory: [],
  });

  return { run_id: input.run_id, ledger, ledger_text, integrity, gate_report, evidence, report, report_input: reportInput, manifest };
}
