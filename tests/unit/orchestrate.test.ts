import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  assembleRun,
  BriefShape,
  ClaudeAdapter,
  CodexAdapter,
  computeBriefHash,
  extractEvidence,
  type GateSpecInput,
} from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const loadJsonl = (p: string): unknown[] =>
  readFileSync(p, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l));

const codexEvents = new CodexAdapter().normalize(
  loadJsonl(join(here, "..", "fixtures", "adapter-events", "codex", "s1-codex-exec-json.redacted.jsonl")),
);
const claudeEvents = new ClaudeAdapter().normalize(
  loadJsonl(join(here, "..", "fixtures", "adapter-events", "claude-code", "s1-claude-stream-json.redacted.jsonl")),
);

const noT5: GateSpecInput = { id: "no-t5", blocking: true, inputs_required: [], waiver_allowed: false };
const baseInput = {
  run_id: "run_test01",
  loop_family: "minimal-bugfix",
  loopeix_version: "v001",
  started_at: "2026-01-01T00:00:00Z",
  gates: [noT5],
  risk_controls: { max_tier_without_approval: "T2", t5_allowed: false },
};

describe("assembleRun — end-to-end on real captured events", () => {
  for (const [name, r, engine] of [
    ["Codex", codexEvents, "codex_cli"],
    ["Claude", claudeEvents, "claude_code_cli"],
  ] as const) {
    describe(name, () => {
      const a = assembleRun({ ...baseInput, engine, events: r.events, capture_gaps: r.capture_gaps });
      it("seals a VALID hash-chained ledger (integrity valid, no findings)", () => {
        expect(a.integrity.integrity_status).toBe("valid");
        expect(a.integrity.findings).toEqual([]);
        expect(a.ledger.length).toBe(r.events.length + 3); // run.started + N + gate.result + terminal
      });
      it("evaluates no-t5 (PASS) and completes the run", () => {
        expect(a.gate_report.summary.pass).toBeGreaterThanOrEqual(1);
        expect(a.integrity.run_state).toBe("completed");
      });
      it("builds a 7-section Markdown report and an HTML timeline matching the ledger", () => {
        expect(a.report.sections).toHaveLength(7);
        expect(a.report.markdown).toContain("## Verified claims");
        expect(a.report.html).toContain("run.started"); // timeline lives in the HTML
        expect(a.report.html).toContain("run.completed");
      });
      it("produces a manifest whose integrity is derived valid", () => {
        expect(a.manifest.integrity_status).toBe("valid");
        expect(a.manifest.run_id).toBe("run_test01");
      });
      it("discloses the engine's capture gaps in the report", () => {
        // both engines have at least one partial capability
        expect(a.report.markdown).toContain("Capture gaps");
      });
    });
  }
});

describe("extractEvidence", () => {
  it("extracts command/file/tool_call events with pass/fail from exit codes; ignores non-evidence kinds", () => {
    const ev = extractEvidence([
      { source: "codex_cli", kind: "command", raw_type: "item.completed", payload: { exit_code: 0 } },
      { source: "codex_cli", kind: "command", raw_type: "item.completed", payload: { exit_code: 2 } },
      { source: "codex_cli", kind: "file_change", raw_type: "item.completed", payload: {} },
      { source: "codex_cli", kind: "message", raw_type: "item.completed", payload: {} }, // not evidence
    ]);
    expect(ev).toHaveLength(3);
    expect(ev[0]).toMatchObject({ type: "command", outcome: "pass", exit_code: 0 });
    expect(ev[1]).toMatchObject({ type: "command", outcome: "fail", exit_code: 2 });
    expect(ev[2]).toMatchObject({ type: "file" });
  });
});

describe("assembleRun — sealed brief (Claims Check M2)", () => {
  const brief = BriefShape.parse({
    brief_version: "0.1",
    task: "make the suite green",
    acceptance: [{ id: "tests-pass", label: "all tests pass", kind: "tests-pass" }],
    forbidden: [{ id: "no-test-deletion", label: "deleting tests", kind: "delete_paths", globs: ["tests/**"] }],
    scope: ["src/**"],
  });
  const base = { ...baseInput, engine: "codex_cli" as const, events: codexEvents.events, capture_gaps: codexEvents.capture_gaps };

  it("brief.sealed is ledger event 1 — BEFORE run.started — carrying { brief, brief_hash }", () => {
    const a = assembleRun({ ...base, brief });
    expect(a.ledger[0]?.event_type).toBe("brief.sealed");
    expect(a.ledger[0]?.sequence).toBe(1);
    expect(a.ledger[1]?.event_type).toBe("run.started");
    const payload = a.ledger[0]?.payload as { brief?: unknown; brief_hash?: string };
    expect(payload.brief).toEqual(brief);
    expect(payload.brief_hash).toBe(computeBriefHash(brief));
    expect(a.ledger.length).toBe(codexEvents.events.length + 4); // + brief.sealed
    expect(a.integrity.integrity_status).toBe("valid");
    expect(a.integrity.run_state).toBe("completed");
  });

  it("briefless run: explicit-undefined brief produces identical ledger to no-brief; no brief.sealed event; exactly +3 base events (no brief.sealed leakage)", () => {
    const a = assembleRun(base);
    const b = assembleRun({ ...base, brief: undefined });
    expect(b.ledger_text).toBe(a.ledger_text); // an explicit undefined brief changes nothing
    expect(a.ledger_text).not.toContain("brief.sealed");
    expect(a.ledger.length).toBe(codexEvents.events.length + 3); // exactly the pre-M2 shape
  });
});

describe("assembleRun — T5 is held, not silently completed", () => {
  it("a run that requests T5 fails no-t5, terminates run.held, and the ledger is still intact", () => {
    const a = assembleRun({
      ...baseInput,
      engine: "codex_cli",
      events: codexEvents.events,
      capture_gaps: codexEvents.capture_gaps,
      risk_controls: { max_tier_without_approval: "T2", t5_allowed: true }, // T5 requested
    });
    expect(a.gate_report.decisions.find((d) => d.gate_id === "no-t5")?.status).toBe("FAIL");
    expect(a.gate_report.blocking_hold_or_fail).toBe(true);
    expect(a.integrity.run_state).toBe("held"); // terminal event is run.held
    expect(a.integrity.integrity_status).toBe("valid"); // ledger intact — held by a gate, not corruption
    expect(a.manifest.run_state).toBe("held");
  });
});

describe("assembleRun — a failed live engine seals run.failed, not completed", () => {
  const withStatus = (engine_status: { exit_code: number; timed_out: boolean }) =>
    assembleRun({ ...baseInput, engine: "codex_cli", events: codexEvents.events, capture_gaps: codexEvents.capture_gaps, engine_status });

  it("non-zero exit → run.failed + a blocking engine finding (never completed)", () => {
    const a = withStatus({ exit_code: 1, timed_out: false });
    expect(a.integrity.run_state).toBe("failed");
    expect(a.manifest.run_state).toBe("failed");
    expect(a.report.markdown).toContain("did not complete cleanly");
  });
  it("timeout → run.failed", () => {
    expect(withStatus({ exit_code: 0, timed_out: true }).integrity.run_state).toBe("failed");
  });
  it("clean exit (0, no timeout) → completed as before", () => {
    expect(withStatus({ exit_code: 0, timed_out: false }).integrity.run_state).toBe("completed");
  });
});
