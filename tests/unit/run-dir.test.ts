import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  assembleRun,
  buildReportFromRunDir,
  CodexAdapter,
  reportHtmlPath,
  RUN_DIR_FILES,
  writeRunDir,
  type GateSpecInput,
} from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const events = new CodexAdapter().normalize(
  readFileSync(join(here, "..", "fixtures", "adapter-events", "codex", "s1-codex-exec-json.redacted.jsonl"), "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l)),
);
const noT5: GateSpecInput = { id: "no-t5", blocking: true, inputs_required: [], waiver_allowed: false };
const assembly = assembleRun({
  run_id: "run_test01",
  loop_family: "minimal-bugfix",
  loopspec_version: "v001",
  started_at: "2026-01-01T00:00:00Z",
  engine: "codex_cli",
  events: events.events,
  capture_gaps: events.capture_gaps,
  gates: [noT5],
  risk_controls: { max_tier_without_approval: "T2", t5_allowed: false },
});

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "loopspec-run-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("writeRunDir + report build/open wiring", () => {
  it("writes every canonical run-dir file", () => {
    writeRunDir(dir, assembly);
    for (const name of Object.values(RUN_DIR_FILES)) expect(existsSync(join(dir, name))).toBe(true);
  });
  it("the persisted ledger and manifest are the assembled ones", () => {
    writeRunDir(dir, assembly);
    expect(readFileSync(join(dir, RUN_DIR_FILES.ledger), "utf8")).toBe(assembly.ledger_text);
    expect(JSON.parse(readFileSync(join(dir, RUN_DIR_FILES.manifest), "utf8")).run_id).toBe("run_test01");
  });
  it("buildReportFromRunDir rebuilds a 7-section report and rewrites report.md/html", () => {
    writeRunDir(dir, assembly);
    const report = buildReportFromRunDir(dir);
    expect(report.sections).toHaveLength(7);
    expect(readFileSync(join(dir, RUN_DIR_FILES.reportMd), "utf8")).toContain("## Verified claims");
    expect(readFileSync(join(dir, RUN_DIR_FILES.reportHtml), "utf8")).toContain("<!doctype html>");
  });
  it("reportHtmlPath points at the run dir's report.html", () => {
    writeRunDir(dir, assembly);
    expect(existsSync(reportHtmlPath(dir))).toBe(true);
  });
});

describe("buildReportFromRunDir anchors status to the SEALED ledger (tamper resistance)", () => {
  const heldAssembly = assembleRun({
    run_id: "run_held01",
    loop_family: "minimal-bugfix",
    loopspec_version: "v001",
    started_at: "2026-01-01T00:00:00Z",
    engine: "codex_cli",
    events: events.events,
    capture_gaps: events.capture_gaps,
    gates: [noT5],
    risk_controls: { max_tier_without_approval: "T2", t5_allowed: true }, // T5 → run.held
  });

  it("a tampered report-input.json cannot make a HELD run render as completed/valid", () => {
    expect(heldAssembly.integrity.run_state).toBe("held"); // sanity: the ledger says held
    writeRunDir(dir, heldAssembly);

    const inputPath = join(dir, RUN_DIR_FILES.reportInput);
    const tampered = JSON.parse(readFileSync(inputPath, "utf8"));
    tampered.run_state = "completed";
    tampered.integrity_status = "valid";
    writeFileSync(inputPath, JSON.stringify(tampered));

    const report = buildReportFromRunDir(dir);
    expect(report.markdown).toContain("**held**"); // ledger's authoritative state, not the tampered value
    expect(report.markdown).not.toContain("**completed**");
    expect(report.markdown).toContain("diverged from the sealed ledger");
  });
});
