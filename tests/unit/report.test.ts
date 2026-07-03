import { describe, expect, it } from "vitest";
import { buildReport, checkReportTruthfulness, type ReportInput } from "../../src/index.js";

const input: ReportInput = {
  run_id: "run_x",
  loop_family: "minimal-bugfix",
  loopeix_version: "v001",
  run_state: "completed",
  integrity_status: "valid",
  evidence: {
    verified: ["claim_ok"],
    unverified: ["claim_bad"],
    claims: [
      { claim_id: "claim_ok", strength: "strong", resolved_status: "verified" },
      { claim_id: "claim_bad", strength: "strong", resolved_status: "unverified" },
    ],
  },
  capture_gaps: [{ engine: "claude_code_cli", capability: "shell_command_execution", level: "partial", note: "inferred from tool_use" }],
  waivers: [{ gate_id: "style-advisory", approver: "operator" }],
  findings: [{ finding_id: "find_0001", title: "flaky test", classification: "accepted-risk", severity: "low" }],
  redaction: { policy_version: "0.1", quarantined: 0, raw_excluded: false, limitations: [] },
  timeline: [
    { sequence: 1, event_type: "run.started", timestamp: "2026-01-01T00:00:01Z" },
    { sequence: 2, event_type: "run.completed", timestamp: "2026-01-01T00:00:02Z" },
  ],
};

describe("buildReport", () => {
  const report = buildReport(input);
  const required = [
    "Verified claims",
    "Unverified claims",
    "Capture gaps",
    "Waivers",
    "Unresolved findings",
    "Redaction and retention state",
    "Known limitations",
  ];
  it("emits EVERY mandatory section", () => {
    for (const s of required) expect(report.markdown).toContain(`## ${s}`);
    expect(report.sections).toEqual(required);
  });
  it("is truthful — the verified section lists exactly the evidence-verified claims", () => {
    expect(report.markdown).toContain("claim_ok");
    // claim_bad appears only under Unverified, never asserted as verified
    const verifiedSection = report.markdown.split("## Unverified claims")[0]!;
    expect(verifiedSection).not.toContain("claim_bad");
  });
  it("discloses the partial capture gap", () => {
    expect(report.markdown).toContain("shell_command_execution");
    expect(report.markdown).toContain("partial");
  });
  it("produces a static, self-contained HTML timeline (no scripts, no network)", () => {
    expect(report.html).toContain("<!doctype html>");
    expect(report.html).not.toContain("<script");
    expect(report.html).not.toMatch(/https?:\/\//);
    expect(report.html).toContain("run.started");
    expect(report.html).toContain("run.completed");
  });
});

describe("checkReportTruthfulness — the unwaivable report-truthfulness gate", () => {
  it("PASS when the report claims a subset of the evidence-verified set", () => {
    expect(checkReportTruthfulness({ reported_verified: ["a"], evidence_verified: ["a", "b"] }).status).toBe("PASS");
  });
  it("HOLD when the report asserts a claim the evidence did not verify (over-claim)", () => {
    const r = checkReportTruthfulness({ reported_verified: ["a", "c"], evidence_verified: ["a"] });
    expect(r.status).toBe("HOLD");
    expect(r.over_claimed).toEqual(["c"]);
  });
  it("case/whitespace mismatch is an over-claim (HOLD), never a false PASS", () => {
    expect(checkReportTruthfulness({ reported_verified: ["A"], evidence_verified: ["a"] }).status).toBe("HOLD");
    expect(checkReportTruthfulness({ reported_verified: [" a"], evidence_verified: ["a"] }).status).toBe("HOLD");
  });
});

describe("buildReport — completeness on EMPTY input (the guarantee that must never regress)", () => {
  const empty: ReportInput = {
    run_id: "run_empty",
    loop_family: "x",
    loopeix_version: "v001",
    run_state: "failed",
    integrity_status: "unknown",
    evidence: { verified: [], unverified: [], claims: [] },
    capture_gaps: [],
    waivers: [],
    findings: [],
    redaction: { policy_version: "0.1", quarantined: 0, raw_excluded: false, limitations: [] },
    timeline: [],
  };
  const report = buildReport(empty);
  it("emits every mandatory section with an explicit empty-state", () => {
    for (const s of [
      "Verified claims",
      "Unverified claims",
      "Capture gaps",
      "Waivers",
      "Unresolved findings",
      "Redaction and retention state",
      "Known limitations",
    ])
      expect(report.markdown).toContain(`## ${s}`);
    expect(report.sections).toHaveLength(7);
    expect(report.markdown).toContain("None recorded."); // empty capture gaps
    expect(report.markdown).toContain("None blocking."); // empty findings
  });
  it("renders valid HTML even with an empty timeline", () => {
    expect(report.html).toContain("<!doctype html>");
    expect(report.html).toContain("<ol>");
  });
});

describe("buildReport — Markdown injection is neutralized", () => {
  it("a pipe / image / heading in a freeform note cannot break the table or add a live image", () => {
    const evil = buildReport({ ...input, capture_gaps: [{ engine: "e", capability: "c", level: "partial", note: "a|b ![](http://x) ## h" }] });
    expect(evil.markdown).not.toContain("![](http://x)"); // image syntax broken
    expect(evil.markdown).toContain("\\|"); // pipe escaped → table row keeps its columns
  });
});
