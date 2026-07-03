import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { assessAgentProof, type AgentProofInput } from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const example = (name: string): AgentProofInput =>
  JSON.parse(readFileSync(join(here, "..", "..", "examples", "agent-proof", name), "utf8")) as AgentProofInput;

describe("AgentProofProfile — against the AI-code-work examples", () => {
  it("meets-bar.json satisfies both rules", () => {
    const r = assessAgentProof(example("meets-bar.json"));
    expect(r.meets_bar).toBe(true);
    expect(r.violations).toEqual([]);
  });
  it("fails-bar.json flags the exact violations", () => {
    const r = assessAgentProof(example("fails-bar.json"));
    expect(r.meets_bar).toBe(false);
    expect(r.strong_claims_without_execution).toEqual(["claim_fix_works"]);
    expect(r.missing_mandatory_gates).toEqual(["evidence-integrity", "report-truthfulness"]);
  });
});

const gates = [
  { id: "no-t5", blocking: true, waiver_allowed: false },
  { id: "evidence-integrity", blocking: true, waiver_allowed: false },
  { id: "report-truthfulness", blocking: true, waiver_allowed: false },
];

describe("AgentProofProfile — executable-evidence rule", () => {
  it("a strong claim backed only by a file diff FAILS (existence ≠ works)", () => {
    const r = assessAgentProof({
      claims: [{ claim_id: "c", strength: "strong", supported_by: ["f"] }],
      evidence: [{ evidence_id: "f", type: "file" }],
      gates,
    });
    expect(r.strong_claims_without_execution).toEqual(["c"]);
    expect(r.meets_bar).toBe(false);
  });
  it("a strong claim with a PASSING test (or command) PASSES", () => {
    const r = assessAgentProof({
      claims: [{ claim_id: "c", strength: "strong", supported_by: ["t"] }],
      evidence: [{ evidence_id: "t", type: "test", outcome: "pass" }],
      gates,
    });
    expect(r.meets_bar).toBe(true);
  });
  it("a strong claim backed by a FAILED test does NOT satisfy the rule", () => {
    const r = assessAgentProof({
      claims: [{ claim_id: "c", strength: "strong", supported_by: ["t"] }],
      evidence: [{ evidence_id: "t", type: "test", outcome: "fail" }],
      gates,
    });
    expect(r.strong_claims_without_execution).toEqual(["c"]);
  });
  it("a test with no recorded pass signal does NOT satisfy (must positively prove it worked)", () => {
    const r = assessAgentProof({
      claims: [{ claim_id: "c", strength: "strong", supported_by: ["t"] }],
      evidence: [{ evidence_id: "t", type: "test" }],
      gates,
    });
    expect(r.meets_bar).toBe(false);
  });
  it("a LIMITED claim is not subject to the executable-evidence rule", () => {
    const r = assessAgentProof({
      claims: [{ claim_id: "c", strength: "limited", supported_by: ["f"] }],
      evidence: [{ evidence_id: "f", type: "file" }],
      gates,
    });
    expect(r.meets_bar).toBe(true);
  });
});

describe("AgentProofProfile — mandatory-gate rule", () => {
  const claims = [{ claim_id: "c", strength: "strong", supported_by: ["t"] }];
  const evidence = [{ evidence_id: "t", type: "test", outcome: "pass" }];
  it("flags a missing mandatory gate", () => {
    const r = assessAgentProof({
      claims,
      evidence,
      gates: gates.filter((g) => g.id !== "no-t5"),
    });
    expect(r.missing_mandatory_gates).toContain("no-t5");
  });
  it("flags a mandatory gate that is non-blocking or waivable", () => {
    const r = assessAgentProof({
      claims,
      evidence,
      gates: gates.map((g) => (g.id === "no-t5" ? { ...g, waiver_allowed: true } : g)),
    });
    expect(r.missing_mandatory_gates).toContain("no-t5");
    expect(r.meets_bar).toBe(false);
  });
});

describe("AgentProofProfile — fail-closed against the S15 review bypasses", () => {
  const goodGates = [
    { id: "no-t5", blocking: true, waiver_allowed: false },
    { id: "evidence-integrity", blocking: true, waiver_allowed: false },
    { id: "report-truthfulness", blocking: true, waiver_allowed: false },
  ];
  it("a miscased strength ('Strong') is STILL subject to the executable-evidence rule", () => {
    const r = assessAgentProof({
      claims: [{ claim_id: "x", strength: "Strong", supported_by: ["f"] }],
      evidence: [{ evidence_id: "f", type: "file" }],
      gates: goodGates,
    });
    expect(r.strong_claims_without_execution).toEqual(["x"]);
    expect(r.meets_bar).toBe(false);
  });
  it("a duplicate evidence id cannot relabel a file diff as a passing test", () => {
    const r = assessAgentProof({
      claims: [{ claim_id: "x", strength: "strong", supported_by: ["e"] }],
      evidence: [
        { evidence_id: "e", type: "file" },
        { evidence_id: "e", type: "test", outcome: "pass" },
      ],
      gates: goodGates,
    });
    expect(r.strong_claims_without_execution).toEqual(["x"]); // not ALL instances executable → fails closed
  });
  it("a weakened duplicate mandatory gate cannot hide behind a strong one", () => {
    const r = assessAgentProof({
      claims: [{ claim_id: "c", strength: "strong", supported_by: ["t"] }],
      evidence: [{ evidence_id: "t", type: "test", outcome: "pass" }],
      gates: [
        { id: "no-t5", blocking: true, waiver_allowed: true }, // weakened real gate
        { id: "no-t5", blocking: true, waiver_allowed: false }, // strong duplicate appended
        { id: "evidence-integrity", blocking: true, waiver_allowed: false },
        { id: "report-truthfulness", blocking: true, waiver_allowed: false },
      ],
    });
    expect(r.missing_mandatory_gates).toContain("no-t5");
    expect(r.meets_bar).toBe(false);
  });
  it("null array elements fail closed rather than crashing", () => {
    const r = assessAgentProof({
      claims: [null as never, { claim_id: "c", strength: "strong", supported_by: ["t"] }],
      evidence: [null as never, { evidence_id: "t", type: "test", outcome: "pass" }],
      gates: [null as never, ...goodGates],
    });
    expect(r.meets_bar).toBe(true);
  });
});
