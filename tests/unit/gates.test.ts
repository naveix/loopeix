import { describe, expect, it } from "vitest";
import { evaluateGates, REQUIRED_V1_GATES, type GateSpecInput, type RunGateContext } from "../../src/index.js";

const noT5 = { max_tier_without_approval: "T2", t5_allowed: false };
const gate = (id: string, extra: Partial<GateSpecInput> = {}): GateSpecInput => ({
  id,
  blocking: true,
  inputs_required: [],
  waiver_allowed: false,
  ...extra,
});
const decisionFor = (ctx: RunGateContext, id: string) => evaluateGates(ctx).decisions.find((d) => d.gate_id === id);

describe("no-t5 gate — the unwaivable V1 control", () => {
  it("PASS when no T5 signal is present", () => {
    expect(decisionFor({ gates: [gate("no-t5")], risk_controls: noT5 }, "no-t5")?.status).toBe("PASS");
  });
  const t5Cases: Array<[string, RunGateContext]> = [
    ["t5_allowed:true", { gates: [gate("no-t5")], risk_controls: { max_tier_without_approval: "T2", t5_allowed: true } }],
    ["max_tier T5", { gates: [gate("no-t5")], risk_controls: { max_tier_without_approval: "T5", t5_allowed: false } }],
    ["tool grant tier T5", { gates: [gate("no-t5")], risk_controls: noT5, tool_grant_tiers: ["T2", "T5"] }],
    ["unattended loop", { gates: [gate("no-t5")], risk_controls: noT5, unattended_loop_present: true }],
  ];
  for (const [label, ctx] of t5Cases) {
    it(`FAIL when T5 is present via ${label}`, () => {
      expect(decisionFor(ctx, "no-t5")?.status).toBe("FAIL");
    });
  }
});

describe("required V1 gates are injected when the spec omits them", () => {
  it("evaluates no-t5 even if not declared", () => {
    const report = evaluateGates({ gates: [], risk_controls: noT5 });
    expect(REQUIRED_V1_GATES).toContain("no-t5");
    expect(report.decisions.some((d) => d.gate_id === "no-t5")).toBe(true);
  });
});

describe("evidence-based gates", () => {
  const ctx = (available: string[]): RunGateContext => ({
    gates: [gate("claim-support", { inputs_required: ["verification-result"] })],
    risk_controls: noT5,
    available_inputs: available,
  });
  it("PASS when all required inputs are present", () => {
    expect(decisionFor(ctx(["verification-result"]), "claim-support")?.status).toBe("PASS");
  });
  it("HOLD (with the missing list) when a required input is absent", () => {
    const d = decisionFor(ctx([]), "claim-support");
    expect(d?.status).toBe("HOLD");
    expect(d?.missing_inputs).toEqual(["verification-result"]);
  });
});

describe("waiver rules", () => {
  it("an unwaivable gate (no-t5) is NOT waived; the waiver becomes a finding", () => {
    const d = decisionFor(
      { gates: [gate("no-t5")], risk_controls: { max_tier_without_approval: "T2", t5_allowed: true }, waivers: ["no-t5"] },
      "no-t5",
    );
    expect(d?.status).toBe("FAIL");
    expect(d?.findings.some((f) => f.includes("unwaivable"))).toBe(true);
  });
  it("a waivable gate with an approved waiver becomes WAIVED", () => {
    const d = decisionFor(
      {
        gates: [gate("style-advisory", { blocking: false, inputs_required: ["style-report"], waiver_allowed: true })],
        risk_controls: noT5,
        available_inputs: [],
        waivers: ["style-advisory"],
      },
      "style-advisory",
    );
    expect(d?.status).toBe("WAIVED");
  });
});

describe("gate report", () => {
  it("blocks completion when a blocking gate is HOLD or FAIL, and summarizes counts", () => {
    const report = evaluateGates({
      gates: [gate("claim-support", { inputs_required: ["missing-thing"] }), gate("no-t5")],
      risk_controls: noT5,
      available_inputs: [],
    });
    expect(report.blocking_hold_or_fail).toBe(true); // claim-support HOLD
    expect(report.summary.hold).toBe(1);
    expect(report.summary.pass).toBe(1); // no-t5
  });
});

describe("security-audit hardening (fail-closed)", () => {
  it("B1: a spec declaring no-t5 as non-blocking/waivable is normalized away; T5 still blocks", () => {
    const report = evaluateGates({
      gates: [{ id: "no-t5", blocking: false, inputs_required: [], waiver_allowed: true }],
      risk_controls: { max_tier_without_approval: "T2", t5_allowed: true },
      waivers: ["no-t5"],
    });
    const noT5Decisions = report.decisions.filter((d) => d.gate_id === "no-t5");
    expect(noT5Decisions).toHaveLength(1);
    expect(noT5Decisions[0]!.blocking).toBe(true);
    expect(noT5Decisions[0]!.status).toBe("FAIL"); // waiver did not apply (unwaivable)
    expect(report.blocking_hold_or_fail).toBe(true);
  });

  it("M1: a gate marked waiver_allowed:false is NOT waived even with a waiver", () => {
    const d = decisionFor(
      {
        gates: [gate("secrets-scan", { inputs_required: ["scan"], waiver_allowed: false })],
        risk_controls: noT5,
        available_inputs: [],
        waivers: ["secrets-scan"],
      },
      "secrets-scan",
    );
    expect(d?.status).toBe("HOLD"); // missing evidence, NOT waived
    expect(d?.findings.some((f) => f.includes("non-waivable"))).toBe(true);
  });

  it("M2: a blocking gate with no declared inputs HOLDs (never a silent PASS)", () => {
    expect(decisionFor({ gates: [gate("mystery", { inputs_required: [] })], risk_controls: noT5 }, "mystery")?.status).toBe("HOLD");
  });

  it("M3: T5 is detected leniently (trailing space, lowercase list entry)", () => {
    expect(
      decisionFor({ gates: [gate("no-t5")], risk_controls: { max_tier_without_approval: "T5 ", t5_allowed: false } }, "no-t5")?.status,
    ).toBe("FAIL");
    expect(decisionFor({ gates: [gate("no-t5")], risk_controls: noT5, tool_grant_tiers: ["t5"] }, "no-t5")?.status).toBe("FAIL");
  });
});
