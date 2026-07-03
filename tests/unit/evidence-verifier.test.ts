import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  verifyEvaluations,
  verifyEvidence,
  type ClaimInput,
  type EvaluationInput,
  type EvidenceInput,
} from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const claim = (over: Partial<ClaimInput> = {}): ClaimInput => ({
  claim_id: "claim_0001",
  strength: "strong",
  required_evidence_types: [],
  supported_by: [],
  status: "verified",
  ...over,
});
const ev = (id: string, type: string): EvidenceInput => ({ evidence_id: id, type });
const only = (over: Partial<ClaimInput>, evidence: EvidenceInput[], waived_claim_ids?: string[]) =>
  verifyEvidence({ claims: [claim(over)], evidence, waived_claim_ids }).claims[0]!;

describe("verifyEvidence — strong claims need present, INDEPENDENT, type-covered evidence", () => {
  it("strong + an independent type covering the requirement → verified", () => {
    expect(only({ required_evidence_types: ["command"], supported_by: ["e1"] }, [ev("e1", "command")]).resolved_status).toBe("verified");
  });
  it("strong + NO supporting evidence → downgraded to unverified", () => {
    const c = only({ supported_by: [] }, []);
    expect(c.resolved_status).toBe("unverified");
    expect(c.issues.some((i) => i.includes("no present supporting evidence"))).toBe(true);
    expect(c.issues.some((i) => i.includes("downgraded"))).toBe(true);
  });
  it("strong + only human_note (weak) → unverified (lacks independent evidence)", () => {
    const c = only({ supported_by: ["n1"] }, [ev("n1", "human_note")]);
    expect(c.resolved_status).toBe("unverified");
    expect(c.issues.some((i) => i.includes("independent evidence"))).toBe(true);
  });
  it("strong + only an approval (circular sign-off) → unverified", () => {
    expect(only({ supported_by: ["a1"] }, [ev("a1", "approval")]).resolved_status).toBe("unverified");
  });
  it("strong + an UNKNOWN/misspelled evidence type → unverified (fail closed)", () => {
    expect(only({ supported_by: ["b1"] }, [ev("b1", "banana")]).resolved_status).toBe("unverified");
    expect(only({ supported_by: ["c1"] }, [ev("c1", "commandd")]).resolved_status).toBe("unverified");
  });
  it("strong + missing a required evidence type → unverified", () => {
    const c = only({ required_evidence_types: ["command", "test"], supported_by: ["e1"] }, [ev("e1", "command")]);
    expect(c.resolved_status).toBe("unverified");
    expect(c.missing_evidence_types).toEqual(["test"]);
  });
  it("limited claim with any present evidence → verified", () => {
    expect(only({ strength: "limited", supported_by: ["n1"], status: "unverified" }, [ev("n1", "human_note")]).resolved_status).toBe("verified");
  });
  it("phantom supported_by ids are flagged", () => {
    expect(only({ supported_by: ["ghost"] }, []).issues.some((i) => i.includes("do not exist"))).toBe(true);
  });
});

describe("verifyEvidence — status is resolved from evidence, not laundered", () => {
  it("a contradicted claim stays contradicted", () => {
    expect(only({ status: "contradicted" }, []).resolved_status).toBe("contradicted");
  });
  it("status:'waived' with NO backing waiver is NOT honored — resolved from evidence", () => {
    const c = only({ status: "waived", supported_by: [] }, []);
    expect(c.resolved_status).toBe("unverified");
    expect(c.issues.some((i) => i.includes("without an approved waiver"))).toBe(true);
  });
  it("status:'waived' WITH a backing waiver id is honored", () => {
    expect(only({ status: "waived" }, [], ["claim_0001"]).resolved_status).toBe("waived");
  });
});

describe("verifyEvidence — against the real invalid/runtime fixture", () => {
  it("evidence-unsupported-strong-claim.json: the strong 'verified' claim is downgraded", () => {
    const bundle = JSON.parse(
      readFileSync(join(here, "..", "fixtures", "invalid", "runtime", "evidence-unsupported-strong-claim.json"), "utf8"),
    ) as { claims: ClaimInput[]; evidence: EvidenceInput[] };
    const r = verifyEvidence(bundle);
    expect(r.verified).toEqual([]);
    expect(r.unverified).toHaveLength(1);
  });
});

describe("verifyEvaluations", () => {
  const cmd = (over: Partial<EvaluationInput>): EvaluationInput => ({ evaluation_id: "e", type: "command", status: "PASS", required: true, ...over });
  it("command PASS with exit 0 → ok", () => {
    expect(verifyEvaluations([cmd({ exit_code: 0 })]).all_required_passed).toBe(true);
  });
  it("command PASS with exit_code != 0 → not ok", () => {
    const r = verifyEvaluations([cmd({ exit_code: 1 })]);
    expect(r.results[0]!.ok).toBe(false);
    expect(r.all_required_passed).toBe(false);
  });
  it("command PASS with ABSENT exit_code → not ok (cannot confirm exit 0)", () => {
    const r = verifyEvaluations([cmd({})]);
    expect(r.results[0]!.ok).toBe(false);
    expect(r.results[0]!.issue).toContain("absent");
  });
  it("a required eval expected but entirely MISSING fails the run", () => {
    const r = verifyEvaluations([cmd({ evaluation_id: "a", exit_code: 0 })], { expected_ids: ["a", "b"] });
    expect(r.missing_required).toEqual(["b"]);
    expect(r.all_required_passed).toBe(false);
  });
  it("duplicate evaluation ids: ALL must be ok (a later pass cannot mask an earlier fail)", () => {
    const r = verifyEvaluations([
      cmd({ evaluation_id: "x", status: "FAIL", exit_code: 2 }),
      cmd({ evaluation_id: "x", status: "PASS", exit_code: 0 }),
    ]);
    expect(r.all_required_passed).toBe(false);
  });
});
