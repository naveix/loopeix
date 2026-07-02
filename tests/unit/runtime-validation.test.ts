import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";
import {
  ArtifactManifest,
  Claim,
  checkClaimInvariants,
  checkFindingInvariants,
  checkGateResultInvariants,
  EvaluationResult,
  EvidenceItem,
  Finding,
  GateResult,
  ResolvedRunPlan,
  RunManifest,
  validateLedger,
  Waiver,
} from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = join(here, "..", "fixtures");
const golden = join(here, "..", "golden");

const loadJson = (p: string): unknown => JSON.parse(readFileSync(p, "utf8"));
const loadYaml = (p: string): unknown => parseYaml(readFileSync(p, "utf8"));
const loadJsonl = (p: string): unknown[] =>
  readFileSync(p, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l));

const vr = join(fx, "valid", "runtime");
const ir = join(fx, "invalid", "runtime");

describe("valid/runtime — records parse and satisfy invariants", () => {
  it("resolved-run-plan-minimal-bugfix.json", () => {
    expect(ResolvedRunPlan.safeParse(loadJson(join(vr, "resolved-run-plan-minimal-bugfix.json"))).success).toBe(true);
  });
  it("evidence-command-pass.json", () => {
    expect(EvidenceItem.safeParse(loadJson(join(vr, "evidence-command-pass.json"))).success).toBe(true);
  });
  it("evidence-file-hash.json", () => {
    expect(EvidenceItem.safeParse(loadJson(join(vr, "evidence-file-hash.json"))).success).toBe(true);
  });
  it("evaluation-test-pass.json", () => {
    expect(EvaluationResult.safeParse(loadJson(join(vr, "evaluation-test-pass.json"))).success).toBe(true);
  });
  it("finding-accepted-risk.json", () => {
    const parsed = Finding.safeParse(loadJson(join(vr, "finding-accepted-risk.json")));
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(checkFindingInvariants(parsed.data)).toEqual([]);
  });
  it("waiver-advisory-expiring.json", () => {
    expect(Waiver.safeParse(loadJson(join(vr, "waiver-advisory-expiring.json"))).success).toBe(true);
  });
});

describe("invalid/runtime — records fail for the intended defect", () => {
  it("ledger-mutated-event.jsonl → hash chain break", () => {
    const issues = validateLedger(loadJsonl(join(ir, "ledger-mutated-event.jsonl")));
    expect(issues.some((i) => i.message.includes("chain break"))).toBe(true);
  });
  it("run-manifest-missing-hash.json → missing ledger hash", () => {
    const parsed = RunManifest.safeParse(loadJson(join(ir, "run-manifest-missing-hash.json")));
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((i) => i.path.join(".").includes("hashes.ledger"))).toBe(true);
    }
  });
  it("artifact-manifest-unknown-retention.json → bad retention_class", () => {
    const parsed = ArtifactManifest.safeParse(loadJson(join(ir, "artifact-manifest-unknown-retention.json")));
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((i) => i.path.join(".").includes("retention_class"))).toBe(true);
    }
  });
  it("waiver-missing-expiry.json → missing required expires_at", () => {
    const parsed = Waiver.safeParse(loadJson(join(ir, "waiver-missing-expiry.json")));
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((i) => i.path.join(".").includes("expires_at"))).toBe(true);
    }
  });
  it("evidence-unsupported-strong-claim.json → strong claim verified without evidence", () => {
    const bundle = loadJson(join(ir, "evidence-unsupported-strong-claim.json")) as { claims: unknown[] };
    const issues = bundle.claims.flatMap((c) => {
      const parsed = Claim.safeParse(c);
      return parsed.success ? checkClaimInvariants(parsed.data) : [{ path: "claim", message: "unparseable" }];
    });
    expect(issues.some((i) => i.message.includes("supporting evidence"))).toBe(true);
  });
  it("gate-waives-no-t5.json → unwaivable gate WAIVED", () => {
    const parsed = GateResult.safeParse(loadJson(join(ir, "gate-waives-no-t5.json")));
    expect(parsed.success).toBe(true); // structurally valid; caught by invariant
    if (parsed.success) {
      expect(checkGateResultInvariants(parsed.data).some((i) => i.message.includes("unwaivable"))).toBe(true);
    }
  });
  it("finding-nonblocking-without-owner.json → non-blocking finding needs owner", () => {
    const parsed = Finding.safeParse(loadJson(join(ir, "finding-nonblocking-without-owner.json")));
    expect(parsed.success).toBe(true); // owner:null is structurally allowed; caught by invariant
    if (parsed.success) {
      expect(checkFindingInvariants(parsed.data).some((i) => i.message.includes("owner"))).toBe(true);
    }
  });
});

describe("golden ledgers — valid append-only chains", () => {
  for (const f of [
    "minimal-bugfix-success",
    "gate-hold-missing-evidence",
    "t5-blocked-fail",
    "redaction-tombstone",
    "interrupted-recovery",
  ]) {
    it(`${f}.ledger.jsonl`, () => {
      expect(validateLedger(loadJsonl(join(golden, "ledgers", `${f}.ledger.jsonl`)))).toEqual([]);
    });
  }
});

describe("golden gates — GateResult records parse and respect waiver rules", () => {
  for (const f of [
    "all-required-pass",
    "hold-missing-evidence",
    "fail-no-t5",
    "waived-nonfinal-risk",
    "report-truthfulness-hold",
  ]) {
    it(`${f}.gates.json`, () => {
      const arr = loadJson(join(golden, "gates", `${f}.gates.json`)) as unknown[];
      for (const g of arr) {
        const parsed = GateResult.safeParse(g);
        expect(parsed.success).toBe(true);
        if (parsed.success) expect(checkGateResultInvariants(parsed.data)).toEqual([]);
      }
    });
  }
});

describe("golden manifests — run + artifact manifests parse", () => {
  it("run-manifest", () => {
    expect(RunManifest.safeParse(loadJson(join(golden, "manifests", "minimal-bugfix-success.run-manifest.json"))).success).toBe(true);
  });
  it("artifact-manifest", () => {
    expect(ArtifactManifest.safeParse(loadJson(join(golden, "manifests", "minimal-bugfix-success.artifact-manifest.json"))).success).toBe(true);
  });
});
