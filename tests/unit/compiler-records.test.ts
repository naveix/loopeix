import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  CatalogResolution,
  checkSpecialistHandoffInvariants,
  CompilationRecord,
  IntakeRecord,
  SpecialistHandoff,
} from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = join(here, "..", "fixtures");
const loadJson = (p: string): unknown => JSON.parse(readFileSync(p, "utf8"));
const valid = join(fx, "valid", "runtime");
const invalid = join(fx, "invalid", "runtime");

describe("compiler runtime records", () => {
  it("valid IntakeRecord parses", () => {
    expect(IntakeRecord.safeParse(loadJson(join(valid, "intake-record-minimal-bugfix.json"))).success).toBe(true);
  });

  it("valid CatalogResolution parses", () => {
    expect(CatalogResolution.safeParse(loadJson(join(valid, "catalog-resolution-minimal-bugfix.json"))).success).toBe(true);
  });

  it("valid CompilationRecord parses", () => {
    expect(CompilationRecord.safeParse(loadJson(join(valid, "compilation-record-minimal-bugfix.json"))).success).toBe(true);
  });

  it("valid SpecialistHandoff parses and passes invariants", () => {
    const parsed = SpecialistHandoff.safeParse(loadJson(join(valid, "specialist-handoff-basic.json")));
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(checkSpecialistHandoffInvariants(parsed.data)).toEqual([]);
  });

  it("ambiguous CatalogResolution cannot be compiled without selected item", () => {
    const parsed = CatalogResolution.safeParse(loadJson(join(invalid, "catalog-resolution-ambiguous.json")));
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((i) => i.path.join(".").includes("selected_item_id"))).toBe(true);
    }
  });

  it("risk escalation cannot use T5 as max_tier_without_approval", () => {
    const parsed = CompilationRecord.safeParse(loadJson(join(invalid, "compilation-record-risk-escalation.json")));
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((i) => i.path.join(".").includes("max_tier_without_approval"))).toBe(true);
    }
  });

  it("handoff with strong claim and no evidence produces invariant issue", () => {
    const parsed = SpecialistHandoff.safeParse(loadJson(join(invalid, "specialist-handoff-missing-evidence.json")));
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(checkSpecialistHandoffInvariants(parsed.data).some((i) => i.path === "evidence_refs")).toBe(true);
    }
  });
});

