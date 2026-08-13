import { describe, expect, it } from "vitest";

import { CompilationRecordV01, CompilationRecordV02 } from "../../src/compiler/records.js";

const HASH = `sha256:${"a".repeat(64)}`;

function validV02() {
  return {
    schema_version: "0.2" as const,
    compilation_id: "compilation_01",
    compiler_bundle_id: "compiler_s35_v02_1",
    catalog_version_hash: HASH,
    binding_input_id: "binding_01",
    binding_input_hash: HASH,
    selected_loop_family: "safe-bugfix",
    selected_loop_version: "v001",
    input_bindings: [
      { key: "project.objective", source: "operator" as const },
      { key: "project.workspace-root", source: "workspace-observation" as const },
    ],
    context_snapshot: {
      required: ["src/parser.ts"],
      forbidden: ["secrets"],
      untrusted_sources: ["issue body"],
    },
    effective_risk_controls: {
      max_tier_without_approval: "T2" as const,
      t5_allowed: false as const,
    },
    approval_requirements: ["operator approval"],
    compiler_findings: ["catalog match is deterministic"],
    proof_boundary: {
      can_prove: ["tests pass"],
      cannot_prove: ["production correctness"],
    },
  };
}

describe("CompilationRecordV02", () => {
  it("accepts the strict typed projection with dotted binding keys", () => {
    expect(CompilationRecordV02.parse(validV02())).toEqual(validV02());
  });

  it.each(["Project.objective", "project/objective", ".project", "project..objective", "project_objective"])(
    "rejects malformed binding key %s",
    (key) => {
      const record = validV02();
      record.input_bindings[0] = { key, source: "operator" };
      expect(CompilationRecordV02.safeParse(record).success).toBe(false);
    },
  );

  it("rejects duplicate and non-UTF-8-sorted binding keys", () => {
    const duplicate = validV02();
    duplicate.input_bindings[1] = { key: "project.objective", source: "workspace-observation" };
    expect(CompilationRecordV02.safeParse(duplicate).success).toBe(false);

    const unsorted = validV02();
    unsorted.input_bindings.reverse();
    expect(CompilationRecordV02.safeParse(unsorted).success).toBe(false);
  });

  it.each(["value", "source_ref", "source_hash", "approved_by"])(
    "rejects forbidden binding field %s",
    (field) => {
      const record: Record<string, unknown> = { ...validV02() };
      record.input_bindings = [{ ...validV02().input_bindings[0], [field]: "forbidden" }];
      expect(CompilationRecordV02.safeParse(record).success).toBe(false);
    },
  );

  it("rejects untyped context and nested extra fields", () => {
    const untypedContext = { ...validV02(), context_snapshot: ["src/parser.ts"] };
    expect(CompilationRecordV02.safeParse(untypedContext).success).toBe(false);

    for (const field of ["context_snapshot", "effective_risk_controls", "proof_boundary"] as const) {
      const record = validV02();
      record[field] = { ...record[field], extra: true } as never;
      expect(CompilationRecordV02.safeParse(record).success).toBe(false);
    }
  });

  it("requires both sides of the proof boundary to contain a non-blank claim", () => {
    for (const field of ["can_prove", "cannot_prove"] as const) {
      const record = validV02();
      record.proof_boundary[field] = [];
      expect(CompilationRecordV02.safeParse(record).success).toBe(false);
    }
  });

  it("keeps the frozen V01 binding map and string-array context behavior", () => {
    const v01 = {
      schema_version: "0.1",
      compilation_id: "compilation_01",
      selected_loop_family: "safe-bugfix",
      selected_loop_version: "v001",
      input_bindings: { "bug-statement": "parser rejects leap day" },
      context_snapshot: ["src/parser.ts"],
      effective_risk_controls: { max_tier_without_approval: "T2", t5_allowed: false },
      approval_requirements: [],
      compiler_findings: [],
      proof_boundary: { can_prove: ["tests pass"], cannot_prove: ["production correctness"] },
    };

    expect(CompilationRecordV01.parse(v01)).toEqual(v01);
    expect(CompilationRecordV01.safeParse({ ...v01, input_bindings: validV02().input_bindings }).success).toBe(false);
  });
});
