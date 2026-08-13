import { describe, expect, it } from "vitest";
import { CompilePackManifestV01, CompilePackManifestV02 } from "../../src/compiler/pack.js";

const hash = (character: string): string => `sha256:${character.repeat(64)}`;

const v01Compiled = {
  schema_version: "0.1",
  pack_manifest_id: "pack_test",
  terminal_state: "compiled",
  work_item_id: "wi_test",
  intake_id: "intake_test",
  resolution_id: "resolution_test",
  selected_item_id: "safe-bugfix",
  compilation_id: "compilation_test",
  generated_loop_hash: hash("a"),
  file_hashes: {
    work_item: hash("b"),
    intake: hash("c"),
    catalog_resolution: hash("d"),
    report: hash("e"),
    compilation: hash("f"),
    generated_loop: hash("a"),
  },
} as const;

const v02Compiled = {
  schema_version: "0.2",
  compiler_bundle_id: "bundle_test",
  catalog_version_hash: hash("0"),
  pack_manifest_id: "pack_test",
  terminal_state: "compiled",
  reason_code: null,
  work_item_id: "wi_test",
  binding_input_id: "binding_test",
  intake_id: "intake_test",
  resolution_id: "resolution_test",
  selected_item_id: "safe-bugfix",
  compilation_id: "compilation_test",
  generated_loop_hash: hash("a"),
  file_hashes: {
    work_item: hash("b"),
    binding_input: hash("1"),
    intake: hash("c"),
    catalog_resolution: hash("d"),
    report: hash("e"),
    compilation: hash("f"),
    generated_loop: hash("a"),
  },
} as const;

describe("S35 compile-pack manifest envelopes", () => {
  it("keeps the V01 manifest literal and rejects V02 selector leakage", () => {
    expect(CompilePackManifestV01.safeParse(v01Compiled).success).toBe(true);
    expect(CompilePackManifestV01.safeParse({ ...v01Compiled, schema_version: "0.2" }).success).toBe(false);
    expect(CompilePackManifestV01.safeParse({ ...v01Compiled, compiler_bundle_id: "bundle_test" }).success).toBe(false);
    expect(CompilePackManifestV01.safeParse({ ...v01Compiled, catalog_version_hash: hash("0") }).success).toBe(false);
    expect(CompilePackManifestV01.safeParse({ ...v01Compiled, binding_input_id: "binding_test" }).success).toBe(false);
  });

  it("requires every V02 selector, binding lineage field, and strict key inventory", () => {
    expect(CompilePackManifestV02.safeParse(v02Compiled).success).toBe(true);
    for (const key of ["compiler_bundle_id", "catalog_version_hash", "binding_input_id"] as const) {
      const candidate = { ...v02Compiled } as Record<string, unknown>;
      delete candidate[key];
      expect(CompilePackManifestV02.safeParse(candidate).success, key).toBe(false);
    }
    expect(CompilePackManifestV02.safeParse({ ...v02Compiled, schema_version: "0.1" }).success).toBe(false);
    expect(CompilePackManifestV02.safeParse({ ...v02Compiled, unexpected: true }).success).toBe(false);
    expect(CompilePackManifestV02.safeParse({
      ...v02Compiled,
      file_hashes: { ...v02Compiled.file_hashes, unexpected: hash("9") },
    }).success).toBe(false);
  });

  it("enforces exact V02 terminal reason, selection, and compiled-only hash membership", () => {
    const holdRisk = {
      ...v02Compiled,
      terminal_state: "hold-risk",
      reason_code: "RISK_BOUNDARY_UNRESOLVED",
      selected_item_id: null,
      compilation_id: null,
      generated_loop_hash: null,
      file_hashes: {
        work_item: hash("b"),
        binding_input: hash("1"),
        intake: hash("c"),
        catalog_resolution: hash("d"),
        report: hash("e"),
      },
    } as const;
    expect(CompilePackManifestV02.safeParse(holdRisk).success).toBe(true);
    expect(CompilePackManifestV02.safeParse({ ...holdRisk, reason_code: "NO_CATALOG_ITEM" }).success).toBe(false);
    expect(CompilePackManifestV02.safeParse({ ...holdRisk, selected_item_id: "safe-bugfix" }).success).toBe(false);
    expect(CompilePackManifestV02.safeParse({
      ...holdRisk,
      file_hashes: { ...holdRisk.file_hashes, generated_loop: hash("a") },
    }).success).toBe(false);
    expect(CompilePackManifestV02.safeParse({ ...v02Compiled, compilation_id: null }).success).toBe(false);
  });

  it("requires binding-project HOLD selection and forbids V01-only terminal states", () => {
    const bindingHold = {
      ...v02Compiled,
      terminal_state: "hold-project-binding-required",
      reason_code: "PROJECT_BINDING_REQUIRED",
      compilation_id: null,
      generated_loop_hash: null,
      file_hashes: {
        work_item: hash("b"), binding_input: hash("1"), intake: hash("c"),
        catalog_resolution: hash("d"), report: hash("e"),
      },
    } as const;
    expect(CompilePackManifestV02.safeParse(bindingHold).success).toBe(true);
    expect(CompilePackManifestV02.safeParse({ ...bindingHold, selected_item_id: null }).success).toBe(false);
    expect(CompilePackManifestV02.safeParse({ ...bindingHold, terminal_state: "failed-invalid-catalog" }).success).toBe(false);
  });
});
