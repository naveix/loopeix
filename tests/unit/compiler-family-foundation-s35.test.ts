import { describe, expect, it } from "vitest";
import {
  CatalogResolution,
  CatalogResolutionV01,
  CatalogResolutionV02,
  CompilerTerminalState,
  CompilerTerminalStateV01,
  CompilerTerminalStateV02,
  dispatchCompilerRecordFamily,
} from "../../src/compiler/records.js";
import {
  CompilePackManifest,
  CompilePackManifestV01,
  CompilePackManifestV02,
} from "../../src/compiler/pack.js";

const hash = `sha256:${"a".repeat(64)}`;

describe("S35 compiler record family foundation", () => {
  it("preserves unsuffixed V01 aliases and dispatches only literal coherent families", () => {
    expect(CompilerTerminalState).toBe(CompilerTerminalStateV01);
    expect(CatalogResolution).toBe(CatalogResolutionV01);
    expect(CompilerTerminalStateV01.safeParse("failed-invalid-catalog").success).toBe(true);
    expect(CompilerTerminalStateV02.safeParse("failed-invalid-catalog").success).toBe(false);
    expect(CompilerTerminalStateV02.safeParse("hold-project-binding-required").success).toBe(true);

    const v02 = CatalogResolutionV02.parse({
      schema_version: "0.2",
      compiler_bundle_id: "compiler_s35_v02_1",
      resolution_id: "resolution_test",
      catalog_version_hash: hash,
      terminal_state: "hold-project-binding-required",
      reason_code: "PROJECT_BINDING_REQUIRED",
      ranked_candidates: [{ item_id: "safe-bugfix", score: 9, reasons: ["positive:bug"] }],
      selected_item_id: "safe-bugfix",
      selection_evidence: ["positive:bug"],
      rejected_candidates: [],
      needs_clarification: true,
      required_binding_keys: ["project.engine", "project.objective"],
    });

    expect(dispatchCompilerRecordFamily([v02, { ...v02 }])).toEqual({ ok: true, schema_version: "0.2" });
    expect(dispatchCompilerRecordFamily([v02, { ...v02, schema_version: "0.1" }])).toMatchObject({
      ok: false,
      reason: "MIXED_SCHEMA_VERSION",
    });
    expect(dispatchCompilerRecordFamily([{ schema_version: "0.3" }])).toEqual({
      ok: false,
      reason: "UNSUPPORTED_SCHEMA_VERSION",
      message: "schema_version is not supported; supported versions are '0.1' and '0.2'.",
    });
  });

  it("models exact V02 manifest lineage and state-specific membership", () => {
    expect(CompilePackManifest).toBe(CompilePackManifestV01);

    const hold = {
      schema_version: "0.2",
      compiler_bundle_id: "compiler_s35_v02_1",
      catalog_version_hash: hash,
      pack_manifest_id: "pack_test",
      terminal_state: "hold-project-binding-required",
      reason_code: "PROJECT_BINDING_REQUIRED",
      work_item_id: "work_test",
      binding_input_id: "binding_test",
      intake_id: "intake_test",
      resolution_id: "resolution_test",
      selected_item_id: "safe-bugfix",
      compilation_id: null,
      generated_loop_hash: null,
      file_hashes: {
        work_item: hash,
        binding_input: hash,
        intake: hash,
        catalog_resolution: hash,
        report: hash,
      },
    } as const;

    expect(CompilePackManifestV02.safeParse(hold).success).toBe(true);
    expect(CompilePackManifestV02.safeParse({ ...hold, binding_input_id: undefined }).success).toBe(false);
    expect(CompilePackManifestV02.safeParse({ ...hold, terminal_state: "failed-invalid-catalog" }).success).toBe(false);
    expect(
      CompilePackManifestV02.safeParse({
        ...hold,
        compilation_id: "compilation_test",
        file_hashes: { ...hold.file_hashes, compilation: hash },
      }).success,
    ).toBe(false);
  });
});
