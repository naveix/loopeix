import { describe, expect, it } from "vitest";

import {
  DEFAULT_CATALOG_SNAPSHOT_V02,
  S35_COMPILER_BUNDLE_ID_V02,
} from "../../src/catalog/default-items.js";
import { regenerateCompilePackV02 } from "../../src/compiler/serialize-v02.js";
import {
  S35_PROJECTION_ORACLES,
  bindingInputForProjectionOracle,
} from "../helpers/s35-projection-oracles.js";

const TOKEN = "mepc_0000000000000000";

function workItem(prompt = "Fix the failing parser bug and prove the correction.") {
  return {
    schema_version: "0.2" as const,
    work_item_id: `wi_${TOKEN}`,
    submitted_at: "2026-08-10T12:00:00Z",
    prompt,
    workspace_root: "/workspace",
    operator_constraints: [],
    source_context: [],
  };
}

function regenerate(bindingInput: unknown) {
  return regenerateCompilePackV02({
    work_item: workItem(),
    binding_input: bindingInput,
    compiler_bundle_id: S35_COMPILER_BUNDLE_ID_V02,
    catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash,
  });
}

describe("S35 V02 pure compiler regeneration and serialization", () => {
  it("emits a binding-required HOLD pack without compiled-only members", () => {
    const result = regenerate({
      schema_version: "0.2",
      binding_input_id: `binding_${TOKEN}`,
      work_item_id: `wi_${TOKEN}`,
      submitted_at: "2026-08-10T12:00:00Z",
      bindings: [],
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.catalog_resolution).toMatchObject({
      terminal_state: "hold-project-binding-required",
      reason_code: "PROJECT_BINDING_REQUIRED",
      selected_item_id: "safe-bugfix",
    });
    expect(result.compilation).toBeNull();
    expect(result.authoring).toBeNull();
    expect(result.pack_members.map(({ name }) => name)).toEqual([
      "work-item.json",
      "binding-input.json",
      "intake-record.json",
      "catalog-resolution.json",
      "compile-report.md",
      "pack-manifest.json",
    ]);
    expect(result.pack_members.at(-1)?.name).toBe("pack-manifest.json");
    const report = new TextDecoder().decode(result.pack_members.find(({ name }) => name === "compile-report.md")!.bytes);
    expect(report.startsWith("# Loopeix Compile Report V02\n\n    {")).toBe(true);
    expect(report.endsWith("\n\nLocal/internal compiler evidence. Export is disabled by default.\n")).toBe(true);
    expect(report).not.toContain(workItem().prompt);
  });

  it("regenerates a compiled pack from WorkItem plus verified BindingInput only", () => {
    const oracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "safe-bugfix")!;
    const fixture = bindingInputForProjectionOracle(oracle);
    const bindingInput = {
      ...fixture,
      binding_input_id: `binding_${TOKEN}`,
      work_item_id: `wi_${TOKEN}`,
      submitted_at: "2026-08-10T12:00:00Z",
    };
    const result = regenerate(bindingInput);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.catalog_resolution.terminal_state).toBe("compiled");
    expect(result.compilation?.input_bindings).toEqual(
      bindingInput.bindings.map(({ key, source }) => ({ key, source })),
    );
    expect(result.compilation?.context_snapshot).toEqual(result.authoring?.context_contract);
    expect(result.compilation?.effective_risk_controls).toEqual(result.authoring?.risk_controls);
    expect(result.binding_input_member.name).toBe("binding-input.json");
    expect(result.compiler_derived_members.map(({ name }) => name)).not.toContain("binding-input.json");
    expect(result.pack_members.map(({ name }) => name)).toEqual([
      "work-item.json",
      "binding-input.json",
      "intake-record.json",
      "catalog-resolution.json",
      "compilation-record.json",
      "compile-report.md",
      "generated.loop.yaml",
      "pack-manifest.json",
    ]);
    expect(result.pack_members.at(-1)?.name).toBe("pack-manifest.json");
  });

  it("rejects unregistered selectors and broken input lineage", () => {
    const emptyBinding = {
      schema_version: "0.2",
      binding_input_id: `binding_${TOKEN}`,
      work_item_id: `wi_${TOKEN}`,
      submitted_at: "2026-08-10T12:00:00Z",
      bindings: [],
    };
    expect(regenerateCompilePackV02({
      work_item: workItem(), binding_input: emptyBinding,
      compiler_bundle_id: "compiler_unknown", catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash,
    })).toMatchObject({ ok: false, reason: "INVALID_CATALOG" });
    expect(regenerate({ ...emptyBinding, work_item_id: "wi_wrong_0000000000000000" }))
      .toMatchObject({ ok: false, reason: "INVALID_V02_PROJECTION" });
  });
});
