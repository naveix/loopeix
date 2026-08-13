import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_CATALOG_SNAPSHOT_V02 } from "../../src/catalog/default-items.js";
import { parseDirectChildName } from "../../src/io/captured-file.js";
import { readCompilePackV02 } from "../../src/compiler/read-pack-v02.js";

const roots: string[] = [];
const token = "m1abc_0123456789abcdef";
const submittedAt = "2026-08-12T10:11:12Z";

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function jsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(value, null, 2)}\n`);
}

function rawHash(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function makeRoot(): string {
  const parent = mkdtempSync(join(tmpdir(), "loopeix-read-pack-v02-"));
  roots.push(parent);
  const root = join(parent, `compile_${token}`);
  mkdirSync(root);
  return root;
}

function writeBytes(root: string, name: string, bytes: Uint8Array): void {
  writeFileSync(join(root, name), bytes);
}

type FixtureMutation = (fixture: {
  workItem: Record<string, unknown>;
  bindingInput: Record<string, unknown>;
  intake: Record<string, unknown>;
  resolution: Record<string, unknown>;
  report: Uint8Array;
  manifest: Record<string, any>;
}) => void;

function writeHoldPack(mutate?: FixtureMutation): string {
  const root = makeRoot();
  const workItem = {
    schema_version: "0.2",
    work_item_id: `wi_${token}`,
    submitted_at: submittedAt,
    prompt: "A bounded prompt.",
    workspace_root: "/workspace",
    operator_constraints: [],
    source_context: [],
  };
  const bindingInput = {
    schema_version: "0.2",
    binding_input_id: `binding_${token}`,
    work_item_id: `wi_${token}`,
    submitted_at: submittedAt,
    bindings: [],
  };
  const intake = {
    schema_version: "0.2",
    intake_id: `intake_${token}`,
    work_item_id: `wi_${token}`,
    objective: "A bounded prompt.",
    requested_outcome: "A bounded prompt.",
    candidate_scope: [],
    forbidden_actions: [],
    required_inputs: [],
    risk_flags: [],
    ambiguities: [],
    untrusted_source_refs: [],
  };
  const resolution = {
    schema_version: "0.2",
    compiler_bundle_id: "compiler_s35_v02_1",
    resolution_id: `resolution_${token}`,
    catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash,
    terminal_state: "hold-no-item",
    reason_code: "NO_CATALOG_ITEM",
    ranked_candidates: [],
    selected_item_id: null,
    selection_evidence: [],
    rejected_candidates: [],
    needs_clarification: false,
    required_binding_keys: [],
  };
  const report = new TextEncoder().encode("# Compile report\n\nNo catalog item matched.\n");
  const bytes = {
    work_item: jsonBytes(workItem),
    binding_input: jsonBytes(bindingInput),
    intake: jsonBytes(intake),
    catalog_resolution: jsonBytes(resolution),
    report,
  };
  const manifest = {
    schema_version: "0.2",
    compiler_bundle_id: "compiler_s35_v02_1",
    catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash,
    pack_manifest_id: `pack_${token}`,
    terminal_state: "hold-no-item",
    reason_code: "NO_CATALOG_ITEM",
    work_item_id: `wi_${token}`,
    binding_input_id: `binding_${token}`,
    intake_id: `intake_${token}`,
    resolution_id: `resolution_${token}`,
    selected_item_id: null,
    compilation_id: null,
    generated_loop_hash: null,
    file_hashes: {
      work_item: rawHash(bytes.work_item),
      binding_input: rawHash(bytes.binding_input),
      intake: rawHash(bytes.intake),
      catalog_resolution: rawHash(bytes.catalog_resolution),
      report: rawHash(bytes.report),
    },
  };

  const fixture = { workItem, bindingInput, intake, resolution, report, manifest };
  mutate?.(fixture);
  writeBytes(root, "work-item.json", jsonBytes(fixture.workItem));
  writeBytes(root, "binding-input.json", jsonBytes(fixture.bindingInput));
  writeBytes(root, "intake-record.json", jsonBytes(fixture.intake));
  writeBytes(root, "catalog-resolution.json", jsonBytes(fixture.resolution));
  writeBytes(root, "compile-report.md", fixture.report);
  writeBytes(root, "pack-manifest.json", jsonBytes(fixture.manifest));
  return root;
}

function fixedName(value: string) {
  const parsed = parseDirectChildName(value);
  if (parsed === null) throw new Error("invalid fixed test member");
  return parsed;
}

describe("S35 strict V02 compile-pack reader", () => {
  it("admits a strict coherent HOLD pack and retains defensive opaque captures", async () => {
    const root = writeHoldPack();
    const result = await readCompilePackV02(root);
    expect(result.ok, result.ok ? undefined : result).toBe(true);
    if (!result.ok) return;

    expect(result.selector).toEqual({
      schema_version: "0.2",
      compiler_bundle_id: "compiler_s35_v02_1",
      catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash,
    });
    expect(result.compilation).toBeNull();
    expect(result.generated_loop).toBeNull();
    expect(result.pack.memberNames()).toEqual([
      "pack-manifest.json",
      "work-item.json",
      "binding-input.json",
      "intake-record.json",
      "catalog-resolution.json",
      "compile-report.md",
    ]);
    const first = result.pack.snapshotMemberBytes(fixedName("work-item.json"));
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    first.value[0] = 0;
    const second = result.pack.snapshotMemberBytes(fixedName("work-item.json"));
    expect(second.ok && new TextDecoder().decode(second.value).startsWith("{\n")).toBe(true);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.manifest)).toBe(true);
  });

  it("rejects missing, extra, symlink, and compiled-state-incomplete inventories", async () => {
    const missing = makeRoot();
    for (const name of ["pack-manifest.json", "work-item.json", "intake-record.json", "compile-report.md"]) {
      writeBytes(missing, name, jsonBytes({ schema_version: "0.2" }));
    }
    await expect(readCompilePackV02(missing)).resolves.toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });

    const extra = writeHoldPack();
    writeFileSync(join(extra, "extra.json"), "{}\n");
    await expect(readCompilePackV02(extra)).resolves.toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });

    const symlink = writeHoldPack();
    rmSync(join(symlink, "compile-report.md"));
    symlinkSync(join(symlink, "work-item.json"), join(symlink, "compile-report.md"));
    await expect(readCompilePackV02(symlink)).resolves.toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });

    const compiled = writeHoldPack(({ manifest, resolution }) => {
      manifest.terminal_state = "compiled";
      manifest.reason_code = null;
      manifest.selected_item_id = "safe-bugfix";
      manifest.compilation_id = `compilation_${token}`;
      manifest.generated_loop_hash = `sha256:${"a".repeat(64)}`;
      manifest.file_hashes.compilation = `sha256:${"b".repeat(64)}`;
      manifest.file_hashes.generated_loop = manifest.generated_loop_hash;
      resolution.terminal_state = "compiled";
      resolution.reason_code = null;
      resolution.selected_item_id = "safe-bugfix";
    });
    await expect(readCompilePackV02(compiled)).resolves.toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });
  });

  it.each([
    ["missing", {}, "MISSING_SCHEMA_VERSION"],
    ["malformed", { schema_version: " 0.2" }, "MALFORMED_SCHEMA_VERSION"],
    ["unsupported", { schema_version: "0.3" }, "UNSUPPORTED_SCHEMA_VERSION"],
  ] as const)("preserves the %s manifest literal-dispatch reason", async (_case, manifest, reason) => {
    const root = makeRoot();
    for (const name of ["work-item.json", "intake-record.json", "catalog-resolution.json", "compile-report.md"]) {
      writeFileSync(join(root, name), "{}\n");
    }
    writeBytes(root, "pack-manifest.json", jsonBytes(manifest));
    await expect(readCompilePackV02(root)).resolves.toMatchObject({ ok: false, reason });
  });

  it("returns INVALID_DOCUMENT_ENVELOPE before member capture for malformed manifest bytes", async () => {
    const root = makeRoot();
    for (const name of ["work-item.json", "intake-record.json", "catalog-resolution.json", "compile-report.md"]) {
      writeFileSync(join(root, name), "{}\n");
    }
    writeFileSync(join(root, "pack-manifest.json"), "{ invalid\n");
    await expect(readCompilePackV02(root)).resolves.toMatchObject({
      ok: false,
      reason: "INVALID_DOCUMENT_ENVELOPE",
    });
  });

  it("returns MIXED_SCHEMA_VERSION before structural parsing for a supported V01 member", async () => {
    const root = writeHoldPack(({ bindingInput }) => {
      bindingInput.schema_version = "0.1";
    });
    await expect(readCompilePackV02(root)).resolves.toEqual({
      ok: false,
      reason: "MIXED_SCHEMA_VERSION",
      message: "Compile pack members do not share one literal schema_version.",
    });
  });

  it("rejects stale raw hashes and exact lineage mutations before bundle lookup", async () => {
    const staleHash = writeHoldPack(({ workItem }) => {
      workItem.prompt = "Mutated after manifest hashing.";
    });
    await expect(readCompilePackV02(staleHash)).resolves.toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });

    const brokenLineage = writeHoldPack(({ intake, manifest }) => {
      intake.work_item_id = `wi_${token}_other`;
      manifest.file_hashes.intake = rawHash(jsonBytes(intake));
    });
    await expect(readCompilePackV02(brokenLineage)).resolves.toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });

    const selectorMismatch = writeHoldPack(({ resolution, manifest }) => {
      resolution.compiler_bundle_id = "compiler_s35_v02_other";
      manifest.file_hashes.catalog_resolution = rawHash(jsonBytes(resolution));
    });
    await expect(readCompilePackV02(selectorMismatch)).resolves.toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });
  });

  it("checks the exact tuple only after coherent structure, lineage, selectors, and hashes", async () => {
    const unavailable = `sha256:${"f".repeat(64)}`;
    const root = writeHoldPack(({ resolution, manifest }) => {
      resolution.catalog_version_hash = unavailable;
      manifest.catalog_version_hash = unavailable;
      manifest.file_hashes.catalog_resolution = rawHash(jsonBytes(resolution));
    });
    await expect(readCompilePackV02(root)).resolves.toEqual({
      ok: false,
      reason: "UNAVAILABLE_REPLAY_BUNDLE",
      message: "The exact replay bundle is unavailable.",
    });
  });
});
