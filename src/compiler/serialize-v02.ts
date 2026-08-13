import { stringify as stringifyYaml } from "yaml";

import { compareUtf8BytesV02, type CatalogEntryV02 } from "../catalog/item-v02.js";
import { lookupRegisteredCatalogV02 } from "../catalog/registry.js";
import { hashRawBytes } from "../hash.js";
import { LoopeixV02Shape, type LoopeixV02 } from "../schema/loopeix-v02.js";
import { parseDirectChildName, type DirectChildName } from "../io/output-capabilities.js";
import {
  BindingInputRecordV02,
  validateBindingsForCatalogEntryV02,
  type BindingInputRecordV02 as BindingInputRecordV02Value,
  type CompileBindingPayloadV02,
} from "./binding-input-v02.js";
import { CompilePackManifestV02, type CompilePackManifestV02 as CompilePackManifestV02Value } from "./pack.js";
import { projectCatalogEntryV02 } from "./project-v02.js";
import {
  CatalogResolutionV02,
  CompilationRecordV02,
  IntakeRecordV02,
  WorkItemRecordV02,
  type CatalogResolutionV02 as CatalogResolutionV02Value,
  type CompilationRecordV02 as CompilationRecordV02Value,
  type IntakeRecordV02 as IntakeRecordV02Value,
  type WorkItemRecordV02 as WorkItemRecordV02Value,
} from "./records.js";
import { resolveCatalogV02 } from "./strategy-v02.js";

const UTF8 = new TextEncoder();
const TOKEN = /^[a-z0-9]+_[0-9a-f]{16}$/;

export type SerializedV02Member = Readonly<{ name: DirectChildName; bytes: Uint8Array; sha256: string }>;

export type RegenerateCompilePackV02Input = Readonly<{
  work_item: unknown;
  binding_input: unknown;
  compiler_bundle_id: string;
  catalog_version_hash: string;
  verified_binding_input_hash?: string;
}>;

export type RegenerateCompilePackV02Success = Readonly<{
  ok: true;
  work_item: WorkItemRecordV02Value;
  binding_input: BindingInputRecordV02Value;
  intake: IntakeRecordV02Value;
  catalog_resolution: CatalogResolutionV02Value;
  compilation: CompilationRecordV02Value | null;
  authoring: LoopeixV02 | null;
  selected_entry: CatalogEntryV02 | null;
  binding_input_member: SerializedV02Member;
  compiler_derived_members: readonly SerializedV02Member[];
  pack_members: readonly SerializedV02Member[];
  manifest: CompilePackManifestV02Value;
  source_authoring_hash: string;
}>;

export type RegenerateCompilePackV02Result =
  | RegenerateCompilePackV02Success
  | { ok: false; reason: "INVALID_CATALOG" | "INVALID_BINDING_INPUT" | "INVALID_V02_PROJECTION" | "OUTPUT_HASH_FAILED"; message: string };

function fixedName(value: string): DirectChildName {
  const parsed = parseDirectChildName(value);
  if (parsed === null) throw new Error("invalid fixed V02 member name");
  return parsed;
}

function jsonBytes(value: unknown): Uint8Array {
  return UTF8.encode(`${JSON.stringify(value, null, 2)}\n`);
}

function createMember(name: string, bytes: Uint8Array): SerializedV02Member {
  const owned = new Uint8Array(bytes);
  return Object.freeze({ name: fixedName(name), bytes: owned, sha256: hashRawBytes(owned) });
}

function invocationToken(workItemId: string): string | null {
  if (!workItemId.startsWith("wi_")) return null;
  const token = workItemId.slice(3);
  return TOKEN.test(token) ? token : null;
}

function objective(bindingInput: BindingInputRecordV02Value): string | null {
  const value = bindingInput.bindings.find(({ key }) => key === "project.objective")?.value;
  return typeof value === "string" && value.length > 0 ? value : null;
}

function normalizeIntake(workItem: WorkItemRecordV02Value, bindingInput: BindingInputRecordV02Value, intakeId: string): IntakeRecordV02Value {
  const lower = workItem.prompt.toLowerCase();
  const riskTerms: Array<[string, string]> = [
    ["stripe", "payment"], ["payment", "payment"], ["billing", "payment"], ["production", "production"],
    ["deploy", "deploy"], ["secret", "secret"], [".env", "secret"], ["dm", "connector-write"],
    ["post", "connector-write"], ["delete", "delete"], ["whatever tools", "approval"], ["don't ask", "approval"],
    ["dont ask", "approval"], ["background", "t5"], ["recurring", "t5"], ["schedule", "t5"], ["any means", "approval"],
  ];
  const ambiguityTerms = ["clean up", "ship", "handle", "monitor", "everything", "make it nicer", "polish"];
  const riskFlags = [...new Set(riskTerms.filter(([term]) => lower.includes(term)).map(([, flag]) => flag))];
  const forbiddenActions = ["whatever tools", "any means", "don't ask", "dont ask"].some((term) => lower.includes(term))
    ? ["unbounded authority"] : [];
  return IntakeRecordV02.parse({
    schema_version: "0.2",
    intake_id: intakeId,
    work_item_id: workItem.work_item_id,
    objective: objective(bindingInput),
    requested_outcome: workItem.prompt,
    candidate_scope: [],
    forbidden_actions: forbiddenActions,
    required_inputs: [],
    risk_flags: riskFlags,
    ambiguities: ambiguityTerms.filter((term) => lower.includes(term)),
    untrusted_source_refs: [],
  });
}

function payloadFrom(record: BindingInputRecordV02Value): CompileBindingPayloadV02 {
  return { bindings: record.bindings.map(({ approved_by: _approvedBy, ...binding }) => binding) };
}

function compileReportBytes(
  workItem: WorkItemRecordV02Value,
  bindingInput: BindingInputRecordV02Value,
  resolution: CatalogResolutionV02Value,
  selectedEntry: CatalogEntryV02 | null,
): Uint8Array | null {
  const requiredBindings = [];
  for (const key of resolution.required_binding_keys) {
    const slot = selectedEntry?.binding_slots.find((candidate) => candidate.slot_id === key);
    if (slot === undefined) return null;
    requiredBindings.push({
      key,
      question: slot.description,
      expected_value_shape: slot.value_schema,
      allowed_sources: slot.allowed_sources,
      sensitivity: slot.sensitivity,
    });
  }
  const reportProjection = {
    schema_version: "0.2",
    compiler_bundle_id: resolution.compiler_bundle_id,
    terminal_state: resolution.terminal_state,
    reason_code: resolution.reason_code,
    work_item_id: workItem.work_item_id,
    binding_input_id: bindingInput.binding_input_id,
    catalog_version_hash: resolution.catalog_version_hash,
    selected_item_id: resolution.selected_item_id,
    selection_evidence: resolution.selection_evidence,
    required_bindings: requiredBindings,
    limitations: selectedEntry === null ? [] : selectedEntry.blueprint.limitation_records,
    next_action: resolution.terminal_state === "compiled"
      ? "review-generated-authoring-before-planning"
      : "resolve-hold-without-fabricating-bindings",
  };
  return UTF8.encode(
    `# Loopeix Compile Report V02\n\n    ${JSON.stringify(reportProjection)}\n\nLocal/internal compiler evidence. Export is disabled by default.\n`,
  );
}

function compilationRecord(
  token: string,
  bindingInput: BindingInputRecordV02Value,
  bindingHash: string,
  resolution: CatalogResolutionV02Value,
  entry: CatalogEntryV02,
  authoring: LoopeixV02,
): CompilationRecordV02Value {
  return CompilationRecordV02.parse({
    schema_version: "0.2",
    compilation_id: `compilation_${token}`,
    compiler_bundle_id: resolution.compiler_bundle_id,
    catalog_version_hash: resolution.catalog_version_hash,
    binding_input_id: bindingInput.binding_input_id,
    binding_input_hash: bindingHash,
    selected_loop_family: entry.loop_family,
    selected_loop_version: entry.version,
    input_bindings: bindingInput.bindings
      .map(({ key, source }) => ({ key, source }))
      .sort((left, right) => compareUtf8BytesV02(left.key, right.key)),
    context_snapshot: authoring.context_contract,
    effective_risk_controls: authoring.risk_controls,
    approval_requirements: authoring.tool_grants
      .filter(({ requires_approval }) => requires_approval)
      .map(({ id }) => id),
    compiler_findings: resolution.selection_evidence,
    proof_boundary: { can_prove: entry.can_prove, cannot_prove: entry.cannot_prove },
  });
}

export function regenerateCompilePackV02(input: RegenerateCompilePackV02Input): RegenerateCompilePackV02Result {
  const registered = lookupRegisteredCatalogV02({
    schema_version: "0.2",
    compiler_bundle_id: input.compiler_bundle_id,
    catalog_version_hash: input.catalog_version_hash,
  });
  if (!registered.ok) return { ok: false, reason: "INVALID_CATALOG", message: registered.message };
  const workItem = WorkItemRecordV02.safeParse(input.work_item);
  const bindingInput = BindingInputRecordV02.safeParse(input.binding_input);
  if (!workItem.success || !bindingInput.success) {
    return { ok: false, reason: "INVALID_BINDING_INPUT", message: "The V02 compiler inputs are invalid." };
  }
  const token = invocationToken(workItem.data.work_item_id);
  if (token === null || bindingInput.data.work_item_id !== workItem.data.work_item_id ||
      bindingInput.data.binding_input_id !== `binding_${token}` || bindingInput.data.submitted_at !== workItem.data.submitted_at) {
    return { ok: false, reason: "INVALID_V02_PROJECTION", message: "The V02 compiler input lineage is invalid." };
  }

  try {
    const intake = normalizeIntake(workItem.data, bindingInput.data, `intake_${token}`);
    const resolution = CatalogResolutionV02.parse(resolveCatalogV02(intake, registered.entries, {
      compiler_bundle_id: registered.compiler_bundle_id,
      catalog_version_hash: registered.catalog_version_hash,
      resolution_id: `resolution_${token}`,
      provided_binding_keys: bindingInput.data.bindings.map(({ key }) => key),
    }));
    const selectedEntry = resolution.selected_item_id === null
      ? null
      : registered.entries.find(({ item_id }) => item_id === resolution.selected_item_id) ?? null;
    if (resolution.selected_item_id !== null && selectedEntry === null) {
      return { ok: false, reason: "INVALID_CATALOG", message: "The selected V02 catalog entry is unavailable." };
    }
    if (selectedEntry !== null) {
      const validated = validateBindingsForCatalogEntryV02(payloadFrom(bindingInput.data), selectedEntry);
      if (!validated.ok) return validated;
    }

    let authoring: LoopeixV02 | null = null;
    let compilation: CompilationRecordV02Value | null = null;
    const bindingMember = createMember("binding-input.json", jsonBytes(bindingInput.data));
    const bindingInputHash = input.verified_binding_input_hash ?? bindingMember.sha256;
    if (!/^sha256:[0-9a-f]{64}$/.test(bindingInputHash)) {
      return { ok: false, reason: "INVALID_V02_PROJECTION", message: "The verified binding-input hash is invalid." };
    }
    if (resolution.terminal_state === "compiled") {
      if (selectedEntry === null) throw new Error("compiled resolution without selected entry");
      const projected = projectCatalogEntryV02({ entry: selectedEntry, binding_input: bindingInput.data });
      if (!projected.ok) {
        const reason = projected.reason === "PLAN_BINDING_MISMATCH" || projected.reason === "PROJECT_BINDING_REQUIRED"
          ? "INVALID_V02_PROJECTION" as const
          : projected.reason;
        return { ok: false, reason, message: "message" in projected ? projected.message : "The V02 projection is incomplete." };
      }
      authoring = LoopeixV02Shape.parse(projected.value.authoring);
      compilation = compilationRecord(token, bindingInput.data, bindingInputHash, resolution, selectedEntry, authoring);
    }
    const reportBytes = compileReportBytes(workItem.data, bindingInput.data, resolution, selectedEntry);
    if (reportBytes === null) return { ok: false, reason: "INVALID_V02_PROJECTION", message: "A required binding slot is unavailable." };

    const derived: SerializedV02Member[] = [
      createMember("work-item.json", jsonBytes(workItem.data)),
      createMember("intake-record.json", jsonBytes(intake)),
      createMember("catalog-resolution.json", jsonBytes(resolution)),
    ];
    let generatedLoopHash: string | null = null;
    if (compilation !== null && authoring !== null) {
      derived.push(createMember("compilation-record.json", jsonBytes(compilation)));
      derived.push(createMember("compile-report.md", reportBytes));
      const generated = createMember("generated.loop.yaml", UTF8.encode(stringifyYaml(authoring)));
      derived.push(generated);
      generatedLoopHash = generated.sha256;
    } else {
      derived.push(createMember("compile-report.md", reportBytes));
    }
    const named = new Map([...derived, bindingMember].map((row) => [row.name, row]));
    const manifest = CompilePackManifestV02.parse({
      schema_version: "0.2",
      compiler_bundle_id: registered.compiler_bundle_id,
      catalog_version_hash: registered.catalog_version_hash,
      pack_manifest_id: `pack_${token}`,
      terminal_state: resolution.terminal_state,
      reason_code: resolution.reason_code,
      work_item_id: workItem.data.work_item_id,
      binding_input_id: bindingInput.data.binding_input_id,
      intake_id: intake.intake_id,
      resolution_id: resolution.resolution_id,
      selected_item_id: resolution.selected_item_id,
      compilation_id: compilation?.compilation_id ?? null,
      generated_loop_hash: generatedLoopHash,
      file_hashes: {
        work_item: named.get(fixedName("work-item.json"))!.sha256,
        binding_input: bindingInputHash,
        intake: named.get(fixedName("intake-record.json"))!.sha256,
        catalog_resolution: named.get(fixedName("catalog-resolution.json"))!.sha256,
        report: named.get(fixedName("compile-report.md"))!.sha256,
        ...(compilation === null ? {} : {
          compilation: named.get(fixedName("compilation-record.json"))!.sha256,
          generated_loop: generatedLoopHash!,
        }),
      },
    });
    const manifestMember = createMember("pack-manifest.json", jsonBytes(manifest));
    const packOrder = resolution.terminal_state === "compiled"
      ? [derived[0]!, bindingMember, derived[1]!, derived[2]!, derived[3]!, derived[4]!, derived[5]!, manifestMember]
      : [derived[0]!, bindingMember, derived[1]!, derived[2]!, derived[3]!, manifestMember];
    return Object.freeze({
      ok: true,
      work_item: workItem.data,
      binding_input: bindingInput.data,
      intake,
      catalog_resolution: resolution,
      compilation,
      authoring,
      selected_entry: selectedEntry,
      binding_input_member: bindingMember,
      compiler_derived_members: Object.freeze([...derived, manifestMember]),
      pack_members: Object.freeze(packOrder),
      manifest,
      source_authoring_hash: generatedLoopHash ?? hashRawBytes(jsonBytes(null)),
    });
  } catch {
    return { ok: false, reason: "INVALID_V02_PROJECTION", message: "The V02 compiler projection is invalid." };
  }
}
