import type { CatalogEntryV02 } from "../catalog/item-v02.js";
import type { CatalogResolutionV02, IntakeRecordV02 } from "./records.js";
import { resolveCatalog } from "./resolve.js";
import { compareUtf8BytesV02 } from "../catalog/item-v02.js";

export interface ResolveCatalogOptionsV02 {
  compiler_bundle_id: string;
  catalog_version_hash: string;
  resolution_id?: string;
  ambiguity_delta?: number;
  minimum_score?: number;
  provided_binding_keys: readonly string[];
}

const REASON_BY_TERMINAL = {
  "hold-ambiguous": "CATALOG_AMBIGUOUS",
  "hold-risk": "RISK_BOUNDARY_UNRESOLVED",
  "hold-no-item": "NO_CATALOG_ITEM",
} as const;

export function resolveCatalogV02(
  intake: IntakeRecordV02,
  catalog: readonly CatalogEntryV02[],
  options: ResolveCatalogOptionsV02,
): CatalogResolutionV02 {
  const v01Resolution = resolveCatalog(
    { ...intake, objective: intake.objective ?? "" },
    catalog,
    options,
  );
  const common = {
    schema_version: "0.2" as const,
    compiler_bundle_id: options.compiler_bundle_id,
    resolution_id: v01Resolution.resolution_id,
    catalog_version_hash: options.catalog_version_hash,
    ranked_candidates: v01Resolution.ranked_candidates,
    selection_evidence: v01Resolution.selection_evidence,
    rejected_candidates: v01Resolution.rejected_candidates,
  };

  if (v01Resolution.terminal_state !== "compiled") {
    const terminalState = v01Resolution.terminal_state as keyof typeof REASON_BY_TERMINAL;
    return {
      ...common,
      terminal_state: terminalState,
      reason_code: REASON_BY_TERMINAL[terminalState],
      selected_item_id: null,
      needs_clarification: terminalState === "hold-ambiguous",
      required_binding_keys: [],
    };
  }

  const selected = catalog.find((entry) => entry.item_id === v01Resolution.selected_item_id);
  const supplied = new Set(options.provided_binding_keys);
  const missing = (selected?.binding_slots ?? [])
    .filter((slot) => slot.required && !supplied.has(slot.slot_id))
    .map((slot) => slot.slot_id)
    .sort(compareUtf8BytesV02);
  if (missing.length > 0) {
    return {
      ...common,
      terminal_state: "hold-project-binding-required",
      reason_code: "PROJECT_BINDING_REQUIRED",
      selected_item_id: v01Resolution.selected_item_id,
      needs_clarification: true,
      required_binding_keys: missing,
    };
  }
  return {
    ...common,
    terminal_state: "compiled",
    reason_code: null,
    selected_item_id: v01Resolution.selected_item_id,
    needs_clarification: false,
    required_binding_keys: [],
  };
}
