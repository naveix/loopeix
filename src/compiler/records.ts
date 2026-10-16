import { z } from "zod";
import { compareUtf8BytesV02 } from "../catalog/item-v02.js";
import { Hash, HumanId, IsoTimestamp, LoopVersion, MachineId, RiskTierV1, SchemaVersion } from "../schema/scalars.js";

export const CompilerTerminalStateV01 = z.enum([
  "compiled",
  "hold-ambiguous",
  "hold-risk",
  "hold-no-item",
  "failed-invalid-catalog",
]);
export const CompilerTerminalState = CompilerTerminalStateV01;

export const CompilerTerminalStateV02 = z.enum([
  "compiled",
  "hold-ambiguous",
  "hold-risk",
  "hold-no-item",
  "hold-project-binding-required",
]);

export const CompilerReasonCodeV02 = z.enum([
  "CATALOG_AMBIGUOUS",
  "RISK_BOUNDARY_UNRESOLVED",
  "NO_CATALOG_ITEM",
  "PROJECT_BINDING_REQUIRED",
]);

const Ref = z.string().min(1);
// The normative project.* inventory takes precedence over stale HumanId prose.
const BindingKeyV02 = z
  .string()
  .regex(/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/, "must be a canonical lowercase dotted or kebab binding key");

export const WorkItemRecord = z
  .object({
    schema_version: SchemaVersion,
    work_item_id: MachineId,
    submitted_at: IsoTimestamp,
    prompt: z.string().min(1),
    workspace_root: z.string().min(1),
    operator_constraints: z.array(z.string()),
    source_context: z.array(z.string()),
  })
  .strict();
export const WorkItemRecordV01 = WorkItemRecord;

export const WorkItemRecordV02 = WorkItemRecord.extend({
  schema_version: z.literal("0.2"),
}).strict();

export const IntakeRecord = z
  .object({
    schema_version: SchemaVersion,
    intake_id: MachineId,
    work_item_id: MachineId,
    objective: z.string().min(1),
    requested_outcome: z.string().min(1),
    candidate_scope: z.array(z.string()),
    forbidden_actions: z.array(z.string()),
    required_inputs: z.array(HumanId),
    risk_flags: z.array(HumanId),
    ambiguities: z.array(z.string()),
    untrusted_source_refs: z.array(Ref),
  })
  .strict();
export const IntakeRecordV01 = IntakeRecord;

export const IntakeRecordV02 = IntakeRecord.extend({
  schema_version: z.literal("0.2"),
  objective: z.string().min(1).nullable(),
}).strict();

export const CatalogCandidate = z
  .object({
    item_id: HumanId,
    score: z.number(),
    reasons: z.array(z.string()).min(1),
  })
  .strict();
export const CatalogCandidateV01 = CatalogCandidate;
export const CatalogCandidateV02 = CatalogCandidate;

export const CatalogResolution = z
  .object({
    schema_version: SchemaVersion,
    resolution_id: MachineId,
    catalog_version_hash: Hash,
    terminal_state: CompilerTerminalState,
    ranked_candidates: z.array(CatalogCandidate),
    selected_item_id: HumanId.nullable(),
    selection_evidence: z.array(z.string()),
    rejected_candidates: z.array(CatalogCandidate),
    needs_clarification: z.boolean(),
  })
  .strict()
  .superRefine((r, ctx) => {
    if (r.terminal_state === "compiled" && r.selected_item_id === null) {
      ctx.addIssue({ code: "custom", path: ["selected_item_id"], message: "compiled resolution requires selected_item_id" });
    }
    if (r.terminal_state !== "compiled" && r.selected_item_id !== null) {
      ctx.addIssue({ code: "custom", path: ["selected_item_id"], message: "HOLD/FAIL resolution cannot select an item" });
    }
    if (r.needs_clarification && r.terminal_state === "compiled") {
      ctx.addIssue({ code: "custom", path: ["needs_clarification"], message: "compiled resolution cannot need clarification" });
    }
  });
export const CatalogResolutionV01 = CatalogResolution;

const V02_REASON_BY_TERMINAL = {
  compiled: null,
  "hold-ambiguous": "CATALOG_AMBIGUOUS",
  "hold-risk": "RISK_BOUNDARY_UNRESOLVED",
  "hold-no-item": "NO_CATALOG_ITEM",
  "hold-project-binding-required": "PROJECT_BINDING_REQUIRED",
} as const;

function isStrictlySortedUniqueUtf8(values: readonly string[]): boolean {
  return values.every((value, index) => index === 0 || compareUtf8BytesV02(values[index - 1]!, value) < 0);
}

export const CatalogResolutionV02 = z
  .object({
    schema_version: z.literal("0.2"),
    compiler_bundle_id: MachineId,
    resolution_id: MachineId,
    catalog_version_hash: Hash,
    terminal_state: CompilerTerminalStateV02,
    reason_code: CompilerReasonCodeV02.nullable(),
    ranked_candidates: z.array(CatalogCandidateV02),
    selected_item_id: HumanId.nullable(),
    selection_evidence: z.array(z.string()),
    rejected_candidates: z.array(CatalogCandidateV02),
    needs_clarification: z.boolean(),
    required_binding_keys: z.array(BindingKeyV02),
  })
  .strict()
  .superRefine((resolution, ctx) => {
    const expectedReason = V02_REASON_BY_TERMINAL[resolution.terminal_state];
    if (resolution.reason_code !== expectedReason) {
      ctx.addIssue({
        code: "custom",
        path: ["reason_code"],
        message: `terminal_state '${resolution.terminal_state}' requires reason_code ${expectedReason === null ? "null" : `'${expectedReason}'`}`,
      });
    }

    const requiresSelectedItem =
      resolution.terminal_state === "compiled" || resolution.terminal_state === "hold-project-binding-required";
    if (requiresSelectedItem && resolution.selected_item_id === null) {
      ctx.addIssue({
        code: "custom",
        path: ["selected_item_id"],
        message: `${resolution.terminal_state} requires selected_item_id`,
      });
    }
    if (!requiresSelectedItem && resolution.selected_item_id !== null) {
      ctx.addIssue({
        code: "custom",
        path: ["selected_item_id"],
        message: `${resolution.terminal_state} cannot select an item`,
      });
    }

    const requiresBindings = resolution.terminal_state === "hold-project-binding-required";
    if (requiresBindings !== (resolution.required_binding_keys.length > 0)) {
      ctx.addIssue({
        code: "custom",
        path: ["required_binding_keys"],
        message: requiresBindings
          ? "hold-project-binding-required requires at least one binding key"
          : "required_binding_keys must be empty outside hold-project-binding-required",
      });
    }
    if (!isStrictlySortedUniqueUtf8(resolution.required_binding_keys)) {
      ctx.addIssue({
        code: "custom",
        path: ["required_binding_keys"],
        message: "required_binding_keys must be unique and sorted by UTF-8 bytes",
      });
    }
    const needsClarification =
      resolution.terminal_state === "hold-ambiguous" ||
      resolution.terminal_state === "hold-project-binding-required";
    if (resolution.needs_clarification !== needsClarification) {
      ctx.addIssue({
        code: "custom",
        path: ["needs_clarification"],
        message: "needs_clarification must be true only for ambiguous or binding-required HOLDs",
      });
    }
  });

export const CompilationRecord = z
  .object({
    schema_version: SchemaVersion,
    compilation_id: MachineId,
    selected_loop_family: HumanId,
    selected_loop_version: LoopVersion,
    input_bindings: z.record(HumanId, z.string().min(1)),
    context_snapshot: z.array(z.string()),
    effective_risk_controls: z.object({
      max_tier_without_approval: RiskTierV1,
      t5_allowed: z.literal(false),
    }),
    approval_requirements: z.array(z.string()),
    compiler_findings: z.array(z.string()),
    proof_boundary: z.object({
      can_prove: z.array(z.string().min(1)).min(1),
      cannot_prove: z.array(z.string().min(1)).min(1),
    }),
  })
  .strict();
export const CompilationRecordV01 = CompilationRecord;

const CompilationInputBindingV02 = z
  .object({
    key: BindingKeyV02,
    source: z.enum(["operator", "workspace-observation"]),
  })
  .strict();

export const CompilationRecordV02 = z
  .object({
    schema_version: z.literal("0.2"),
    compilation_id: MachineId,
    compiler_bundle_id: MachineId,
    catalog_version_hash: Hash,
    binding_input_id: MachineId,
    binding_input_hash: Hash,
    selected_loop_family: HumanId,
    selected_loop_version: LoopVersion,
    input_bindings: z.array(CompilationInputBindingV02),
    context_snapshot: z
      .object({
        required: z.array(z.string()),
        forbidden: z.array(z.string()),
        untrusted_sources: z.array(z.string()),
      })
      .strict(),
    effective_risk_controls: z
      .object({
        max_tier_without_approval: RiskTierV1,
        t5_allowed: z.literal(false),
      })
      .strict(),
    approval_requirements: z.array(z.string()),
    compiler_findings: z.array(z.string()),
    proof_boundary: z
      .object({
        can_prove: z.array(z.string().min(1)).min(1),
        cannot_prove: z.array(z.string().min(1)).min(1),
      })
      .strict(),
  })
  .strict()
  .superRefine((record, ctx) => {
    const keys = record.input_bindings.map(({ key }) => key);
    if (!isStrictlySortedUniqueUtf8(keys)) {
      ctx.addIssue({
        code: "custom",
        path: ["input_bindings"],
        message: "input_bindings must have unique keys sorted by UTF-8 bytes",
      });
    }
  });

export const ApprovedIntakeBrief = z
  .object({
    schema_version: SchemaVersion,
    intake_brief_id: MachineId,
    objective: z.string().min(1),
    scope: z.array(z.string()).min(1),
    allowed_context: z.array(z.string()),
    forbidden_context: z.array(z.string()),
    allowed_tools: z.array(HumanId),
    allowed_connectors: z.array(HumanId),
    max_risk_tier: RiskTierV1,
    approval_bindings: z.array(z.string()),
    terminal_states: z.array(CompilerTerminalState).min(1),
  })
  .strict();
export const ApprovedIntakeBriefV01 = ApprovedIntakeBrief;

export const ApprovedIntakeBriefV02 = ApprovedIntakeBrief.omit({ terminal_states: true }).extend({
  schema_version: z.literal("0.2"),
}).strict();

export const SpecialistHandoff = z
  .object({
    schema_version: SchemaVersion,
    handoff_id: MachineId,
    run_id: MachineId,
    from_role: HumanId,
    to_role: HumanId,
    task_id: HumanId,
    owned_scope: z.array(z.string()).min(1),
    inputs_consumed: z.array(Ref),
    outputs_produced: z.array(Ref),
    files_read: z.array(z.string()),
    files_written: z.array(z.string()),
    evidence_refs: z.array(Ref),
    gate_refs: z.array(Ref),
    strong_claims: z.array(z.string()),
    findings: z.array(z.string()),
    unresolved_risks: z.array(z.string()),
    next_acceptance_checks: z.array(z.string()).min(1),
    must_not_assume: z.array(z.string()),
    created_at: IsoTimestamp,
  })
  .strict();

export type WorkItemRecord = z.infer<typeof WorkItemRecord>;
export type WorkItemRecordV01 = z.infer<typeof WorkItemRecordV01>;
export type WorkItemRecordV02 = z.infer<typeof WorkItemRecordV02>;
export type IntakeRecord = z.infer<typeof IntakeRecord>;
export type IntakeRecordV01 = z.infer<typeof IntakeRecordV01>;
export type IntakeRecordV02 = z.infer<typeof IntakeRecordV02>;
export type CatalogResolution = z.infer<typeof CatalogResolution>;
export type CatalogResolutionV01 = z.infer<typeof CatalogResolutionV01>;
export type CatalogResolutionV02 = z.infer<typeof CatalogResolutionV02>;
export type CompilationRecord = z.infer<typeof CompilationRecord>;
export type CompilationRecordV01 = z.infer<typeof CompilationRecordV01>;
export type CompilationRecordV02 = z.infer<typeof CompilationRecordV02>;
export type ApprovedIntakeBrief = z.infer<typeof ApprovedIntakeBrief>;
export type ApprovedIntakeBriefV01 = z.infer<typeof ApprovedIntakeBriefV01>;
export type ApprovedIntakeBriefV02 = z.infer<typeof ApprovedIntakeBriefV02>;
export type SpecialistHandoff = z.infer<typeof SpecialistHandoff>;

export type CompilerRecordFamilyDispatchResult =
  | { ok: true; schema_version: "0.1" | "0.2" }
  | {
      ok: false;
      reason:
        | "MISSING_SCHEMA_VERSION"
        | "MALFORMED_SCHEMA_VERSION"
        | "UNSUPPORTED_SCHEMA_VERSION"
        | "MIXED_SCHEMA_VERSION";
      message: string;
    };

const SUPPORTED_COMPILER_SCHEMA_VERSIONS = new Set(["0.1", "0.2"]);

export function dispatchCompilerRecordFamily(records: readonly unknown[]): CompilerRecordFamilyDispatchResult {
  let selected: "0.1" | "0.2" | undefined;
  for (const record of records) {
    if (typeof record !== "object" || record === null || !("schema_version" in record)) {
      return { ok: false, reason: "MISSING_SCHEMA_VERSION", message: "schema_version is required." };
    }
    const schemaVersion = (record as { schema_version?: unknown }).schema_version;
    if (typeof schemaVersion !== "string" || !/^\d+\.\d+$/.test(schemaVersion)) {
      return {
        ok: false,
        reason: "MALFORMED_SCHEMA_VERSION",
        message: "schema_version must be a canonical major.minor string.",
      };
    }
    if (!SUPPORTED_COMPILER_SCHEMA_VERSIONS.has(schemaVersion)) {
      return {
        ok: false,
        reason: "UNSUPPORTED_SCHEMA_VERSION",
        message: "schema_version is not supported; supported versions are '0.1' and '0.2'.",
      };
    }
    const supportedVersion = schemaVersion as "0.1" | "0.2";
    if (selected !== undefined && selected !== supportedVersion) {
      return {
        ok: false,
        reason: "MIXED_SCHEMA_VERSION",
        message: "Compile pack members do not share one literal schema_version.",
      };
    }
    selected = supportedVersion;
  }
  if (selected === undefined) {
    return { ok: false, reason: "MISSING_SCHEMA_VERSION", message: "schema_version is required." };
  }
  return { ok: true, schema_version: selected };
}

export interface CompilerIssue {
  path: string;
  message: string;
}

export function checkSpecialistHandoffInvariants(handoff: SpecialistHandoff): CompilerIssue[] {
  const issues: CompilerIssue[] = [];
  if (handoff.strong_claims.length > 0 && handoff.evidence_refs.length === 0) {
    issues.push({
      path: "evidence_refs",
      message: "handoff with strong_claims requires evidence_refs",
    });
  }
  if (handoff.files_written.length > 0 && handoff.owned_scope.length === 0) {
    issues.push({
      path: "owned_scope",
      message: "handoff with files_written requires owned_scope",
    });
  }
  return issues;
}
