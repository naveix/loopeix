import { z } from "zod";
import { Hash, HumanId, IsoTimestamp, LoopVersion, MachineId, RiskTierV1, SchemaVersion } from "../schema/scalars.js";

export const CompilerTerminalState = z.enum([
  "compiled",
  "hold-ambiguous",
  "hold-risk",
  "hold-no-item",
  "failed-invalid-catalog",
]);

const Ref = z.string().min(1);

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

export const CatalogCandidate = z
  .object({
    item_id: HumanId,
    score: z.number(),
    reasons: z.array(z.string()).min(1),
  })
  .strict();

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
export type IntakeRecord = z.infer<typeof IntakeRecord>;
export type CatalogResolution = z.infer<typeof CatalogResolution>;
export type CompilationRecord = z.infer<typeof CompilationRecord>;
export type ApprovedIntakeBrief = z.infer<typeof ApprovedIntakeBrief>;
export type SpecialistHandoff = z.infer<typeof SpecialistHandoff>;

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
